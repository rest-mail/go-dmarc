package dmarc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Exercise net.LookupTXT itself, rather than joining strings in the test's
// resolver stub. Each inner slice is one TXT RR; its strings must be joined
// without separators, while different RRs must remain separate candidates.
//
// checklist: DMARC-REC-01
func TestRFC7489TXTCharacterStrings(t *testing.T) {
	const record = "v=DMARC1; p=reject; rua=mailto:reports@example.test"
	cases := []struct {
		name    string
		records [][]string
		want    string
	}{
		{"split version policy and URI", [][]string{{"v=DM", "ARC1; p=re", "ject; rua=mailto:re", "ports@example.test"}}, record},
		{"empty strings add no separators", [][]string{{"", "v=DMARC1; p=", "", "re", "ject", ""}}, "v=DMARC1; p=reject"},
		{"unrelated record stays separate", [][]string{{"verification=", "token"}, {"v=DMARC1; ", "p=reject"}}, "v=DMARC1; p=reject"},
		{"two DMARC records stay ambiguous", [][]string{{"v=DM", "ARC1; p=reject"}, {"v=DMARC1; p=", "none"}}, ""},
		{"version cannot span records", [][]string{{"v=DM"}, {"ARC1; p=reject"}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useWireTXTResolver(t, map[string][][]string{"_dmarc.example.test.": tc.records})
			got, err := Lookup("example.test", nil)
			if err != nil || got != tc.want {
				t.Fatalf("Lookup = %q, %v; want %q", got, err, tc.want)
			}
			policy, err := Discover("example.test", nil, nil)
			if err != nil || policy.Raw != tc.want {
				t.Fatalf("Discover = %+v, %v; want raw %q", policy, err, tc.want)
			}
			if tc.want != "" && policy.Requested != "reject" {
				t.Errorf("joined policy = %q; want reject", policy.Requested)
			}
		})
	}

	t.Run("organizational fallback", func(t *testing.T) {
		useWireTXTResolver(t, map[string][][]string{
			"_dmarc.mail.example.test.": nil,
			"_dmarc.example.test.":      {{"v=DMARC1; p=none; s", "p=quaran", "tine"}},
		})
		policy, err := Discover("mail.example.test", nil, nil)
		if err != nil || policy.Requested != "quarantine" || !policy.ViaOrgDomain || policy.Domain != "example.test" {
			t.Fatalf("Discover = %+v, %v; want organizational quarantine policy", policy, err)
		}
	})

	t.Run("external destination confirmation", func(t *testing.T) {
		useWireTXTResolver(t, map[string][][]string{
			"example.test._report._dmarc.other.test.": {{"v=DM", "ARC1; rua=mailto:over", "ride@other.test!2", "k"}},
		})
		got, err := AuthorizeReportURIs("example.test", "rua", uris("mailto:original@other.test"), nil, nil)
		if err != nil || len(got) != 1 || got[0].URI != "mailto:override@other.test" || got[0].MaxSize != 2048 {
			t.Fatalf("AuthorizeReportURIs = %+v, %v; want joined override with 2048-byte limit", got, err)
		}
	})
}

func TestWireTXTResolverSearchNames(t *testing.T) {
	const record = "v=DMARC1; p=reject"
	useWireTXTResolver(t, map[string][][]string{
		"_dmarc.example.test.": {{"v=DMARC1; ", "p=reject"}},
	})
	// A system resolver may append its search suffix after a NODATA answer.
	// Query such a name explicitly so this check does not depend on resolv.conf.
	_, err := net.LookupTXT("_dmarc.example.test.search.invalid.")
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("search name lookup = %v; want DNS not-found error", err)
	}
	got, err := Lookup("example.test", nil)
	if err != nil || got != record {
		t.Fatalf("Lookup = %q, %v; want %q", got, err, record)
	}
}

// useWireTXTResolver keeps the production nil-resolver path (net.LookupTXT)
// and replaces only DNS transport. net.Pipe carries length-prefixed DNS wire
// messages, so no public DNS or listening socket is needed. Names outside the
// fixture zone receive NXDOMAIN, including host-configured search suffixes.
// These tests must remain sequential because net.DefaultResolver is global.
func useWireTXTResolver(t *testing.T, zone map[string][][]string) {
	t.Helper()
	var workers sync.WaitGroup
	saved := net.DefaultResolver
	t.Cleanup(func() {
		net.DefaultResolver = saved
		workers.Wait()
	})
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			client, server := net.Pipe()
			// Bound both sides even if a broken fixture or resolver stops reading.
			deadline := time.Now().Add(3 * time.Second)
			if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
				deadline = d
			}
			if err := server.SetDeadline(deadline); err != nil {
				_ = client.Close()
				_ = server.Close()
				return nil, err
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { _ = server.Close() }()
				if err := answerWireTXT(server, zone); err != nil {
					t.Errorf("DNS fixture: %v", err)
				}
			}()
			return client, nil
		},
	}
}

func answerWireTXT(conn net.Conn, zone map[string][][]string) error {
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return err
	}
	query := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(conn, query); err != nil {
		return err
	}
	var request dnsmessage.Message
	if err := request.Unpack(query); err != nil {
		return err
	}
	if len(request.Questions) != 1 || request.Questions[0].Type != dnsmessage.TypeTXT {
		return fmt.Errorf("unexpected DNS questions: %+v", request.Questions)
	}
	question := request.Questions[0]
	records, ok := zone[question.Name.String()]
	response := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID: request.ID, Response: true, Authoritative: true,
			RecursionDesired: request.RecursionDesired, RecursionAvailable: true,
		},
		Questions: request.Questions,
	}
	if !ok {
		response.Header.RCode = dnsmessage.RCodeNameError
	}
	for _, fragments := range records {
		response.Answers = append(response.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   &dnsmessage.TXTResource{TXT: fragments},
		})
	}
	packet, err := response.Pack()
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(length[:], uint16(len(packet)))
	_, err = conn.Write(append(length[:], packet...))
	return err
}
