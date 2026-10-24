package dmarc

import (
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
)

// uris is its arguments, as a list of report URIs.
func uris(ss ...string) []string { return ss }

// TestAuthorizeReportURIs checks the RFC 9990 §4 verification of external
// report destinations: URIs inside the policy's Organizational Domain (found
// by a DNS Tree Walk, RFC 9989 §4.10.2) pass unchecked; others need a
// v=DMARC1 record at
// <policy domain>._report._dmarc.<host>; a confirming record's rua=/ruf= may
// replace the URI, but only with URIs on the same host; and a DNS failure is
// returned.
//
// checklist: DMARC-EXT-01 DMARC-EXT-02 DMARC-EXT-03 DMARC-EXT-04 DMARC-EXT-05 DMARC-EXT-06 DMARC-EXT-08
func TestAuthorizeReportURIs(t *testing.T) {
	zone := map[string][]string{
		// example.test is its subdomains' Organizational Domain.
		"_dmarc.example.test": {"v=DMARC1; p=reject"},
		// Confirms, with no override.
		"example.test._report._dmarc.reports.test": {"v=spf1 -all", "v=DMARC1"},
		// Only non-DMARC records, or v=DMARC1 not first: not confirmed.
		"example.test._report._dmarc.notdmarc.test": {"v=spf1 -all", "rua=mailto:x@notdmarc.test; v=DMARC1"},
		// Confirms and overrides rua= on the same host.
		"example.test._report._dmarc.override.test": {"v=DMARC1; rua=mailto:a@override.test!1m, mailto:b@override.test"},
		// Overrides rua= with a different host: neither is used.
		"example.test._report._dmarc.elsewhere.test": {"v=DMARC1; rua=mailto:a@elsewhere.test,mailto:a@victim.test"},
		// Overrides ruf= only; the rua= URI stands.
		"example.test._report._dmarc.rufonly.test": {"v=DMARC1; ruf=mailto:f@rufonly.test"},
		// A wildcard confirmation, as §7.1 describes, appears to the resolver
		// as a record at the queried name.
		"example.test._report._dmarc.any.test": {"v=DMARC1"},
		// Overrides with an empty rua=: no URI is left.
		"example.test._report._dmarc.empty.test": {"v=DMARC1; rua="},
		// An A-label policy domain, as §7.1 step 3 requires.
		"xn--bcher-kva.example._report._dmarc.reports.test": {"v=DMARC1"},
	}
	var queries []string
	resolver := func(name string) ([]string, error) {
		if strings.Contains(name, "._report.") {
			queries = append(queries, name)
		}
		if name == "example.test._report._dmarc.broken.test" {
			return nil, &net.DNSError{Err: "server misbehaving", IsTemporary: true}
		}
		if recs, ok := zone[name]; ok {
			return recs, nil
		}
		return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	}
	cases := []struct {
		name  string
		tag   string
		in    []string
		want  []string
		query int
	}{
		{"same organizational domain", "rua", uris("mailto:dmarc@example.test", "mailto:dmarc@mail.example.test", "https://r.example.test/x"),
			uris("mailto:dmarc@example.test", "mailto:dmarc@mail.example.test", "https://r.example.test/x"), 0},
		{"confirmed", "rua", uris("mailto:dmarc@reports.test"), uris("mailto:dmarc@reports.test"), 1},
		{"confirmed for https", "rua", uris("https://reports.test/dmarc"), uris("https://reports.test/dmarc"), 1},
		{"not confirmed (no record)", "rua", uris("mailto:dmarc@victim.test"), nil, 1},
		{"not confirmed (no v=DMARC1 first)", "rua", uris("mailto:dmarc@notdmarc.test"), nil, 1},
		{"override on the same host", "rua", uris("mailto:dmarc@override.test"),
			uris("mailto:a@override.test", "mailto:b@override.test"), 1},
		{"override to another host", "rua", uris("mailto:dmarc@elsewhere.test"), nil, 1},
		{"override of the other tag", "rua", uris("mailto:dmarc@rufonly.test"), uris("mailto:dmarc@rufonly.test"), 1},
		{"override of this tag", "RUF", uris("mailto:dmarc@rufonly.test"), uris("mailto:f@rufonly.test"), 1},
		{"empty override", "rua", uris("mailto:dmarc@empty.test"), nil, 1},
		{"mixed, in order", "rua", uris("mailto:a@victim.test", "mailto:dmarc@example.test", "mailto:b@any.test"),
			uris("mailto:dmarc@example.test", "mailto:b@any.test"), 2},
		{"encoded address and headers", "rua", uris("mailto:dmarc%40x@reports.test?subject=hi"), uris("mailto:dmarc%40x@reports.test?subject=hi"), 1},
		{"no host", "rua", uris("mailto:nobody", "mailto:%zz@reports.test", "urn:isbn:1", "mailto:a@b..test", "%"), nil, 0},
		// RFC 9990 §4 step 4: a name too long for the DNS cannot confirm anything.
		{"name too long", "rua", uris("mailto:a@" + strings.Repeat("x", 60) + "." + strings.Repeat("y", 60) + "." + strings.Repeat("z", 60) + "." + strings.Repeat("w", 50) + ".test"), nil, 0},
	}
	for _, c := range cases {
		queries = nil
		got, err := AuthorizeReportURIs("example.test", c.tag, c.in, resolver)
		if err != nil || !reflect.DeepEqual(got, c.want) || len(queries) != c.query {
			t.Errorf("%s: got %+v, %v after %d queries %q; want %+v after %d", c.name, got, err, len(queries), queries, c.want, c.query)
		}
	}

	// The policy domain is queried as an A-label.
	queries = nil
	if got, err := AuthorizeReportURIs("Bücher.example", "rua", uris("mailto:d@reports.test"), resolver); err != nil || len(got) != 1 {
		t.Errorf("U-label policy domain: got %+v, %v (queries %q)", got, err, queries)
	}
	// A policy domain that is not a domain authorizes nothing.
	if got, err := AuthorizeReportURIs("not a domain", "rua", uris("mailto:d@reports.test"), resolver); err != nil || got != nil {
		t.Errorf("bad policy domain: got %+v, %v", got, err)
	}
	// A DNS error while walking the tree for the policy domain, or for a
	// destination host, is returned too.
	walkErr := &net.DNSError{Err: "server misbehaving", IsTemporary: true}
	failing := func(at string) TXTResolver {
		return func(name string) ([]string, error) {
			if name == at {
				return nil, walkErr
			}
			return resolver(name)
		}
	}
	if got, err := AuthorizeReportURIs("example.test", "rua", uris("mailto:a@reports.test"), failing("_dmarc.example.test")); !errors.Is(err, walkErr) || got != nil {
		t.Errorf("policy walk error: got %+v, %v", got, err)
	}
	if got, err := AuthorizeReportURIs("example.test", "rua", uris("mailto:a@example.test", "mailto:b@reports.test"), failing("_dmarc.reports.test")); !errors.Is(err, walkErr) ||
		!reflect.DeepEqual(got, uris("mailto:a@example.test")) {
		t.Errorf("host walk error: got %+v, %v", got, err)
	}

	// A temporary DNS error is returned with the URIs checked so far.
	got, err := AuthorizeReportURIs("example.test", "rua", uris("mailto:a@example.test", "mailto:b@broken.test", "mailto:c@any.test"), resolver)
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !reflect.DeepEqual(got, uris("mailto:a@example.test")) {
		t.Errorf("temporary error: got %+v, %v", got, err)
	}
}
