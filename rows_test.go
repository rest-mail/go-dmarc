package dmarc

import (
	"fmt"
	"math"
	"reflect"
	"testing"
)

// tracingResolver answers from zone and records every name it is asked for.
type tracingResolver struct {
	zone    map[string][]string
	queries []string
}

func (r *tracingResolver) lookup(name string) ([]string, error) {
	r.queries = append(r.queries, name)
	return r.zone[name], nil
}

// TestNoRUANoAggregateDestinations checks that a record without a usable rua=
// gives a reporter nowhere to send an aggregate report: Record.RUA is empty,
// whether rua= is missing or lists only invalid URIs, through ParseRecord and
// Discover alike, and AuthorizeReportURIs turns the empty list into no
// destinations without a DNS query.
//
// checklist: DMARC-URI-08
func TestNoRUANoAggregateDestinations(t *testing.T) {
	for _, txt := range []string{
		"v=DMARC1; p=reject",
		"v=DMARC1; p=reject; ruf=mailto:forensic@example.com",
		"v=DMARC1; p=quarantine; rua=not a uri, also-not-a-uri",
		"v=DMARC1; p=none; rua=mailto:reports@example.com!12x",
	} {
		rec, err := ParseRecord(txt)
		if err != nil {
			t.Fatalf("ParseRecord(%q): %v", txt, err)
		}
		if len(rec.RUA) != 0 {
			t.Errorf("ParseRecord(%q).RUA = %v, want none", txt, rec.RUA)
		}

		r := &tracingResolver{zone: map[string][]string{"_dmarc.example.com": {txt}}}
		p, err := Discover("example.com", r.lookup, nil)
		if err != nil {
			t.Fatalf("Discover with %q: %v", txt, err)
		}
		if p.Raw != txt || len(p.Record.RUA) != 0 {
			t.Errorf("Discover with %q = raw %q, RUA %v; want the record with no RUA", txt, p.Raw, p.Record.RUA)
		}

		r.queries = nil
		dest, err := AuthorizeReportURIs(p.Domain, "rua", p.Record.RUA, r.lookup, nil)
		if err != nil || len(dest) != 0 {
			t.Errorf("AuthorizeReportURIs for %q = %v, %v; want no destinations", txt, dest, err)
		}
		if len(r.queries) != 0 {
			t.Errorf("AuthorizeReportURIs for %q queried %v; want no DNS queries", txt, r.queries)
		}
	}

	// A record whose only rua= URI is invalid and whose p= is missing has no
	// policy at all (§6.6.3 step 6), so there is nothing to report on.
	if _, err := ParseRecord("v=DMARC1; rua=not a uri"); err != ErrNoPolicy {
		t.Errorf("ParseRecord without p= or a valid rua= = %v, want ErrNoPolicy", err)
	}
}

// TestRUADeliveryOrderAndLimits checks what §7.2.1's delivery rule needs from
// the record: the rua= URIs in the order published, each with its size limit
// in bytes, so a reporter can try them in order and skip those too small for
// the report (ExampleReportURI_delivery shows the loop).
//
// checklist: DMARC-AGG-09
func TestRUADeliveryOrderAndLimits(t *testing.T) {
	rec, err := ParseRecord("v=DMARC1; p=none; rua=mailto:small@example.com!1k, https://reports.example.com/dmarc, mailto:big@example.com!10m, mailto:tiny@example.com!500")
	if err != nil {
		t.Fatal(err)
	}
	want := []ReportURI{
		{URI: "mailto:small@example.com", MaxSize: 1 << 10},
		{URI: "https://reports.example.com/dmarc", MaxSize: math.MaxUint64},
		{URI: "mailto:big@example.com", MaxSize: 10 << 20},
		{URI: "mailto:tiny@example.com", MaxSize: 500},
	}
	if !reflect.DeepEqual(rec.RUA, want) {
		t.Fatalf("RUA = %v, want %v", rec.RUA, want)
	}

	// Authorization keeps the order and the limits of the URIs it keeps.
	dest, err := AuthorizeReportURIs("example.com", "rua", rec.RUA, (&tracingResolver{}).lookup, nil)
	if err != nil || !reflect.DeepEqual(dest, want) {
		t.Fatalf("AuthorizeReportURIs = %v, %v; want %v", dest, err, want)
	}

	for _, tc := range []struct {
		size uint64
		want []string
	}{
		{size: 500, want: []string{"mailto:small@example.com", "https://reports.example.com/dmarc", "mailto:big@example.com", "mailto:tiny@example.com"}},
		{size: 501, want: []string{"mailto:small@example.com", "https://reports.example.com/dmarc", "mailto:big@example.com"}},
		{size: 1 << 10, want: []string{"mailto:small@example.com", "https://reports.example.com/dmarc", "mailto:big@example.com"}},
		{size: 1<<10 + 1, want: []string{"https://reports.example.com/dmarc", "mailto:big@example.com"}},
		{size: 10<<20 + 1, want: []string{"https://reports.example.com/dmarc"}},
	} {
		if got := deliveryTargets(dest, tc.size); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("a %d-byte report goes to %v, want %v", tc.size, got, tc.want)
		}
	}
}

// deliveryTargets is the §7.2.1 rule a reporter applies to the URIs: every
// one, in order, except those whose size limit the report exceeds.
func deliveryTargets(uris []ReportURI, size uint64) []string {
	var out []string
	for _, u := range uris {
		if size > u.MaxSize {
			continue
		}
		out = append(out, u.URI)
	}
	return out
}

// ExampleReportURI_delivery sends a report to each rua= URI in the order
// published, skipping the URIs whose size limit it exceeds (§7.2.1).
//
// checklist: DMARC-AGG-09
func ExampleReportURI_delivery() {
	rec, err := ParseRecord("v=DMARC1; p=none; rua=mailto:a@example.com!2k, mailto:b@example.com!50k, mailto:c@example.com")
	if err != nil {
		panic(err)
	}
	report := make([]byte, 4096) // the gzipped report
	for _, u := range rec.RUA {
		if uint64(len(report)) > u.MaxSize {
			fmt.Println("skip", u.URI)
			continue
		}
		fmt.Println("send to", u.URI)
	}
	// Output:
	// skip mailto:a@example.com
	// send to mailto:b@example.com
	// send to mailto:c@example.com
}

// TestDiscoverWithoutOneFromDomain checks §6.6.1's edge: a message with no
// From domain, several, or a group address has no single domain to look up.
// Given anything that is not one domain, Discover applies no policy and
// queries no DNS, so such mail is left to the caller's local policy.
//
// checklist: DMARC-DISC-11
func TestDiscoverWithoutOneFromDomain(t *testing.T) {
	r := &tracingResolver{zone: map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=reject"},
		"_dmarc.example.org": {"v=DMARC1; p=reject"},
	}}
	for _, from := range []string{
		"",                                 // no From field, or one without a domain
		".",                                // the root, not a domain
		"example.com, example.org",         // several From addresses
		"example.com example.org",          // several, space-separated
		"undisclosed-recipients:;",         // a group with no members
		"friends: a@example.com;",          // a group
		"a@example.com",                    // an address, not its domain
		"<example.com>",                    // still not a bare domain
		"example.com\r\nFrom: example.org", // two From fields run together
	} {
		r.queries = nil
		p, err := Discover(from, r.lookup, nil)
		if err != nil {
			t.Errorf("Discover(%q): %v", from, err)
		}
		if p.Raw != "" || p.Domain != "" || p.Requested != "none" {
			t.Errorf("Discover(%q) = %+v, want no policy", from, p)
		}
		if len(r.queries) != 0 {
			t.Errorf("Discover(%q) queried %v, want no DNS queries", from, r.queries)
		}
	}

	// The same resolver does give a policy for one domain.
	if p, err := Discover("example.com", r.lookup, nil); err != nil || p.Requested != "reject" {
		t.Fatalf("Discover(example.com) = %+v, %v; want p=reject", p, err)
	}
}
