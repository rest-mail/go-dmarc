package dmarc

import (
	"errors"
	"math"
	"net"
	"reflect"
	"testing"
)

// uris builds report URIs without size limits.
func uris(ss ...string) []ReportURI {
	out := make([]ReportURI, len(ss))
	for i, s := range ss {
		out[i] = ReportURI{URI: s, MaxSize: math.MaxUint64}
	}
	return out
}

// TestAuthorizeReportURIs checks the RFC 7489 §7.1 verification of external
// report destinations: URIs inside the policy's Organizational Domain pass
// unchecked; others need a v=DMARC1 record at
// <policy domain>._report._dmarc.<host>; a confirming record's rua=/ruf= may
// replace the URI, but only with URIs on the same host; and a DNS failure is
// returned.
//
// checklist: DMARC-EXT-01 DMARC-EXT-02 DMARC-EXT-03 DMARC-EXT-04 DMARC-EXT-05 DMARC-EXT-06
func TestAuthorizeReportURIs(t *testing.T) {
	zone := map[string][]string{
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
		queries = append(queries, name)
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
		in    []ReportURI
		want  []ReportURI
		query int
	}{
		{"same organizational domain", "rua", uris("mailto:dmarc@example.test", "mailto:dmarc@mail.example.test", "https://r.example.test/x"),
			uris("mailto:dmarc@example.test", "mailto:dmarc@mail.example.test", "https://r.example.test/x"), 0},
		{"confirmed", "rua", uris("mailto:dmarc@reports.test"), uris("mailto:dmarc@reports.test"), 1},
		{"confirmed for https", "rua", uris("https://reports.test/dmarc"), uris("https://reports.test/dmarc"), 1},
		{"not confirmed (no record)", "rua", uris("mailto:dmarc@victim.test"), nil, 1},
		{"not confirmed (no v=DMARC1 first)", "rua", uris("mailto:dmarc@notdmarc.test"), nil, 1},
		{"override on the same host", "rua", uris("mailto:dmarc@override.test"),
			[]ReportURI{{"mailto:a@override.test", 1 << 20}, {"mailto:b@override.test", math.MaxUint64}}, 1},
		{"override to another host", "rua", uris("mailto:dmarc@elsewhere.test"), nil, 1},
		{"override of the other tag", "rua", uris("mailto:dmarc@rufonly.test"), uris("mailto:dmarc@rufonly.test"), 1},
		{"override of this tag", "RUF", uris("mailto:dmarc@rufonly.test"), uris("mailto:f@rufonly.test"), 1},
		{"empty override", "rua", uris("mailto:dmarc@empty.test"), nil, 1},
		{"mixed, in order", "rua", uris("mailto:a@victim.test", "mailto:dmarc@example.test", "mailto:b@any.test"),
			uris("mailto:dmarc@example.test", "mailto:b@any.test"), 2},
		{"encoded address and headers", "rua", uris("mailto:dmarc%40x@reports.test?subject=hi"), uris("mailto:dmarc%40x@reports.test?subject=hi"), 1},
		{"no host", "rua", uris("mailto:nobody", "mailto:%zz@reports.test", "urn:isbn:1", "mailto:a@b..test", "%"), nil, 0},
	}
	for _, c := range cases {
		queries = nil
		got, err := AuthorizeReportURIs("example.test", c.tag, c.in, resolver, nil)
		if err != nil || !reflect.DeepEqual(got, c.want) || len(queries) != c.query {
			t.Errorf("%s: got %+v, %v after %d queries %q; want %+v after %d", c.name, got, err, len(queries), queries, c.want, c.query)
		}
	}

	// The policy domain is queried as an A-label.
	queries = nil
	if got, err := AuthorizeReportURIs("Bücher.example", "rua", uris("mailto:d@reports.test"), resolver, nil); err != nil || len(got) != 1 {
		t.Errorf("U-label policy domain: got %+v, %v (queries %q)", got, err, queries)
	}
	// A policy domain that is not a domain authorizes nothing.
	if got, err := AuthorizeReportURIs("not a domain", "rua", uris("mailto:d@reports.test"), resolver, nil); err != nil || got != nil {
		t.Errorf("bad policy domain: got %+v, %v", got, err)
	}
	// A temporary DNS error is returned with the URIs checked so far.
	got, err := AuthorizeReportURIs("example.test", "rua", uris("mailto:a@example.test", "mailto:b@broken.test", "mailto:c@any.test"), resolver, nil)
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !reflect.DeepEqual(got, uris("mailto:a@example.test")) {
		t.Errorf("temporary error: got %+v, %v", got, err)
	}
}
