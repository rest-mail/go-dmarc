package recordgrammar

import (
	"reflect"
	"testing"
)

// TestParseReportURIs checks rua= and ruf=: comma-separated URIs in order,
// the obsolete "!" size limit checked for its syntax and dropped, and invalid
// URIs left out.
//
// checklist: DMARC-URI-01 DMARC-URI-02 DMARC-URI-04 DMARC-URI-05
func TestParseReportURIs(t *testing.T) {
	cases := []struct {
		value string
		want  []string
	}{
		{"mailto:a@example.test", []string{"mailto:a@example.test"}},
		{"mailto:a@example.test,mailto:b@example.test, mailto:c@example.test ,https://r.example.test/x",
			[]string{"mailto:a@example.test", "mailto:b@example.test", "mailto:c@example.test", "https://r.example.test/x"}},
		// The obsolete size limit is dropped, whatever its size.
		{"mailto:a@example.test!100", []string{"mailto:a@example.test"}},
		{"mailto:a@example.test!10k", []string{"mailto:a@example.test"}},
		{"mailto:a@example.test!50m,mailto:b@example.test!2G", []string{"mailto:a@example.test", "mailto:b@example.test"}},
		{"mailto:a@example.test!1T", []string{"mailto:a@example.test"}},
		{"mailto:a@example.test!0", []string{"mailto:a@example.test"}},
		{"mailto:a@example.test!18446744073709551616", []string{"mailto:a@example.test"}},
		// A "!" not followed by a size makes the URI invalid, and so does an
		// unencoded "!" in it.
		{"mailto:a@example.test!", nil},
		{"mailto:a@example.test!10x", nil},
		{"mailto:a@example.test!k", nil},
		{"mailto:a!b@example.test!10", nil},
		// An encoded comma or "!" belongs to the URI.
		{"mailto:a%2Cb@example.test,mailto:c%21d@example.test!1k",
			[]string{"mailto:a%2Cb@example.test", "mailto:c%21d@example.test"}},
		// Not URIs: no scheme, nothing after it, whitespace or control
		// characters inside, a bad scheme.
		{"a@example.test,mailto:,mailto:a b@example.test,mailto:a\x00@example.test,1x:a@example.test,,", nil},
		{"", nil},
	}
	for _, c := range cases {
		got := ParseReportURIs(c.value)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("rua=%q: got %+v, want %+v", c.value, got, c.want)
		}
	}
}
