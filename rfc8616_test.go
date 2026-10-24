package dmarc

import (
	"reflect"
	"strings"
	"testing"
)

// TestRFC8616ULabels checks RFC 8616 §6, which updates RFC 7489 §§6.6.1 and
// 7.1 (RFC 9989 §5.3.1 says the same): every U-label in a domain DMARC
// handles is converted to an A-label before further processing. The From
// domain is looked up and aligned as A-labels, and the policy domain in a
// §7.1 authorization query is an A-label.
//
// checklist: DMARC-EAI-01 DMARC-EAI-02
func TestRFC8616ULabels(t *testing.T) {
	r := &tracingResolver{zone: map[string][]string{
		"_dmarc.xn--bcher-kva.example": {"v=DMARC1; p=reject; rua=mailto:d@reports.test"},
	}}
	p, err := Discover("Mail.BÜCHER.example", r.lookup, nil)
	if err != nil || p.Requested != "reject" {
		t.Fatalf("Discover = %+v, %v", p, err)
	}
	want := []string{"_dmarc.mail.xn--bcher-kva.example", "_dmarc.xn--bcher-kva.example", "_dmarc.example"}
	if !reflect.DeepEqual(r.queries, want) {
		t.Errorf("queried %q, want %q", r.queries, want)
	}
	for _, c := range [][2]string{
		{"bücher.example", "xn--bcher-kva.example"},
		{"mail.xn--bcher-kva.example", "Bücher.Example"},
	} {
		if ok, err := AlignedMode(c[0], c[1], AlignmentRelaxed, r.lookup); !ok || err != nil {
			t.Errorf("%q and %q do not align as A-labels: %v", c[0], c[1], err)
		}
	}

	r.zone["xn--bcher-kva.example._report._dmarc.reports.test"] = []string{"v=DMARC1"}
	r.queries = nil
	uris := []string{"mailto:d@reports.test"}
	got, err := AuthorizeReportURIs("bücher.example", "rua", uris, r.lookup)
	if err != nil || !reflect.DeepEqual(got, uris) {
		t.Errorf("AuthorizeReportURIs = %+v, %v; want %+v", got, err, uris)
	}
	var asked []string
	for _, q := range r.queries {
		if strings.Contains(q, "._report.") {
			asked = append(asked, q)
		}
	}
	if want := []string{"xn--bcher-kva.example._report._dmarc.reports.test"}; !reflect.DeepEqual(asked, want) {
		t.Errorf("asked %q, want %q", asked, want)
	}
}

// TestRFC8616ConventionalReportAddresses checks RFC 8616 §6: a policy record
// serves internationalized and conventional mail alike, so its rua= and ruf=
// addresses are conventional. A mailto: URI naming an internationalized
// address (a UTF-8 local part or a U-label domain, raw or percent-encoded) is
// not a valid report URI and is left out; the conventional ones around it,
// including an A-label domain, keep their order.
//
// checklist: DMARC-EAI-03
func TestRFC8616ConventionalReportAddresses(t *testing.T) {
	valid := []string{
		"mailto:a@example.test",
		"mailto:b@xn--bcher-kva.example",
		"MAILTO:c%2Bd@example.test?subject=dmarc",
		"https://reports.example.test/r%C3%A9",
	}
	cases := []string{
		"mailto:rëports@example.test",
		"mailto:reports@bücher.example",
		"mailto:r%C3%ABports@example.test",
		"mailto:reports@b%C3%BCcher.example",
		"mailto:a@example.test%2Cr%C3%AB@example.test",
		"mailto:a%ZZ@example.test",
		"https://bücher.example/reports",
	}
	for _, bad := range cases {
		value := "mailto:a@example.test, " + bad + ", mailto:b@xn--bcher-kva.example!1m, " +
			"MAILTO:c%2Bd@example.test?subject=dmarc, https://reports.example.test/r%C3%A9"
		r := mustParse(t, "v=DMARC1; p=none; rua="+value+"; ruf="+value)
		if !reflect.DeepEqual(r.RUA, valid) || !reflect.DeepEqual(r.RUF, valid) {
			t.Errorf("%q:\nrua %+v\nruf %+v\nwant %+v", bad, r.RUA, r.RUF, valid)
		}
	}
}
