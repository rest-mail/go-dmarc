package dmarc

import (
	"encoding/xml"
	"testing"
)

// TestAuthResults_ReportsAuthenticatingDomains is the issue #6 regression: the
// auth_results section must report the DKIM signature's d= domain and the
// SPF-checked domain, not the header-From domain, and must report every DKIM
// signature (RFC 7489 §7.2, Appendix C).
func TestAuthResults_ReportsAuthenticatingDomains(t *testing.T) {
	rec := AggregateRecord{
		Domain:      "example.test", // header-From / reported-on domain
		SourceIP:    "192.0.2.1",
		HeaderFrom:  "example.test",
		Disposition: "reject",
		DKIM: []DKIMAuth{
			{Domain: "thirdparty-signer.net", Selector: "sel1", Result: "pass", Aligned: false},
			{Domain: "example.test", Selector: "sel2", Result: "pass", Aligned: true},
		},
		SPF: []SPFAuth{
			{Domain: "bounce.marketing.net", Scope: "mfrom", Result: "pass", Aligned: false},
		},
	}
	rows := AggregateRecords([]AggregateRecord{rec})
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	ar := rows[0].AuthResults

	// Every DKIM signature must be reported with its own d= domain and selector.
	if len(ar.DKIM) != 2 {
		t.Fatalf("want 2 dkim entries (one per signature), got %d: %+v", len(ar.DKIM), ar.DKIM)
	}
	if ar.DKIM[0].Domain != "thirdparty-signer.net" || ar.DKIM[0].Selector != "sel1" {
		t.Errorf("dkim[0] = %+v, want d=thirdparty-signer.net s=sel1 (the signature's own domain, not header-From)", ar.DKIM[0])
	}
	if ar.DKIM[1].Domain != "example.test" || ar.DKIM[1].Selector != "sel2" {
		t.Errorf("dkim[1] = %+v, want d=example.test s=sel2", ar.DKIM[1])
	}

	// The SPF entry must carry the checked domain and scope, not the From domain.
	if len(ar.SPF) != 1 {
		t.Fatalf("want 1 spf entry, got %d: %+v", len(ar.SPF), ar.SPF)
	}
	if ar.SPF[0].Domain != "bounce.marketing.net" {
		t.Errorf("spf.Domain = %q, want the checked domain bounce.marketing.net (not the header-From domain)", ar.SPF[0].Domain)
	}
	if ar.SPF[0].Scope != "mfrom" {
		t.Errorf("spf.Scope = %q, want mfrom", ar.SPF[0].Scope)
	}

	// policy_evaluated is still the DMARC-aligned verdict: the aligned DKIM
	// signature passed, the SPF check did not align.
	if pe := rows[0].Row.PolicyEvaluated; pe.DKIM != "pass" || pe.SPF != "fail" {
		t.Errorf("policy_evaluated = %+v, want dkim=pass spf=fail", pe)
	}
}

// TestAuthResults_OmitsDKIMWhenUnsigned checks that an unsigned message produces
// no <dkim> element at all (RFC 7489 Appendix C: dkim is minOccurs="0").
func TestAuthResults_OmitsDKIMWhenUnsigned(t *testing.T) {
	rec := AggregateRecord{
		Domain: "example.test", SourceIP: "192.0.2.2", HeaderFrom: "example.test", Disposition: "none",
		SPF: []SPFAuth{{Domain: "example.test", Scope: "mfrom", Result: "pass", Aligned: true}},
	}
	rows := AggregateRecords([]AggregateRecord{rec})
	if n := len(rows[0].AuthResults.DKIM); n != 0 {
		t.Errorf("unsigned message must emit no <dkim> entry, got %d: %+v", n, rows[0].AuthResults.DKIM)
	}
	xmlBytes, err := BuildReport(ReportMetadata{}, PolicyPublished{Domain: "example.test", P: "none"}, []AggregateRecord{rec})
	if err != nil {
		t.Fatal(err)
	}
	// Round-trip: the auth_results dkim slice must be empty. (A substring check
	// for "<dkim>" would false-positive on policy_evaluated's own <dkim> element.)
	var fb Feedback
	if err := xml.Unmarshal(xmlBytes, &fb); err != nil {
		t.Fatal(err)
	}
	if n := len(fb.Records[0].AuthResults.DKIM); n != 0 {
		t.Errorf("unsigned message must not marshal any auth_results <dkim>, got %d:\n%s", n, xmlBytes)
	}
}
