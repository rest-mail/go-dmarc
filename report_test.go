package dmarc

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"io"
	"strings"
	"testing"
)

func TestAggregateRecords_GroupsAndCounts(t *testing.T) {
	recs := []AggregateRecord{
		{Domain: "example.test", SourceIP: "10.0.0.1", HeaderFrom: "a@example.test", Disposition: "none",
			DKIM: []DKIMAuth{{Domain: "example.test", Selector: "s1", Result: "pass", Aligned: true}},
			SPF:  []SPFAuth{{Domain: "example.test", Scope: "mfrom", Result: "pass", Aligned: true}}},
		{Domain: "example.test", SourceIP: "10.0.0.1", HeaderFrom: "a@example.test", Disposition: "none",
			DKIM: []DKIMAuth{{Domain: "example.test", Selector: "s1", Result: "pass", Aligned: true}},
			SPF:  []SPFAuth{{Domain: "example.test", Scope: "mfrom", Result: "pass", Aligned: true}}},
		{Domain: "example.test", SourceIP: "10.0.0.2", HeaderFrom: "a@example.test", Disposition: "reject",
			DKIM: []DKIMAuth{{Domain: "evil.test", Selector: "s9", Result: "fail", Aligned: false}},
			SPF:  []SPFAuth{{Domain: "bounce.evil.test", Scope: "mfrom", Result: "fail", Aligned: false}}},
	}
	rows := AggregateRecords(recs)
	if len(rows) != 2 {
		t.Fatalf("want 2 aggregated rows, got %d", len(rows))
	}
	if rows[0].Row.SourceIP != "10.0.0.1" || rows[0].Row.Count != 2 {
		t.Errorf("first row: %+v", rows[0].Row)
	}
	if rows[0].Row.PolicyEvaluated.DKIM != "pass" || rows[0].Row.PolicyEvaluated.Disposition != "none" {
		t.Errorf("first row eval: %+v", rows[0].Row.PolicyEvaluated)
	}
	if rows[1].Row.Count != 1 || rows[1].Row.PolicyEvaluated.Disposition != "reject" || rows[1].Row.PolicyEvaluated.DKIM != "fail" {
		t.Errorf("second row: %+v", rows[1].Row)
	}
}

func TestEvaluated_RequiresPassAndAlign(t *testing.T) {
	if evaluated("pass", false) != "fail" {
		t.Error("pass-but-unaligned must evaluate to fail")
	}
	if evaluated("pass", true) != "pass" {
		t.Error("pass+aligned must evaluate to pass")
	}
	if evaluated("fail", true) != "fail" {
		t.Error("fail must evaluate to fail")
	}
}

func TestBuildReport_ValidXML(t *testing.T) {
	meta := ReportMetadata{
		OrgName:   "restmail.test",
		Email:     "dmarc@restmail.test",
		ReportID:  "report-1",
		DateRange: DateRange{Begin: 1784700000, End: 1784786400},
	}
	policy := PolicyPublished{Domain: "example.test", ADKIM: "r", ASPF: "r", P: "reject", PCT: 100}
	recs := []AggregateRecord{
		{Domain: "example.test", SourceIP: "10.0.0.1", HeaderFrom: "a@example.test", Disposition: "none",
			DKIM: []DKIMAuth{{Domain: "example.test", Selector: "sel", Result: "pass", Aligned: true}},
			SPF:  []SPFAuth{{Domain: "example.test", Scope: "mfrom", Result: "pass", Aligned: true}}},
	}
	xmlBytes, err := BuildReport(meta, policy, recs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(xmlBytes, []byte("<?xml")) {
		t.Error("missing XML declaration")
	}
	// Round-trip: unmarshal and check the key fields survived.
	var fb Feedback
	if err := xml.Unmarshal(xmlBytes, &fb); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if fb.ReportMetadata.OrgName != "restmail.test" || fb.PolicyPublished.Domain != "example.test" || fb.PolicyPublished.P != "reject" {
		t.Errorf("metadata/policy not preserved: %+v / %+v", fb.ReportMetadata, fb.PolicyPublished)
	}
	if len(fb.Records) != 1 || fb.Records[0].Row.SourceIP != "10.0.0.1" || fb.Records[0].Row.Count != 1 {
		t.Errorf("record not preserved: %+v", fb.Records)
	}
	if len(fb.Records[0].AuthResults.DKIM) != 1 || fb.Records[0].AuthResults.DKIM[0].Result != "pass" {
		t.Errorf("auth_results dkim not preserved: %+v", fb.Records[0].AuthResults)
	}
}

// TestBuildReport_SchemaConformance asserts the marshalled XML honours the
// RFC 7489 Appendix C grammar for the identifiers and auth_results sections:
// the required envelope_from and spf/scope elements are present, and every
// emitted dkim/spf result is a member of the closed enumerations (an empty or
// unknown value must be normalised to "none", never emitted verbatim).
func TestBuildReport_SchemaConformance(t *testing.T) {
	meta := ReportMetadata{OrgName: "restmail.test", Email: "dmarc@restmail.test", ReportID: "r-1", DateRange: DateRange{Begin: 1784700000, End: 1784786400}}
	policy := PolicyPublished{Domain: "example.test", P: "none"}
	// The auth results deliberately carry an empty DKIM result, an empty SPF
	// scope, and an unknown SPF result: the corrected marshaller must supply the
	// required elements and normalise the values into the enumerations.
	recs := []AggregateRecord{{
		Domain: "example.test", SourceIP: "192.0.2.1", Disposition: "none",
		DKIM: []DKIMAuth{{Domain: "example.test", Selector: "sel", Result: ""}},
		SPF:  []SPFAuth{{Domain: "mail.example.test", Scope: "", Result: "bogus"}},
	}}
	out, err := BuildReport(meta, policy, recs)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)

	// identifiers/envelope_from is minOccurs="1"; derive it from the SPF mfrom
	// domain when the caller did not supply one.
	if !strings.Contains(s, "<envelope_from>mail.example.test</envelope_from>") {
		t.Errorf("missing/underived required identifiers/envelope_from element:\n%s", s)
	}
	// spf/scope is minOccurs="1" and must default to a valid enum member.
	if !strings.Contains(s, "<scope>mfrom</scope>") {
		t.Errorf("missing required spf/scope element:\n%s", s)
	}
	// An empty string is not a member of the result enumerations.
	if strings.Contains(s, "<result></result>") {
		t.Errorf("empty <result> violates the DKIM/SPF result enumerations:\n%s", s)
	}
	// An out-of-enumeration value must not survive to the document.
	if strings.Contains(s, "bogus") {
		t.Errorf("unknown SPF result not normalised to a valid enum member:\n%s", s)
	}
	// Both the empty DKIM result and the unknown SPF result normalise to "none".
	if c := strings.Count(s, "<result>none</result>"); c != 2 {
		t.Errorf("want both results normalised to none, got %d occurrences:\n%s", c, s)
	}
}

// TestBuildReport_OmitsDKIMWhenUnsigned asserts that a message that carried no
// DKIM signature produces no <dkim> auth_results element (RFC 7489: dkim is
// minOccurs="0"; an empty <dkim> with no domain/result would be invalid).
func TestBuildReport_OmitsDKIMWhenUnsigned(t *testing.T) {
	meta := ReportMetadata{OrgName: "o", Email: "e", ReportID: "r", DateRange: DateRange{Begin: 1, End: 2}}
	policy := PolicyPublished{Domain: "example.test", P: "none"}
	recs := []AggregateRecord{{
		Domain: "example.test", SourceIP: "192.0.2.1", Disposition: "none",
		SPF: []SPFAuth{{Domain: "mail.example.test", Scope: "mfrom", Result: "pass"}},
	}}
	out, err := BuildReport(meta, policy, recs)
	if err != nil {
		t.Fatal(err)
	}
	var fb Feedback
	if err := xml.Unmarshal(out, &fb); err != nil {
		t.Fatal(err)
	}
	if len(fb.Records) != 1 {
		t.Fatalf("want 1 record, got %d", len(fb.Records))
	}
	if n := len(fb.Records[0].AuthResults.DKIM); n != 0 {
		t.Errorf("unsigned message must not emit a <dkim> auth_results element, got %d:\n%s", n, out)
	}
}

// wantGoldenXML is a known-good RFC 7489 Appendix C aggregate report: it locks
// the element ordering and the presence of every required field.
const wantGoldenXML = `<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <version>1.0</version>
  <report_metadata>
    <org_name>restmail.test</org_name>
    <email>dmarc@restmail.test</email>
    <report_id>report-1</report_id>
    <date_range>
      <begin>1784700000</begin>
      <end>1784786400</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.test</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>reject</p>
    <sp>reject</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.10</source_ip>
      <count>1</count>
      <policy_evaluated>
        <disposition>quarantine</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <envelope_from>mail.example.test</envelope_from>
      <header_from>example.test</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>example.test</domain>
        <selector>sel</selector>
        <result>pass</result>
      </dkim>
      <spf>
        <domain>mail.example.test</domain>
        <scope>mfrom</scope>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
</feedback>`

// TestBuildReport_GoldenXML compares a fully populated report against a
// known-good fixture, locking element order and required-field presence.
func TestBuildReport_GoldenXML(t *testing.T) {
	meta := ReportMetadata{OrgName: "restmail.test", Email: "dmarc@restmail.test", ReportID: "report-1", DateRange: DateRange{Begin: 1784700000, End: 1784786400}}
	policy := PolicyPublished{Domain: "example.test", ADKIM: "r", ASPF: "r", P: "reject", SP: "reject", PCT: 100}
	recs := []AggregateRecord{{
		Domain: "example.test", SourceIP: "192.0.2.10", Disposition: "quarantine",
		DKIM: []DKIMAuth{{Domain: "example.test", Selector: "sel", Result: "pass", Aligned: true}},
		SPF:  []SPFAuth{{Domain: "mail.example.test", Scope: "mfrom", Result: "pass", Aligned: true}},
	}}
	out, err := BuildReport(meta, policy, recs)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(out); got != wantGoldenXML {
		t.Errorf("golden XML mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, wantGoldenXML)
	}
}

func TestGzip_RoundTrip(t *testing.T) {
	data := []byte("<?xml version=\"1.0\"?><feedback>hello</feedback>")
	gz, err := Gzip(data)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(zr)
	if !bytes.Equal(got, data) {
		t.Errorf("gzip round-trip mismatch")
	}
}
