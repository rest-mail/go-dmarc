package dmarc

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"io"
	"reflect"
	"strings"
	"testing"
)

// TestAggregateRecords_GroupsAndCounts checks that identical rows are summed into one count and every message is counted.
//
// checklist: DMARC-AGG-05 DMARC-POL-07
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

// TestEvaluated_RequiresPassAndAlign checks that a mechanism counts for DMARC only when it passed and aligned.
//
// checklist: DMARC-ALIGN-05
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

// TestBuildReport_ValidXML checks the document is well-formed XML with version 1.0.
//
// checklist: DMARC-XML-01
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
//
// checklist: DMARC-XML-06 DMARC-XML-10 DMARC-AGG-02
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
//
// checklist: DMARC-XML-05
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
    <fo>0</fo>
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
//
// checklist: DMARC-XML-02 DMARC-XML-03
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

// TestGzip_RoundTrip checks that Gzip output decompresses to the report.
//
// checklist: DMARC-AGG-12
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

// testMeta is the report metadata the tests use.
var testMeta = ReportMetadata{OrgName: "receiver.test", Email: "dmarc@receiver.test", ReportID: "r-1", DateRange: DateRange{Begin: 1784700000, End: 1784786400}}

// mustValidReport builds a report and checks it against the Appendix C schema.
func mustValidReport(t *testing.T, policy PolicyPublished, recs []AggregateRecord) Feedback {
	t.Helper()
	out, err := BuildReport(testMeta, policy, recs)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateReport(out); err != nil {
		t.Fatalf("report does not validate: %v\n%s", err, out)
	}
	var fb Feedback
	if err := xml.Unmarshal(out, &fb); err != nil {
		t.Fatal(err)
	}
	return fb
}

// TestReportValidatesAgainstAppendixC checks reports of every shape against
// the Appendix C schema: signed and unsigned, with and without SPF results,
// with IPv4, IPv6 and IPv4-mapped addresses, with override reasons, and with
// the values the normalizers map to their enumerations.
//
// checklist: DMARC-XML-02 DMARC-XML-06
func TestReportValidatesAgainstAppendixC(t *testing.T) {
	policies := []PolicyPublished{
		{Domain: "example.test", P: "reject"},
		{Domain: "example.test", ADKIM: "s", ASPF: "R", P: "Quarantine", SP: "none", PCT: 25, FO: "1:d"},
		{Domain: "example.test", ADKIM: "strict", ASPF: "x", P: "bogus", SP: "bogus", PCT: 0},
	}
	recs := []AggregateRecord{
		{Domain: "example.test", SourceIP: "192.0.2.1", Disposition: "reject"},
		{Domain: "example.test", SourceIP: "2001:db8::1", Disposition: "QUARANTINE", EnvelopeFrom: "bounce.example.test",
			DKIM: []DKIMAuth{{Domain: "example.test", Result: "PASS", Aligned: true}, {Domain: "other.test", Selector: "s", Result: "weird"}},
			SPF:  []SPFAuth{{Domain: "bounce.example.test", Scope: "HELO", Result: "SoftFail"}, {Domain: "x.test", Scope: "", Result: ""}}},
		{Domain: "example.test", SourceIP: "::ffff:198.51.100.7", HeaderFrom: "news.example.test", Disposition: "none",
			Reasons: []PolicyOverrideReason{{Type: "sampled_out"}, {Type: "Forwarded", Comment: "via list"}, {Type: "arc", Comment: "sealed"}}},
		{Domain: "example.test", SourceIP: " 203.0.113.9 ", Disposition: "", SPF: []SPFAuth{{Domain: "example.test", Scope: "mfrom", Result: "pass", Aligned: true}}},
	}
	for _, p := range policies {
		mustValidReport(t, p, recs)
		for _, r := range recs {
			mustValidReport(t, p, []AggregateRecord{r})
		}
	}
}

// TestBuildReportPolicyPublished checks policy_published: NewPolicyPublished
// takes the discovered record's values with their defaults, and BuildReport
// writes the required sp, pct and fo even when the caller leaves them empty.
//
// checklist: DMARC-XML-03 DMARC-AGG-01
func TestBuildReportPolicyPublished(t *testing.T) {
	resolver := func(string) ([]string, error) {
		return []string{"v=DMARC1; p=quarantine; adkim=s; pct=25; fo=1:d; ruf=mailto:f@example.test"}, nil
	}
	pol, err := Discover("example.test", resolver, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := PolicyPublished{Domain: "example.test", ADKIM: "s", ASPF: "r", P: "quarantine", SP: "quarantine", PCT: 25, FO: "1:d"}
	if got := NewPolicyPublished(pol); got != want {
		t.Errorf("NewPolicyPublished = %+v, want %+v", got, want)
	}
	if got := NewPolicyPublished(Policy{Domain: "x.test", Record: Record{Policy: "reject", SubdomainPolicy: "none", Pct: 100}}); got.SP != "none" || got.FO != "0" || got.PCT != 100 {
		t.Errorf("NewPolicyPublished without fo: %+v", got)
	}
	recs := []AggregateRecord{{Domain: "example.test", SourceIP: "192.0.2.1"}}
	fb := mustValidReport(t, PolicyPublished{Domain: "example.test", P: "reject"}, recs)
	if got := fb.PolicyPublished; got.SP != "reject" || got.FO != "0" || got.ADKIM != "" {
		t.Errorf("policy_published = %+v, want sp reject, fo 0, no adkim", got)
	}
}

// TestBuildReportAlwaysHasSPF checks that a record without an SPF result
// still carries the spf element the schema requires: none, for the envelope
// From domain or else the header From domain.
//
// checklist: DMARC-XML-04
func TestBuildReportAlwaysHasSPF(t *testing.T) {
	fb := mustValidReport(t, PolicyPublished{Domain: "example.test", P: "none"}, []AggregateRecord{
		{Domain: "example.test", SourceIP: "192.0.2.1", EnvelopeFrom: "bounce.example.test"},
		{Domain: "example.test", SourceIP: "192.0.2.2"},
	})
	want := []SPFResult{{Domain: "bounce.example.test", Scope: "mfrom", Result: "none"}, {Domain: "example.test", Scope: "mfrom", Result: "none"}}
	for i, r := range fb.Records {
		if len(r.AuthResults.SPF) != 1 || r.AuthResults.SPF[0] != want[i] {
			t.Errorf("record %d spf = %+v, want %+v", i, r.AuthResults.SPF, want[i])
		}
	}
}

// TestBuildReportSourceIP checks that source_ip is written in a form the
// schema's IPAddress pattern accepts, that equal addresses group, and that a
// value that is not an IP address is refused.
//
// checklist: DMARC-XML-07
func TestBuildReportSourceIP(t *testing.T) {
	cases := map[string]string{
		"192.0.2.1":         "192.0.2.1",
		"::ffff:192.0.2.1":  "192.0.2.1",
		"2001:db8::1":       "2001:0db8:0000:0000:0000:0000:0000:0001",
		"2001:DB8:0:0:8::1": "2001:0db8:0000:0000:0008:0000:0000:0001",
		"::":                "0000:0000:0000:0000:0000:0000:0000:0000",
	}
	for in, want := range cases {
		rows := AggregateRecords([]AggregateRecord{{SourceIP: in}})
		if got := rows[0].Row.SourceIP; got != want || !appendixCPatterns["IPAddress"].MatchString(got) {
			t.Errorf("source_ip for %q = %q, want %q", in, got, want)
		}
	}
	if rows := AggregateRecords([]AggregateRecord{{SourceIP: "192.0.2.1"}, {SourceIP: "::ffff:192.0.2.1"}}); len(rows) != 1 || rows[0].Row.Count != 2 {
		t.Errorf("one address in two forms gave rows %+v", rows)
	}
	for _, bad := range []string{"", "192.0.2.1:25", "fe80::1%eth0", "mail.example.test", "300.1.1.1"} {
		if _, err := BuildReport(testMeta, PolicyPublished{P: "none"}, []AggregateRecord{{SourceIP: bad}}); err == nil {
			t.Errorf("BuildReport accepted source IP %q", bad)
		}
	}
}

// TestBuildReportNeedsRecords checks that a report without records, which the
// schema does not allow, is refused.
//
// checklist: DMARC-XML-08
func TestBuildReportNeedsRecords(t *testing.T) {
	if out, err := BuildReport(testMeta, PolicyPublished{Domain: "example.test", P: "none"}, nil); err == nil {
		t.Errorf("BuildReport with no records = %s, nil", out)
	}
}

// TestBuildReportOverrideReasons checks policy_evaluated's reason elements:
// each reason is reported with a PolicyOverrideType value (unknown types as
// "other", keeping the text), and messages whose reasons differ are counted
// apart.
//
// checklist: DMARC-POL-03 DMARC-AGG-04 DMARC-XML-09
func TestBuildReportOverrideReasons(t *testing.T) {
	base := AggregateRecord{Domain: "example.test", SourceIP: "192.0.2.1", Disposition: "none"}
	sampled := base
	sampled.Reasons = []PolicyOverrideReason{{Type: PolicyOverrideSampledOut}}
	odd := base
	odd.Reasons = []PolicyOverrideReason{{Type: "ARC", Comment: "sealed by list.test"}, {Type: "", Comment: "x"}, {Type: "y"}}
	fb := mustValidReport(t, PolicyPublished{Domain: "example.test", P: "reject"}, []AggregateRecord{base, sampled, sampled, odd})
	if len(fb.Records) != 3 {
		t.Fatalf("got %d rows, want 3", len(fb.Records))
	}
	if r := fb.Records[1].Row; r.Count != 2 || len(r.PolicyEvaluated.Reasons) != 1 || r.PolicyEvaluated.Reasons[0].Type != "sampled_out" {
		t.Errorf("sampled row = %+v", r)
	}
	want := []PolicyOverrideReason{{Type: "other", Comment: "ARC: sealed by list.test"}, {Type: "other", Comment: "x"}, {Type: "other", Comment: "y"}}
	if got := fb.Records[2].Row.PolicyEvaluated.Reasons; !reflect.DeepEqual(got, want) {
		t.Errorf("reasons = %+v, want %+v", got, want)
	}
	if len(fb.Records[0].Row.PolicyEvaluated.Reasons) != 0 {
		t.Errorf("a row without reasons has %+v", fb.Records[0].Row.PolicyEvaluated.Reasons)
	}
}

// TestAggregateRecordsSeparatesSubdomains checks that mail from a subdomain
// is reported in its own rows, apart from the Organizational Domain's.
//
// checklist: DMARC-AGG-03
func TestAggregateRecordsSeparatesSubdomains(t *testing.T) {
	rows := AggregateRecords([]AggregateRecord{
		{Domain: "example.test", SourceIP: "192.0.2.1", HeaderFrom: "example.test"},
		{Domain: "example.test", SourceIP: "192.0.2.1", HeaderFrom: "news.example.test"},
		{Domain: "example.test", SourceIP: "192.0.2.1", HeaderFrom: "example.test"},
	})
	if len(rows) != 2 || rows[0].Identifiers.HeaderFrom != "example.test" || rows[0].Row.Count != 2 ||
		rows[1].Identifiers.HeaderFrom != "news.example.test" || rows[1].Row.Count != 1 {
		t.Errorf("rows = %+v", rows)
	}
}

// TestPolicyEvaluatedAnySignature checks that policy_evaluated's dkim is pass
// when any one signature passed and aligned, whatever the others did, and
// that spf is likewise pass for any aligned pass.
//
// checklist: DMARC-ALIGN-05
func TestPolicyEvaluatedAnySignature(t *testing.T) {
	rows := AggregateRecords([]AggregateRecord{{
		SourceIP: "192.0.2.1",
		DKIM: []DKIMAuth{{Domain: "list.test", Result: "pass"}, {Domain: "example.test", Result: "fail", Aligned: true},
			{Domain: "example.test", Result: " Pass ", Aligned: true}},
		SPF: []SPFAuth{{Domain: "list.test", Result: "pass"}, {Domain: "example.test", Scope: "helo", Result: "pass", Aligned: true}},
	}, {
		SourceIP: "192.0.2.1",
		DKIM:     []DKIMAuth{{Domain: "list.test", Result: "pass"}, {Domain: "example.test", Result: "fail", Aligned: true}},
		SPF:      []SPFAuth{{Domain: "list.test", Result: "pass"}},
	}})
	if e := rows[0].Row.PolicyEvaluated; e.DKIM != "pass" || e.SPF != "pass" {
		t.Errorf("one aligned pass among others: %+v", e)
	}
	if e := rows[1].Row.PolicyEvaluated; e.DKIM != "fail" || e.SPF != "fail" {
		t.Errorf("no aligned pass: %+v", e)
	}
}
