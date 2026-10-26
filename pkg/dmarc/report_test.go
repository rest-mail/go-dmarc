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
// checklist: DMARC-AGG-05
func TestAggregateRecords_GroupsAndCounts(t *testing.T) {
	recs := []AggregateRecord{
		{Domain: "example.test", SourceIP: "10.0.0.1", HeaderFrom: "a@example.test", Disposition: "none",
			DKIM: []DKIMAuth{{Domain: "example.test", Selector: "s1", Result: "pass", Aligned: true}},
			SPF:  &SPFAuth{Domain: "example.test", Result: "pass", Aligned: true}},
		{Domain: "example.test", SourceIP: "10.0.0.1", HeaderFrom: "a@example.test", Disposition: "none",
			DKIM: []DKIMAuth{{Domain: "example.test", Selector: "s1", Result: "pass", Aligned: true}},
			SPF:  &SPFAuth{Domain: "example.test", Result: "pass", Aligned: true}},
		{Domain: "example.test", SourceIP: "10.0.0.2", HeaderFrom: "a@example.test", Disposition: "reject",
			DKIM: []DKIMAuth{{Domain: "evil.test", Selector: "s9", Result: "fail", Aligned: false}},
			SPF:  &SPFAuth{Domain: "bounce.evil.test", Result: "fail", Aligned: false}},
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
	policy := PolicyPublished{Domain: "example.test", ADKIM: "r", ASPF: "r", P: "reject"}
	recs := []AggregateRecord{
		{Domain: "example.test", SourceIP: "10.0.0.1", HeaderFrom: "a@example.test", Disposition: "none",
			DKIM: []DKIMAuth{{Domain: "example.test", Selector: "sel", Result: "pass", Aligned: true}},
			SPF:  &SPFAuth{Domain: "example.test", Result: "pass", Aligned: true}},
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
// RFC 9990 Appendix A grammar for the identifiers and auth_results sections:
// envelope_from is derived from the SPF check, spf has the mfrom scope, and
// every emitted dkim/spf result is a member of the closed enumerations (an
// empty or unknown value must be normalised to "none", never emitted
// verbatim).
//
// checklist: DMARC-XML-06 DMARC-XML-10 DMARC-AGG-02
func TestBuildReport_SchemaConformance(t *testing.T) {
	meta := ReportMetadata{OrgName: "restmail.test", Email: "dmarc@restmail.test", ReportID: "r-1", DateRange: DateRange{Begin: 1784700000, End: 1784786400}}
	policy := PolicyPublished{Domain: "example.test", P: "none"}
	// The auth results deliberately carry an empty DKIM result and an unknown
	// SPF result: the marshaller must normalise the values into the
	// enumerations.
	recs := []AggregateRecord{{
		Domain: "example.test", SourceIP: "192.0.2.1", Disposition: "none",
		DKIM: []DKIMAuth{{Domain: "example.test", Selector: "sel", Result: ""}},
		SPF:  &SPFAuth{Domain: "mail.example.test", Result: "bogus"},
	}}
	out, err := BuildReport(meta, policy, recs)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)

	// identifiers/envelope_from comes from the SPF check's domain when the
	// caller did not supply one.
	if !strings.Contains(s, "<envelope_from>mail.example.test</envelope_from>") {
		t.Errorf("missing/underived identifiers/envelope_from element:\n%s", s)
	}
	// The only SPF scope DMARC uses is mfrom.
	if !strings.Contains(s, "<scope>mfrom</scope>") {
		t.Errorf("missing spf/scope element:\n%s", s)
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
	if err := validateReport(out); err != nil {
		t.Errorf("report does not validate: %v", err)
	}
}

// TestBuildReport_OmitsDKIMWhenUnsigned asserts that a message that carried no
// DKIM signature produces no <dkim> auth_results element (RFC 9990: dkim is
// minOccurs="0"; an empty <dkim> with no domain/result would be invalid).
//
// checklist: DMARC-XML-05
func TestBuildReport_OmitsDKIMWhenUnsigned(t *testing.T) {
	meta := ReportMetadata{OrgName: "o", Email: "e", ReportID: "r", DateRange: DateRange{Begin: 1, End: 2}}
	policy := PolicyPublished{Domain: "example.test", P: "none"}
	recs := []AggregateRecord{{
		Domain: "example.test", SourceIP: "192.0.2.1", Disposition: "none",
		SPF: &SPFAuth{Domain: "mail.example.test", Result: "pass"},
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

// wantGoldenXML is a known-good RFC 9990 aggregate report: it locks the
// namespace, the element ordering and the presence of every field.
const wantGoldenXML = `<?xml version="1.0" encoding="UTF-8"?>
<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">
  <version>1.0</version>
  <report_metadata>
    <org_name>restmail.test</org_name>
    <email>dmarc@restmail.test</email>
    <report_id>report-1</report_id>
    <date_range>
      <begin>1784700000</begin>
      <end>1784786400</end>
    </date_range>
    <generator>go-dmarc</generator>
  </report_metadata>
  <policy_published>
    <domain>example.test</domain>
    <discovery_method>treewalk</discovery_method>
    <p>reject</p>
    <sp>reject</sp>
    <np>reject</np>
    <fo>0</fo>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <testing>n</testing>
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
      <header_from>example.test</header_from>
      <envelope_from>mail.example.test</envelope_from>
      <envelope_to>receiver.test</envelope_to>
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
// known-good fixture, locking element order and field presence.
//
// checklist: DMARC-XML-02 DMARC-XML-03 DMARC-XML-11 DMARC-XML-12
func TestBuildReport_GoldenXML(t *testing.T) {
	meta := ReportMetadata{OrgName: "restmail.test", Email: "dmarc@restmail.test", ReportID: "report-1",
		DateRange: DateRange{Begin: 1784700000, End: 1784786400}, Generator: "go-dmarc"}
	policy := PolicyPublished{Domain: "example.test", DiscoveryMethod: "treewalk", ADKIM: "r", ASPF: "r", P: "reject", SP: "reject"}
	recs := []AggregateRecord{{
		Domain: "example.test", SourceIP: "192.0.2.10", Disposition: "quarantine", EnvelopeTo: "receiver.test",
		DKIM: []DKIMAuth{{Domain: "example.test", Selector: "sel", Result: "pass", Aligned: true}},
		SPF:  &SPFAuth{Domain: "mail.example.test", Result: "pass", Aligned: true},
	}}
	out, err := BuildReport(meta, policy, recs)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(out); got != wantGoldenXML {
		t.Errorf("golden XML mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, wantGoldenXML)
	}
	if err := validateReport(out); err != nil {
		t.Errorf("the golden report does not validate: %v", err)
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

// mustValidReport builds a report and checks it against the Appendix A schema.
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

// TestReportValidatesAgainstAppendixA checks reports of every shape against
// RFC 9990's Appendix A schema: signed and unsigned, with and without an SPF
// result, with IPv4, IPv6 and IPv4-mapped addresses, with override reasons
// and metadata, and with the values the normalizers map to their
// enumerations.
//
// checklist: DMARC-XML-02 DMARC-XML-06 DMARC-XML-14 DMARC-XML-11 DMARC-XML-12
func TestReportValidatesAgainstAppendixA(t *testing.T) {
	policies := []PolicyPublished{
		{Domain: "example.test", P: "reject"},
		{Domain: "example.test", DiscoveryMethod: "TreeWalk", ADKIM: "s", ASPF: "R", P: "Quarantine", SP: "none", NP: "reject", FO: "1:d", Testing: "Y"},
		{Domain: "example.test", DiscoveryMethod: "guess", ADKIM: "strict", ASPF: "x", P: "bogus", SP: "bogus", NP: "bogus", Testing: "maybe"},
	}
	recs := []AggregateRecord{
		{Domain: "example.test", SourceIP: "192.0.2.1", Disposition: "reject"},
		{Domain: "example.test", SourceIP: "2001:db8::1", Disposition: "QUARANTINE", EnvelopeFrom: "bounce.example.test", EnvelopeTo: "receiver.test",
			DKIM: []DKIMAuth{{Domain: "example.test", Result: "PASS", Aligned: true}, {Domain: "other.test", Selector: "s", Result: "weird"}},
			SPF:  &SPFAuth{Domain: "bounce.example.test", Result: "SoftFail"}},
		{Domain: "example.test", SourceIP: "::ffff:198.51.100.7", HeaderFrom: "news.example.test", Disposition: "pass",
			Reasons: []PolicyOverrideReason{{Type: "sampled_out"}, {Type: "Forwarded", Comment: "via list"}, {Type: "policy_test_mode"}}},
		{Domain: "example.test", SourceIP: " 203.0.113.9 ", Disposition: "", SPF: &SPFAuth{Domain: "example.test", Result: "policy", Aligned: true}},
	}
	metas := []ReportMetadata{testMeta, {OrgName: "o", Email: "e", ExtraContactInfo: "call us", ReportID: "r", Error: "two records at _dmarc.example.test", Generator: "go-dmarc v0.5.0"}}
	for _, m := range metas {
		for _, p := range policies {
			out, err := BuildReport(m, p, recs)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateReport(out); err != nil {
				t.Fatalf("report does not validate: %v\n%s", err, out)
			}
			for _, r := range recs {
				mustValidReport(t, p, []AggregateRecord{r})
			}
		}
	}
}

// TestBuildReportPolicyPublished checks policy_published (RFC 9990
// §3.1.1.5): NewPolicyPublished takes the discovered record's values, with
// their defaults, and the tree walk as the discovery method; and BuildReport
// writes the default of each value the caller leaves empty.
//
// checklist: DMARC-XML-03 DMARC-AGG-01
func TestBuildReportPolicyPublished(t *testing.T) {
	resolver := func(string) ([]string, error) {
		return []string{"v=DMARC1; p=quarantine; np=reject; adkim=s; pct=25; t=y; fo=1:d; ruf=mailto:f@example.test"}, nil
	}
	pol, err := Discover("example.test", resolver, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := PolicyPublished{Domain: "example.test", DiscoveryMethod: "treewalk", P: "quarantine", SP: "quarantine", NP: "reject",
		FO: "1:d", ADKIM: "s", ASPF: "r", Testing: "y"}
	if got := NewPolicyPublished(pol); got != want {
		t.Errorf("NewPolicyPublished = %+v, want %+v", got, want)
	}
	if got := NewPolicyPublished(Policy{Domain: "x.test", Record: Record{Policy: "reject", SubdomainPolicy: "none"}}); got.SP != "none" || got.NP != "none" || got.FO != "0" || got.Testing != "n" {
		t.Errorf("NewPolicyPublished without np, fo or t: %+v", got)
	}
	recs := []AggregateRecord{{Domain: "example.test", SourceIP: "192.0.2.1"}}
	fb := mustValidReport(t, PolicyPublished{Domain: "example.test", P: "reject"}, recs)
	if got := fb.PolicyPublished; got != (PolicyPublished{Domain: "example.test", P: "reject", SP: "reject", NP: "reject", FO: "0", ADKIM: "r", ASPF: "r", Testing: "n"}) {
		t.Errorf("policy_published = %+v, want the defaults filled in and no discovery method", got)
	}
}

// TestBuildReportSPF checks auth_results' spf (RFC 9990 §3.1.1.11,
// §3.1.1.13): the MAIL FROM result alone, with the mfrom scope, and none at
// all when SPF was not checked; and identifiers' envelope_from, from the
// caller or the SPF check, left out when neither gives it.
//
// checklist: DMARC-XML-04 DMARC-XML-10
func TestBuildReportSPF(t *testing.T) {
	fb := mustValidReport(t, PolicyPublished{Domain: "example.test", P: "none"}, []AggregateRecord{
		{Domain: "example.test", SourceIP: "192.0.2.1", EnvelopeFrom: "bounce.example.test"},
		{Domain: "example.test", SourceIP: "192.0.2.2"},
		{Domain: "example.test", SourceIP: "192.0.2.3", SPF: &SPFAuth{Domain: "mail.example.test", Result: "fail"}},
	})
	if r := fb.Records[0]; r.AuthResults.SPF != nil || r.Identifiers.EnvelopeFrom != "bounce.example.test" {
		t.Errorf("record 0 = %+v", r)
	}
	if r := fb.Records[1]; r.AuthResults.SPF != nil || r.Identifiers.EnvelopeFrom != "" {
		t.Errorf("record 1 = %+v", r)
	}
	if r := fb.Records[2]; r.AuthResults.SPF == nil || *r.AuthResults.SPF != (SPFResult{Domain: "mail.example.test", Scope: "mfrom", Result: "fail"}) ||
		r.Identifiers.EnvelopeFrom != "mail.example.test" {
		t.Errorf("record 2 = %+v", r)
	}
}

// TestBuildReportSourceIP checks that source_ip is an RFC 3986 IPv4address or
// IPv6address (RFC 9990 §3.1.1.8), IPv6 in its compressed form, that equal
// addresses group, and that a value that is not an IP address is refused.
//
// checklist: DMARC-XML-07
func TestBuildReportSourceIP(t *testing.T) {
	cases := map[string]string{
		"192.0.2.1":         "192.0.2.1",
		"::ffff:192.0.2.1":  "192.0.2.1",
		"2001:db8::1":       "2001:db8::1",
		"2001:DB8:0:0:8::1": "2001:db8::8:0:0:1",
		"::":                "::",
	}
	for in, want := range cases {
		rows := AggregateRecords([]AggregateRecord{{SourceIP: in}})
		if got := rows[0].Row.SourceIP; got != want || validateSimple(got, "RFC3986IP", "source_ip") != nil {
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

// TestBuildReportOverrideReasons checks policy_evaluated's reason elements
// (RFC 9990 §3.1.6): each reason is reported with a PolicyOverrideType value
// (unknown types, RFC 7489's forwarded and sampled_out among them, as
// "other", keeping the text), and messages whose reasons differ are counted
// apart.
//
// checklist: DMARC-POL-03 DMARC-AGG-04 DMARC-XML-09
func TestBuildReportOverrideReasons(t *testing.T) {
	base := AggregateRecord{Domain: "example.test", SourceIP: "192.0.2.1", Disposition: "none"}
	testing := base
	testing.Reasons = []PolicyOverrideReason{{Type: PolicyOverridePolicyTestMode}}
	odd := base
	odd.Reasons = []PolicyOverrideReason{{Type: "ARC", Comment: "sealed by list.test"}, {Type: "", Comment: "x"}, {Type: "sampled_out"}}
	fb := mustValidReport(t, PolicyPublished{Domain: "example.test", P: "reject"}, []AggregateRecord{base, testing, testing, odd})
	if len(fb.Records) != 3 {
		t.Fatalf("got %d rows, want 3", len(fb.Records))
	}
	if r := fb.Records[1].Row; r.Count != 2 || len(r.PolicyEvaluated.Reasons) != 1 || r.PolicyEvaluated.Reasons[0].Type != "policy_test_mode" {
		t.Errorf("test mode row = %+v", r)
	}
	want := []PolicyOverrideReason{{Type: "other", Comment: "ARC: sealed by list.test"}, {Type: "other", Comment: "x"}, {Type: "other", Comment: "sampled_out"}}
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
// that spf is pass for an aligned MAIL FROM pass.
//
// checklist: DMARC-ALIGN-05 DMARC-XML-13
func TestPolicyEvaluatedAnySignature(t *testing.T) {
	rows := AggregateRecords([]AggregateRecord{{
		SourceIP: "192.0.2.1",
		DKIM: []DKIMAuth{{Domain: "list.test", Result: "pass"}, {Domain: "example.test", Result: "fail", Aligned: true},
			{Domain: "example.test", Result: " Pass ", Aligned: true}},
		SPF: &SPFAuth{Domain: "example.test", Result: "pass", Aligned: true},
	}, {
		SourceIP: "192.0.2.1",
		DKIM:     []DKIMAuth{{Domain: "list.test", Result: "pass"}, {Domain: "example.test", Result: "fail", Aligned: true}},
		SPF:      &SPFAuth{Domain: "list.test", Result: "pass"},
	}})
	if e := rows[0].Row.PolicyEvaluated; e.DKIM != "pass" || e.SPF != "pass" {
		t.Errorf("one aligned pass among others: %+v", e)
	}
	if e := rows[1].Row.PolicyEvaluated; e.DKIM != "fail" || e.SPF != "fail" {
		t.Errorf("no aligned pass: %+v", e)
	}
}

// TestBuildReportDKIMOrderAndLimit checks RFC 9990 §3.1.3: a row reports the
// passing signature in strict alignment first, then those in relaxed
// alignment, the other passing ones and the failing ones, and no more than
// 100 of them.
//
// checklist: DMARC-AGG-25
func TestBuildReportDKIMOrderAndLimit(t *testing.T) {
	sigs := []DKIMAuth{
		{Domain: "fail.example.test", Selector: "f", Result: "fail", Aligned: true},
		{Domain: "esp.test", Selector: "o", Result: "pass"},
		{Domain: "mail.example.test", Selector: "r", Result: "pass", Aligned: true},
		{Domain: "Example.Test.", Selector: "s", Result: "PASS", Aligned: true},
	}
	rows := AggregateRecords([]AggregateRecord{{SourceIP: "192.0.2.1", HeaderFrom: "example.test", DKIM: sigs}})
	var got []string
	for _, d := range rows[0].AuthResults.DKIM {
		got = append(got, d.Selector)
	}
	if want := []string{"s", "r", "o", "f"}; !reflect.DeepEqual(got, want) {
		t.Errorf("signatures reported in the order %q, want %q", got, want)
	}
	if sigs[0].Selector != "f" {
		t.Error("ordering the report changed the caller's slice")
	}

	many := make([]DKIMAuth, 150)
	for i := range many {
		many[i] = DKIMAuth{Domain: "other.test", Selector: "x", Result: "fail"}
	}
	many[149] = DKIMAuth{Domain: "example.test", Selector: "keep", Result: "pass", Aligned: true}
	ar := AggregateRecords([]AggregateRecord{{SourceIP: "192.0.2.1", HeaderFrom: "example.test", DKIM: many}})[0].AuthResults
	if len(ar.DKIM) != 100 || ar.DKIM[0].Selector != "keep" {
		t.Errorf("%d signatures reported, the first %+v; want 100, the aligned pass first", len(ar.DKIM), ar.DKIM[0])
	}
}
