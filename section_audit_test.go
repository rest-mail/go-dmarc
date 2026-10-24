package dmarc

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"io"
	"reflect"
	"strconv"
	"testing"
)

// TestAggregateAttachmentXML checks RFC 9990 §3.5.2's file requirement
// through the public report/attachment pipeline, both with and without
// compression: the aggregate data is an XML file. MIME headers belong to the
// sending application; ReportFilename names the file.
//
// checklist: DMARC-AGG-19
func TestAggregateAttachmentXML(t *testing.T) {
	meta := ReportMetadata{
		OrgName: "receiver.example", Email: "reports@receiver.example",
		ReportID: "audit<&>1", DateRange: DateRange{Begin: 100, End: 200},
	}
	policy := PolicyPublished{Domain: "example.com", P: "reject"}
	data, err := BuildReport(meta, policy, []AggregateRecord{{
		Domain: "example.com", SourceIP: "192.0.2.1", Disposition: "reject",
		SPF: &SPFAuth{Domain: "example.net", Result: "fail"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, compressed := range []bool{false, true} {
		t.Run(strconv.FormatBool(compressed), func(t *testing.T) {
			attachment := data
			if compressed {
				attachment, err = Gzip(data)
				if err != nil {
					t.Fatal(err)
				}
				zr, err := gzip.NewReader(bytes.NewReader(attachment))
				if err != nil {
					t.Fatal(err)
				}
				attachment, err = io.ReadAll(zr)
				if err != nil {
					t.Fatal(err)
				}
				if err := zr.Close(); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(attachment, data) {
					t.Fatal("compressed attachment changed the XML file")
				}
			}
			if !bytes.HasPrefix(attachment, []byte(xml.Header)) {
				t.Fatal("attachment is missing the XML declaration")
			}
			var report Feedback
			if err := xml.Unmarshal(attachment, &report); err != nil {
				t.Fatalf("attachment is not XML: %v", err)
			}
			if report.XMLName.Local != "feedback" || report.Version != "1.0" ||
				!reflect.DeepEqual(report.ReportMetadata, meta) {
				t.Fatalf("attachment lost feedback metadata: %+v", report)
			}
			if report.PolicyPublished.Domain != "example.com" || report.PolicyPublished.P != "reject" ||
				len(report.Records) != 1 || report.Records[0].Row.Count != 1 ||
				report.Records[0].Row.SourceIP != "192.0.2.1" {
				t.Fatalf("attachment lost policy or message data: %+v", report)
			}
		})
	}
}

// TestBuildReportKeepsAllMessages checks at the serialized reporting
// boundary that every message is reported (RFC 9990 §3.1: "all messages
// received"): duplicated messages and different dispositions and
// authentication outcomes all survive, whether or not the record asked for
// test mode and the receiver exempted messages for it.
//
// checklist: DMARC-AGG-05
func TestBuildReportKeepsAllMessages(t *testing.T) {
	records := []AggregateRecord{
		{Domain: "example.com", SourceIP: "192.0.2.1", Disposition: "none",
			Reasons: []PolicyOverrideReason{{Type: PolicyOverridePolicyTestMode}}},
		{Domain: "example.com", SourceIP: "192.0.2.1", Disposition: "none",
			Reasons: []PolicyOverrideReason{{Type: PolicyOverridePolicyTestMode}}},
		{Domain: "example.com", SourceIP: "192.0.2.2", Disposition: "quarantine"},
		{Domain: "example.com", SourceIP: "192.0.2.3", Disposition: "reject"},
		{Domain: "example.com", SourceIP: "192.0.2.4", Disposition: "pass",
			DKIM: []DKIMAuth{{Domain: "example.com", Selector: "s", Result: "pass", Aligned: true}}},
	}
	for _, mode := range []string{"y", "n"} {
		t.Run(mode, func(t *testing.T) {
			data, err := BuildReport(ReportMetadata{
				OrgName: "receiver.example", Email: "reports@receiver.example",
				ReportID: "all", DateRange: DateRange{Begin: 100, End: 200},
			},
				PolicyPublished{Domain: "example.com", P: "reject", Testing: mode}, records)
			if err != nil {
				t.Fatal(err)
			}
			var report Feedback
			if err := xml.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
			if report.PolicyPublished.Testing != mode || len(report.Records) != 4 {
				t.Fatalf("testing=%s lost policy/rows: %+v", mode, report)
			}
			want := []struct {
				ip, disposition, dkim, reason string
				count                         int
			}{
				{"192.0.2.1", "none", "fail", PolicyOverridePolicyTestMode, 2},
				{"192.0.2.2", "quarantine", "fail", "", 1},
				{"192.0.2.3", "reject", "fail", "", 1},
				{"192.0.2.4", "pass", "pass", "", 1},
			}
			for i, w := range want {
				row := report.Records[i].Row
				if row.SourceIP != w.ip || row.Count != w.count ||
					row.PolicyEvaluated.Disposition != w.disposition || row.PolicyEvaluated.DKIM != w.dkim {
					t.Errorf("row %d = %+v, want %+v", i, row, w)
				}
				if w.reason != "" && (len(row.PolicyEvaluated.Reasons) != 1 ||
					row.PolicyEvaluated.Reasons[0].Type != w.reason) {
					t.Errorf("row %d lost its reason: %+v", i, row.PolicyEvaluated.Reasons)
				}
			}
		})
	}
}

// TestReportFilename checks the attachment's name (RFC 9990 §3.5.2):
// receiver, policy domain, begin and end, an optional unique ID, and the
// extension for plain or compressed XML; a re-sent report keeps its name.
//
// checklist: DMARC-AGG-13
func TestReportFilename(t *testing.T) {
	period := DateRange{Begin: 1013662812, End: 1013749130}
	cases := []struct {
		receiver, domain, id string
		gzipped              bool
		want                 string
	}{
		{"mail.receiver.example", "example.com", "", true, "mail.receiver.example!example.com!1013662812!1013749130.xml.gz"},
		{"mail.receiver.example", "example.com", "", false, "mail.receiver.example!example.com!1013662812!1013749130.xml"},
		{"Mail.Receiver.Example.", "Bücher.example", "a1B2", true, "mail.receiver.example!xn--bcher-kva.example!1013662812!1013749130!a1B2.xml.gz"},
	}
	for _, c := range cases {
		got, ok := ReportFilename(c.receiver, c.domain, period, c.id, c.gzipped)
		if !ok || got != c.want {
			t.Errorf("ReportFilename(%q, %q, %q) = %q, %v; want %q", c.receiver, c.domain, c.id, got, ok, c.want)
		}
		if again, _ := ReportFilename(c.receiver, c.domain, period, c.id, c.gzipped); again != got {
			t.Errorf("a re-sent report got another name: %q, then %q", got, again)
		}
	}
	for _, bad := range []struct {
		receiver, domain, id string
		period               DateRange
	}{
		{"a..b", "example.com", "", period}, {"r.example", "", "", period}, {"r.example", "example.com", "a-b", period},
		{"r.example", "example.com", "", DateRange{Begin: -1, End: 2}},
	} {
		if got, ok := ReportFilename(bad.receiver, bad.domain, bad.period, bad.id, true); ok {
			t.Errorf("ReportFilename(%+v) = %q, want refused", bad, got)
		}
	}
}

// TestReportSubject checks the report message's Subject (RFC 9990 §3.5.2):
// the policy domain, the submitter, and an optional Report-ID that is a
// ridtxt (§3.5.1).
//
// checklist: DMARC-AGG-15
func TestReportSubject(t *testing.T) {
	cases := []struct{ domain, submitter, id, want string }{
		{"example.com", "mail.receiver.example", "<sample-ridtxt@example.com>",
			"Report Domain: example.com Submitter: mail.receiver.example Report-ID: <sample-ridtxt@example.com>"},
		{"example.com", "mail.receiver.example", "", "Report Domain: example.com Submitter: mail.receiver.example"},
		{"example.com", "mail.receiver.example", "1721054318-example.com@example.org",
			"Report Domain: example.com Submitter: mail.receiver.example Report-ID: 1721054318-example.com@example.org"},
		{"Example.COM", "receiver.example", "2024-03-27_example.com", "Report Domain: example.com Submitter: receiver.example Report-ID: 2024-03-27_example.com"},
	}
	for _, c := range cases {
		if got, ok := ReportSubject(c.domain, c.submitter, c.id); !ok || got != c.want {
			t.Errorf("ReportSubject(%q, %q, %q) = %q, %v; want %q", c.domain, c.submitter, c.id, got, ok, c.want)
		}
	}
	for _, bad := range [][3]string{
		{"", "r.example", ""}, {"example.com", "a b", ""}, {"example.com", "r.example", "has space"},
		{"example.com", "r.example", "a..b@c"}, {"example.com", "r.example", "a@b@c"}, {"example.com", "r.example", "<>"},
		{"example.com", "r.example", "a@"},
	} {
		if got, ok := ReportSubject(bad[0], bad[1], bad[2]); ok {
			t.Errorf("ReportSubject(%q) = %q, want refused", bad, got)
		}
	}
}
