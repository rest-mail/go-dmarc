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

// TestAggregateAttachmentXML checks §7.2.1.1's file requirement through the
// public report/attachment pipeline, both with and without compression.
// MIME headers and attachment filenames belong to the sending application.
//
// checklist: DMARC-AGG-19
func TestAggregateAttachmentXML(t *testing.T) {
	meta := ReportMetadata{
		OrgName: "receiver.example", Email: "reports@receiver.example",
		ReportID: "audit<&>1", DateRange: DateRange{Begin: 100, End: 200},
	}
	policy := PolicyPublished{Domain: "example.com", P: "reject", PCT: 100}
	data, err := BuildReport(meta, policy, []AggregateRecord{{
		Domain: "example.com", SourceIP: "192.0.2.1", Disposition: "reject",
		SPF: []SPFAuth{{Domain: "example.net", Scope: "mfrom", Result: "fail"}},
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

// TestBuildReportSamplingKeepsAllMessages checks §6.6.4 at the serialized
// reporting boundary: pct limits enforcement, never the records reported.
// Both duplicated messages and different dispositions/authentication outcomes
// must survive, including when pct=0.
//
// checklist: DMARC-POL-07
func TestBuildReportSamplingKeepsAllMessages(t *testing.T) {
	records := []AggregateRecord{
		{Domain: "example.com", SourceIP: "192.0.2.1", Disposition: "none",
			Reasons: []PolicyOverrideReason{{Type: PolicyOverrideSampledOut}}},
		{Domain: "example.com", SourceIP: "192.0.2.1", Disposition: "none",
			Reasons: []PolicyOverrideReason{{Type: PolicyOverrideSampledOut}}},
		{Domain: "example.com", SourceIP: "192.0.2.2", Disposition: "quarantine"},
		{Domain: "example.com", SourceIP: "192.0.2.3", Disposition: "reject"},
		{Domain: "example.com", SourceIP: "192.0.2.4", Disposition: "none",
			DKIM: []DKIMAuth{{Domain: "example.com", Result: "pass", Aligned: true}}},
	}
	for _, pct := range []int{0, 1, 99, 100} {
		t.Run(strconv.Itoa(pct), func(t *testing.T) {
			data, err := BuildReport(ReportMetadata{
				OrgName: "receiver.example", Email: "reports@receiver.example",
				ReportID: "sampling", DateRange: DateRange{Begin: 100, End: 200},
			},
				PolicyPublished{Domain: "example.com", P: "reject", PCT: pct}, records)
			if err != nil {
				t.Fatal(err)
			}
			var report Feedback
			if err := xml.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
			if report.PolicyPublished.PCT != pct || len(report.Records) != 4 {
				t.Fatalf("pct=%d lost policy/rows: %+v", pct, report)
			}
			want := []struct {
				ip, disposition, dkim, reason string
				count                         int
			}{
				{"192.0.2.1", "none", "fail", PolicyOverrideSampledOut, 2},
				{"192.0.2.2", "quarantine", "fail", "", 1},
				{"192.0.2.3", "reject", "fail", "", 1},
				{"192.0.2.4", "none", "pass", "", 1},
			}
			for i, w := range want {
				row := report.Records[i].Row
				if row.SourceIP != w.ip || row.Count != w.count ||
					row.PolicyEvaluated.Disposition != w.disposition || row.PolicyEvaluated.DKIM != w.dkim {
					t.Errorf("row %d = %+v, want %+v", i, row, w)
				}
				if w.reason != "" && (len(row.PolicyEvaluated.Reasons) != 1 ||
					row.PolicyEvaluated.Reasons[0].Type != w.reason) {
					t.Errorf("row %d lost sampling reason: %+v", i, row.PolicyEvaluated.Reasons)
				}
			}
		})
	}
}
