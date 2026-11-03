package dmarc

import (
	"bufio"
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"net/textproto"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestFailureReportsFor checks the fo= decision of RFC 9989 §4.7 against
// each SPF and DKIM outcome: 0 reports a DMARC failure, 1 any mechanism
// without an aligned pass, d a failed signature and s a failed SPF check; no
// ruf= means no report at all, and a psd=y record's ruf= is not considered
// (RFC 9991 §2).
//
// checklist: DMARC-URI-09 DMARC-FAIL-02 DMARC-FAIL-03
func TestFailureReportsFor(t *testing.T) {
	alignedPass := []DKIMAuth{{Domain: "example.com", Selector: "s", Result: "pass", Aligned: true}}
	alignedFail := []DKIMAuth{{Domain: "example.com", Selector: "s", Result: "fail", Aligned: true}}
	unalignedFail := []DKIMAuth{{Domain: "other.test", Selector: "s", Result: "permerror"}}
	unalignedPass := []DKIMAuth{{Domain: "other.test", Selector: "s", Result: "pass"}}
	spfPass := &SPFAuth{Domain: "example.com", Result: "pass", Aligned: true}
	spfFail := &SPFAuth{Domain: "example.com", Result: "fail", Aligned: true}
	spfSoftUnaligned := &SPFAuth{Domain: "bounce.test", Result: "softfail"}
	spfNeutral := &SPFAuth{Domain: "bounce.test", Result: "neutral"}

	rec := func(txt string) Record {
		t.Helper()
		r, err := ParseRecord(txt)
		if err != nil {
			t.Fatalf("ParseRecord(%q): %v", txt, err)
		}
		return r
	}
	none := FailureReportsDue{}
	dmarcOnly := FailureReportsDue{DMARC: true}
	cases := []struct {
		name   string
		record string
		dkim   []DKIMAuth
		spf    *SPFAuth
		want   FailureReportsDue
	}{
		{"no ruf: fo ignored", "v=DMARC1; p=reject; fo=1:d:s", alignedFail, spfFail, none},
		{"psd=y: ruf not considered", "v=DMARC1; p=reject; psd=y; ruf=mailto:f@example.com; fo=1", alignedFail, spfFail, none},
		{"fo default 0, both fail", "v=DMARC1; p=reject; ruf=mailto:f@example.com", unalignedFail, spfSoftUnaligned, dmarcOnly},
		{"fo=0, dkim aligned pass", "v=DMARC1; p=reject; ruf=mailto:f@example.com; fo=0", alignedPass, spfFail, none},
		{"fo=0, spf aligned pass", "v=DMARC1; p=reject; ruf=mailto:f@example.com; fo=0", alignedFail, spfPass, none},
		{"fo=0, unsigned and spf unchecked", "v=DMARC1; p=reject; ruf=mailto:f@example.com; fo=0", nil, nil, dmarcOnly},
		{"fo=1, spf aligned fail", "v=DMARC1; p=reject; ruf=mailto:f@example.com; fo=1", alignedPass, spfFail, dmarcOnly},
		{"fo=1, dkim not aligned", "v=DMARC1; p=reject; ruf=mailto:f@example.com; fo=1", unalignedPass, spfPass, dmarcOnly},
		{"fo=1, unsigned", "v=DMARC1; p=reject; ruf=mailto:f@example.com; fo=1", nil, spfPass, dmarcOnly},
		{"fo=1, both aligned pass", "v=DMARC1; p=reject; ruf=mailto:f@example.com; fo=1", alignedPass, spfPass, none},
		{"fo=d, unaligned signature failed", "v=DMARC1; p=reject; ruf=mailto:f@example.com; fo=d", append(alignedPass, unalignedFail...), spfPass, FailureReportsDue{DKIM: true}},
		{"fo=d, signatures pass", "v=DMARC1; p=reject; ruf=mailto:f@example.com; fo=d", unalignedPass, spfFail, none},
		{"fo=s, unaligned softfail", "v=DMARC1; p=reject; ruf=mailto:f@example.com; fo=s", alignedPass, spfSoftUnaligned, FailureReportsDue{SPF: true}},
		{"fo=s, neutral is no failure", "v=DMARC1; p=reject; ruf=mailto:f@example.com; fo=s", alignedPass, spfNeutral, none},
		{"fo=s, spf unchecked", "v=DMARC1; p=reject; ruf=mailto:f@example.com; fo=s", nil, nil, none},
		{"fo=0:d:s, all fail", "v=DMARC1; p=reject; ruf=mailto:f@example.com; fo=0:d:s", unalignedFail, spfSoftUnaligned, FailureReportsDue{DMARC: true, DKIM: true, SPF: true}},
		{"fo=1:s, spf only", "v=DMARC1; p=reject; ruf=mailto:f@example.com; fo=1:s", alignedPass, spfFail, FailureReportsDue{DMARC: true, SPF: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := FailureReportsFor(rec(c.record), c.dkim, c.spf)
			if got != c.want {
				t.Errorf("FailureReportsFor = %+v, want %+v", got, c.want)
			}
			if got.Any() != (c.want != none) {
				t.Errorf("Any() = %v", got.Any())
			}
		})
	}
}

// TestIdentityAlignment checks the Identity-Alignment value of RFC 9991 §4
// item 2: the mechanisms without an aligned pass, or "none".
//
// checklist: DMARC-FAIL-05
func TestIdentityAlignment(t *testing.T) {
	pass := []DKIMAuth{{Domain: "example.com", Result: "pass", Aligned: true}}
	fail := []DKIMAuth{{Domain: "example.com", Result: "fail", Aligned: true}}
	spfPass := &SPFAuth{Result: "pass", Aligned: true}
	spfFail := &SPFAuth{Result: "pass", Aligned: false}
	cases := []struct {
		dkim []DKIMAuth
		spf  *SPFAuth
		want string
	}{
		{pass, spfPass, "none"},
		{fail, spfPass, "dkim"},
		{pass, spfFail, "spf"},
		{fail, spfFail, "dkim, spf"},
		{nil, nil, "dkim, spf"},
	}
	for _, c := range cases {
		if got := IdentityAlignment(c.dkim, c.spf); got != c.want {
			t.Errorf("IdentityAlignment(%v, %v) = %q, want %q", c.dkim, c.spf, got, c.want)
		}
	}
}

// TestFailureReportURIs checks where failure reports may go: nowhere without
// ruf= or with psd=y; otherwise the ruf= URIs that pass the RFC 9990 §4
// check, with "ruf" overrides (RFC 9991 §5). The obsolete "!" size limit is
// ignored (RFC 9989 §4.8).
//
// checklist: DMARC-FAIL-03 DMARC-FAIL-04
func TestFailureReportURIs(t *testing.T) {
	zone := map[string][]string{
		"_dmarc.example.com":                          {"v=DMARC1; p=reject"},
		"example.com._report._dmarc.reports.test":     {"v=DMARC1"},
		"example.com._report._dmarc.override.test":    {"v=DMARC1; ruf=mailto:forensic@override.test"},
		"example.com._report._dmarc.overriderua.test": {"v=DMARC1; rua=mailto:agg@overriderua.test"},
	}
	resolver := func(name string) ([]string, error) {
		if recs, ok := zone[name]; ok {
			return recs, nil
		}
		return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	}
	cases := []struct {
		name   string
		record string
		want   []string
	}{
		{"no ruf", "v=DMARC1; p=reject; rua=mailto:a@example.com", nil},
		{"psd=y", "v=DMARC1; p=reject; psd=y; ruf=mailto:f@example.com", nil},
		{"internal, size limit dropped", "v=DMARC1; p=reject; ruf=mailto:f@example.com!10k,mailto:g@mail.example.com", uris("mailto:f@example.com", "mailto:g@mail.example.com")},
		{"external confirmed", "v=DMARC1; p=reject; ruf=mailto:f@reports.test!1m", uris("mailto:f@reports.test")},
		{"external unconfirmed", "v=DMARC1; p=reject; ruf=mailto:f@victim.test", nil},
		{"ruf override", "v=DMARC1; p=reject; ruf=mailto:f@override.test", uris("mailto:forensic@override.test")},
		{"rua override does not touch ruf", "v=DMARC1; p=reject; ruf=mailto:f@overriderua.test", uris("mailto:f@overriderua.test")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := ParseRecord(c.record)
			if err != nil {
				t.Fatal(err)
			}
			got, err := FailureReportURIs(Policy{Domain: "example.com", Raw: c.record, Record: r}, resolver)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("FailureReportURIs = %q, want %q", got, c.want)
			}
		})
	}
}

// TestReportMailbox checks that a mailto: ruf= URI yields the address to
// send to.
//
// checklist: DMARC-FAIL-04
func TestReportMailbox(t *testing.T) {
	cases := []struct {
		uri  string
		want string
		ok   bool
	}{
		{"mailto:dmarc@example.com", "dmarc@example.com", true},
		{"MAILTO:dmarc%2Bfail@example.com?subject=x", "dmarc+fail@example.com", true},
		{"mailto:a@example.com,b@example.com", "a@example.com", true},
		{"mailto:", "", false},
		{"mailto:%zz@example.com", "", false},
		{"https://example.com/report", "", false},
		{"%", "", false},
	}
	for _, c := range cases {
		got, ok := ReportMailbox(c.uri)
		if got != c.want || ok != c.ok {
			t.Errorf("ReportMailbox(%q) = %q, %v; want %q, %v", c.uri, got, ok, c.want, c.ok)
		}
	}
}

const originalMessage = "Received: from mail.example.com (mail.example.com [192.0.2.4])\n" +
	"\tby mx.receiver.test; Tue, 19 Jul 2022 07:57:41 +0200\n" +
	"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=epsilon;\n" +
	"\tb=abc\n" +
	"From: Message Author <author@example.com>\n" +
	"To: users@lists.test\n" +
	"Subject: This is the original subject\n" +
	"Message-ID: <1234@example.com>\n" +
	"\n" +
	"Hello users,\n" +
	"the body.\n"

// sampleReport is a failure report input in the shape of RFC 9991 Appendix
// A.
func sampleReport() FailureReport {
	return FailureReport{
		From:                  "DMARC Reporter <dmarc@receiver.test>",
		To:                    "dmarcfail@example.com",
		Date:                  time.Date(2022, 7, 19, 0, 57, 48, 0, time.FixedZone("", -5*3600)),
		MessageID:             "<20220719055748.4AE9D403CC@receiver.test>",
		UserAgent:             "go-dmarc/0.7",
		ReportingMTA:          "dns; mx.receiver.test",
		AuthenticationResults: "mx.receiver.test; dmarc=fail header.from=example.com",
		ReportedDomain:        "example.com",
		DKIM: []DKIMAuth{
			{Domain: "lists.test", Selector: "list", Result: "pass"},
			{Domain: "example.com", Selector: "epsilon", Result: "fail", Aligned: true},
			{Domain: "example.com", Selector: "delta", Result: "fail", Aligned: true, Identity: "x@example.com"},
		},
		SPF:                &SPFAuth{Domain: "lists.test", Result: "pass"},
		DeliveryResult:     "Reject",
		OriginalEnvelopeID: "65E1A3F0A0",
		OriginalMailFrom:   "<bounce@lists.test>",
		OriginalRcptTo:     []string{"<x@receiver.test>", "<y@receiver.test>"},
		ArrivalDate:        time.Date(2022, 7, 19, 7, 57, 44, 0, time.FixedZone("", 2*3600)),
		SourceIP:           "192.0.2.2",
		SourcePort:         12345,
		Incidents:          3,
		Message:            []byte(originalMessage),
		Boundary:           "=_mime_boundary_",
	}
}

// reportParts parses a generated report and returns its header and parts.
func reportParts(t *testing.T, report []byte) (*mail.Message, []*multipart.Part, [][]byte) {
	t.Helper()
	msg, err := mail.ReadMessage(bytes.NewReader(report))
	if err != nil {
		t.Fatalf("report is not a message: %v\n%s", err, report)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/report" || params["report-type"] != "feedback-report" {
		t.Fatalf("Content-Type = %q (%v)", msg.Header.Get("Content-Type"), err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	var parts []*multipart.Part
	var bodies [][]byte
	for {
		p, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(p)
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, p)
		bodies = append(bodies, b)
	}
	return msg, parts, bodies
}

// feedbackFieldList parses the message/feedback-report part as ordered
// name/value pairs.
func feedbackFieldList(t *testing.T, b []byte) [][2]string {
	t.Helper()
	var out [][2]string
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSuffix(sc.Text(), "\r")
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ": ")
		if !ok {
			t.Fatalf("feedback line %q is not a field", line)
		}
		out = append(out, [2]string{name, value})
	}
	return out
}

// TestBuildFailureReport checks a full generated report field by field: the
// multipart/report wrapper (RFC 5965 §2), the human-readable part, the
// message/feedback-report part with the required fields of RFC 5965 §3.1,
// RFC 6591 §3 and RFC 9991 §4, and the original header as
// text/rfc822-headers.
//
// checklist: DMARC-FAIL-01 DMARC-FAIL-05 DMARC-FAIL-06 DMARC-FAIL-07 DMARC-FAIL-08
func TestBuildFailureReport(t *testing.T) {
	report, err := BuildFailureReport(sampleReport())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bytes.ReplaceAll(report, []byte("\r\n"), nil), []byte("\n")) {
		t.Error("report has a bare LF")
	}
	msg, parts, bodies := reportParts(t, report)
	for name, want := range map[string]string{
		"From":         "DMARC Reporter <dmarc@receiver.test>",
		"To":           "dmarcfail@example.com",
		"Date":         "Tue, 19 Jul 2022 00:57:48 -0500",
		"Subject":      "This is the original subject",
		"Message-Id":   "<20220719055748.4AE9D403CC@receiver.test>",
		"Mime-Version": "1.0",
	} {
		if got := msg.Header.Get(name); got != want {
			t.Errorf("header %s = %q, want %q", name, got, want)
		}
	}
	if len(parts) != 3 {
		t.Fatalf("got %d parts, want 3", len(parts))
	}

	wantTypes := []string{"text/plain; charset=us-ascii", "message/feedback-report", "text/rfc822-headers"}
	for i, p := range parts {
		if got := p.Header.Get("Content-Type"); got != wantTypes[i] {
			t.Errorf("part %d Content-Type = %q, want %q", i+1, got, wantTypes[i])
		}
		if got := p.Header.Get("Content-Transfer-Encoding"); got != "7bit" {
			t.Errorf("part %d Content-Transfer-Encoding = %q", i+1, got)
		}
	}

	human := string(bodies[0])
	for _, s := range []string{"DMARC failure report", "192.0.2.2", "Tue, 19 Jul 2022 07:57:44 +0200", "example.com", "Identity-Alignment: dkim"} {
		if !strings.Contains(human, s) {
			t.Errorf("human-readable part lacks %q:\n%s", s, human)
		}
	}

	want := [][2]string{
		{"Feedback-Type", "auth-failure"},
		{"User-Agent", "go-dmarc/0.7"},
		{"Version", "1"},
		{"Auth-Failure", "dmarc"},
		{"Authentication-Results", "mx.receiver.test; dmarc=fail header.from=example.com"},
		{"Identity-Alignment", "dkim, spf"},
		{"Delivery-Result", "reject"},
		{"DKIM-Domain", "example.com"},
		{"DKIM-Identity", "@example.com"},
		{"DKIM-Selector", "epsilon"},
		{"Original-Envelope-Id", "65E1A3F0A0"},
		{"Original-Mail-From", "<bounce@lists.test>"},
		{"Original-Rcpt-To", "<x@receiver.test>"},
		{"Original-Rcpt-To", "<y@receiver.test>"},
		{"Arrival-Date", "Tue, 19 Jul 2022 07:57:44 +0200"},
		{"Reporting-MTA", "dns; mx.receiver.test"},
		{"Source-IP", "192.0.2.2"},
		{"Source-Port", "12345"},
		{"Incidents", "3"},
		{"Reported-Domain", "example.com"},
	}
	got := feedbackFieldList(t, bodies[1])
	if len(got) != len(want) {
		t.Errorf("feedback part has %d fields, want %d:\n%s", len(got), len(want), bodies[1])
	}
	for i := range min(len(got), len(want)) {
		if got[i] != want[i] {
			t.Errorf("feedback field %d = %q, want %q", i+1, got[i], want[i])
		}
	}
	// RFC 5965 §3.1 and RFC 6591 §3.1, §3.2.1: these appear exactly once.
	for _, name := range []string{"Feedback-Type", "User-Agent", "Version", "Auth-Failure", "Authentication-Results", "Identity-Alignment"} {
		n := 0
		for _, f := range got {
			if f[0] == name {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%s appears %d times", name, n)
		}
	}
	// The part is a valid header block, as message/feedback-report is.
	if _, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(append(bodies[1], '\r', '\n')))).ReadMIMEHeader(); err != nil {
		t.Errorf("feedback part does not parse as a header: %v", err)
	}

	wantHeader := strings.ReplaceAll(originalMessage[:strings.Index(originalMessage, "\n\n")+1], "\n", "\r\n")
	if string(bodies[2]) != wantHeader {
		t.Errorf("original header part =\n%q\nwant\n%q", bodies[2], wantHeader)
	}
}

// TestBuildFailureReportOriginal checks the third part: the header alone by
// default, the whole message on request, the fall back to the header when the
// message is over MaxOriginalSize, and the redaction hooks (RFC 9991 §7,
// RFC 6590).
//
// checklist: DMARC-FAIL-08 DMARC-FAIL-09
func TestBuildFailureReportOriginal(t *testing.T) {
	secret := []byte("k")
	redact := RedactLocalParts(secret)
	token, _ := redact("To", " users@lists.test")
	token = strings.TrimSpace(strings.TrimSuffix(token, "@lists.test"))
	if token == "users" || len(token) != 8 {
		t.Fatalf("redacted local part = %q", token)
	}
	if again, _ := RedactLocalParts(secret)("Cc", "users@lists.test"); again != token+"@lists.test" {
		t.Errorf("redaction is not stable: %q vs %q", again, token)
	}
	if other, _ := RedactLocalParts([]byte("other"))("Cc", "users@lists.test"); other == token+"@lists.test" {
		t.Error("redaction ignores the secret")
	}
	for _, c := range []struct{ in, want string }{
		{" mx.test; dkim=pass header.i=@example.com header.s=s", " mx.test; dkim=pass header.i=@example.com header.s=s"},
		{" v=1; d=example.com; i=users@example.com; s=s", " v=1; d=example.com; i=" + token + "@example.com; s=s"},
		{" <SRS0=HHH=TT=example.com=users@lists.test>", " <SRS0=HHH=TT=example.com=" + token + "@lists.test>"},
		{` "users"@example.com`, ` ` + mustRedact(redact, `"users"`) + `@example.com`},
		{" no address here", " no address here"},
	} {
		if got, keep := redact("X", c.in); got != c.want || !keep {
			t.Errorf("redact(%q) = %q, %v; want %q", c.in, got, keep, c.want)
		}
	}

	dropReceived := func(name, value string) (string, bool) {
		if strings.EqualFold(name, "Received") {
			return "", false
		}
		return redact(name, value)
	}
	cases := []struct {
		name     string
		edit     func(*FailureReport)
		wantType string
		has      []string
		lacks    []string
		feedback []string
	}{
		{"header only by default", func(*FailureReport) {}, "text/rfc822-headers",
			[]string{"Subject: This is the original subject", "\tb=abc"}, []string{"Hello users"}, nil},
		{"whole message", func(r *FailureReport) { r.IncludeBody = true }, "message/rfc822",
			[]string{"Message-ID: <1234@example.com>\r\n\r\nHello users,\r\nthe body.\r\n"}, nil, nil},
		{"body redacted", func(r *FailureReport) {
			r.IncludeBody = true
			r.RedactBody = func([]byte) []byte { return []byte("[ Message body was here ]\n") }
		}, "message/rfc822", []string{"\r\n\r\n[ Message body was here ]\r\n"}, []string{"Hello users"}, nil},
		{"over the size limit: header only", func(r *FailureReport) {
			r.IncludeBody = true
			r.MaxOriginalSize = len(originalMessage) - 5
		}, "text/rfc822-headers", []string{"Subject: This is the original subject"}, []string{"Hello users"}, nil},
		{"headers redacted and dropped", func(r *FailureReport) { r.RedactHeader = dropReceived }, "text/rfc822-headers",
			[]string{"To: " + token + "@lists.test", "@example.com>"}, []string{"Received:", "users@", "author@"},
			[]string{"Original-Rcpt-To: <" + mustRedact(redact, "x") + "@receiver.test>"}},
		{"report fields dropped", func(r *FailureReport) {
			r.RedactHeader = func(name, v string) (string, bool) { return v, !strings.HasPrefix(name, "Original-") }
		}, "text/rfc822-headers", []string{"Received:"}, nil, nil},
		{"8-bit body", func(r *FailureReport) {
			r.IncludeBody = true
			r.Message = []byte("Subject: caf\xc3\xa9\r\n\r\ncaf\xc3\xa9\r\n")
		}, "message/rfc822", []string{"caf\xc3\xa9\r\n"}, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := sampleReport()
			c.edit(&r)
			report, err := BuildFailureReport(r)
			if err != nil {
				t.Fatal(err)
			}
			_, parts, bodies := reportParts(t, report)
			if got := parts[2].Header.Get("Content-Type"); got != c.wantType {
				t.Errorf("Content-Type = %q, want %q", got, c.wantType)
			}
			for _, s := range c.has {
				if !bytes.Contains(bodies[2], []byte(s)) {
					t.Errorf("original part lacks %q:\n%s", s, bodies[2])
				}
			}
			for _, s := range c.lacks {
				if bytes.Contains(bodies[2], []byte(s)) {
					t.Errorf("original part has %q:\n%s", s, bodies[2])
				}
			}
			for _, s := range c.feedback {
				if !bytes.Contains(bodies[1], []byte(s)) {
					t.Errorf("feedback part lacks %q:\n%s", s, bodies[1])
				}
			}
			if c.name == "report fields dropped" && bytes.Contains(bodies[1], []byte("Original-Rcpt-To")) {
				t.Errorf("dropped report field kept:\n%s", bodies[1])
			}
			if c.name == "8-bit body" && parts[2].Header.Get("Content-Transfer-Encoding") != "8bit" {
				t.Error("8-bit content not marked 8bit")
			}
		})
	}
}

// mustRedact returns the redacted form of a local part.
func mustRedact(redact HeaderRedactor, local string) string {
	v, _ := redact("", local+"@x.test")
	return strings.TrimSuffix(v, "@x.test")
}

// TestBuildFailureReportFields checks the conditional fields: SPF-DNS for an
// aligned SPF failure (RFC 9991 §4 item 1, RFC 6591 §4), the RFC 5321
// §4.1.3 form of an IPv6 Source-IP, and the fields left out when unknown.
//
// checklist: DMARC-FAIL-06 DMARC-FAIL-07
func TestBuildFailureReportFields(t *testing.T) {
	r := sampleReport()
	r.DKIM = []DKIMAuth{{Domain: "example.com", Selector: "delta", Result: "fail", Aligned: true, Identity: "x@example.com"}}
	r.SPF = &SPFAuth{Domain: "example.com", Result: "softfail", Aligned: true}
	r.SPFDNS = []SPFDNS{{Domain: "example.com", Record: "v=spf1 include:_spf.example.com ~all"}, {Domain: "_spf.example.com", Record: "v=spf1 ip4:192.0.2.0/24 -all"}}
	r.SourceIP = "::ffff:192.0.2.9"
	r.DeliveryResult, r.OriginalEnvelopeID, r.OriginalMailFrom, r.OriginalRcptTo = "", "", "", nil
	r.ArrivalDate, r.ReportingMTA, r.SourcePort, r.Incidents, r.MessageID = time.Time{}, "", 0, 1, ""
	report, err := BuildFailureReport(r)
	if err != nil {
		t.Fatal(err)
	}
	msg, _, bodies := reportParts(t, report)
	want := [][2]string{
		{"Feedback-Type", "auth-failure"},
		{"User-Agent", "go-dmarc/0.7"},
		{"Version", "1"},
		{"Auth-Failure", "dmarc"},
		{"Authentication-Results", "mx.receiver.test; dmarc=fail header.from=example.com"},
		{"Identity-Alignment", "dkim, spf"},
		{"DKIM-Domain", "example.com"},
		{"DKIM-Identity", "x@example.com"},
		{"DKIM-Selector", "delta"},
		{"SPF-DNS", `txt : example.com : "v=spf1 include:_spf.example.com ~all"`},
		{"SPF-DNS", `txt : _spf.example.com : "v=spf1 ip4:192.0.2.0/24 -all"`},
		{"Source-IP", "192.0.2.9"},
		{"Reported-Domain", "example.com"},
	}
	if got := feedbackFieldList(t, bodies[1]); !reflect.DeepEqual(got, want) {
		t.Errorf("feedback fields =\n%q\nwant\n%q", got, want)
	}
	if msg.Header.Get("Message-Id") != "" {
		t.Error("empty Message-ID written")
	}

	r.SourceIP = "2001:db8::23ac"
	r.Message = []byte("X-No-Subject: 1\n")
	r.Boundary = ""
	report, err = BuildFailureReport(r)
	if err != nil {
		t.Fatal(err)
	}
	msg, _, bodies = reportParts(t, report)
	if !bytes.Contains(bodies[1], []byte("Source-IP: IPv6:2001:db8::23ac\r\n")) {
		t.Errorf("IPv6 Source-IP not in RFC 5321 form:\n%s", bodies[1])
	}
	if msg.Header.Get("Subject") != "" || string(bodies[2]) != "X-No-Subject: 1\r\n" {
		t.Errorf("Subject %q, original %q", msg.Header.Get("Subject"), bodies[2])
	}

	// An mbox "From " line is not a field and is dropped; a header with no
	// final line break still ends with one.
	r.Message = []byte("From author@example.com Tue Jul 19 07:57:33 2022\nSubject: s")
	report, err = BuildFailureReport(r)
	if err != nil {
		t.Fatal(err)
	}
	_, _, bodies = reportParts(t, report)
	if string(bodies[2]) != "Subject: s\r\n" {
		t.Errorf("original %q, want only the Subject field", bodies[2])
	}
}

// TestBuildFailureReportErrors checks the inputs that cannot make a valid
// report.
//
// checklist: DMARC-FAIL-07
func TestBuildFailureReportErrors(t *testing.T) {
	cases := []struct {
		name string
		edit func(*FailureReport)
		want string
	}{
		{"no From", func(r *FailureReport) { r.From = "" }, "From and To"},
		{"no To", func(r *FailureReport) { r.To = "" }, "From and To"},
		{"no Date", func(r *FailureReport) { r.Date = time.Time{} }, "Date"},
		{"no User-Agent", func(r *FailureReport) { r.UserAgent = "" }, "User-Agent"},
		{"no Authentication-Results", func(r *FailureReport) { r.AuthenticationResults = "" }, "Authentication-Results"},
		{"bad domain", func(r *FailureReport) { r.ReportedDomain = "not a domain" }, "not a domain name"},
		{"no header", func(r *FailureReport) { r.Message = []byte("\r\nbody only") }, "no header"},
		{"empty message", func(r *FailureReport) { r.Message = nil }, "no header"},
		{"bad delivery result", func(r *FailureReport) { r.DeliveryResult = "bounced" }, "delivery result"},
		{"aligned SPF failure without SPF-DNS", func(r *FailureReport) { r.SPF = &SPFAuth{Result: "fail", Aligned: true} }, "SPF-DNS"},
		{"bad source IP", func(r *FailureReport) { r.SourceIP = "192.0.2.300" }, "source IP"},
		{"zoned source IP", func(r *FailureReport) { r.SourceIP = "fe80::1%eth0" }, "source IP"},
		{"field injection", func(r *FailureReport) { r.OriginalEnvelopeID = "x\r\nInjected: y" }, "Original-Envelope-Id"},
		{"non-ASCII field", func(r *FailureReport) { r.UserAgent = "caf\xc3\xa9" }, "User-Agent"},
		{"header injection", func(r *FailureReport) { r.To = "a@example.com\r\nBcc: b@example.com" }, "To is not one line"},
		{"boundary in content", func(r *FailureReport) { r.Message = []byte("Subject: --=_mime_boundary_\r\n") }, "boundary"},
		{"header over the size limit", func(r *FailureReport) { r.MaxOriginalSize = 10 }, "over the 10 allowed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := sampleReport()
			c.edit(&r)
			_, err := BuildFailureReport(r)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want one containing %q", err, c.want)
			}
		})
	}
}
