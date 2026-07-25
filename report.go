// Package dmarc implements the receiver side of DMARC (RFC 7489): looking up and
// parsing a domain's published policy, evaluating identifier alignment, and
// generating aggregate (rua) report XML. It depends only on the Go standard
// library.
//
// DMARC (Domain-based Message Authentication, Reporting, and Conformance) lets
// the owner of a From domain publish, at _dmarc.<domain>, how receivers should
// treat mail that is not authenticated as coming from that domain. A receiver
// checks whether a passing SPF or DKIM identifier aligns with the From domain;
// if neither does, it applies the domain's published policy (none, quarantine,
// or reject) and, later, reports what it saw back to the domain owner.
//
// The package is deliberately free of any storage or scheduling concerns. A
// caller records per-message evaluations however it likes, then hands a slice of
// neutral [AggregateRecord] values to [BuildReport] to produce the RFC 7489
// aggregate-report document.
//
// # Policy discovery and evaluation
//
// [Discover] performs full policy discovery for a From domain, including the
// RFC 7489 §6.6.3 Organizational-Domain fallback: when a subdomain publishes no
// record of its own, it applies the organizational domain's subdomain policy
// (the sp= tag, or p= when sp= is absent). [Lookup] is the lower-level primitive
// that fetches the raw record at exactly _dmarc.<domain>, and [ParsePolicy]
// reads a record's requested policy from the p= tag. [Aligned] reports whether
// an authenticated domain — from an SPF smtp.mailfrom or a verified DKIM
// signature's d= — aligns with the From domain:
//
//	policy, _ := dmarc.Discover("mail.example.com", nil, nil)
//	if !dmarc.Aligned(authDomain, "mail.example.com") && policy.Requested == "reject" {
//		// no aligned identifier passed: reject per published policy
//	}
//
// # Aggregate reporting
//
// A reporter collects one [AggregateRecord] per evaluated message, then calls
// [BuildReport] to marshal them into the RFC 7489 aggregate-report XML document.
// [AggregateRecords] performs the grouping (identical rows are summed into a
// count) and is called by [BuildReport], but is exported for callers that want
// the grouped rows directly. [Gzip] compresses the document for delivery as the
// application/gzip attachment RFC 7489 §7.2.1 specifies.
package dmarc

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"strings"
)

// AggregateRecord is one message's DMARC evaluation, the neutral input to
// [AggregateRecords] and [BuildReport]. It carries only what the aggregate
// report needs, so the package depends on no particular storage model.
type AggregateRecord struct {
	Domain      string // header-From (RFC5322.From) domain: the reported-on domain
	SourceIP    string
	HeaderFrom  string // header_from identifier; defaults to Domain when empty
	Disposition string // none|quarantine|reject (policy applied)

	// DKIM holds the per-signature DKIM authentication results, each carrying the
	// signature's own d= domain, for the auth_results section. It is empty when
	// the message carried no signature (no <dkim> element is then emitted).
	DKIM []DKIMAuth
	// SPF holds the SPF authentication result(s), each carrying the checked
	// domain (smtp.mailfrom or HELO) — never the header-From domain.
	SPF []SPFAuth
}

// DKIMAuth is one DKIM signature's authentication result as reported in the
// aggregate report's auth_results (RFC 7489 Appendix C, DKIMAuthResultType).
type DKIMAuth struct {
	Domain   string // the signature's d= domain (the authenticating domain)
	Selector string // the signature's s= selector, if known (optional)
	Result   string // pass|fail|none|neutral|policy|temperror|permerror
	Aligned  bool   // whether Domain aligns with the From domain (feeds policy_evaluated)
}

// SPFAuth is an SPF authentication result as reported in the aggregate report's
// auth_results (RFC 7489 Appendix C, SPFAuthResultType).
type SPFAuth struct {
	Domain  string // the checked domain: smtp.mailfrom, or the HELO name for scope=helo
	Scope   string // mfrom|helo
	Result  string // pass|fail|softfail|neutral|none|temperror|permerror
	Aligned bool   // whether Domain aligns with the From domain (feeds policy_evaluated)
}

// Feedback is the root element of an RFC 7489 aggregate report.
type Feedback struct {
	XMLName         xml.Name        `xml:"feedback"`
	Version         string          `xml:"version,omitempty"`
	ReportMetadata  ReportMetadata  `xml:"report_metadata"`
	PolicyPublished PolicyPublished `xml:"policy_published"`
	Records         []ReportRecord  `xml:"record"`
}

// ReportMetadata identifies the reporting organization and period.
type ReportMetadata struct {
	OrgName   string    `xml:"org_name"`
	Email     string    `xml:"email"`
	ReportID  string    `xml:"report_id"`
	DateRange DateRange `xml:"date_range"`
}

// DateRange is the reporting period as UNIX epoch seconds.
type DateRange struct {
	Begin int64 `xml:"begin"`
	End   int64 `xml:"end"`
}

// PolicyPublished is the DMARC record the reported-on domain published.
type PolicyPublished struct {
	Domain string `xml:"domain"`
	ADKIM  string `xml:"adkim,omitempty"`
	ASPF   string `xml:"aspf,omitempty"`
	P      string `xml:"p"`
	SP     string `xml:"sp,omitempty"`
	PCT    int    `xml:"pct,omitempty"`
}

// ReportRecord is one aggregated row: a source IP + evaluation + counts.
type ReportRecord struct {
	Row         Row         `xml:"row"`
	Identifiers Identifiers `xml:"identifiers"`
	AuthResults AuthResults `xml:"auth_results"`
}

type Row struct {
	SourceIP        string          `xml:"source_ip"`
	Count           int             `xml:"count"`
	PolicyEvaluated PolicyEvaluated `xml:"policy_evaluated"`
}

type PolicyEvaluated struct {
	Disposition string `xml:"disposition"`
	DKIM        string `xml:"dkim"`
	SPF         string `xml:"spf"`
}

type Identifiers struct {
	HeaderFrom string `xml:"header_from"`
}

type AuthResults struct {
	DKIM []DKIMResult `xml:"dkim,omitempty"`
	SPF  []SPFResult  `xml:"spf,omitempty"`
}

type DKIMResult struct {
	Domain   string `xml:"domain"`
	Selector string `xml:"selector,omitempty"`
	Result   string `xml:"result"`
}

type SPFResult struct {
	Domain string `xml:"domain"`
	Scope  string `xml:"scope,omitempty"`
	Result string `xml:"result"`
}

// evaluated returns the DMARC-aligned pass/fail: a mechanism only counts as
// passing DMARC when it both passed AND aligned with the From domain.
func evaluated(result string, aligned bool) string {
	if result == "pass" && aligned {
		return "pass"
	}
	return "fail"
}

// dmarcDKIM returns the DKIM component of policy_evaluated: "pass" when at least
// one signature both passed and aligned with the From domain, else "fail"
// (RFC 7489 §6.6.2). An unsigned message is "fail".
func dmarcDKIM(sigs []DKIMAuth) string {
	for _, s := range sigs {
		if evaluated(s.Result, s.Aligned) == "pass" {
			return "pass"
		}
	}
	return "fail"
}

// dmarcSPF returns the SPF component of policy_evaluated: "pass" when at least
// one SPF check both passed and aligned with the From domain, else "fail".
func dmarcSPF(checks []SPFAuth) string {
	for _, c := range checks {
		if evaluated(c.Result, c.Aligned) == "pass" {
			return "pass"
		}
	}
	return "fail"
}

// AggregateRecords groups raw per-message evaluations into report rows by source
// IP, header-From, disposition, the DMARC-aligned dkim/spf verdict, and the
// full set of authentication results, summing counts.
func AggregateRecords(records []AggregateRecord) []ReportRecord {
	type key struct {
		sourceIP, headerFrom, disposition, dkimEval, spfEval, auth string
	}
	order := []key{}
	counts := map[key]int{}
	rep := map[key]AggregateRecord{}
	for _, r := range records {
		k := key{
			sourceIP:    r.SourceIP,
			headerFrom:  r.HeaderFrom,
			disposition: r.Disposition,
			dkimEval:    dmarcDKIM(r.DKIM),
			spfEval:     dmarcSPF(r.SPF),
			auth:        authResultsKey(r.DKIM, r.SPF),
		}
		if _, seen := counts[k]; !seen {
			order = append(order, k)
			rep[k] = r
		}
		counts[k]++
	}

	out := make([]ReportRecord, 0, len(order))
	for _, k := range order {
		r := rep[k]
		hf := r.HeaderFrom
		if hf == "" {
			hf = r.Domain
		}
		out = append(out, ReportRecord{
			Row: Row{
				SourceIP: r.SourceIP,
				Count:    counts[k],
				PolicyEvaluated: PolicyEvaluated{
					Disposition: r.Disposition,
					DKIM:        k.dkimEval,
					SPF:         k.spfEval,
				},
			},
			Identifiers: Identifiers{HeaderFrom: hf},
			AuthResults: authResults(r.DKIM, r.SPF),
		})
	}
	return out
}

// authResults maps a message's DKIM/SPF authentication results to the report
// schema, reporting each DKIM signature's d= domain and selector and each SPF
// check's checked domain and scope individually (RFC 7489 §7.2, Appendix C). No
// <dkim> element is produced when the message carried no signature.
func authResults(dkim []DKIMAuth, spf []SPFAuth) AuthResults {
	var ar AuthResults
	for _, d := range dkim {
		ar.DKIM = append(ar.DKIM, DKIMResult{Domain: d.Domain, Selector: d.Selector, Result: d.Result})
	}
	for _, s := range spf {
		ar.SPF = append(ar.SPF, SPFResult{Domain: s.Domain, Scope: s.Scope, Result: s.Result})
	}
	return ar
}

// authResultsKey builds a comparable identity for a message's auth_results so
// that rows with identical authentication details group and count together. The
// NUL separators cannot appear in a domain, selector, or result value, so the
// encoding is unambiguous.
func authResultsKey(dkim []DKIMAuth, spf []SPFAuth) string {
	var b strings.Builder
	for _, d := range dkim {
		b.WriteString("dkim\x00")
		b.WriteString(d.Domain)
		b.WriteByte(0)
		b.WriteString(d.Selector)
		b.WriteByte(0)
		b.WriteString(d.Result)
		b.WriteByte(0)
	}
	b.WriteByte('\n')
	for _, s := range spf {
		b.WriteString("spf\x00")
		b.WriteString(s.Domain)
		b.WriteByte(0)
		b.WriteString(s.Scope)
		b.WriteByte(0)
		b.WriteString(s.Result)
		b.WriteByte(0)
	}
	return b.String()
}

// BuildReport assembles an RFC 7489 aggregate report XML document (with the XML
// declaration prepended).
func BuildReport(meta ReportMetadata, policy PolicyPublished, records []AggregateRecord) ([]byte, error) {
	fb := Feedback{
		Version:         "1.0",
		ReportMetadata:  meta,
		PolicyPublished: policy,
		Records:         AggregateRecords(records),
	}
	body, err := xml.MarshalIndent(fb, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal dmarc report: %w", err)
	}
	return append([]byte(xml.Header), body...), nil
}

// Gzip compresses report bytes for the report attachment (reports are delivered
// as application/gzip per RFC 7489 §7.2.1).
func Gzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
