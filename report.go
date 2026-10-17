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
// (the sp= tag, or p= when sp= is absent). [ParseRecord] reads every tag of a
// record, with defaults for those it omits or gets wrong; [Lookup] is the
// lower-level primitive that fetches the raw record at exactly _dmarc.<domain>,
// and [ParsePolicy] reads only a record's p=. [AlignedMode] reports whether an
// authenticated domain — from an SPF smtp.mailfrom or a verified DKIM
// signature's d= — aligns with the From domain under the record's adkim= or
// aspf= mode:
//
//	policy, _ := dmarc.Discover("mail.example.com", nil, orgDomain)
//	if !dmarc.AlignedMode(dkimDomain, "mail.example.com", policy.Record.ADKIM, orgDomain) &&
//		policy.Requested == "reject" {
//		// no aligned identifier passed: reject per published policy
//	}
//
// The Organizational Domain needs the Public Suffix List, which this package
// does not carry: pass an [OrgDomainFunc] backed by one (a wrapper around
// golang.org/x/net/publicsuffix.EffectiveTLDPlusOne). With nil, the
// two-label [DefaultOrgDomain] heuristic is used, which wrongly aligns two
// registrants under a multi-label public suffix such as co.uk.
//
// # Aggregate reporting
//
// A reporter collects one [AggregateRecord] per evaluated message, then calls
// [BuildReport] to marshal them into the RFC 7489 aggregate-report XML document,
// valid against the schema of its Appendix C; [NewPolicyPublished] describes
// the discovered policy. [AggregateRecords] performs the grouping (identical
// rows are summed into a count) and is called by [BuildReport], but is exported
// for callers that want the grouped rows directly. [Gzip] compresses the
// document for delivery as the application/gzip attachment RFC 7489 §7.2.1
// specifies. Before sending to a rua= or ruf= address outside the domain's own
// Organizational Domain, [AuthorizeReportURIs] checks that the destination
// agreed to receive the reports (§7.1).
package dmarc

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// AggregateRecord is one message's DMARC evaluation, the neutral input to
// [AggregateRecords] and [BuildReport]. It carries only what the aggregate
// report needs, so the package depends on no particular storage model.
type AggregateRecord struct {
	Domain      string // header-From (RFC5322.From) domain: the reported-on domain
	SourceIP    string
	HeaderFrom  string // header_from identifier; defaults to Domain when empty
	Disposition string // none|quarantine|reject (policy applied); other values normalize to none

	// EnvelopeFrom is the RFC5321.MailFrom domain (the identifiers/envelope_from
	// element, which RFC 7489 requires). When empty it is derived from the SPF
	// mfrom check's domain; the element is always emitted.
	EnvelopeFrom string

	// DKIM holds the per-signature DKIM authentication results, each carrying the
	// signature's own d= domain, for the auth_results section. It is empty when
	// the message carried no signature (no <dkim> element is then emitted).
	DKIM []DKIMAuth
	// SPF holds the SPF authentication result(s), each carrying the checked
	// domain (smtp.mailfrom or HELO) — never the header-From domain. The
	// report schema needs at least one, so a message without one is reported
	// with an SPF result of none for its envelope_from (or header_from)
	// domain.
	SPF []SPFAuth

	// Reasons says why the disposition differs from the policy the domain
	// requested, if it does: a message sampled out by pct=, or accepted from a
	// trusted forwarder, say (RFC 7489 §6, Appendix C PolicyOverrideReason).
	Reasons []PolicyOverrideReason
}

// PolicyOverrideReason is one reason the applied disposition differs from the
// requested policy (RFC 7489 Appendix C). Type is one of the
// PolicyOverride* constants; any other value is reported as "other" with the
// value kept in the comment.
type PolicyOverrideReason struct {
	Type    string `xml:"type"`
	Comment string `xml:"comment,omitempty"`
}

// The PolicyOverrideType values of RFC 7489 Appendix C.
const (
	PolicyOverrideForwarded        = "forwarded"
	PolicyOverrideSampledOut       = "sampled_out"
	PolicyOverrideTrustedForwarder = "trusted_forwarder"
	PolicyOverrideMailingList      = "mailing_list"
	PolicyOverrideLocalPolicy      = "local_policy"
	PolicyOverrideOther            = "other"
)

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
// [NewPolicyPublished] fills it from a discovered [Policy].
//
// The Appendix C schema requires domain, p, sp, pct and fo. [BuildReport]
// writes an empty SP as P (the policy subdomains get without sp=) and an
// empty FO as "0" (the default); PCT is written as it is, so set it (to 100
// when the record has no pct=). ADKIM and ASPF are "r" or "s", and are left
// out when empty.
type PolicyPublished struct {
	Domain string `xml:"domain"`
	ADKIM  string `xml:"adkim,omitempty"`
	ASPF   string `xml:"aspf,omitempty"`
	P      string `xml:"p"`
	SP     string `xml:"sp"`
	PCT    int    `xml:"pct"`
	FO     string `xml:"fo"`
}

// NewPolicyPublished returns the policy_published element for a policy found
// by [Discover]: the domain the record was found at and its p=, sp=, adkim=,
// aspf=, pct= and fo= values, with defaults for those it omits.
func NewPolicyPublished(p Policy) PolicyPublished {
	r := p.Record
	sp := r.SubdomainPolicy
	if sp == "" {
		sp = r.Policy
	}
	fo := strings.Join(r.FailureOptions, ":")
	if fo == "" {
		fo = "0"
	}
	return PolicyPublished{
		Domain: p.Domain,
		ADKIM:  alignmentLetter(r.ADKIM),
		ASPF:   alignmentLetter(r.ASPF),
		P:      r.Policy,
		SP:     sp,
		PCT:    r.Pct,
		FO:     fo,
	}
}

// alignmentLetter is the AlignmentType value of a mode: "s" or "r".
func alignmentLetter(m AlignmentMode) string {
	if m == AlignmentStrict {
		return "s"
	}
	return "r"
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
	Disposition string                 `xml:"disposition"`
	DKIM        string                 `xml:"dkim"`
	SPF         string                 `xml:"spf"`
	Reasons     []PolicyOverrideReason `xml:"reason,omitempty"`
}

type Identifiers struct {
	EnvelopeFrom string `xml:"envelope_from"`
	HeaderFrom   string `xml:"header_from"`
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
	Scope  string `xml:"scope"`
	Result string `xml:"result"`
}

// evaluated returns the DMARC-aligned pass/fail: a mechanism only counts as
// passing DMARC when it both passed AND aligned with the From domain.
func evaluated(result string, aligned bool) string {
	if aligned && strings.EqualFold(strings.TrimSpace(result), "pass") {
		return "pass"
	}
	return "fail"
}

// The RFC 7489 Appendix C result/scope/disposition types are closed
// enumerations; a value outside the set makes the document fail schema
// validation. The normalize* helpers lower-case the input and fall back to a
// safe in-enumeration default (none for results/disposition, mfrom for scope)
// so an unknown or empty value never reaches the emitted XML.

func normalizeDKIMResult(s string) string {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "none", "pass", "fail", "policy", "neutral", "temperror", "permerror":
		return v
	default:
		return "none"
	}
}

func normalizeSPFResult(s string) string {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "none", "neutral", "pass", "fail", "softfail", "temperror", "permerror":
		return v
	default:
		return "none"
	}
}

func normalizeSPFScope(s string) string {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "helo", "mfrom":
		return v
	default:
		return "mfrom"
	}
}

// normalizeAlignment keeps an adkim/aspf value of r or s and drops anything
// else, which the schema's AlignmentType does not allow.
func normalizeAlignment(s string) string {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "r", "s":
		return v
	default:
		return ""
	}
}

// normalizeReasons maps each reason's type to the PolicyOverrideType
// enumeration; an unknown type becomes "other" and keeps its text in the
// comment.
func normalizeReasons(reasons []PolicyOverrideReason) []PolicyOverrideReason {
	var out []PolicyOverrideReason
	for _, r := range reasons {
		t := strings.ToLower(strings.TrimSpace(r.Type))
		switch t {
		case PolicyOverrideForwarded, PolicyOverrideSampledOut, PolicyOverrideTrustedForwarder,
			PolicyOverrideMailingList, PolicyOverrideLocalPolicy, PolicyOverrideOther:
		default:
			if r.Comment == "" {
				r.Comment = r.Type
			} else if r.Type != "" {
				r.Comment = r.Type + ": " + r.Comment
			}
			t = PolicyOverrideOther
		}
		out = append(out, PolicyOverrideReason{Type: t, Comment: r.Comment})
	}
	return out
}

// reportIP writes a source IP address the way the Appendix C IPAddress
// pattern accepts it: an IPv4 address as a dotted quad (an IPv4-mapped IPv6
// address included), and an IPv6 address in full, as eight groups, since the
// pattern has no "::" form. It returns false for a string that is not an IP
// address.
func reportIP(s string) (string, bool) {
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || ip.Zone() != "" {
		return s, false
	}
	if ip = ip.Unmap(); ip.Is4() {
		return ip.String(), true
	}
	return ip.StringExpanded(), true
}

func normalizeDisposition(s string) string {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "none", "quarantine", "reject":
		return v
	default:
		return "none"
	}
}

// headerFrom resolves the header_from identifier, defaulting to the reported-on
// domain when the record carried no explicit header-From.
func headerFrom(r AggregateRecord) string {
	if r.HeaderFrom != "" {
		return r.HeaderFrom
	}
	return r.Domain
}

// envelopeFrom resolves the RFC5321.MailFrom domain for the required
// identifiers/envelope_from element, deriving it from the SPF mfrom check's
// domain when the caller did not supply one.
func envelopeFrom(r AggregateRecord) string {
	if r.EnvelopeFrom != "" {
		return r.EnvelopeFrom
	}
	for _, s := range r.SPF {
		if normalizeSPFScope(s.Scope) == "mfrom" && s.Domain != "" {
			return s.Domain
		}
	}
	return ""
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
		sourceIP, headerFrom, envelopeFrom, disposition, dkimEval, spfEval, auth, reasons string
	}
	order := []key{}
	counts := map[key]int{}
	rep := map[key]AggregateRecord{}
	for _, r := range records {
		ip, _ := reportIP(r.SourceIP)
		k := key{
			sourceIP:     ip,
			headerFrom:   headerFrom(r),
			envelopeFrom: envelopeFrom(r),
			disposition:  normalizeDisposition(r.Disposition),
			dkimEval:     dmarcDKIM(r.DKIM),
			spfEval:      dmarcSPF(r.SPF),
			auth:         authResultsKey(r.DKIM, r.SPF),
			reasons:      reasonsKey(r.Reasons),
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
		out = append(out, ReportRecord{
			Row: Row{
				SourceIP: k.sourceIP,
				Count:    counts[k],
				PolicyEvaluated: PolicyEvaluated{
					Disposition: k.disposition,
					DKIM:        k.dkimEval,
					SPF:         k.spfEval,
					Reasons:     normalizeReasons(r.Reasons),
				},
			},
			Identifiers: Identifiers{
				EnvelopeFrom: k.envelopeFrom,
				HeaderFrom:   k.headerFrom,
			},
			AuthResults: authResults(r, k.envelopeFrom, k.headerFrom),
		})
	}
	return out
}

// authResults maps a message's DKIM/SPF authentication results to the report
// schema, reporting each DKIM signature's d= domain and selector and each SPF
// check's checked domain and scope individually (RFC 7489 §7.2, Appendix C). No
// <dkim> element is produced when the message carried no signature. The
// schema requires an <spf> element, so a message without an SPF result gets
// one of none for its envelope (or, failing that, header) From domain.
func authResults(r AggregateRecord, envelopeFrom, headerFrom string) AuthResults {
	var ar AuthResults
	for _, d := range r.DKIM {
		ar.DKIM = append(ar.DKIM, DKIMResult{
			Domain:   d.Domain,
			Selector: d.Selector,
			Result:   normalizeDKIMResult(d.Result),
		})
	}
	for _, s := range r.SPF {
		ar.SPF = append(ar.SPF, SPFResult{
			Domain: s.Domain,
			Scope:  normalizeSPFScope(s.Scope),
			Result: normalizeSPFResult(s.Result),
		})
	}
	if len(ar.SPF) == 0 {
		domain := envelopeFrom
		if domain == "" {
			domain = headerFrom
		}
		ar.SPF = []SPFResult{{Domain: domain, Scope: "mfrom", Result: "none"}}
	}
	return ar
}

// reasonsKey is a comparable identity for a message's override reasons.
func reasonsKey(reasons []PolicyOverrideReason) string {
	var b strings.Builder
	for _, r := range normalizeReasons(reasons) {
		b.WriteString(r.Type)
		b.WriteByte(0)
		b.WriteString(r.Comment)
		b.WriteByte(0)
	}
	return b.String()
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
		b.WriteString(normalizeDKIMResult(d.Result))
		b.WriteByte(0)
	}
	b.WriteByte('\n')
	for _, s := range spf {
		b.WriteString("spf\x00")
		b.WriteString(s.Domain)
		b.WriteByte(0)
		b.WriteString(normalizeSPFScope(s.Scope))
		b.WriteByte(0)
		b.WriteString(normalizeSPFResult(s.Result))
		b.WriteByte(0)
	}
	return b.String()
}

// BuildReport assembles an RFC 7489 aggregate report XML document (with the XML
// declaration prepended) that conforms to the Appendix C schema. The policy's
// values are normalized as [PolicyPublished] describes. It returns an error,
// and no document, when there are no records (the schema requires one) or a
// record's SourceIP is not an IP address.
func BuildReport(meta ReportMetadata, policy PolicyPublished, records []AggregateRecord) ([]byte, error) {
	if len(records) == 0 {
		return nil, errors.New("dmarc: an aggregate report needs at least one record")
	}
	for _, r := range records {
		if _, ok := reportIP(r.SourceIP); !ok {
			return nil, fmt.Errorf("dmarc: source IP %q is not an IP address", r.SourceIP)
		}
	}
	policy.P = normalizeDisposition(policy.P)
	if policy.SP == "" {
		policy.SP = policy.P
	}
	policy.SP = normalizeDisposition(policy.SP)
	policy.ADKIM = normalizeAlignment(policy.ADKIM)
	policy.ASPF = normalizeAlignment(policy.ASPF)
	if policy.FO = strings.TrimSpace(policy.FO); policy.FO == "" {
		policy.FO = "0"
	}
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
