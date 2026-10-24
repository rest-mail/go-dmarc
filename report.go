// Package dmarc implements the receiver side of DMARC (RFC 9989): looking up
// and parsing a domain's published policy with the DNS Tree Walk, evaluating
// identifier alignment, and generating aggregate (rua) report XML (RFC 9990).
// It depends only on the Go standard library.
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
// neutral [AggregateRecord] values to [BuildReport] to produce the aggregate
// report.
//
// # Policy discovery and evaluation
//
// [Discover] performs policy discovery for an Author Domain (RFC 9989
// §4.10.1): its own record, or else, by the DNS Tree Walk (§4.10), the record
// of its Organizational Domain or its Public Suffix Domain, whose subdomain
// policy applies (sp=, np= for a domain that does not exist, else p=), one
// level lower in test mode (t=y). [ParseRecord] reads every tag of a record,
// with defaults for those it omits or gets wrong; [Lookup] is the lower-level
// primitive that fetches the raw record at exactly _dmarc.<domain>, and
// [ParsePolicy] reads only a record's p=. [AlignedMode] reports whether an
// authenticated domain — from an SPF smtp.mailfrom or a verified DKIM
// signature's d= — aligns with the From domain under the record's adkim= or
// aspf= mode, comparing the Organizational Domains [OrgDomain] finds:
//
//	policy, _ := dmarc.Discover("mail.example.com", nil, nil)
//	aligned, _ := dmarc.AlignedMode(dkimDomain, "mail.example.com", policy.Record.ADKIM, nil)
//	if !aligned && policy.Applied == "reject" {
//		// no aligned identifier passed: weigh the published policy (§5.4)
//	}
//
// The Organizational Domain comes from DNS, not from the Public Suffix List:
// the Tree Walk reads the records published above a domain, and a Public
// Suffix Domain that publishes one with psd=y marks itself.
//
// # Aggregate reporting
//
// A reporter collects one [AggregateRecord] per evaluated message, then calls
// [BuildReport] to marshal them into the RFC 9990 aggregate-report XML
// document, valid against the schema of its Appendix A; [NewPolicyPublished]
// describes the discovered policy. [AggregateRecords] performs the grouping
// (identical rows are summed into a count) and is called by [BuildReport], but
// is exported for callers that want the grouped rows directly. [Gzip]
// compresses the document for delivery as the application/gzip attachment,
// which [ReportFilename] names and whose message [ReportSubject] titles
// (RFC 9990 §3.5.2). Before sending to a rua= or ruf= address outside the
// domain's own Organizational Domain, [AuthorizeReportURIs] checks that the
// destination agreed to receive the reports (RFC 9990 §4).
package dmarc

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Namespace is the XML namespace of an RFC 9990 aggregate report, which its
// root element declares (§3.1.1.1, §6.1).
const Namespace = "urn:ietf:params:xml:ns:dmarc-2.0"

// AggregateRecord is one message's DMARC evaluation, the neutral input to
// [AggregateRecords] and [BuildReport]. It carries only what the aggregate
// report needs, so the package depends on no particular storage model.
type AggregateRecord struct {
	Domain      string // header-From (RFC5322.From) domain: the reported-on domain
	SourceIP    string
	HeaderFrom  string // header_from identifier; defaults to Domain when empty
	Disposition string // none|pass|quarantine|reject (the action taken); other values normalize to none

	// EnvelopeFrom is the RFC5321.MailFrom domain (identifiers/envelope_from).
	// When empty it is the SPF check's domain, and when there is none the
	// element is left out, as RFC 9990 §3.1.1.10 allows (a null reverse-path
	// has no domain).
	EnvelopeFrom string
	// EnvelopeTo is the RFC5321.RcptTo domain (identifiers/envelope_to),
	// left out when empty.
	EnvelopeTo string

	// DKIM holds the per-signature DKIM authentication results, each carrying the
	// signature's own d= domain and s= selector, for the auth_results section.
	// It is empty when the message carried no signature (no <dkim> element is
	// then emitted). A row reports at most 100, those that matter most first
	// (RFC 9990 §3.1.3).
	DKIM []DKIMAuth
	// SPF is the SPF result for the MAIL FROM identity, the only one DMARC
	// uses (RFC 9990 §3.1.1.13), or nil when SPF was not checked; no <spf>
	// element is then emitted.
	SPF *SPFAuth

	// Reasons says why the disposition differs from the policy the domain
	// requested, if it does: a message accepted from a trusted forwarder or a
	// mailing list, or one the record's test mode exempted, say (RFC 9990
	// §3.1.6).
	Reasons []PolicyOverrideReason
}

// PolicyOverrideReason is one reason the applied disposition differs from the
// requested policy (RFC 9990 §3.1.6). Type is one of the PolicyOverride*
// constants; any other value is reported as "other" with the value kept in
// the comment.
type PolicyOverrideReason struct {
	Type    string `xml:"type"`
	Comment string `xml:"comment,omitempty"`
}

// The PolicyOverrideType values of RFC 9990 §3.1.6.
const (
	PolicyOverrideLocalPolicy      = "local_policy"
	PolicyOverrideMailingList      = "mailing_list"
	PolicyOverrideOther            = "other"
	PolicyOverridePolicyTestMode   = "policy_test_mode"
	PolicyOverrideTrustedForwarder = "trusted_forwarder"
)

// DKIMAuth is one DKIM signature's authentication result as reported in the
// aggregate report's auth_results (RFC 9990 §3.1.1.12).
type DKIMAuth struct {
	Domain   string // the signature's d= domain (the authenticating domain)
	Selector string // the signature's s= selector, which the report requires
	Result   string // pass|fail|none|neutral|policy|temperror|permerror
	Aligned  bool   // whether Domain aligns with the From domain (feeds policy_evaluated)
}

// SPFAuth is the SPF authentication result of the MAIL FROM identity as
// reported in the aggregate report's auth_results (RFC 9990 §3.1.1.13).
type SPFAuth struct {
	Domain  string // the checked domain: the smtp.mailfrom domain
	Result  string // pass|fail|softfail|neutral|policy|none|temperror|permerror
	Aligned bool   // whether Domain aligns with the From domain (feeds policy_evaluated)
}

// Feedback is the root element of an RFC 9990 aggregate report.
type Feedback struct {
	XMLName         xml.Name        `xml:"urn:ietf:params:xml:ns:dmarc-2.0 feedback"`
	Version         string          `xml:"version,omitempty"`
	ReportMetadata  ReportMetadata  `xml:"report_metadata"`
	PolicyPublished PolicyPublished `xml:"policy_published"`
	Records         []ReportRecord  `xml:"record"`
}

// ReportMetadata identifies the reporting organization and period (RFC 9990
// §3.1.1.3). ExtraContactInfo, Error and Generator are left out when empty.
type ReportMetadata struct {
	OrgName          string    `xml:"org_name"`
	Email            string    `xml:"email"`
	ExtraContactInfo string    `xml:"extra_contact_info,omitempty"`
	ReportID         string    `xml:"report_id"`
	DateRange        DateRange `xml:"date_range"`
	// Error describes problems found with the domain's DMARC Policy Record,
	// such as an invalid tag or several records at one name (§3.1.5).
	Error string `xml:"error,omitempty"`
	// Generator names the software that wrote the report, and its version.
	Generator string `xml:"generator,omitempty"`
}

// DateRange is the reporting period as UNIX epoch seconds.
type DateRange struct {
	Begin int64 `xml:"begin"`
	End   int64 `xml:"end"`
}

// PolicyPublished is the DMARC Policy Record the reported-on domain
// published (RFC 9990 §3.1.1.5). [NewPolicyPublished] fills it from a
// discovered [Policy].
//
// The elements from p on carry the discovered value or the default, so
// [BuildReport] writes an empty SP as P, an empty NP as SP, an empty FO as
// "0", empty ADKIM and ASPF as "r" and an empty Testing as "n". An empty
// DiscoveryMethod is left out.
type PolicyPublished struct {
	Domain          string `xml:"domain"`
	DiscoveryMethod string `xml:"discovery_method,omitempty"` // treewalk (RFC 9989) or psl (RFC 7489)
	P               string `xml:"p"`
	SP              string `xml:"sp"`
	NP              string `xml:"np"`
	FO              string `xml:"fo"`
	ADKIM           string `xml:"adkim"`
	ASPF            string `xml:"aspf"`
	Testing         string `xml:"testing"` // y or n
}

// NewPolicyPublished returns the policy_published element for a policy found
// by [Discover]: the domain the record was found at, found by the DNS Tree
// Walk, and its p=, sp=, np=, fo=, adkim=, aspf= and t= values, with defaults
// for those it omits.
func NewPolicyPublished(p Policy) PolicyPublished {
	r := p.Record
	sp := r.SubdomainPolicy
	if sp == "" {
		sp = r.Policy
	}
	np := r.NonExistentPolicy
	if np == "" {
		np = sp
	}
	fo := strings.Join(r.FailureOptions, ":")
	if fo == "" {
		fo = "0"
	}
	testing := "n"
	if r.Testing {
		testing = "y"
	}
	return PolicyPublished{
		Domain:          p.Domain,
		DiscoveryMethod: "treewalk",
		P:               r.Policy,
		SP:              sp,
		NP:              np,
		FO:              fo,
		ADKIM:           alignmentLetter(r.ADKIM),
		ASPF:            alignmentLetter(r.ASPF),
		Testing:         testing,
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
	HeaderFrom   string `xml:"header_from"`
	EnvelopeFrom string `xml:"envelope_from,omitempty"`
	EnvelopeTo   string `xml:"envelope_to,omitempty"`
}

type AuthResults struct {
	DKIM []DKIMResult `xml:"dkim,omitempty"`
	SPF  *SPFResult   `xml:"spf,omitempty"`
}

type DKIMResult struct {
	Domain   string `xml:"domain"`
	Selector string `xml:"selector"`
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

// The RFC 9990 Appendix A result and disposition types are closed
// enumerations; a value outside the set makes the document fail schema
// validation. The normalize* helpers lower-case the input and fall back to a
// safe in-enumeration default (none for results and dispositions) so an
// unknown or empty value never reaches the emitted XML.

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
	case "none", "neutral", "pass", "fail", "softfail", "policy", "temperror", "permerror":
		return v
	default:
		return "none"
	}
}

// normalizeAlignment keeps an adkim/aspf value of r or s and takes the
// default r for anything else, which the schema's AlignmentType does not
// allow.
func normalizeAlignment(s string) string {
	if v := strings.ToLower(strings.TrimSpace(s)); v == "s" {
		return v
	}
	return "r"
}

// normalizeTesting keeps a testing value of y and takes the default n for
// anything else (TestingType).
func normalizeTesting(s string) string {
	if v := strings.ToLower(strings.TrimSpace(s)); v == "y" {
		return v
	}
	return "n"
}

// normalizeDiscovery keeps a discovery_method of treewalk or psl and drops
// anything else (DiscoveryType).
func normalizeDiscovery(s string) string {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "treewalk", "psl":
		return v
	default:
		return ""
	}
}

// normalizeReasons maps each reason's type to the PolicyOverrideType
// enumeration; an unknown type becomes "other" and keeps its text in the
// comment, as do RFC 7489's forwarded and sampled_out.
func normalizeReasons(reasons []PolicyOverrideReason) []PolicyOverrideReason {
	var out []PolicyOverrideReason
	for _, r := range reasons {
		t := strings.ToLower(strings.TrimSpace(r.Type))
		switch t {
		case PolicyOverrideLocalPolicy, PolicyOverrideMailingList, PolicyOverrideOther,
			PolicyOverridePolicyTestMode, PolicyOverrideTrustedForwarder:
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

// reportIP writes a source IP address as RFC 9990 §3.1.1.8 asks, an
// IPv4address or IPv6address of RFC 3986 §3.2.2: an IPv4 address as a dotted
// quad (an IPv4-mapped IPv6 address included), and an IPv6 address in its
// canonical compressed form. It returns false for a string that is not an IP
// address.
func reportIP(s string) (string, bool) {
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || ip.Zone() != "" {
		return s, false
	}
	return ip.Unmap().String(), true
}

// normalizeDisposition keeps an ActionDispositionType value: none, pass (a
// message that passed DMARC under an enforcing policy), quarantine or
// reject.
func normalizeDisposition(s string) string {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "none", "pass", "quarantine", "reject":
		return v
	default:
		return "none"
	}
}

// normalizePolicy keeps a DispositionType value (none, quarantine or
// reject), the policies p, sp and np publish.
func normalizePolicy(s string) string {
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

// envelopeFrom resolves the RFC5321.MailFrom domain of identifiers/
// envelope_from, deriving it from the SPF check's domain when the caller did
// not supply one, and "" when neither says.
func envelopeFrom(r AggregateRecord) string {
	if r.EnvelopeFrom != "" {
		return r.EnvelopeFrom
	}
	if r.SPF != nil {
		return r.SPF.Domain
	}
	return ""
}

// dmarcDKIM returns the DKIM component of policy_evaluated: "pass" when at least
// one signature both passed and aligned with the From domain, else "fail"
// (RFC 9989 §4.4.1). An unsigned message is "fail".
func dmarcDKIM(sigs []DKIMAuth) string {
	for _, s := range sigs {
		if evaluated(s.Result, s.Aligned) == "pass" {
			return "pass"
		}
	}
	return "fail"
}

// dmarcSPF returns the SPF component of policy_evaluated: "pass" when the
// MAIL FROM check both passed and aligned with the From domain, else "fail".
func dmarcSPF(check *SPFAuth) string {
	if check != nil && evaluated(check.Result, check.Aligned) == "pass" {
		return "pass"
	}
	return "fail"
}

// AggregateRecords groups raw per-message evaluations into report rows by source
// IP, the identifiers, disposition, the DMARC-aligned dkim/spf verdict, the
// full set of authentication results and the override reasons, summing
// counts.
func AggregateRecords(records []AggregateRecord) []ReportRecord {
	type key struct {
		sourceIP, headerFrom, envelopeFrom, envelopeTo, disposition, dkimEval, spfEval, auth, reasons string
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
			envelopeTo:   r.EnvelopeTo,
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
				HeaderFrom:   k.headerFrom,
				EnvelopeFrom: k.envelopeFrom,
				EnvelopeTo:   k.envelopeTo,
			},
			AuthResults: authResults(r, k.headerFrom),
		})
	}
	return out
}

// maxDKIMPerRow is how many signatures a row reports at most (RFC 9990
// §3.1.3: "no more than 100 signatures for a given row").
const maxDKIMPerRow = 100

// authResults maps a message's DKIM and SPF results to the report schema
// (RFC 9990 §3.1.1.11): each DKIM signature's d= domain, selector and result,
// in the order of preference of §3.1.3 (passing signatures in strict
// alignment with the From domain, then in relaxed alignment, then the other
// passing ones, then those that did not pass), at most 100 of them; and the
// MAIL FROM SPF result, with the mfrom scope. No <dkim> element is produced
// for an unsigned message, and no <spf> for one SPF did not check.
func authResults(r AggregateRecord, headerFrom string) AuthResults {
	var ar AuthResults
	sigs := slices.Clone(r.DKIM)
	slices.SortStableFunc(sigs, func(a, b DKIMAuth) int {
		return dkimPreference(a, headerFrom) - dkimPreference(b, headerFrom)
	})
	for _, d := range sigs[:min(len(sigs), maxDKIMPerRow)] {
		ar.DKIM = append(ar.DKIM, DKIMResult{
			Domain:   d.Domain,
			Selector: d.Selector,
			Result:   normalizeDKIMResult(d.Result),
		})
	}
	if r.SPF != nil {
		ar.SPF = &SPFResult{Domain: r.SPF.Domain, Scope: "mfrom", Result: normalizeSPFResult(r.SPF.Result)}
	}
	return ar
}

// dkimPreference ranks a signature for reporting (RFC 9990 §3.1.3): 0 for one
// that passed in strict alignment with the From domain, 1 in relaxed
// alignment, 2 for any other that passed, and 3 for one that did not pass.
func dkimPreference(d DKIMAuth, headerFrom string) int {
	switch {
	case normalizeDKIMResult(d.Result) != "pass":
		return 3
	case !d.Aligned:
		return 2
	case strings.EqualFold(strings.TrimSuffix(d.Domain, "."), strings.TrimSuffix(headerFrom, ".")):
		return 0
	default:
		return 1
	}
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
func authResultsKey(dkim []DKIMAuth, spf *SPFAuth) string {
	var b strings.Builder
	for _, d := range dkim {
		b.WriteString("dkim\x00")
		b.WriteString(d.Domain)
		b.WriteByte(0)
		b.WriteString(d.Selector)
		b.WriteByte(0)
		b.WriteString(normalizeDKIMResult(d.Result))
		b.WriteByte(0)
		if d.Aligned {
			b.WriteByte('a')
		}
		b.WriteByte(0)
	}
	b.WriteByte('\n')
	if spf != nil {
		b.WriteString("spf\x00")
		b.WriteString(spf.Domain)
		b.WriteByte(0)
		b.WriteString(normalizeSPFResult(spf.Result))
		b.WriteByte(0)
	}
	return b.String()
}

// BuildReport assembles an RFC 9990 aggregate report XML document (with the
// XML declaration prepended) that conforms to the Appendix A schema, in the
// DMARC namespace. The policy's values are normalized as [PolicyPublished]
// describes. It returns an error, and no document, when there are no records
// (the schema requires one) or a record's SourceIP is not an IP address.
func BuildReport(meta ReportMetadata, policy PolicyPublished, records []AggregateRecord) ([]byte, error) {
	if len(records) == 0 {
		return nil, errors.New("dmarc: an aggregate report needs at least one record")
	}
	for _, r := range records {
		if _, ok := reportIP(r.SourceIP); !ok {
			return nil, fmt.Errorf("dmarc: source IP %q is not an IP address", r.SourceIP)
		}
	}
	policy.P = normalizePolicy(policy.P)
	if strings.TrimSpace(policy.SP) == "" {
		policy.SP = policy.P
	}
	policy.SP = normalizePolicy(policy.SP)
	if strings.TrimSpace(policy.NP) == "" {
		policy.NP = policy.SP
	}
	policy.NP = normalizePolicy(policy.NP)
	policy.ADKIM = normalizeAlignment(policy.ADKIM)
	policy.ASPF = normalizeAlignment(policy.ASPF)
	policy.Testing = normalizeTesting(policy.Testing)
	policy.DiscoveryMethod = normalizeDiscovery(policy.DiscoveryMethod)
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

// Gzip compresses report bytes for the report attachment: RFC 9990 §3.5.2
// says the XML SHOULD be compressed and sent as application/gzip.
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

// ReportFilename returns the name of a report attachment (RFC 9990 §3.5.2):
// receiver "!" policy-domain "!" begin "!" end, then "!" uniqueID when it is
// not empty, and ".xml.gz" for a compressed report or ".xml". receiver is the
// reporting Mail Receiver's domain and policyDomain the DMARC Policy Domain
// the report covers. A re-sent report must keep its name, so the same inputs
// always give the same name. It returns false when a domain is not a domain
// name or uniqueID is not letters and digits.
func ReportFilename(receiver, policyDomain string, period DateRange, uniqueID string, gzipped bool) (string, bool) {
	r, ok1 := queryDomain(receiver)
	p, ok2 := queryDomain(policyDomain)
	if !ok1 || !ok2 || period.Begin < 0 || period.End < 0 || !alphaNumeric(uniqueID) {
		return "", false
	}
	name := r + "!" + p + "!" + strconv.FormatInt(period.Begin, 10) + "!" + strconv.FormatInt(period.End, 10)
	if uniqueID != "" {
		name += "!" + uniqueID
	}
	if gzipped {
		return name + ".xml.gz", true
	}
	return name + ".xml", true
}

// ReportSubject returns the Subject field value of a report message (RFC 9990
// §3.5.2): "Report Domain: <policy domain> Submitter: <report generator>",
// then " Report-ID: <reportID>" when reportID is not empty. It returns false
// when a domain is not a domain name, or reportID is not the ridtxt of
// §3.5.1 (dot-atom-text, optionally "@" dot-atom-text, optionally in angle
// brackets).
func ReportSubject(policyDomain, submitter, reportID string) (string, bool) {
	p, ok1 := queryDomain(policyDomain)
	s, ok2 := queryDomain(submitter)
	if !ok1 || !ok2 || reportID != "" && !reportIDText(reportID) {
		return "", false
	}
	subject := "Report Domain: " + p + " Submitter: " + s
	if reportID != "" {
		subject += " Report-ID: " + reportID
	}
	return subject, true
}

// alphaNumeric reports whether s holds only ASCII letters and digits
// (unique-id = 1*(ALPHA / DIGIT), or empty for none).
func alphaNumeric(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isAlphaNum(s[i]) {
			return false
		}
	}
	return true
}

// isAlphaNum reports whether c is an ASCII letter or digit.
func isAlphaNum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// reportIDText reports whether s is a ridtxt (RFC 9990 §3.5.1): ridfmt or
// "<" ridfmt ">", where ridfmt is dot-atom-text ["@" dot-atom-text].
func reportIDText(s string) bool {
	if strings.HasPrefix(s, "<") && strings.HasSuffix(s, ">") && len(s) > 1 {
		s = s[1 : len(s)-1]
	}
	local, domain, hasAt := strings.Cut(s, "@")
	return dotAtomText(local) && (!hasAt || dotAtomText(domain))
}

// dotAtomText reports whether s is 1*atext *("." 1*atext) (RFC 5322 §3.2.3).
func dotAtomText(s string) bool {
	if s == "" {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if part == "" {
			return false
		}
		for i := 0; i < len(part); i++ {
			if c := part[i]; !isAlphaNum(c) && strings.IndexByte("!#$%&'*+-/=?^_`{|}~", c) < 0 {
				return false
			}
		}
	}
	return true
}
