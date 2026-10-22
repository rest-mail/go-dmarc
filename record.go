package dmarc

import (
	"errors"
	"math"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// systemResolver is the resolver a nil TXTResolver stands for; tests replace it.
var systemResolver TXTResolver = net.LookupTXT

// TXTResolver resolves the TXT records for a name. Its signature matches
// [net.LookupTXT], so that (or a fake in tests) can be passed directly. A nil
// resolver passed to [Lookup] falls back to net.LookupTXT.
//
// Each returned string is one TXT record with its character-strings already
// joined in order, which is what RFC 7489 §6.1 asks for and what
// net.LookupTXT does.
type TXTResolver func(name string) ([]string, error)

var (
	// ErrNotDMARC is returned by [ParseRecord] for a TXT record whose first
	// tag is not v=DMARC1. RFC 7489 §6.3 says such a record is ignored.
	ErrNotDMARC = errors.New("dmarc: not a DMARC record (v=DMARC1 must be the first tag)")

	// ErrNoPolicy is returned by [ParseRecord] for a DMARC record with no
	// valid p= tag, or an invalid sp= tag, and no valid rua= URI to report
	// to. RFC 7489 §6.6.3 step 6 says DMARC is then not applied at all.
	ErrNoPolicy = errors.New("dmarc: record has no valid policy and no valid rua")
)

// Record is a parsed DMARC policy record (RFC 7489 §6.3). Every tag the
// record omits, or carries with a syntax error, holds its default.
type Record struct {
	// Policy is the p= tag: "none", "quarantine" or "reject". It is "none"
	// when p= is missing or invalid but the record names a valid rua= URI
	// (§6.6.3 step 6).
	Policy string
	// SubdomainPolicy is the sp= tag, or "" when the record has none, in
	// which case Policy applies to subdomains too.
	SubdomainPolicy string
	// ADKIM and ASPF are the DKIM and SPF alignment modes of the adkim= and
	// aspf= tags; relaxed by default.
	ADKIM AlignmentMode
	ASPF  AlignmentMode
	// Pct is the pct= tag, the percentage (0 to 100) of failing messages
	// the policy is applied to; 100 by default (§6.6.4).
	Pct int
	// FailureOptions is the fo= tag split at its colons ("0", "1", "d",
	// "s"). It is ["0"], the default, when the record has no ruf= URI, whose
	// absence makes fo= ignored.
	FailureOptions []string
	// ReportFormats is the rf= tag: the failure-report formats, of which
	// "afrf" is the only one registered; ["afrf"] by default.
	ReportFormats []string
	// ReportInterval is the ri= tag, the requested number of seconds
	// between aggregate reports; 86400 by default.
	ReportInterval uint32
	// RUA and RUF are the aggregate and failure report URIs (the rua= and
	// ruf= tags), in the order published. URIs that are not valid are left
	// out.
	RUA []ReportURI
	RUF []ReportURI
}

// ReportURI is one DMARC URI of a rua= or ruf= tag (RFC 7489 §6.2).
type ReportURI struct {
	// URI is the address without its size limit, for example
	// "mailto:reports@example.com".
	URI string
	// MaxSize is the largest report, in bytes, the URI accepts: its "!" size
	// limit with the unit applied (a "k" is 2^10 bytes), or math.MaxUint64
	// when it sets none. A limit too large for 64 bits is math.MaxUint64.
	MaxSize uint64
}

// ParseRecord parses a DMARC TXT record (RFC 7489 §6.3, §6.4).
//
// The first tag must be v=DMARC1, with the value matched exactly; otherwise
// the record is not a DMARC record and the error is [ErrNotDMARC]. Tag names
// and the enumerated values (none, quarantine, reject, r, s, the fo= options)
// are matched case-insensitively, as the ABNF's quoted strings are, and
// whitespace around "=" and ";" is ignored. Unknown tags are ignored.
//
// A tag with a syntax error, and a tag that appears more than once, is
// discarded in favour of its default (§6.3). For p= and sp= that leaves the
// record without a valid policy, which §6.6.3 step 6 settles: with at least
// one valid rua= URI the record reads as p=none, and without one the error is
// [ErrNoPolicy] and DMARC does not apply.
func ParseRecord(txt string) (Record, error) {
	parts := strings.Split(txt, ";")
	if !isVersionTag(parts[0]) {
		return Record{}, ErrNotDMARC
	}
	tags := map[string]string{}
	repeated := map[string]bool{}
	for _, part := range parts[1:] {
		name, value, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if _, seen := tags[name]; seen {
			repeated[name] = true
		}
		tags[name] = strings.TrimSpace(value)
	}
	for name := range repeated {
		delete(tags, name)
	}

	r := Record{
		ADKIM:          alignmentTag(tags, "adkim"),
		ASPF:           alignmentTag(tags, "aspf"),
		Pct:            pctTag(tags),
		FailureOptions: []string{"0"},
		ReportFormats:  []string{"afrf"},
		ReportInterval: intervalTag(tags),
	}
	if v, ok := tags["rua"]; ok {
		r.RUA = parseReportURIs(v)
	}
	if v, ok := tags["ruf"]; ok {
		r.RUF = parseReportURIs(v)
	}
	if len(r.RUF) > 0 {
		if fo, ok := failureOptions(tags["fo"]); ok {
			r.FailureOptions = fo
		}
	}
	if rf, ok := reportFormats(tags["rf"]); ok {
		r.ReportFormats = rf
	}

	p, pValid := policyValue(tags, "p")
	sp, spValid := policyValue(tags, "sp")
	if _, present := tags["sp"]; !present && !repeated["sp"] {
		spValid = true // an absent sp= is valid; p= then covers subdomains
	}
	switch {
	case pValid && spValid:
		r.Policy, r.SubdomainPolicy = p, sp
	case len(r.RUA) > 0:
		// §6.6.3 step 6.1: act as if the record were v=DMARC1; p=none.
		r.Policy = "none"
	default:
		return Record{}, ErrNoPolicy
	}
	return r, nil
}

// isVersionTag reports whether a record's first tag is the version tag,
// dmarc-version = "v" *WSP "=" *WSP %x44 %x4d %x41 %x52 %x43 %x31 (§6.4): the
// tag name is case-insensitive like every quoted ABNF string, while the value
// is the exact upper-case DMARC1 (§6.3: it "MUST match precisely").
func isVersionTag(tag string) bool {
	name, value, found := strings.Cut(tag, "=")
	return found && strings.EqualFold(strings.TrimSpace(name), "v") && strings.TrimSpace(value) == "DMARC1"
}

// hasDMARCVersion reports whether a TXT record is a DMARC record: its first
// tag is v=DMARC1 (RFC 7489 §6.3, §6.6.3 steps 2 and 4).
func hasDMARCVersion(record string) bool {
	first, _, _ := strings.Cut(record, ";")
	return isVersionTag(first)
}

// policyValue returns the lower-cased value of a p= or sp= tag and whether it
// is present with one of the values none, quarantine and reject (§6.3).
func policyValue(tags map[string]string, name string) (string, bool) {
	v, ok := tags[name]
	if !ok {
		return "", false
	}
	v = strings.ToLower(v)
	switch v {
	case "none", "quarantine", "reject":
		return v, true
	}
	return "", false
}

// alignmentTag reads adkim= or aspf=: "s" is strict, and anything else,
// including an absent or invalid tag, is the relaxed default.
func alignmentTag(tags map[string]string, name string) AlignmentMode {
	if strings.EqualFold(tags[name], "s") {
		return AlignmentStrict
	}
	return AlignmentRelaxed
}

// pctTag reads pct= (dmarc-percent = "pct" *WSP "=" *WSP 1*3DIGIT, at most
// 100); an absent or invalid tag is the default of 100.
func pctTag(tags map[string]string) int {
	v, ok := tags["pct"]
	if !ok || len(v) == 0 || len(v) > 3 || !allDigits(v) {
		return 100
	}
	n, _ := strconv.Atoi(v)
	if n > 100 {
		return 100
	}
	return n
}

// intervalTag reads ri= (1*DIGIT, a 32-bit unsigned number of seconds); an
// absent or invalid tag is the default of 86400.
func intervalTag(tags map[string]string) uint32 {
	v, ok := tags["ri"]
	if !ok || !allDigits(v) {
		return 86400
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return 86400
	}
	return uint32(n)
}

// failureOptions reads fo=, a colon-separated list of 0, 1, d and s with
// optional whitespace around the colons. It returns false for an invalid
// list, which then takes the default.
func failureOptions(v string) ([]string, bool) {
	var opts []string
	for _, o := range strings.Split(v, ":") {
		o = strings.ToLower(strings.TrimSpace(o))
		switch o {
		case "0", "1", "d", "s":
			opts = append(opts, o)
		default:
			return nil, false
		}
	}
	return opts, true
}

// reportFormats reads rf=, keeping the registered formats (only afrf) and
// ignoring the others, as §6.3 says a receiver should. It returns false when
// none is left, which then takes the default.
func reportFormats(v string) ([]string, bool) {
	var formats []string
	for _, f := range strings.Split(v, ":") {
		if f = strings.ToLower(strings.TrimSpace(f)); f == "afrf" {
			formats = append(formats, f)
		}
	}
	return formats, len(formats) > 0
}

// parseReportURIs reads a comma-separated list of DMARC URIs (§6.2, §6.4),
// keeping the valid ones in order.
func parseReportURIs(v string) []ReportURI {
	var uris []ReportURI
	for _, s := range strings.Split(v, ",") {
		if u, ok := parseReportURI(strings.TrimSpace(s)); ok {
			uris = append(uris, u)
		}
	}
	return uris
}

// parseReportURI reads one dmarc-uri = URI [ "!" 1*DIGIT [ "k" / "m" / "g" /
// "t" ] ]. A "!" inside the URI must be percent-encoded, so the first one
// starts the size limit. The URI must be absolute (have a scheme) and contain
// no whitespace, control or non-ASCII characters (an RFC 3986 URI is ASCII);
// the size must fit in 64 bits. A mailto: URI must name conventional
// addresses: RFC 8616 §6 says a record serves internationalized and
// conventional mail alike, so its report addresses are never
// internationalized, even percent-encoded.
func parseReportURI(s string) (ReportURI, bool) {
	raw, limit, hasLimit := strings.Cut(s, "!")
	u := ReportURI{URI: raw, MaxSize: math.MaxUint64}
	if hasLimit {
		size, ok := parseSizeLimit(limit)
		if !ok {
			return ReportURI{}, false
		}
		u.MaxSize = size
	}
	if raw == "" || strings.ContainsFunc(raw, func(r rune) bool { return r <= ' ' || r >= 0x7f }) {
		return ReportURI{}, false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Opaque == "" && parsed.Host == "" && parsed.Path == "" {
		return ReportURI{}, false
	}
	if strings.EqualFold(parsed.Scheme, "mailto") && !conventionalMailto(parsed.Opaque) {
		return ReportURI{}, false
	}
	return u, true
}

// conventionalMailto reports whether the addresses of a mailto: URI's opaque
// part (RFC 6068 to-field, before any "?") are all-ASCII once
// percent-decoded, so none is an internationalized address (RFC 6531 §3.2).
func conventionalMailto(opaque string) bool {
	to, _, _ := strings.Cut(opaque, "?")
	addrs, err := url.PathUnescape(to)
	if err != nil {
		return false
	}
	for i := 0; i < len(addrs); i++ {
		if addrs[i] >= 0x80 {
			return false
		}
	}
	return true
}

// parseSizeLimit reads 1*DIGIT [ "k" / "m" / "g" / "t" ]: a count of bytes,
// or of 2^10, 2^20, 2^30 or 2^40 bytes with a unit. The count must fit in an
// unsigned 64-bit integer (§6.4); the product saturates at math.MaxUint64.
func parseSizeLimit(s string) (uint64, bool) {
	shift := uint(0)
	if s != "" {
		switch s[len(s)-1] {
		case 'k', 'K':
			shift = 10
		case 'm', 'M':
			shift = 20
		case 'g', 'G':
			shift = 30
		case 't', 'T':
			shift = 40
		}
		if shift > 0 {
			s = s[:len(s)-1]
		}
	}
	if !allDigits(s) {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	if n > math.MaxUint64>>shift {
		return math.MaxUint64, true
	}
	return n << shift, true
}

// allDigits reports whether s is one or more ASCII digits.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// Lookup fetches and returns the raw DMARC record published at
// _dmarc.<domain>. It maps DNS outcomes to the three RFC 7489 §6.6.3 cases:
//
//   - Record found: the raw "v=DMARC1..." TXT record and a nil error.
//   - No DMARC policy: ("", nil). This covers a name that carries no v=DMARC1
//     record, a name that does not exist at all (a not-found/NXDOMAIN result is
//     "DMARC does not apply", not a failure), a name that carries more than
//     one v=DMARC1 record (an ambiguous set §6.6.3 discards), and a domain
//     that is not a valid DNS name, for which no query is sent.
//   - Transient failure (SERVFAIL, timeout, and other non-not-found DNS
//     errors): ("", err). Callers must treat this as temperror and not fail
//     open — the domain's policy is unknown, not absent.
//
// The domain is queried in its A-label form (§6.6.1): lower case, without a
// root dot, and with Unicode labels punycode-encoded. Lookup does not fall
// back to the Organizational Domain; [Discover] does.
//
// The distinction relies on the resolver reporting not-found via a
// *net.DNSError whose IsNotFound is set, which is what [net.LookupTXT] does;
// fakes returning such an error are classified the same way.
func Lookup(domain string, resolver TXTResolver) (string, error) {
	domain, ok := queryDomain(domain)
	if !ok {
		return "", nil
	}
	records, err := lookupDMARC(domain, resolver)
	if err != nil {
		return "", err
	}
	// RFC 7489 §6.6.3 step 5: exactly one v=DMARC1 record is a usable policy.
	// Zero records, or more than one (an ambiguous set that is discarded), both
	// mean the domain has no applicable policy.
	if len(records) != 1 {
		return "", nil
	}
	return records[0], nil
}

// lookupDMARC queries _dmarc.<domain> and returns the TXT records at that name
// whose first tag is the v=DMARC1 version tag — the RFC 7489 §6.6.3 filtering that discards
// non-DMARC TXT records (SPF, verification tokens, and the like). A nil resolver
// falls back to [net.LookupTXT]. It applies Lookup's error contract: a not-found
// (NXDOMAIN) result maps to an empty set with a nil error, while other resolver
// errors surface unchanged so callers can treat them as temperror. Returning the
// full filtered set (rather than the first match) lets callers distinguish the
// no-record, single-record, and ambiguous multi-record cases.
func lookupDMARC(domain string, resolver TXTResolver) ([]string, error) {
	return lookupVersioned("_dmarc."+domain, resolver)
}

// lookupVersioned queries name for TXT records and keeps those whose first tag
// is v=DMARC1, mapping not-found to an empty set.
func lookupVersioned(name string, resolver TXTResolver) ([]string, error) {
	if resolver == nil {
		resolver = systemResolver
	}
	records, err := resolver(name)
	if err != nil {
		// A not-found result means the name publishes no DMARC record, which
		// RFC 7489 §6.6.3 treats as "no policy", not a lookup failure. Only
		// genuine transient errors surface to the caller.
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, nil
		}
		return nil, err
	}
	var dmarc []string
	for _, r := range records {
		if hasDMARCVersion(r) {
			dmarc = append(dmarc, r)
		}
	}
	return dmarc, nil
}

// ParsePolicy returns the policy (the p= tag) a DMARC record requests for its
// own domain: "none", "quarantine" or "reject", in lower case. It is
// [ParseRecord] reduced to the policy, so a record with a missing, invalid or
// repeated p= (or an invalid sp=) reads as "none" when it names a valid rua=
// URI, and is an error otherwise: [ErrNoPolicy], or [ErrNotDMARC] for a record
// that does not start with v=DMARC1. Either error means DMARC does not apply
// (§6.6.3).
func ParsePolicy(record string) (string, error) {
	r, err := ParseRecord(record)
	if err != nil {
		return "", err
	}
	return r.Policy, nil
}
