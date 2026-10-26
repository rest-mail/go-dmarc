package dmarc

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

// systemResolver is the resolver a nil TXTResolver stands for; tests replace it.
var systemResolver TXTResolver = net.LookupTXT

// TXTResolver resolves the TXT records for a name. Its signature matches
// [net.LookupTXT], so that (or a fake in tests) can be passed directly. A nil
// resolver passed to [Lookup] falls back to net.LookupTXT.
//
// Each returned string is one TXT record with its character-strings already
// joined in order, which is what RFC 9989 §4.5 asks for and what
// net.LookupTXT does.
type TXTResolver func(name string) ([]string, error)

var (
	// ErrNotDMARC is returned by [ParseRecord] for a TXT record whose first
	// tag is not v=DMARC1. RFC 9989 §4.7 says such a record is ignored.
	ErrNotDMARC = errors.New("dmarc: not a DMARC record (v=DMARC1 must be the first tag)")

	// ErrNoPolicy is returned by [ParseRecord] for a DMARC record with no
	// valid p= tag, or an invalid sp= or np= tag, and no valid rua= URI to
	// report to. RFC 9989 §4.10.1 says DMARC is then not applied at all.
	ErrNoPolicy = errors.New("dmarc: record has no valid policy and no valid rua")
)

// Record is a parsed DMARC Policy Record (RFC 9989 §4.7). Every tag the
// record omits, or carries with a syntax error, holds its default. The tags
// RFC 9989 removed (pct, rf and ri, Appendix C.5.2) are unknown tags now, and
// ignored like any other.
type Record struct {
	// Policy is the p= tag: "none", "quarantine" or "reject". It is "none"
	// when p= is missing or invalid but the record names a valid rua= URI
	// (§4.10.1).
	Policy string
	// SubdomainPolicy is the sp= tag, the policy for existing subdomains, or
	// "" when the record has none, in which case Policy applies to them.
	SubdomainPolicy string
	// NonExistentPolicy is the np= tag, the policy for subdomains that do not
	// exist (an NXDOMAIN answer, §3.2.13), or "" when the record has none, in
	// which case SubdomainPolicy, or else Policy, applies to them.
	NonExistentPolicy string
	// PSD is the psd= tag: "y" for a Public Suffix Domain's record, "n" for a
	// record that is the Organizational Domain of itself and its subdomains,
	// and "u", the default, when the DNS Tree Walk decides (§4.10.2).
	PSD string
	// Testing is the t= tag set to "y": the Domain Owner is testing its
	// policy and expects one level less to be applied (§4.7, Appendix A.6).
	// It is false, the default, for t=n.
	Testing bool
	// ADKIM and ASPF are the DKIM and SPF alignment modes of the adkim= and
	// aspf= tags; relaxed by default.
	ADKIM AlignmentMode
	ASPF  AlignmentMode
	// FailureOptions is the fo= tag split at its colons ("0" or "1", and
	// "d" and "s"). It is ["0"], the default, when the record has no ruf=
	// URI, whose absence makes fo= ignored.
	FailureOptions []string
	// RUA and RUF are the aggregate and failure report URIs (the rua= and
	// ruf= tags), in the order published. URIs that are not valid are left
	// out, and the obsolete "!" size limit is dropped from those that carry
	// one (§4.8).
	RUA []string
	RUF []string
}

// ParseRecord parses a DMARC TXT record (RFC 9989 §4.7, §4.8).
//
// The first tag must be v=DMARC1, with the value matched exactly; otherwise
// the record is not a DMARC record and the error is [ErrNotDMARC]. Tag names
// and the enumerated values (none, quarantine, reject, y, n, u, r, s, the fo=
// options) are matched case-insensitively, as the ABNF's quoted strings are,
// and whitespace around "=" and ";" is ignored. Unknown tags, among them the
// pct, rf and ri that RFC 7489 had, are ignored.
//
// A tag with a syntax error, and a tag that appears more than once, is
// discarded in favour of its default (§4.8). For p=, sp= and np= that leaves
// the record without a valid policy, which §4.10.1 settles: with at least one
// valid rua= URI the record reads as p=none, and without one the error is
// [ErrNoPolicy] and DMARC does not apply.
func ParseRecord(txt string) (Record, error) {
	tags, repeated, ok := recordTags(txt)
	if !ok {
		return Record{}, ErrNotDMARC
	}

	r := Record{
		PSD:            psdTag(tags),
		Testing:        strings.EqualFold(tags["t"], "y"),
		ADKIM:          alignmentTag(tags, "adkim"),
		ASPF:           alignmentTag(tags, "aspf"),
		FailureOptions: []string{"0"},
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

	p, pValid := policyValue(tags, "p")
	sp, spValid := subdomainPolicy(tags, repeated, "sp")
	np, npValid := subdomainPolicy(tags, repeated, "np")
	switch {
	case pValid && spValid && npValid:
		r.Policy, r.SubdomainPolicy, r.NonExistentPolicy = p, sp, np
	case len(r.RUA) > 0:
		// §4.10.1: act as if the record were v=DMARC1; p=none.
		r.Policy = "none"
	default:
		return Record{}, ErrNoPolicy
	}
	return r, nil
}

// recordTags splits a DMARC record into its tags after v=DMARC1, keyed by
// lower-case name, with whitespace around the names and values trimmed. A
// tag that appears more than once is left out and named in repeated (RFC
// 6376 §3.2). ok is false for a record that does not start with v=DMARC1.
func recordTags(txt string) (tags map[string]string, repeated map[string]bool, ok bool) {
	parts := strings.Split(txt, ";")
	if !isVersionTag(parts[0]) {
		return nil, nil, false
	}
	tags = map[string]string{}
	repeated = map[string]bool{}
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
	return tags, repeated, true
}

// isVersionTag reports whether a record's first tag is the version tag,
// dmarc-version = "v" equals %s"DMARC1" (§4.8): the tag name is
// case-insensitive like every quoted ABNF string, while the value is the
// exact upper-case DMARC1 (§4.7: "The tag value is case sensitive").
func isVersionTag(tag string) bool {
	name, value, found := strings.Cut(tag, "=")
	return found && strings.EqualFold(strings.TrimSpace(name), "v") && strings.TrimSpace(value) == "DMARC1"
}

// hasDMARCVersion reports whether a TXT record is a DMARC record: its first
// tag is v=DMARC1 (RFC 9989 §4.7, §4.10 step 2).
func hasDMARCVersion(record string) bool {
	first, _, _ := strings.Cut(record, ";")
	return isVersionTag(first)
}

// policyValue returns the lower-cased value of a p=, sp= or np= tag and
// whether it is present with one of the values none, quarantine and reject
// (dmarc-request, §4.8).
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

// subdomainPolicy reads sp= or np=: an absent tag is valid and empty, since
// the policy above it then applies, while one that is present must be valid,
// and so must not be repeated (§4.10.1).
func subdomainPolicy(tags map[string]string, repeated map[string]bool, name string) (string, bool) {
	if _, present := tags[name]; !present && !repeated[name] {
		return "", true
	}
	return policyValue(tags, name)
}

// psdTag reads psd= (dmarc-psd = "y" / "n" / "u", §4.8); an absent or
// invalid tag is the default "u".
func psdTag(tags map[string]string) string {
	switch v := strings.ToLower(tags["psd"]); v {
	case "y", "n":
		return v
	}
	return "u"
}

// alignmentTag reads adkim= or aspf=: "s" is strict, and anything else,
// including an absent or invalid tag, is the relaxed default.
func alignmentTag(tags map[string]string, name string) AlignmentMode {
	if strings.EqualFold(tags[name], "s") {
		return AlignmentStrict
	}
	return AlignmentRelaxed
}

// failureOptions reads fo= (dmarc-fo, §4.8): a colon-separated list of
// "0" or "1", which exclude each other, and "d" and "s", each at most once,
// in any order, with optional whitespace around the colons. It returns false
// for an invalid list, which then takes the default.
func failureOptions(v string) ([]string, bool) {
	var opts []string
	seen := map[string]bool{}
	for _, o := range strings.Split(v, ":") {
		o = strings.ToLower(strings.TrimSpace(o))
		switch o {
		case "0", "1", "d", "s":
		default:
			return nil, false
		}
		if seen[o] || (o == "0" && seen["1"]) || (o == "1" && seen["0"]) {
			return nil, false
		}
		seen[o] = true
		opts = append(opts, o)
	}
	return opts, true
}

// parseReportURIs reads a comma-separated list of DMARC URIs (dmarc-urilist,
// §4.8), keeping the valid ones in order.
func parseReportURIs(v string) []string {
	var uris []string
	for _, s := range strings.Split(v, ",") {
		if u, ok := parseReportURI(strings.TrimSpace(s)); ok {
			uris = append(uris, u)
		}
	}
	return uris
}

// parseReportURI reads one dmarc-uri, or an obs-dmarc-uri, which is a
// dmarc-uri followed by "!" 1*DIGIT [ "k" / "m" / "g" / "t" ] (§4.8). The
// size limit is obsolete, so it is checked for its syntax and dropped: a
// reporter "should ignore" it. A "!" inside the URI must be percent-encoded,
// so the first one starts the size limit. The URI must be absolute (have a
// scheme) and contain no whitespace, control or non-ASCII characters (an RFC
// 3986 URI is ASCII). A mailto: URI must name conventional addresses: RFC
// 8616 §6 says a record serves internationalized and conventional mail
// alike, so its report addresses are never internationalized, even
// percent-encoded.
func parseReportURI(s string) (string, bool) {
	raw, limit, hasLimit := strings.Cut(s, "!")
	if hasLimit && !obsoleteSizeLimit(limit) {
		return "", false
	}
	if raw == "" || strings.ContainsFunc(raw, func(r rune) bool { return r <= ' ' || r >= 0x7f }) {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Opaque == "" && parsed.Host == "" && parsed.Path == "" {
		return "", false
	}
	if strings.EqualFold(parsed.Scheme, "mailto") && !conventionalMailto(parsed.Opaque) {
		return "", false
	}
	return raw, true
}

// obsoleteSizeLimit reports whether s, what follows a URI's "!", is the
// obsolete size limit 1*DIGIT [ "k" / "m" / "g" / "t" ] (§4.8).
func obsoleteSizeLimit(s string) bool {
	if s != "" && strings.ContainsRune("kmgtKMGT", rune(s[len(s)-1])) {
		s = s[:len(s)-1]
	}
	return allDigits(s)
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
// _dmarc.<domain>. It maps DNS outcomes to three cases (RFC 9989 §4.10,
// §4.10.1):
//
//   - Record found: the raw "v=DMARC1..." TXT record and a nil error.
//   - No DMARC policy: ("", nil). This covers a name that carries no v=DMARC1
//     record, a name that does not exist at all (a not-found/NXDOMAIN result is
//     "DMARC does not apply", not a failure), a name that carries more than
//     one v=DMARC1 record (all of which §4.10 discards), and a domain
//     that is not a valid DNS name, for which no query is sent.
//   - Transient failure (SERVFAIL, timeout, and other non-not-found DNS
//     errors): ("", err). Callers must treat this as temperror and not fail
//     open — the domain's policy is unknown, not absent.
//
// The domain is queried in its A-label form (§5.3.1): lower case, without a
// root dot, and with Unicode labels punycode-encoded. Lookup does not walk
// the DNS tree; [Discover] does.
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
	// RFC 9989 §4.10 step 2: exactly one v=DMARC1 record is a record. Zero
	// records, or more than one (all of which are discarded), both mean the
	// name publishes none.
	if len(records) != 1 {
		return "", nil
	}
	return records[0], nil
}

// lookupDMARC queries _dmarc.<domain> and returns the TXT records at that name
// whose first tag is the v=DMARC1 version tag — the RFC 9989 §4.10 filtering that discards
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
		// RFC 9989 §4.10.1 treats as "no record", not a lookup failure. Only
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
