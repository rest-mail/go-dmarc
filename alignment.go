package dmarc

import (
	"math"
	"strconv"
	"strings"
)

// Aligned reports whether an authenticated domain aligns with the From domain
// under DMARC relaxed alignment (RFC 7489 §3.1): their Organizational Domains
// (§3.2) must be equal. Strict alignment is a plain exact match, which Aligned
// also reports since an exact match trivially shares an organizational domain.
//
// Alignment is NOT a raw suffix test. Comparing organizational domains both
// accepts alignments the RFC requires (sibling subdomains such as
// em.example.com and mail.example.com, which share example.com) and rejects
// ones it forbids (a lookalike like evil-example.com, or an authenticated
// domain that is itself a public suffix — the RFC notes a DKIM signature
// bearing d=com never yields an aligned result).
//
// Both identifiers are sanitized before comparison (see [AlignedOrg]): an empty
// identifier never aligns, a single trailing (root) dot is ignored, and each is
// folded to a single lower-case A-label form so that a Unicode domain and its
// xn-- punycode encoding are treated as the same name.
//
// Aligned uses the registry-free [DefaultOrgDomain] heuristic, which is correct
// for single-label public suffixes but not multi-label ones (e.g. it treats
// co.uk itself as an organizational domain). For full accuracy under
// multi-label public suffixes, use [AlignedOrg] with a PSL-backed
// [OrgDomainFunc].
func Aligned(authDomain, fromDomain string) bool {
	return AlignedOrg(authDomain, fromDomain, nil)
}

// AlignedOrg is [Aligned] with an injectable [OrgDomainFunc], so callers can
// supply a Public Suffix List-backed organizational-domain derivation (a small
// wrapper around golang.org/x/net/publicsuffix.EffectiveTLDPlusOne). A nil
// orgDomain uses [DefaultOrgDomain]. Keeping the hook injectable is what lets
// this package stay dependency-free while still supporting correct relaxed
// alignment under multi-label public suffixes such as co.uk — the same hook
// [Discover] uses for its §6.6.3 organizational-domain fallback.
//
// Both inputs are first sanitized with [normalizeDomain]: a single trailing
// (root) dot is stripped, the name is lower-cased, and any Unicode labels are
// converted to their ASCII (xn-- punycode) A-label form. Sanitizing closes three
// ways the raw equality test would otherwise misfire (RFC 7489 §3.1):
//
//   - An empty identifier means "no authenticated domain" and must never align.
//     Two empty inputs would trivially compare equal and yield a false DMARC
//     pass, so an empty input on either side returns false up front.
//   - A fully-qualified name carrying the root dot ("example.com.") denotes the
//     same domain as "example.com" and must align with it.
//   - The same domain written as a Unicode U-label and as its xn-- A-label is one
//     domain; normalizing both to the A-label form keeps them from spuriously
//     failing (or, for the org-domain comparison, spuriously matching) on
//     encoding form alone.
//
// Relaxed alignment (RFC 7489 §3.1) holds when the two Organizational Domains
// are non-empty and equal. A domain that is itself a public suffix has no
// registrable Organizational Domain: a PSL-backed OrgDomainFunc returns "" for
// it, so such a domain never aligns. Strict alignment (an exact,
// case-insensitive match) is always reported, independent of the hook.
func AlignedOrg(authDomain, fromDomain string, orgDomain OrgDomainFunc) bool {
	authDomain = normalizeDomain(authDomain)
	fromDomain = normalizeDomain(fromDomain)
	// An empty input is an absent identifier, not a domain; it can never align
	// (and two empties must not compare equal into a false pass).
	if authDomain == "" || fromDomain == "" {
		return false
	}
	// Strict alignment: an exact match always aligns.
	if authDomain == fromDomain {
		return true
	}
	if orgDomain == nil {
		orgDomain = DefaultOrgDomain
	}
	authOrg := orgDomain(authDomain)
	fromOrg := orgDomain(fromDomain)
	// Relaxed alignment: the Organizational Domains must match. An empty result
	// marks an input that is itself a public suffix (per a PSL-backed hook),
	// which can never align.
	return authOrg != "" && authOrg == fromOrg
}

// AlignmentMode is the DMARC identifier-alignment mode a record requests through
// its adkim= / aspf= tag (RFC 7489 §6.3): relaxed (the default) or strict.
type AlignmentMode int

const (
	// AlignmentRelaxed is DMARC relaxed alignment (adkim=r / aspf=r — the default
	// applied when the tag is absent). Two identifiers align when their
	// Organizational Domains are equal, so sibling and parent/child subdomains of
	// one organizational domain align. It is the zero value, so a zero-valued
	// [Policy] (no published record) reports the correct default.
	AlignmentRelaxed AlignmentMode = iota
	// AlignmentStrict is DMARC strict alignment (adkim=s / aspf=s). The two
	// identifier domains must be an exact, case-insensitive FQDN match; a
	// subdomain of the From domain does NOT align. RFC 7489 §10.4 documents strict
	// alignment as the mitigation for a hostile delegated subdomain.
	AlignmentStrict
)

// String returns "relaxed" or "strict"; any other value renders as
// AlignmentMode(<n>).
func (m AlignmentMode) String() string {
	switch m {
	case AlignmentRelaxed:
		return "relaxed"
	case AlignmentStrict:
		return "strict"
	default:
		return "AlignmentMode(" + strconv.Itoa(int(m)) + ")"
	}
}

// AlignedMode reports whether authDomain aligns with fromDomain under the given
// DMARC alignment mode (RFC 7489 §3.1), with an injectable [OrgDomainFunc] for
// the relaxed org-domain derivation (nil uses [DefaultOrgDomain]). Callers pass
// the mode parsed from a record with [ParseADKIM] (for a DKIM d= identifier) or
// [ParseASPF] (for an SPF-authenticated identifier), or exposed on
// [Policy.ADKIM] / [Policy.ASPF].
//
// Under [AlignmentRelaxed] the result is exactly [AlignedOrg]: equal
// Organizational Domains align. Under [AlignmentStrict] the org-domain hook is
// not consulted — the two identifier domains must be an exact, case-insensitive
// FQDN match after [normalizeDomain], so a From domain and a delegated subdomain
// of it do NOT align. Both inputs are sanitized as in [AlignedOrg]; an empty
// identifier never aligns.
func AlignedMode(authDomain, fromDomain string, mode AlignmentMode, orgDomain OrgDomainFunc) bool {
	if mode != AlignmentStrict {
		return AlignedOrg(authDomain, fromDomain, orgDomain)
	}
	// Strict alignment: an exact, case-insensitive FQDN match after
	// normalization. The org-domain hook is deliberately not consulted, so a
	// delegated subdomain of the From domain does not align. An empty (absent)
	// identifier never aligns, and two empties must not compare equal into a
	// false pass.
	authDomain = normalizeDomain(authDomain)
	fromDomain = normalizeDomain(fromDomain)
	return authDomain != "" && authDomain == fromDomain
}

// normalizeDomain canonicalizes a domain name for alignment comparison. It
// strips a single trailing root dot, then lower-cases and converts each label to
// its ASCII A-label (xn-- punycode) form so that two spellings of the same name —
// differing only in case, a trailing dot, or Unicode vs punycode encoding — reduce
// to one string. An empty input (or one that reduces to empty, such as a lone
// ".") returns "", which callers treat as "no domain": it never aligns.
//
// The mapping is idempotent: an already-A-label input is all-ASCII and is only
// lower-cased, so normalizeDomain(normalizeDomain(x)) == normalizeDomain(x). Case
// folding is Unicode simple lower-casing; the full IDNA2008 mapping (NFC
// normalization, special folds such as ß, and label validation) is intentionally
// out of scope for a dependency-free comparison and would only matter for
// deliberately unusual spellings.
func normalizeDomain(domain string) string {
	// Strip a single trailing dot (the DNS root label); "example.com." and
	// "example.com" are the same name.
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return ""
	}
	domain = strings.ToLower(domain)
	if isASCII(domain) {
		// Already an A-label / plain-ASCII name; lower-casing was enough. This is
		// the common case and covers existing xn-- labels (which are ASCII).
		return domain
	}
	labels := strings.Split(domain, ".")
	for i, label := range labels {
		labels[i] = labelToASCII(label)
	}
	return strings.Join(labels, ".")
}

// labelToASCII returns the ASCII A-label form of a single DNS label. An all-ASCII
// label (including an already-encoded xn-- label) is returned unchanged; a label
// containing non-ASCII runes is punycode-encoded and given the xn-- prefix. If
// encoding is not possible the (lower-cased) input is returned unchanged, so a
// pathological label degrades to a plain non-match rather than a panic.
func labelToASCII(label string) string {
	if isASCII(label) {
		return label
	}
	encoded, ok := punycodeEncode(label)
	if !ok {
		return label
	}
	return "xn--" + encoded
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// Punycode (RFC 3492) bootstring parameters for IDNA.
const (
	punyBase        = 36
	punyTMin        = 1
	punyTMax        = 26
	punySkew        = 38
	punyDamp        = 700
	punyInitialBias = 72
	punyInitialN    = 128 // first non-ASCII code point
	punyDelimiter   = '-'
)

// punycodeEncode encodes a string of Unicode code points into its punycode
// (RFC 3492) basic-string form, i.e. the part that follows the xn-- prefix in an
// IDNA A-label. It returns ok=false only if an internal counter would overflow,
// which cannot happen for real domain labels. This is the RFC 3492 reference
// "Encoding procedure" adapted to Go.
func punycodeEncode(input string) (string, bool) {
	runes := []rune(input)
	var out strings.Builder

	// Copy all basic (ASCII) code points first, in order.
	basic := 0
	for _, r := range runes {
		if r < punyInitialN {
			out.WriteByte(byte(r))
			basic++
		}
	}
	handled := basic
	if basic > 0 {
		out.WriteByte(punyDelimiter)
	}

	n := punyInitialN
	delta := 0
	bias := punyInitialBias
	for handled < len(runes) {
		// Find the next-smallest code point not yet handled.
		m := math.MaxInt32
		for _, r := range runes {
			if int(r) >= n && int(r) < m {
				m = int(r)
			}
		}
		// delta += (m - n) * (handled + 1), guarding against overflow.
		if m-n > (math.MaxInt32-delta)/(handled+1) {
			return "", false
		}
		delta += (m - n) * (handled + 1)
		n = m
		for _, r := range runes {
			c := int(r)
			if c < n {
				delta++
				if delta < 0 {
					return "", false
				}
			}
			if c == n {
				q := delta
				for k := punyBase; ; k += punyBase {
					t := punyThreshold(k, bias)
					if q < t {
						break
					}
					out.WriteByte(punyDigit(t + (q-t)%(punyBase-t)))
					q = (q - t) / (punyBase - t)
				}
				out.WriteByte(punyDigit(q))
				bias = punyAdapt(delta, handled+1, handled == basic)
				delta = 0
				handled++
			}
		}
		delta++
		n++
	}
	return out.String(), true
}

func punyThreshold(k, bias int) int {
	switch {
	case k <= bias+punyTMin:
		return punyTMin
	case k >= bias+punyTMax:
		return punyTMax
	default:
		return k - bias
	}
}

func punyAdapt(delta, numPoints int, firstTime bool) int {
	if firstTime {
		delta /= punyDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((punyBase-punyTMin)*punyTMax)/2 {
		delta /= punyBase - punyTMin
		k += punyBase
	}
	return k + (punyBase-punyTMin+1)*delta/(delta+punySkew)
}

// punyDigit maps a value 0..35 to its punycode digit: 0..25 -> 'a'..'z',
// 26..35 -> '0'..'9'.
func punyDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}
