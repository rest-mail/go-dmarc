package dnsname

import (
	"math"
	"strings"
	"unicode/utf8"
)

// QueryDomain returns the A-label form of a domain (see [NormalizeDomain]) and
// whether it is a DNS name a DMARC check can use: 1 to 253 characters of
// dot-separated labels, each 1 to 63 letters, digits, hyphens or underscores.
// Anything else (an empty string, a leading or doubled dot, a space) is not a
// domain: it has no policy to look up and never aligns.
func QueryDomain(domain string) (string, bool) {
	// Punycode encoding takes time quadratic in a label's length, and every
	// code point needs at least one character of the A-label, so a name of
	// more than 254 code points (253 and a root dot) cannot be a domain and is
	// refused before it is encoded.
	if utf8.RuneCountInString(domain) > 254 {
		return "", false
	}
	domain = NormalizeDomain(domain)
	if domain == "" || len(domain) > 253 {
		return "", false
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			if !isLDHU(label[i]) {
				return "", false
			}
		}
	}
	return domain, true
}

// NormalizeDomain canonicalizes a domain name for alignment comparison. It
// strips a single trailing root dot, then lower-cases and converts each label to
// its ASCII A-label (xn-- punycode) form so that two spellings of the same name —
// differing only in case, a trailing dot, or Unicode vs punycode encoding — reduce
// to one string. An empty input (or one that reduces to empty, such as a lone
// ".") returns "", which callers treat as "no domain": it never aligns.
//
// The mapping is idempotent: an already-A-label input is all-ASCII and is only
// lower-cased, so NormalizeDomain(NormalizeDomain(x)) == NormalizeDomain(x). Case
// folding is Unicode simple lower-casing; the full IDNA2008 mapping (NFC
// normalization, special folds such as ß, and label validation) is intentionally
// out of scope for a dependency-free comparison and would only matter for
// deliberately unusual spellings.
func NormalizeDomain(domain string) string {
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
// containing non-ASCII runes is punycode-encoded and given the xn-- prefix.
func labelToASCII(label string) string {
	// An A-label has at most 63 characters, at least one per code point, so a
	// longer label is left as it is (and is then no valid domain); this also
	// bounds the quadratic encoder.
	if isASCII(label) || utf8.RuneCountInString(label) > 63 {
		return label
	}
	return "xn--" + punycodeEncode(label)
}

// isLDHU reports whether c is a lower-case letter, a digit, a hyphen or an
// underscore: the characters of a lower-cased DNS label.
func isLDHU(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
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
// IDNA A-label. This is the RFC 3492 reference "Encoding procedure" adapted to
// Go. Its input is at most 63 code points (see labelToASCII), so delta stays
// below 64 * 0x110000 and cannot overflow, which the reference code checks.
func punycodeEncode(input string) string {
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
		delta += (m - n) * (handled + 1)
		n = m
		for _, r := range runes {
			c := int(r)
			if c < n {
				delta++
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
	return out.String()
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
