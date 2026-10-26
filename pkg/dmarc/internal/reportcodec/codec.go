package reportcodec

import (
	"net/netip"
	"strings"
)

// Evaluated returns the DMARC-aligned pass/fail: a mechanism only counts as
// passing DMARC when it both passed AND aligned with the From domain.
func Evaluated(result string, aligned bool) string {
	if aligned && strings.EqualFold(strings.TrimSpace(result), "pass") {
		return "pass"
	}
	return "fail"
}

// The RFC 9990 Appendix A result and disposition types are closed
// enumerations; a value outside the set makes the document fail schema
// validation. The Normalize* helpers lower-case the input and fall back to a
// safe in-enumeration default (none for results and dispositions) so an
// unknown or empty value never reaches the emitted XML.

// NormalizeDKIMResult keeps a DKIMResultType value, defaulting to none.
func NormalizeDKIMResult(s string) string {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "none", "pass", "fail", "policy", "neutral", "temperror", "permerror":
		return v
	default:
		return "none"
	}
}

// NormalizeSPFResult keeps an SPFResultType value, defaulting to none.
func NormalizeSPFResult(s string) string {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "none", "neutral", "pass", "fail", "softfail", "policy", "temperror", "permerror":
		return v
	default:
		return "none"
	}
}

// NormalizeAlignment keeps an adkim/aspf value of r or s and takes the
// default r for anything else, which the schema's AlignmentType does not
// allow.
func NormalizeAlignment(s string) string {
	if v := strings.ToLower(strings.TrimSpace(s)); v == "s" {
		return v
	}
	return "r"
}

// NormalizeTesting keeps a testing value of y and takes the default n for
// anything else (TestingType).
func NormalizeTesting(s string) string {
	if v := strings.ToLower(strings.TrimSpace(s)); v == "y" {
		return v
	}
	return "n"
}

// NormalizeDiscovery keeps a discovery_method of treewalk or psl and drops
// anything else (DiscoveryType).
func NormalizeDiscovery(s string) string {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "treewalk", "psl":
		return v
	default:
		return ""
	}
}

// ReportIP writes a source IP address as RFC 9990 §3.1.1.8 asks, an
// IPv4address or IPv6address of RFC 3986 §3.2.2: an IPv4 address as a dotted
// quad (an IPv4-mapped IPv6 address included), and an IPv6 address in its
// canonical compressed form. It returns false for a string that is not an IP
// address.
func ReportIP(s string) (string, bool) {
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || ip.Zone() != "" {
		return s, false
	}
	return ip.Unmap().String(), true
}

// NormalizeDisposition keeps an ActionDispositionType value: none, pass (a
// message that passed DMARC under an enforcing policy), quarantine or
// reject.
func NormalizeDisposition(s string) string {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "none", "pass", "quarantine", "reject":
		return v
	default:
		return "none"
	}
}

// NormalizePolicy keeps a DispositionType value (none, quarantine or
// reject), the policies p, sp and np publish.
func NormalizePolicy(s string) string {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "none", "quarantine", "reject":
		return v
	default:
		return "none"
	}
}

// AlphaNumeric reports whether s holds only ASCII letters and digits
// (unique-id = 1*(ALPHA / DIGIT), or empty for none).
func AlphaNumeric(s string) bool {
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

// ReportIDText reports whether s is a ridtxt (RFC 9990 §3.5.1): ridfmt or
// "<" ridfmt ">", where ridfmt is dot-atom-text ["@" dot-atom-text].
func ReportIDText(s string) bool {
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
