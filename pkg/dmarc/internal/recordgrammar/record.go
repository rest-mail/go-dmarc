package recordgrammar

import (
	"net/url"
	"strings"
)

// RecordTags splits a DMARC record into its tags after v=DMARC1, keyed by
// lower-case name, with whitespace around the names and values trimmed. A
// tag that appears more than once is left out and named in repeated (RFC
// 6376 §3.2). ok is false for a record that does not start with v=DMARC1.
func RecordTags(txt string) (tags map[string]string, repeated map[string]bool, ok bool) {
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

// HasDMARCVersion reports whether a TXT record is a DMARC record: its first
// tag is v=DMARC1 (RFC 9989 §4.7, §4.10 step 2).
func HasDMARCVersion(record string) bool {
	first, _, _ := strings.Cut(record, ";")
	return isVersionTag(first)
}

// PolicyValue returns the lower-cased value of a p=, sp= or np= tag and
// whether it is present with one of the values none, quarantine and reject
// (dmarc-request, §4.8).
func PolicyValue(tags map[string]string, name string) (string, bool) {
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

// SubdomainPolicy reads sp= or np=: an absent tag is valid and empty, since
// the policy above it then applies, while one that is present must be valid,
// and so must not be repeated (§4.10.1).
func SubdomainPolicy(tags map[string]string, repeated map[string]bool, name string) (string, bool) {
	if _, present := tags[name]; !present && !repeated[name] {
		return "", true
	}
	return PolicyValue(tags, name)
}

// PSDTag reads psd= (dmarc-psd = "y" / "n" / "u", §4.8); an absent or
// invalid tag is the default "u".
func PSDTag(tags map[string]string) string {
	switch v := strings.ToLower(tags["psd"]); v {
	case "y", "n":
		return v
	}
	return "u"
}

// FailureOptions reads fo= (dmarc-fo, §4.8): a colon-separated list of
// "0" or "1", which exclude each other, and "d" and "s", each at most once,
// in any order, with optional whitespace around the colons. It returns false
// for an invalid list, which then takes the default.
func FailureOptions(v string) ([]string, bool) {
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

// ParseReportURIs reads a comma-separated list of DMARC URIs (dmarc-urilist,
// §4.8), keeping the valid ones in order.
func ParseReportURIs(v string) []string {
	var uris []string
	for _, s := range strings.Split(v, ",") {
		if u, ok := ParseReportURI(strings.TrimSpace(s)); ok {
			uris = append(uris, u)
		}
	}
	return uris
}

// ParseReportURI reads one dmarc-uri, or an obs-dmarc-uri, which is a
// dmarc-uri followed by "!" 1*DIGIT [ "k" / "m" / "g" / "t" ] (§4.8). The
// size limit is obsolete, so it is checked for its syntax and dropped: a
// reporter "should ignore" it. A "!" inside the URI must be percent-encoded,
// so the first one starts the size limit. The URI must be absolute (have a
// scheme) and contain no whitespace, control or non-ASCII characters (an RFC
// 3986 URI is ASCII). A mailto: URI must name conventional addresses: RFC
// 8616 §6 says a record serves internationalized and conventional mail
// alike, so its report addresses are never internationalized, even
// percent-encoded.
func ParseReportURI(s string) (string, bool) {
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
