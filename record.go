package dmarc

import (
	"net"
	"strings"
)

// TXTResolver resolves the TXT records for a name. Its signature matches
// [net.LookupTXT], so that (or a fake in tests) can be passed directly. A nil
// resolver passed to [Lookup] falls back to net.LookupTXT.
type TXTResolver func(name string) ([]string, error)

// Lookup fetches and returns the raw DMARC record published at
// _dmarc.<domain>. It returns ("", nil) when the domain publishes no DMARC
// record (this is not an error: DMARC simply does not apply), and ("", err)
// when the underlying TXT lookup fails.
func Lookup(domain string, resolver TXTResolver) (string, error) {
	if resolver == nil {
		resolver = net.LookupTXT
	}
	records, err := resolver("_dmarc." + domain)
	if err != nil {
		return "", err
	}
	for _, r := range records {
		if strings.HasPrefix(r, "v=DMARC1") {
			return r, nil
		}
	}
	return "", nil
}

// ParsePolicy extracts the requested policy (the p= tag) from a DMARC record.
// It returns "none" when no p= tag is present.
func ParsePolicy(record string) string {
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "p=") {
			return strings.TrimPrefix(part, "p=")
		}
	}
	return "none"
}

// Aligned reports whether an authenticated domain aligns with the From domain
// under DMARC relaxed alignment (RFC 7489 §3.1): the organizational domains
// must match. This uses the simple, registry-free rule that the two are equal
// or one is a subdomain of the other (case-insensitive).
func Aligned(authDomain, fromDomain string) bool {
	authDomain = strings.ToLower(authDomain)
	fromDomain = strings.ToLower(fromDomain)
	if authDomain == fromDomain {
		return true
	}
	if strings.HasSuffix(authDomain, "."+fromDomain) || strings.HasSuffix(fromDomain, "."+authDomain) {
		return true
	}
	return false
}
