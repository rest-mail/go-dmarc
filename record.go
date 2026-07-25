package dmarc

import (
	"errors"
	"net"
	"strings"
)

// TXTResolver resolves the TXT records for a name. Its signature matches
// [net.LookupTXT], so that (or a fake in tests) can be passed directly. A nil
// resolver passed to [Lookup] falls back to net.LookupTXT.
type TXTResolver func(name string) ([]string, error)

// Lookup fetches and returns the raw DMARC record published at
// _dmarc.<domain>. It maps DNS outcomes to the three RFC 7489 §6.6.3 cases:
//
//   - Record found: the raw "v=DMARC1..." TXT record and a nil error.
//   - No DMARC policy: ("", nil). This covers both a name that exists but
//     carries no v=DMARC1 record and a name that does not exist at all — a
//     not-found (NXDOMAIN) result is "DMARC does not apply", not a failure.
//   - Transient failure (SERVFAIL, timeout, and other non-not-found DNS
//     errors): ("", err). Callers must treat this as temperror and not fail
//     open — the domain's policy is unknown, not absent.
//
// The distinction relies on the resolver reporting not-found via a
// *net.DNSError whose IsNotFound is set, which is what [net.LookupTXT] does;
// fakes returning such an error are classified the same way.
func Lookup(domain string, resolver TXTResolver) (string, error) {
	if resolver == nil {
		resolver = net.LookupTXT
	}
	records, err := resolver("_dmarc." + domain)
	if err != nil {
		// A not-found result means the domain publishes no DMARC record, which
		// RFC 7489 §6.6.3 treats as "no policy", not a lookup failure. Only
		// genuine transient errors surface to the caller.
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return "", nil
		}
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
