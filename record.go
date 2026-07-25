package dmarc

import (
	"errors"
	"fmt"
	"net"
	"strconv"
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
//   - No DMARC policy: ("", nil). This covers a name that carries no v=DMARC1
//     record, a name that does not exist at all (a not-found/NXDOMAIN result is
//     "DMARC does not apply", not a failure), and a name that carries more than
//     one v=DMARC1 record — an ambiguous set §6.6.3 discards, so it too is "no
//     policy" rather than a non-deterministic first-wins guess.
//   - Transient failure (SERVFAIL, timeout, and other non-not-found DNS
//     errors): ("", err). Callers must treat this as temperror and not fail
//     open — the domain's policy is unknown, not absent.
//
// The distinction relies on the resolver reporting not-found via a
// *net.DNSError whose IsNotFound is set, which is what [net.LookupTXT] does;
// fakes returning such an error are classified the same way.
func Lookup(domain string, resolver TXTResolver) (string, error) {
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
// that begin with the v=DMARC1 tag — the RFC 7489 §6.6.3 filtering that discards
// non-DMARC TXT records (SPF, verification tokens, and the like). A nil resolver
// falls back to [net.LookupTXT]. It applies Lookup's error contract: a not-found
// (NXDOMAIN) result maps to an empty set with a nil error, while other resolver
// errors surface unchanged so callers can treat them as temperror. Returning the
// full filtered set (rather than the first match) lets callers distinguish the
// no-record, single-record, and ambiguous multi-record cases.
func lookupDMARC(domain string, resolver TXTResolver) ([]string, error) {
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
			return nil, nil
		}
		return nil, err
	}
	var dmarc []string
	for _, r := range records {
		if strings.HasPrefix(r, "v=DMARC1") {
			dmarc = append(dmarc, r)
		}
	}
	return dmarc, nil
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

// ParsePct extracts the pct= tag from a DMARC record: the percentage (0–100) of
// failing messages to which the requested policy is applied during a staged
// rollout (RFC 7489 §6.3). It returns the default of 100 when the record carries
// no pct= tag, so a receiver that ignores pct still gets the correct full-
// enforcement value.
//
// A pct= value that is not an integer in the range 0–100 is a malformed record
// and is rejected with a non-nil error rather than silently coerced; a caller
// can then treat the record as unusable instead of enforcing at an unintended
// rate. Per §6.6.4 a receiver applies the requested policy to a random pct
// percent of failing messages and the next-lower policy to the remainder;
// selecting that sample from crypto/rand is the caller's responsibility.
func ParsePct(record string) (int, error) {
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, "pct=") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(part, "pct="))
		pct, err := strconv.Atoi(value)
		if err != nil {
			return 0, fmt.Errorf("dmarc: invalid pct=%q: %w", value, err)
		}
		if pct < 0 || pct > 100 {
			return 0, fmt.Errorf("dmarc: pct=%d out of range 0-100", pct)
		}
		return pct, nil
	}
	return 100, nil
}

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
// Relaxed alignment (RFC 7489 §3.1) holds when the two Organizational Domains
// are non-empty and equal. A domain that is itself a public suffix has no
// registrable Organizational Domain: a PSL-backed OrgDomainFunc returns "" for
// it, so such a domain never aligns. Strict alignment (an exact,
// case-insensitive match) is always reported, independent of the hook.
func AlignedOrg(authDomain, fromDomain string, orgDomain OrgDomainFunc) bool {
	authDomain = strings.ToLower(strings.TrimSuffix(authDomain, "."))
	fromDomain = strings.ToLower(strings.TrimSuffix(fromDomain, "."))
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
