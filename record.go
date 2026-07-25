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
// whose first tag is the v=DMARC1 version tag — the RFC 7489 §6.6.3 filtering that discards
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
		if hasDMARCVersion(r) {
			dmarc = append(dmarc, r)
		}
	}
	return dmarc, nil
}

// hasDMARCVersion reports whether a TXT record is a DMARC record, i.e. its first
// tag is the version tag "v=DMARC1". RFC 7489 §6.3 requires v to be the first
// tag with a value that "MUST match precisely"; §6.4 gives the ABNF
// dmarc-version = "v" *WSP "=" *WSP "DMARC1", with tags separated by
// dmarc-sep = *WSP ";" *WSP.
//
// The match is deliberately neither a raw prefix nor an exact string compare:
//
//   - The value is a complete token, so "v=DMARC10" and "v=DMARC1x" — distinct,
//     longer tokens — are NOT DMARC records (the old strings.HasPrefix accepted
//     them).
//   - Whitespace is tolerated around "=" and before the separator, and the tag
//     name and value are compared case-insensitively (tag names are
//     case-insensitive per §6.4, and "DMARC1" is matched case-insensitively by
//     convention), so ABNF-legal forms such as "V=DMARC1 ; p=none" and
//     "v = DMARC1" ARE DMARC records (the old prefix compare rejected them).
//
// The version tag MUST be first: a "v=DMARC1" appearing after another tag does
// not qualify, since only the first ";"-delimited field is inspected.
func hasDMARCVersion(record string) bool {
	first, _, _ := strings.Cut(record, ";")
	name, value, found := strings.Cut(first, "=")
	if !found {
		return false
	}
	name = strings.TrimSpace(name)
	value = strings.TrimSpace(value)
	return strings.EqualFold(name, "v") && strings.EqualFold(value, "DMARC1")
}

// tagValue returns the value of the named tag from a DMARC record, or ("",
// false) when the tag is absent. Tag names are matched case-insensitively and
// whitespace around the "=" is tolerated, per the RFC 7489 §6.4 ABNF
// (dmarc-tag = key *WSP "=" *WSP value; tag names are case-insensitive). The
// value is returned with surrounding whitespace trimmed but its case preserved:
// callers matching an enumerated value (p=, sp=) lower-case it themselves, while
// opaque values such as rua/ruf URIs must keep their case.
func tagValue(record, name string) (string, bool) {
	for _, part := range strings.Split(record, ";") {
		tag, value, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(tag), name) {
			return strings.TrimSpace(value), true
		}
	}
	return "", false
}

// isPolicyValue reports whether v is one of the enumerated DMARC policy values
// none/quarantine/reject (RFC 7489 §6.3). It expects v already trimmed and
// lower-cased; the closed set means any other value is a malformed p=/sp= tag.
func isPolicyValue(v string) bool {
	switch v {
	case "none", "quarantine", "reject":
		return true
	}
	return false
}

// policyTag reads the single value of an enumerated policy tag (p= or sp=) and
// validates it against the RFC 7489 §6.3 set none/quarantine/reject. Like
// [tagValue] the tag name is matched case-insensitively and whitespace around
// "=" is tolerated; the value is additionally lower-cased so the comparison
// against the policy names is case-insensitive (§6.4). It returns:
//
//   - ("", false, nil) when the tag is absent, so the caller supplies its own
//     default;
//   - (value, true, nil) for exactly one occurrence carrying a recognised value;
//   - ("", false, err) when the tag appears more than once (a duplicate tag is a
//     malformed record — §6.4 tags occur at most once) or carries an
//     unrecognised value.
//
// Returning an error rather than a raw or first-wins value is what stops a caller
// from applying a garbage disposition (e.g. "bogus") or a non-deterministic pick
// from a duplicated tag; §6.6.3 treats a record without a valid p as if none were
// published, which the caller effects by declining to use the record.
func policyTag(record, name string) (string, bool, error) {
	var (
		value string
		count int
	)
	for _, part := range strings.Split(record, ";") {
		tag, v, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(tag), name) {
			value = strings.ToLower(strings.TrimSpace(v))
			count++
		}
	}
	switch {
	case count == 0:
		return "", false, nil
	case count > 1:
		return "", false, fmt.Errorf("dmarc: duplicate %s= tag", name)
	case !isPolicyValue(value):
		return "", false, fmt.Errorf("dmarc: invalid %s=%q", name, value)
	}
	return value, true, nil
}

// ParsePolicy extracts the requested policy (the p= tag) from a DMARC record. It
// returns "none" when no p= tag is present.
//
// The tag name and the enumerated value (none/quarantine/reject) are matched
// case-insensitively per RFC 7489 §6.3/§6.4: "P=Reject" is recognised, and the
// value is normalised to lower case so a downstream comparison against the
// lower-case policy names is not defeated by a record that writes "REJECT".
//
// A p= tag whose value is not one of the three enumerated values, or a record
// that carries the p= tag more than once, is malformed: ParsePolicy returns a
// non-nil error rather than the raw ("bogus") or first-wins value, so a caller
// cannot apply an unintended disposition. Per §6.6.3 such a record has no valid
// policy and is treated as if none were published; the caller effects that by
// declining to use it.
func ParsePolicy(record string) (string, error) {
	value, present, err := policyTag(record, "p")
	if err != nil {
		return "", err
	}
	if !present {
		return "none", nil
	}
	return value, nil
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
	value, ok := tagValue(record, "pct")
	if !ok {
		return 100, nil
	}
	pct, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("dmarc: invalid pct=%q: %w", value, err)
	}
	if pct < 0 || pct > 100 {
		return 0, fmt.Errorf("dmarc: pct=%d out of range 0-100", pct)
	}
	return pct, nil
}
