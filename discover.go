package dmarc

import "strings"

// Policy is the result of DMARC policy discovery (RFC 7489 §6.6.3) for a domain.
// A zero Policy (empty Record, "none" Requested) means the domain publishes no
// applicable DMARC policy.
type Policy struct {
	// Domain is the DNS name whose _dmarc record supplied the policy: the queried
	// domain for an exact match, or its Organizational Domain when the policy was
	// found via the §6.6.3 fallback.
	Domain string
	// Record is the raw DMARC TXT record, or "" when no policy applies.
	Record string
	// Requested is the policy to apply to the queried domain: the p= tag for an
	// exact match, or the subdomain policy (sp= if present, otherwise p=) when the
	// record was found via the Organizational-Domain fallback. It is "none" when
	// no policy applies.
	Requested string
	// Pct is the percentage (0–100) of failing messages to which Requested is
	// applied for a staged rollout, from the record's pct= tag (RFC 7489 §6.3); it
	// is 100 (the default) when the record omits pct=, and 0 for a zero Policy (no
	// applicable record). A receiver honouring a rollout applies Requested to a
	// random Pct percent of failing messages and the next-lower policy to the rest
	// (§6.6.4); enforcing Requested unconditionally ignores the requested rate. It
	// is meaningful only when Record is non-empty.
	Pct int
	// ViaOrgDomain reports whether the record was obtained through the §6.6.3
	// Organizational-Domain fallback rather than an exact match on the queried
	// domain.
	ViaOrgDomain bool
}

// OrgDomainFunc derives the Organizational Domain (RFC 7489 §3.2) of a domain,
// used for the policy-discovery fallback in [Discover]. Determining it correctly
// requires the Public Suffix List, so callers that need full accuracy (for
// example to protect subdomains under multi-label public suffixes such as
// co.uk) should pass a PSL-backed implementation — a small wrapper around
// golang.org/x/net/publicsuffix.EffectiveTLDPlusOne does this. A nil func passed
// to [Discover] uses [DefaultOrgDomain]. Keeping this injectable is what lets the
// package stay dependency-free while still supporting correct org-domain
// derivation.
type OrgDomainFunc func(domain string) string

// DefaultOrgDomain is the registry-free Organizational Domain heuristic used when
// [Discover] is given a nil [OrgDomainFunc]: it returns the last two labels of
// the domain (e.g. "sub.example.com" -> "example.com"). Like [Aligned], it uses
// no Public Suffix List, so it is correct for single-label public suffixes but
// wrong for multi-label ones (it would treat "co.uk" itself as the org domain).
// For those, inject a PSL-backed [OrgDomainFunc]. The result is lower-cased with
// any trailing dot removed.
func DefaultOrgDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	labels := strings.Split(domain, ".")
	if len(labels) <= 2 {
		return domain
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// Discover performs DMARC policy discovery for domain, including the RFC 7489
// §6.6.3 Organizational-Domain fallback: it first looks up _dmarc.<domain>, and
// if that publishes no DMARC record it looks up _dmarc.<org-domain> and, when
// found, applies that record's subdomain policy (sp= if present, otherwise p=).
// Without this fallback a subdomain that publishes no record of its own would be
// treated as having no DMARC policy, letting spoofed subdomains bypass the
// organizational domain's p= policy.
//
// resolver and orgDomain may be nil: resolver then uses system DNS
// (net.LookupTXT) and orgDomain uses [DefaultOrgDomain]. A resolver error is
// returned; a domain that simply publishes no policy is reported as a zero
// [Policy] with a nil error.
func Discover(domain string, resolver TXTResolver, orgDomain OrgDomainFunc) (Policy, error) {
	// Step: query the DMARC record at the exact From domain.
	record, err := Lookup(domain, resolver)
	if err != nil {
		return Policy{}, err
	}
	if record != "" {
		pct, err := ParsePct(record)
		if err != nil {
			return Policy{}, err
		}
		return Policy{Domain: domain, Record: record, Requested: ParsePolicy(record), Pct: pct}, nil
	}

	// §6.6.3: the exact-domain set is empty, so fall back to the record at the
	// Organizational Domain (unless the domain already is its own org domain).
	if orgDomain == nil {
		orgDomain = DefaultOrgDomain
	}
	org := orgDomain(domain)
	if org == "" || strings.EqualFold(org, domain) {
		return Policy{Requested: "none"}, nil
	}

	orgRecord, err := Lookup(org, resolver)
	if err != nil {
		return Policy{}, err
	}
	if orgRecord == "" {
		return Policy{Requested: "none"}, nil
	}
	pct, err := ParsePct(orgRecord)
	if err != nil {
		return Policy{}, err
	}
	return Policy{
		Domain:       org,
		Record:       orgRecord,
		Requested:    parseSubdomainPolicy(orgRecord),
		Pct:          pct,
		ViaOrgDomain: true,
	}, nil
}

// parseSubdomainPolicy returns the policy an Organizational-Domain record
// requests for its subdomains: the sp= tag when present, otherwise the p= tag
// (RFC 7489 §6.3). It returns "none" when neither is present.
func parseSubdomainPolicy(record string) string {
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "sp=") {
			return strings.TrimPrefix(part, "sp=")
		}
	}
	return ParsePolicy(record)
}
