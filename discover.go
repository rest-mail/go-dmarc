package dmarc

import "strings"

// Policy is the result of DMARC policy discovery (RFC 7489 §6.6.3) for a domain.
// A Policy with an empty Raw record (and "none" Requested) means DMARC does not
// apply: the domain publishes no usable DMARC record.
type Policy struct {
	// Domain is the DNS name whose _dmarc record supplied the policy, in its
	// A-label form: the queried domain for an exact match, or its
	// Organizational Domain when the policy was found via the §6.6.3 fallback.
	Domain string
	// Raw is the DMARC TXT record as published, or "" when no policy applies.
	Raw string
	// Record is Raw parsed by [ParseRecord]. It carries the alignment modes
	// (pass Record.ADKIM and Record.ASPF to [AlignedMode]), the pct= sampling
	// rate, and the rua= and ruf= report URIs.
	Record Record
	// Requested is the policy to apply to the queried domain: the p= tag for an
	// exact match, or the subdomain policy (sp= if present, otherwise p=) when the
	// record was found via the Organizational-Domain fallback. It is "none" when
	// no policy applies. A receiver honouring a staged rollout applies it to
	// Record.Pct percent of failing messages (§6.6.4).
	Requested string
	// ViaOrgDomain reports whether the record was obtained through the §6.6.3
	// Organizational-Domain fallback rather than an exact match on the queried
	// domain.
	ViaOrgDomain bool
}

// OrgDomainFunc derives the Organizational Domain (RFC 7489 §3.2) of a domain,
// used for the policy-discovery fallback in [Discover] and for relaxed
// alignment in [AlignedOrg]. It is given a lower-case A-label name without a
// root dot, and returns "" for a name that is itself a public suffix (which
// has no Organizational Domain).
//
// Determining it correctly requires the Public Suffix List, so callers that
// need full accuracy (for example to keep two registrants under a multi-label
// public suffix such as co.uk apart) should pass a PSL-backed implementation —
// a small wrapper around golang.org/x/net/publicsuffix.EffectiveTLDPlusOne
// does this. A nil func uses [DefaultOrgDomain]. Keeping this injectable is
// what lets the package stay dependency-free while still supporting correct
// org-domain derivation.
type OrgDomainFunc func(domain string) string

// DefaultOrgDomain is the registry-free Organizational Domain heuristic used when
// [Discover] is given a nil [OrgDomainFunc]: it returns the last two labels of
// the domain (e.g. "sub.example.com" -> "example.com"). Like [Aligned], it uses
// no Public Suffix List, so it is correct for single-label public suffixes but
// wrong for multi-label ones (it would treat "co.uk" itself as the org domain,
// so example.co.uk and attacker.co.uk would align). For those, inject a
// PSL-backed [OrgDomainFunc]. The result is lower-cased with any trailing dot
// removed.
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
// The domain is queried in its A-label form (§6.6.1); a domain that is not a
// valid DNS name has no policy and sends no query. The record is read by
// [ParseRecord]: one with no valid policy and no valid rua= URI leaves DMARC
// not applied, and one with no valid policy but a valid rua= requests "none"
// (§6.6.3 step 6).
//
// resolver and orgDomain may be nil: resolver then uses system DNS
// (net.LookupTXT) and orgDomain uses [DefaultOrgDomain]. A resolver error is
// returned, so the caller can treat it as a temporary failure; a domain that
// publishes no usable policy is reported as a Policy with an empty Raw record
// and a nil error.
func Discover(domain string, resolver TXTResolver, orgDomain OrgDomainFunc) (Policy, error) {
	none := Policy{Requested: "none"}
	domain, ok := queryDomain(domain)
	if !ok {
		return none, nil
	}
	// §6.6.3 steps 1-2: query the exact From domain and keep only v=DMARC1 records.
	records, err := lookupDMARC(domain, resolver)
	if err != nil {
		return Policy{}, err
	}
	// §6.6.3 step 5: more than one v=DMARC1 record is an ambiguous set that is
	// discarded, and discovery terminates with no policy. The set is non-empty,
	// so step 3's org-domain fallback (which runs only on an empty set) does not
	// apply — we must not fall back and adopt the org domain's policy.
	if len(records) > 1 {
		return none, nil
	}
	if len(records) == 1 {
		rec, err := ParseRecord(records[0])
		if err != nil {
			return none, nil // §6.6.3 step 6.2: DMARC is not applied
		}
		return Policy{Domain: domain, Raw: records[0], Record: rec, Requested: rec.Policy}, nil
	}

	// §6.6.3 step 3: the exact-domain set is empty, so fall back to the record at
	// the Organizational Domain (unless the domain already is its own org domain).
	if orgDomain == nil {
		orgDomain = DefaultOrgDomain
	}
	org, ok := queryDomain(orgDomain(domain))
	if !ok || org == domain {
		return none, nil
	}

	orgRecords, err := lookupDMARC(org, resolver)
	if err != nil {
		return Policy{}, err
	}
	// Step 5 again for the org-domain set: no record, or an ambiguous multi-record
	// set that is discarded, both leave the subdomain with no policy.
	if len(orgRecords) != 1 {
		return none, nil
	}
	rec, err := ParseRecord(orgRecords[0])
	if err != nil {
		return none, nil
	}
	requested := rec.SubdomainPolicy
	if requested == "" {
		requested = rec.Policy
	}
	return Policy{Domain: org, Raw: orgRecords[0], Record: rec, Requested: requested, ViaOrgDomain: true}, nil
}
