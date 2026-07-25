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
	// ADKIM and ASPF are the DKIM and SPF identifier-alignment modes the record
	// requests via its adkim= / aspf= tags (RFC 7489 §6.3): AlignmentRelaxed (the
	// default) or AlignmentStrict. Pass them to [AlignedMode] to evaluate DKIM and
	// SPF alignment under the mode the domain published. Both are AlignmentRelaxed
	// for a zero Policy (no applicable record), the documented default.
	ADKIM AlignmentMode
	ASPF  AlignmentMode
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
		return Policy{Requested: "none"}, nil
	}
	if len(records) == 1 {
		record := records[0]
		requested, err := ParsePolicy(record)
		if err != nil {
			return Policy{}, err
		}
		pct, err := ParsePct(record)
		if err != nil {
			return Policy{}, err
		}
		return Policy{
			Domain:    domain,
			Record:    record,
			Requested: requested,
			Pct:       pct,
			ADKIM:     ParseADKIM(record),
			ASPF:      ParseASPF(record),
		}, nil
	}

	// §6.6.3 step 3: the exact-domain set is empty, so fall back to the record at
	// the Organizational Domain (unless the domain already is its own org domain).
	if orgDomain == nil {
		orgDomain = DefaultOrgDomain
	}
	org := orgDomain(domain)
	if org == "" || strings.EqualFold(org, domain) {
		return Policy{Requested: "none"}, nil
	}

	orgRecords, err := lookupDMARC(org, resolver)
	if err != nil {
		return Policy{}, err
	}
	// Step 5 again for the org-domain set: no record, or an ambiguous multi-record
	// set that is discarded, both leave the subdomain with no policy.
	if len(orgRecords) != 1 {
		return Policy{Requested: "none"}, nil
	}
	orgRecord := orgRecords[0]
	requested, err := parseSubdomainPolicy(orgRecord)
	if err != nil {
		return Policy{}, err
	}
	pct, err := ParsePct(orgRecord)
	if err != nil {
		return Policy{}, err
	}
	return Policy{
		Domain:       org,
		Record:       orgRecord,
		Requested:    requested,
		Pct:          pct,
		ViaOrgDomain: true,
		ADKIM:        ParseADKIM(orgRecord),
		ASPF:         ParseASPF(orgRecord),
	}, nil
}

// parseSubdomainPolicy returns the policy an Organizational-Domain record
// requests for its subdomains: the sp= tag when present, otherwise the p= tag
// (RFC 7489 §6.3). It returns "none" when neither is present. Like p=, the sp=
// tag name and its enumerated value (none/quarantine/reject) are matched
// case-insensitively and the value is normalised to lower case.
//
// An sp= tag with an unrecognised value, or one that appears more than once, is
// malformed and returns a non-nil error rather than a raw value (§6.6.3); when
// sp= is absent the subdomain policy is the record's p=, so a malformed p= (see
// [ParsePolicy]) likewise surfaces as an error.
func parseSubdomainPolicy(record string) (string, error) {
	value, present, err := policyTag(record, "sp")
	if err != nil {
		return "", err
	}
	if present {
		return value, nil
	}
	return ParsePolicy(record)
}
