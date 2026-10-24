package dmarc

import "strings"

// Policy is the result of DMARC policy discovery (RFC 9989 §4.10.1) for an
// Author Domain. A Policy with an empty Raw record (and "none" Requested)
// means DMARC does not apply: no usable DMARC Policy Record was found.
type Policy struct {
	// Domain is the DNS name whose _dmarc record supplied the policy, in its
	// A-label form: the Author Domain, its Organizational Domain, or its
	// Public Suffix Domain (PSD).
	Domain string
	// Raw is the DMARC TXT record as published, or "" when no policy applies.
	Raw string
	// Record is Raw parsed by [ParseRecord]. It carries the alignment modes
	// (pass Record.ADKIM and Record.ASPF to [AlignedMode]), the test mode,
	// and the rua= and ruf= report URIs.
	Record Record
	// Requested is the Domain Owner Assessment Policy for the Author Domain:
	// the p= tag of its own record; for a record of its Organizational Domain
	// or PSD, the np= tag when the Author Domain does not exist and sp= when
	// it does, each falling back to the policy above it (np= to sp=, sp= to
	// p=). It is "none" when no policy applies.
	Requested string
	// Applied is Requested as a receiver applies it: one level lower when the
	// record asks for test mode (t=y), so reject is applied as quarantine and
	// quarantine as none (§4.7). It is "none" when no policy applies.
	Applied string
	// Inherited reports whether the record is the Organizational Domain's or
	// the PSD's, found by the DNS Tree Walk, rather than the Author Domain's
	// own.
	Inherited bool
	// PSD reports whether the record is a Public Suffix Domain's (psd=y),
	// applied because neither the Author Domain nor its Organizational Domain
	// publishes one.
	PSD bool
}

// ExistsFunc reports whether a domain exists. RFC 9989 §3.2.13 takes the
// meaning of RFC 8020: a domain does not exist when the DNS answers a query
// for it with NXDOMAIN. Any other answer, records or none, means it exists.
// An error is a transient failure, which the caller of [Discover] gets back.
type ExistsFunc func(domain string) (bool, error)

// Discover performs DMARC policy discovery for an Author Domain (RFC 9989
// §4.10.1). It looks up _dmarc.<domain>; when that holds no single v=DMARC1
// record, it walks up the DNS tree (§4.10) and applies the record of the
// Author Domain's Organizational Domain (§4.10.2) or, when that has none, of
// its Public Suffix Domain. For an inherited record the policy is sp=, or np=
// when exists says the Author Domain does not exist (§4.7).
//
// The domain is queried in its A-label form; a domain that is not a valid DNS
// name has no policy and sends no query. The record is read by [ParseRecord]:
// one with no valid policy and no valid rua= URI leaves DMARC not applied,
// and one with no valid policy but a valid rua= requests "none" (§4.10.1).
//
// resolver may be nil, for system DNS (net.LookupTXT). exists may be nil, and
// is only called when the record that applies has an np= tag; with a nil
// exists the Author Domain is taken to exist, so np= is never applied. A
// resolver or exists error is returned, so the caller can treat it as a
// temporary failure (§4.10.1 leaves the choice of failing open or closed to
// the receiver); a domain with no usable policy is reported as a Policy with
// an empty Raw record and a nil error.
func Discover(domain string, resolver TXTResolver, exists ExistsFunc) (Policy, error) {
	none := Policy{Requested: "none", Applied: "none"}
	domain, ok := queryDomain(domain)
	if !ok {
		return none, nil
	}
	records, err := lookupDMARC(domain, resolver)
	if err != nil {
		return Policy{}, err
	}
	// A single record at the Author Domain is the one that applies, whatever
	// it holds. More than one is no record at all (§4.10 step 2), so the
	// Tree Walk looks above it.
	if len(records) == 1 {
		rec, err := ParseRecord(records[0])
		if err != nil {
			return none, nil
		}
		return newPolicy(domain, records[0], rec, rec.Policy, false, false), nil
	}

	found, err := treeWalk(domain, resolver, false)
	if err != nil {
		return Policy{}, err
	}
	org := orgDomainOf(domain, found)
	var chosen *walkRecord
	psd := false
	for i := range found {
		if found[i].domain == org {
			chosen = &found[i]
		}
	}
	if chosen == nil {
		for i := range found {
			if recordPSD(found[i].raw) == "y" {
				chosen, psd = &found[i], true
			}
		}
	}
	if chosen == nil {
		return none, nil // §4.10.1: no record, so DMARC does not apply
	}
	rec, err := ParseRecord(chosen.raw)
	if err != nil {
		return none, nil
	}
	requested := rec.Policy
	if rec.SubdomainPolicy != "" {
		requested = rec.SubdomainPolicy
	}
	if rec.NonExistentPolicy != "" && exists != nil {
		ok, err := exists(domain)
		if err != nil {
			return Policy{}, err
		}
		if !ok {
			requested = rec.NonExistentPolicy
		}
	}
	return newPolicy(chosen.domain, chosen.raw, rec, requested, true, psd), nil
}

// newPolicy builds the Policy a record found at domain gives, with the
// policy it requests applied one level lower in test mode (§4.7).
func newPolicy(domain, raw string, rec Record, requested string, inherited, psd bool) Policy {
	applied := requested
	if rec.Testing {
		switch requested {
		case "reject":
			applied = "quarantine"
		case "quarantine":
			applied = "none"
		}
	}
	return Policy{Domain: domain, Raw: raw, Record: rec, Requested: requested, Applied: applied, Inherited: inherited, PSD: psd}
}

// OrgDomain returns the Organizational Domain of domain (RFC 9989 §4.10.2),
// found by a DNS Tree Walk from domain up to the root (§4.10). Of the names
// that publish a single v=DMARC1 record, taken from the longest to the
// shortest, it is the first one with psd=n, or the name one label below the
// first one with psd=y (other than domain itself); otherwise it is the one
// with the fewest labels, and when no name publishes a record, domain itself.
//
// The result is in A-label form, without a root dot, and "" for a name that
// is not a valid DNS name. resolver may be nil, for system DNS; its errors
// are returned.
func OrgDomain(domain string, resolver TXTResolver) (string, error) {
	domain, ok := queryDomain(domain)
	if !ok {
		return "", nil
	}
	found, err := treeWalk(domain, resolver, true)
	if err != nil {
		return "", err
	}
	return orgDomainOf(domain, found), nil
}

// walkRecord is the single v=DMARC1 record a DNS Tree Walk found at a name.
type walkRecord struct {
	domain string
	raw    string
}

// treeWalk performs the DNS Tree Walk of RFC 9989 §4.10 for subject, an
// A-label name: it queries _dmarc.<subject> (when querySubject is set) and
// then each name above it up to the last label. When subject has eight
// labels or more, the name after subject is its last seven, so no walk sends
// more than eight queries. A name with more than one v=DMARC1 record yields
// none. The walk stops after a single record with psd=y or psd=n, after the
// last label, or at a resolver error, which it returns. The records come in
// the order found, the longest name first.
func treeWalk(subject string, resolver TXTResolver, querySubject bool) ([]walkRecord, error) {
	var found []walkRecord
	target, ok := subject, true
	if !querySubject {
		target, ok = nextTarget(subject, subject)
	}
	for ok {
		records, err := lookupDMARC(target, resolver)
		if err != nil {
			return found, err
		}
		if len(records) == 1 {
			found = append(found, walkRecord{domain: target, raw: records[0]})
			if psd := recordPSD(records[0]); psd == "y" || psd == "n" {
				return found, nil
			}
		}
		target, ok = nextTarget(subject, target)
	}
	return found, nil
}

// nextTarget is the name a Tree Walk for subject queries after target
// (§4.10 steps 3, 4 and 7): target without its left-most label, or, after
// subject itself when it has eight labels or more, its last seven labels.
// There is none after a single label.
func nextTarget(subject, target string) (string, bool) {
	labels := strings.Split(target, ".")
	switch {
	case len(labels) <= 1:
		return "", false
	case target == subject && len(labels) >= 8:
		return strings.Join(labels[len(labels)-7:], "."), true
	default:
		return strings.Join(labels[1:], "."), true
	}
}

// orgDomainOf selects the Organizational Domain of subject from the records
// a Tree Walk for it found, longest name first (§4.10.2): the first with
// psd=n; the name one label below the first with psd=y, unless that record is
// subject's own; otherwise the record with the fewest labels; and subject
// itself when there are none.
func orgDomainOf(subject string, found []walkRecord) string {
	for _, r := range found {
		switch recordPSD(r.raw) {
		case "n":
			return r.domain
		case "y":
			if r.domain != subject {
				return oneLabelBelow(subject, r.domain)
			}
		}
	}
	if len(found) > 0 {
		return found[len(found)-1].domain
	}
	return subject
}

// oneLabelBelow returns the name under ancestor on the way to subject: the
// last labels of subject, one more than ancestor has. ancestor is a Tree Walk
// target above subject, so subject has that many labels.
func oneLabelBelow(subject, ancestor string) string {
	labels := strings.Split(subject, ".")
	return strings.Join(labels[len(labels)-strings.Count(ancestor, ".")-2:], ".")
}

// recordPSD returns a record's psd= tag ("y", "n" or the default "u"), read
// whether or not the record has a valid policy: the Tree Walk stops on it
// and the Organizational Domain depends on it either way.
func recordPSD(raw string) string {
	tags, _, _ := recordTags(raw) // nil, and so "u", for a record that is not DMARC
	return psdTag(tags)
}
