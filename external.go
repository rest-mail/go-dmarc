package dmarc

import (
	"net/url"
	"strings"
)

// AuthorizeReportURIs returns the report URIs a reporter may send to, after
// the RFC 7489 §7.1 check of external destinations. policyDomain is the
// domain whose record listed the URIs ([Policy.Domain]), tag is "rua" or
// "ruf", and uris are that record's [Record.RUA] or [Record.RUF].
//
// A URI whose host has the same Organizational Domain as policyDomain is kept
// as it is. For any other URI the destination host must confirm it wants the
// reports by publishing a record starting with v=DMARC1 at
// <policyDomain>._report._dmarc.<host>; a URI without one is dropped. When the
// confirming record carries the same tag, its URIs replace the original, but
// only if they all use the same host: otherwise neither the original nor the
// override is used. URIs whose host cannot be found (a mailto: without an
// address, say) are dropped.
//
// A resolver error other than not-found is returned with the URIs checked so
// far, so the caller can try again later (§7.1 step 4). A nil resolver uses
// net.LookupTXT and a nil orgDomain uses [DefaultOrgDomain].
func AuthorizeReportURIs(policyDomain, tag string, uris []ReportURI, resolver TXTResolver, orgDomain OrgDomainFunc) ([]ReportURI, error) {
	if orgDomain == nil {
		orgDomain = DefaultOrgDomain
	}
	policyDomain, ok := queryDomain(policyDomain)
	if !ok {
		return nil, nil
	}
	policyOrg, _ := queryDomain(orgDomain(policyDomain))
	var out []ReportURI
	for _, u := range uris {
		host, ok := reportURIHost(u.URI)
		if !ok {
			continue
		}
		if hostOrg, ok := queryDomain(orgDomain(host)); ok && hostOrg == policyOrg {
			out = append(out, u)
			continue
		}
		records, err := lookupVersioned(policyDomain+"._report._dmarc."+host, resolver)
		if err != nil {
			return out, err
		}
		if len(records) == 0 {
			continue // §7.1 step 6: not confirmed, so the URI is ignored
		}
		override := overrideURIs(records, tag)
		if override == nil {
			out = append(out, u)
			continue
		}
		// §7.1 step 8: an override must keep the destination host, or neither
		// the original nor the override is used.
		sameHost := true
		for _, o := range override {
			if h, ok := reportURIHost(o.URI); !ok || h != host {
				sameHost = false
			}
		}
		if sameHost {
			out = append(out, override...)
		}
	}
	return out, nil
}

// overrideURIs returns the valid URIs of tag in the first confirming record
// that carries it, or nil when none does.
func overrideURIs(records []string, tag string) []ReportURI {
	tag = strings.ToLower(tag)
	for _, rec := range records {
		for _, part := range strings.Split(rec, ";")[1:] {
			name, value, found := strings.Cut(part, "=")
			if found && strings.EqualFold(strings.TrimSpace(name), tag) {
				return append([]ReportURI{}, parseReportURIs(strings.TrimSpace(value))...)
			}
		}
	}
	return nil
}

// reportURIHost returns the destination host of a report URI in A-label form:
// the domain of a mailto: URI's address, or the host of any other URI's
// authority (§7.1 step 1).
func reportURIHost(uri string) (string, bool) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", false
	}
	host := u.Hostname()
	if strings.EqualFold(u.Scheme, "mailto") {
		addr, _, _ := strings.Cut(u.Opaque, "?")
		if addr, err = url.PathUnescape(addr); err != nil {
			return "", false
		}
		at := strings.LastIndexByte(addr, '@')
		if at < 0 {
			return "", false
		}
		host = addr[at+1:]
	}
	return queryDomain(host)
}
