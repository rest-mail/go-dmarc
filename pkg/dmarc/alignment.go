package dmarc

import (
	"strconv"

	"github.com/rest-mail/go-dmarc/pkg/dmarc/internal/dnsname"
)

// AlignmentMode is the DMARC identifier-alignment mode a record requests through
// its adkim= / aspf= tag (RFC 9989 §4.7): relaxed (the default) or strict.
type AlignmentMode int

const (
	// AlignmentRelaxed is DMARC relaxed alignment (adkim=r / aspf=r — the default
	// applied when the tag is absent). Two identifiers align when their
	// Organizational Domains are equal, so sibling and parent/child subdomains of
	// one organizational domain align. It is the zero value, so a zero-valued
	// [Policy] (no published record) reports the correct default.
	AlignmentRelaxed AlignmentMode = iota
	// AlignmentStrict is DMARC strict alignment (adkim=s / aspf=s). The two
	// identifier domains must be an exact, case-insensitive FQDN match; a
	// subdomain of the From domain does NOT align.
	AlignmentStrict
)

// String returns "relaxed" or "strict"; any other value renders as
// AlignmentMode(<n>).
func (m AlignmentMode) String() string {
	switch m {
	case AlignmentRelaxed:
		return "relaxed"
	case AlignmentStrict:
		return "strict"
	default:
		return "AlignmentMode(" + strconv.Itoa(int(m)) + ")"
	}
}

// AlignedMode reports whether an Authenticated Identifier, authDomain (an SPF
// smtp.mailfrom domain or a verified DKIM signature's d=), is in alignment
// with the Author Domain, fromDomain, under the record's adkim= or aspf= mode
// (RFC 9989 §4.4): identical names under [AlignmentStrict], and names with
// the same Organizational Domain under [AlignmentRelaxed]. The Organizational
// Domains come from a DNS Tree Walk for each name ([OrgDomain], §4.10.2),
// which is only sent when the two names differ and the mode is relaxed.
//
// Both names are compared in their lower-case A-label form, without a root
// dot (§4.4: comparisons are case-insensitive). An empty identifier, or one
// that is not a DNS name, never aligns, so two empty inputs cannot compare
// equal into a false pass. A name that is itself a public suffix with no
// record of its own (d=com, say) is its own Organizational Domain, so it
// aligns with no other. resolver may be nil, for system DNS; its errors are
// returned, and the caller decides whether to fail open or closed.
func AlignedMode(authDomain, fromDomain string, mode AlignmentMode, resolver TXTResolver) (bool, error) {
	authDomain, authOK := dnsname.QueryDomain(authDomain)
	fromDomain, fromOK := dnsname.QueryDomain(fromDomain)
	if !authOK || !fromOK {
		return false, nil
	}
	if authDomain == fromDomain {
		return true, nil
	}
	if mode == AlignmentStrict {
		return false, nil
	}
	authOrg, err := OrgDomain(authDomain, resolver)
	if err != nil {
		return false, err
	}
	fromOrg, err := OrgDomain(fromDomain, resolver)
	if err != nil {
		return false, err
	}
	return authOrg == fromOrg, nil
}
