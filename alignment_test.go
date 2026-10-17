package dmarc

import (
	"strings"
	"testing"
	"time"
)

// TestAligned checks relaxed alignment with the default org-domain heuristic.
//
// checklist: DMARC-ALIGN-01 DMARC-ALIGN-02
func TestAligned(t *testing.T) {
	cases := []struct {
		auth, from string
		want       bool
	}{
		{"example.test", "example.test", true},      // exact
		{"Example.Test", "example.test", true},      // case-insensitive
		{"mail.example.test", "example.test", true}, // auth is subdomain of from
		{"example.test", "mail.example.test", true}, // from is subdomain of auth
		{"evil.test", "example.test", false},        // unrelated
		{"notexample.test", "example.test", false},  // suffix but not a subdomain boundary

		// Issue #9: relaxed alignment compares Organizational Domains
		// (RFC 7489 §3.1), not raw suffixes.
		//
		// Fail-closed defect: sibling subdomains that share an organizational
		// domain must align. A naive suffix test rejects these (neither is a
		// suffix of the other), quarantining legitimate ESP mail.
		{"em.example.test", "mail.example.test", true}, // siblings share example.test
		{"mail.example.test", "em.example.test", true}, // symmetric
		{"a.b.example.test", "c.d.example.test", true}, // deeper siblings
		// Fail-open defect: an authenticated domain that is itself a public
		// suffix (the RFC's own d=<TLD> counter-example) must never align with a
		// From domain registered under it.
		{"test", "mail.example.test", false}, // d=test (TLD) never aligns
		{"mail.example.test", "test", false}, // symmetric
		// Lookalike domains sharing a textual suffix but not a label boundary or
		// organizational domain must not align.
		{"evil-example.test", "example.test", false},    // hyphenated lookalike
		{"notexample.test", "mail.example.test", false}, // different org domain
	}
	for _, c := range cases {
		if got := Aligned(c.auth, c.from); got != c.want {
			t.Errorf("Aligned(%q, %q) = %v, want %v", c.auth, c.from, got, c.want)
		}
	}
}

// Issue #16: Aligned must sanitize its inputs before comparing (RFC 7489 §3.1).
// An empty identifier means "no authenticated domain" and must never align — two
// empty strings comparing equal would be a false DMARC pass. A single trailing
// (root) dot denotes the same name and must be ignored. And a domain written as a
// Unicode U-label must align with its equivalent xn-- A-label, since they are one
// domain in two encodings; comparing raw strings would spuriously fail (or, once
// org-domains are compared, spuriously match) on encoding form alone.
//
// checklist: DMARC-ALIGN-01
func TestAlignedSanitizesInputs(t *testing.T) {
	cases := []struct {
		name       string
		auth, from string
		want       bool
	}{
		// Empty inputs are absent identifiers, never an alignment. Raw "" == ""
		// would report aligned — a false pass on empty input.
		{"both empty", "", "", false},
		{"auth empty", "", "example.com", false},
		{"from empty", "example.com", "", false},
		{"root dot only", ".", ".", false}, // reduces to empty after trimming

		// A single trailing dot is the FQDN root and denotes the same name.
		{"trailing dot on from", "example.com", "example.com.", true},
		{"trailing dot on auth", "example.com.", "example.com", true},
		{"trailing dot both", "example.com.", "example.com.", true},
		{"trailing dot relaxed", "mail.example.com.", "shop.example.com", true},

		// A Unicode domain and its punycode A-label are the same domain.
		{"u-label vs a-label", "münchen.de", "xn--mnchen-3ya.de", true},
		{"a-label vs u-label", "xn--mnchen-3ya.de", "münchen.de", true},
		{"u-label both", "münchen.de", "münchen.de", true},
		{"u-label case fold", "MÜNCHEN.de", "xn--mnchen-3ya.de", true},
		{"u-label relaxed siblings", "mail.münchen.de", "shop.münchen.de", true},
		{"mixed encoding relaxed", "mail.xn--mnchen-3ya.de", "shop.münchen.de", true},
		// Distinct Unicode domains still must not align.
		{"distinct u-labels", "münchen.de", "köln.de", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Aligned(c.auth, c.from); got != c.want {
				t.Errorf("Aligned(%q, %q) = %v, want %v", c.auth, c.from, got, c.want)
			}
		})
	}
}

// TestAlignedOrg exercises the injectable public-suffix hook. The registry-free
// DefaultOrgDomain used by Aligned cannot see multi-label public suffixes such
// as co.uk (it would treat "co.uk" itself as an organizational domain), so a
// PSL-backed OrgDomainFunc is required to get those cases right. Callers plug in
// golang.org/x/net/publicsuffix; the test uses an equivalent minimal fake to
// keep the package dependency-free.
//
// checklist: DMARC-ALIGN-02 DMARC-ALIGN-04
func TestAlignedOrg(t *testing.T) {
	// fakePSL mimics a PSL-backed OrgDomainFunc: it returns the registrable
	// domain (public suffix + one label) or "" when the input is itself a
	// public suffix. It knows co.uk is a two-label public suffix.
	fakePSL := func(domain string) string {
		domain = strings.ToLower(strings.TrimSuffix(domain, "."))
		labels := strings.Split(domain, ".")
		for _, suf := range []string{"co.uk", "uk", "com", "test"} { // longest first
			sl := strings.Split(suf, ".")
			if len(labels) < len(sl) {
				continue
			}
			if strings.Join(labels[len(labels)-len(sl):], ".") == suf {
				if len(labels) == len(sl) {
					return "" // domain is itself a public suffix
				}
				return strings.Join(labels[len(labels)-len(sl)-1:], ".")
			}
		}
		return DefaultOrgDomain(domain)
	}

	cases := []struct {
		auth, from string
		org        OrgDomainFunc
		want       bool
	}{
		// Multi-label public suffix: only a shared registrable domain aligns.
		{"a.example.co.uk", "b.example.co.uk", fakePSL, true}, // siblings under co.uk
		{"example.co.uk", "sub.example.co.uk", fakePSL, true}, // parent/child
		{"foo.co.uk", "co.uk", fakePSL, false},                // issue #9 fail-open: *.co.uk vs co.uk
		{"foo.co.uk", "bar.co.uk", fakePSL, false},            // different registrable domains
		{"com", "mail.example.com", fakePSL, false},           // d=com never aligns (RFC counter-example)
		{"co.uk", "com", fakePSL, false},                      // two public suffixes never align
		// A nil hook falls back to DefaultOrgDomain (same as Aligned).
		{"em.example.test", "mail.example.test", nil, true}, // siblings via default heuristic
		{"test", "mail.example.test", nil, false},           // public suffix via default heuristic
	}
	for _, c := range cases {
		if got := AlignedOrg(c.auth, c.from, c.org); got != c.want {
			t.Errorf("AlignedOrg(%q, %q, org) = %v, want %v", c.auth, c.from, got, c.want)
		}
	}
}

// Issue #10: AlignedMode must honour the alignment mode. Under strict alignment
// the identifier domain must be an exact FQDN match with the From domain, so a
// delegated subdomain that aligns under relaxed must NOT align under strict.
// This is the reported defect: adkim=s was ignored, so a DKIM signature with
// d=example.com was reported aligned for a From of mail.example.com even though
// the domain opted into strict alignment specifically to reject it.
//
// checklist: DMARC-ALIGN-03
func TestAlignedModeStrictDKIM(t *testing.T) {
	const record = "v=DMARC1; p=reject; adkim=s"
	const dkimDomain = "example.com"      // DKIM d=
	const fromDomain = "mail.example.com" // header From, a subdomain of d=

	// Relaxed: the two share organizational domain example.com and align.
	if !AlignedMode(dkimDomain, fromDomain, AlignmentRelaxed, nil) {
		t.Fatalf("relaxed: AlignedMode(%q, %q) = false, want true (share org domain)", dkimDomain, fromDomain)
	}
	// Strict, parsed from adkim=s: an exact FQDN match is required, so the
	// subdomain does not align.
	if mode := mustParse(t, record).ADKIM; AlignedMode(dkimDomain, fromDomain, mode, nil) {
		t.Errorf("strict: AlignedMode(%q, %q, %v) = true, want false (adkim=s needs exact match)", dkimDomain, fromDomain, mode)
	}
	// An exact match still aligns under strict.
	if !AlignedMode("mail.example.com", "mail.example.com", AlignmentStrict, nil) {
		t.Errorf("strict: an exact FQDN match must align")
	}
}

// Issue #10: aspf=s applies strict alignment to the SPF-authenticated domain.
//
// checklist: DMARC-ALIGN-03
func TestAlignedModeStrictSPF(t *testing.T) {
	const record = "v=DMARC1; p=reject; aspf=s"
	const spfDomain = "bounce.example.com" // SPF-checked MAIL FROM domain
	const fromDomain = "example.com"       // header From, parent of the SPF domain

	if !AlignedMode(spfDomain, fromDomain, AlignmentRelaxed, nil) {
		t.Fatalf("relaxed: AlignedMode(%q, %q) = false, want true (subdomain of From)", spfDomain, fromDomain)
	}
	if mode := mustParse(t, record).ASPF; AlignedMode(spfDomain, fromDomain, mode, nil) {
		t.Errorf("strict: AlignedMode(%q, %q, %v) = true, want false (aspf=s needs exact match)", spfDomain, fromDomain, mode)
	}
}

// Issue #10: with no adkim/aspf tag the mode defaults to relaxed, so AlignedMode
// is identical to Aligned/AlignedOrg — existing behaviour is unchanged for
// records that do not opt into strict alignment.
//
// checklist: DMARC-ALIGN-02 DMARC-REC-10
func TestAlignedModeDefaultRelaxed(t *testing.T) {
	const record = "v=DMARC1; p=reject" // no adkim/aspf
	adkim := mustParse(t, record).ADKIM // AlignmentRelaxed
	cases := []struct {
		auth, from string
		want       bool
	}{
		{"em.example.test", "mail.example.test", true}, // siblings align under relaxed
		{"mail.example.test", "example.test", true},    // subdomain aligns under relaxed
		{"evil-example.test", "example.test", false},   // lookalike never aligns
	}
	for _, c := range cases {
		got := AlignedMode(c.auth, c.from, adkim, nil)
		if got != c.want {
			t.Errorf("AlignedMode(%q, %q, relaxed) = %v, want %v", c.auth, c.from, got, c.want)
		}
		if got != Aligned(c.auth, c.from) {
			t.Errorf("AlignedMode relaxed default must equal Aligned for %q/%q", c.auth, c.from)
		}
	}
}

// TestAlignedRejectsNonDomains checks that strings that are not DNS names
// never align, not even with themselves, in either mode.
//
// checklist: DMARC-ALIGN-01
func TestAlignedRejectsNonDomains(t *testing.T) {
	for _, s := range []string{"..", ".example.com", "a..b", "exa mple.com", "a/b.com", strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 127) + "com"} {
		for _, mode := range []AlignmentMode{AlignmentRelaxed, AlignmentStrict} {
			if AlignedMode(s, s, mode, nil) {
				t.Errorf("AlignedMode(%q, %q, %v) = true, want false", s, s, mode)
			}
		}
	}
	if s := strings.Repeat("a.", 125) + "com"; !Aligned(s, s) {
		t.Errorf("a 253-character name must align with itself")
	}
	if AlignmentMode(7).String() != "AlignmentMode(7)" || AlignmentStrict.String() != "strict" || AlignmentRelaxed.String() != "relaxed" {
		t.Errorf("AlignmentMode.String")
	}
}

// TestLongNamesRefusedQuickly checks that a name too long to be a DNS name is
// refused before it is punycode-encoded, whose time is quadratic in the
// label's length: a megabyte of Unicode in a From domain once took minutes.
//
// checklist: DMARC-DISC-15
func TestLongNamesRefusedQuickly(t *testing.T) {
	long := strings.Repeat("ü", 1<<19) + ".com"
	start := time.Now()
	if Aligned(long, long) || AlignedMode(long, "example.com", AlignmentStrict, nil) {
		t.Error("an over-long name aligned")
	}
	if _, ok := queryDomain(strings.Repeat("ü", 255)); ok {
		t.Error("a 255-code-point name is a domain")
	}
	if got := labelToASCII(strings.Repeat("ü", 64)); got != strings.Repeat("ü", 64) {
		t.Errorf("a 64-code-point label was encoded to %q", got)
	}
	if got := labelToASCII(strings.Repeat("ü", 63)); !strings.HasPrefix(got, "xn--") {
		t.Errorf("a 63-code-point label encodes to %q", got)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
}
