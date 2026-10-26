package dmarc

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/rest-mail/go-dmarc/pkg/dmarc/internal/dnsname"
)

// alignZone publishes the DMARC records the alignment tests need: one
// Organizational Domain each for example.test, example.com, example.co.uk
// and münchen.de, a few lookalikes with their own, and a PSD record at co.uk.
func alignZone() *zone {
	return dmarcZone(map[string]string{
		"example.test":      "v=DMARC1; p=reject",
		"evil-example.test": "v=DMARC1; p=none",
		"notexample.test":   "v=DMARC1; p=none",
		"evil.test":         "v=DMARC1; p=none",
		"example.com":       "v=DMARC1; p=reject",
		"example.co.uk":     "v=DMARC1; p=reject",
		"co.uk":             "v=DMARC1; p=none; psd=y",
		"xn--mnchen-3ya.de": "v=DMARC1; p=reject",
		"xn--kln-sna.de":    "v=DMARC1; p=reject",
	})
}

// aligned is AlignedMode in relaxed mode over alignZone, failing the test on
// a DNS error.
func aligned(t *testing.T, auth, from string) bool {
	t.Helper()
	ok, err := AlignedMode(auth, from, AlignmentRelaxed, alignZone().lookup)
	if err != nil {
		t.Fatalf("AlignedMode(%q, %q): %v", auth, from, err)
	}
	return ok
}

// TestAligned checks relaxed alignment: the Author Domain and the
// Authenticated Identifier have the same Organizational Domain (RFC 9989
// §4.4), found by a DNS Tree Walk for each.
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

		// Issue #9: relaxed alignment compares Organizational Domains, not
		// raw suffixes. Sibling subdomains that share one must align (a
		// suffix test rejects them, quarantining legitimate ESP mail)...
		{"em.example.test", "mail.example.test", true},
		{"mail.example.test", "em.example.test", true},
		{"a.b.example.test", "c.d.example.test", true},
		// ...and a domain that is a public suffix (d=<TLD>) must never align
		// with a From domain registered under it.
		{"test", "mail.example.test", false},
		{"mail.example.test", "test", false},
		// Lookalikes share a textual suffix but no Organizational Domain.
		{"evil-example.test", "example.test", false},
		{"notexample.test", "mail.example.test", false},
	}
	for _, c := range cases {
		if got := aligned(t, c.auth, c.from); got != c.want {
			t.Errorf("AlignedMode(%q, %q, relaxed) = %v, want %v", c.auth, c.from, got, c.want)
		}
	}
}

// Issue #16: alignment must sanitize its inputs before comparing (RFC 9989
// §4.4). An empty identifier means "no authenticated domain" and must never
// align — two empty strings comparing equal would be a false DMARC pass. A
// single trailing (root) dot denotes the same name and must be ignored. And a
// domain written as a Unicode U-label must align with its equivalent xn--
// A-label, since they are one domain in two encodings.
//
// checklist: DMARC-ALIGN-01
func TestAlignedSanitizesInputs(t *testing.T) {
	cases := []struct {
		name       string
		auth, from string
		want       bool
	}{
		{"both empty", "", "", false},
		{"auth empty", "", "example.com", false},
		{"from empty", "example.com", "", false},
		{"root dot only", ".", ".", false},

		{"trailing dot on from", "example.com", "example.com.", true},
		{"trailing dot on auth", "example.com.", "example.com", true},
		{"trailing dot both", "example.com.", "example.com.", true},
		{"trailing dot relaxed", "mail.example.com.", "shop.example.com", true},

		{"u-label vs a-label", "münchen.de", "xn--mnchen-3ya.de", true},
		{"a-label vs u-label", "xn--mnchen-3ya.de", "münchen.de", true},
		{"u-label both", "münchen.de", "münchen.de", true},
		{"u-label case fold", "MÜNCHEN.de", "xn--mnchen-3ya.de", true},
		{"u-label relaxed siblings", "mail.münchen.de", "shop.münchen.de", true},
		{"mixed encoding relaxed", "mail.xn--mnchen-3ya.de", "shop.münchen.de", true},
		{"distinct u-labels", "münchen.de", "köln.de", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := aligned(t, c.auth, c.from); got != c.want {
				t.Errorf("AlignedMode(%q, %q, relaxed) = %v, want %v", c.auth, c.from, got, c.want)
			}
		})
	}
}

// TestAlignedModeTreeWalk checks relaxed alignment under a multi-label public
// suffix, which the DNS Tree Walk tells apart by the PSD's psd=y record
// (RFC 9989 §4.10.2), and that a public suffix aligns with no other domain.
// Only differing names in relaxed mode send queries.
//
// checklist: DMARC-ALIGN-02 DMARC-ALIGN-04 DMARC-ORG-02
func TestAlignedModeTreeWalk(t *testing.T) {
	cases := []struct {
		auth, from string
		want       bool
	}{
		{"a.example.co.uk", "b.example.co.uk", true}, // siblings under co.uk
		{"example.co.uk", "sub.example.co.uk", true}, // parent and child
		{"foo.co.uk", "co.uk", false},                // issue #9: *.co.uk vs co.uk
		{"foo.co.uk", "bar.co.uk", false},            // different registrants
		{"com", "mail.example.com", false},           // d=com never aligns
		{"co.uk", "com", false},                      // two public suffixes
	}
	for _, c := range cases {
		if got := aligned(t, c.auth, c.from); got != c.want {
			t.Errorf("AlignedMode(%q, %q, relaxed) = %v, want %v", c.auth, c.from, got, c.want)
		}
	}

	z := alignZone()
	if ok, err := AlignedMode("bounce.example.com", "example.com", AlignmentRelaxed, z.lookup); !ok || err != nil {
		t.Fatalf("AlignedMode = %v, %v", ok, err)
	}
	want := []string{"_dmarc.bounce.example.com", "_dmarc.example.com", "_dmarc.com", "_dmarc.example.com", "_dmarc.com"}
	if !reflect.DeepEqual(z.queried, want) {
		t.Errorf("queried %q, want a walk from each name %q", z.queried, want)
	}
	z.queried = nil
	for _, mode := range []AlignmentMode{AlignmentRelaxed, AlignmentStrict} {
		if ok, err := AlignedMode("Example.com", "example.com.", mode, z.lookup); !ok || err != nil {
			t.Errorf("%v: AlignedMode of one name = %v, %v", mode, ok, err)
		}
	}
	if ok, err := AlignedMode("bounce.example.com", "example.com", AlignmentStrict, z.lookup); ok || err != nil {
		t.Errorf("strict: AlignedMode = %v, %v", ok, err)
	}
	if len(z.queried) != 0 {
		t.Errorf("identical names or strict mode queried %q", z.queried)
	}

	// A DNS error during either walk is returned.
	temp := errors.New("timeout")
	for _, name := range []string{"_dmarc.mail.example.test", "_dmarc.example.com"} {
		z := alignZone()
		z.errs = map[string]error{name: temp}
		if _, err := AlignedMode("mail.example.test", "example.com", AlignmentRelaxed, z.lookup); !errors.Is(err, temp) {
			t.Errorf("an error at %s: AlignedMode error = %v, want %v", name, err, temp)
		}
	}
}

// TestOrgDomain checks how the Organizational Domain is chosen from what a
// DNS Tree Walk from the domain finds (RFC 9989 §4.10.2), with the examples
// of that section.
//
// checklist: DMARC-ORG-01 DMARC-ORG-02
func TestOrgDomain(t *testing.T) {
	cases := []struct {
		name    string
		domain  string
		records map[string]string
		want    string
	}{
		{"§4.10.2: records at mail.example.com and example.com", "a.mail.example.com",
			map[string]string{"mail.example.com": "v=DMARC1; p=none", "example.com": "v=DMARC1; p=none"}, "example.com"},
		{"§4.10.2: psd=n at mail.example.com", "a.mail.example.com",
			map[string]string{"mail.example.com": "v=DMARC1; p=none; psd=n", "example.com": "v=DMARC1; p=none"}, "mail.example.com"},
		{"§4.10.2: psd=y at example.com", "mail.example.com",
			map[string]string{"example.com": "v=DMARC1; p=none; psd=y"}, "mail.example.com"},
		{"psd=y at com only", "a.mail.example.com",
			map[string]string{"com": "v=DMARC1; p=none; psd=y"}, "example.com"},
		{"psd=n at the domain itself", "a.mail.example.com",
			map[string]string{"a.mail.example.com": "v=DMARC1; p=none; psd=n", "example.com": "v=DMARC1; p=none"}, "a.mail.example.com"},
		{"psd=y at the domain itself is not used", "co.uk",
			map[string]string{"co.uk": "v=DMARC1; p=none; psd=y"}, "co.uk"},
		{"no record: the domain itself", "a.mail.example.com", nil, "a.mail.example.com"},
		{"a record without a valid policy still counts", "a.example.com",
			map[string]string{"example.com": "v=DMARC1; psd=n"}, "example.com"},
	}
	for _, c := range cases {
		z := dmarcZone(c.records)
		if got, err := OrgDomain(c.domain, z.lookup); err != nil || got != c.want {
			t.Errorf("%s: OrgDomain(%q) = %q, %v; want %q", c.name, c.domain, got, err, c.want)
		}
		if z.queried[0] != "_dmarc."+dnsname.NormalizeDomain(c.domain) {
			t.Errorf("%s: the walk started at %s, not the domain", c.name, z.queried[0])
		}
	}

	// Several records at a name are none, so they neither stop the walk nor
	// count.
	z := &zone{records: map[string][]string{
		"_dmarc.mail.example.com": {"v=DMARC1; p=none; psd=n", "v=DMARC1; p=reject; psd=n"},
		"_dmarc.example.com":      {"v=DMARC1; p=none"},
	}}
	if got, err := OrgDomain("a.mail.example.com", z.lookup); err != nil || got != "example.com" {
		t.Errorf("several records: OrgDomain = %q, %v; want example.com", got, err)
	}

	if got, err := OrgDomain("a..b", z.lookup); got != "" || err != nil {
		t.Errorf("OrgDomain of a non-domain = %q, %v", got, err)
	}
	temp := errors.New("timeout")
	z = &zone{errs: map[string]error{"_dmarc.example.com": temp}}
	if _, err := OrgDomain("mail.example.com", z.lookup); !errors.Is(err, temp) {
		t.Errorf("OrgDomain error = %v, want %v", err, temp)
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

	if !aligned(t, dkimDomain, fromDomain) {
		t.Fatalf("relaxed: AlignedMode(%q, %q) = false, want true (share org domain)", dkimDomain, fromDomain)
	}
	if mode := mustParse(t, record).ADKIM; mustAlign(t, dkimDomain, fromDomain, mode) {
		t.Errorf("strict: AlignedMode(%q, %q, %v) = true, want false (adkim=s needs exact match)", dkimDomain, fromDomain, mode)
	}
	if !mustAlign(t, "mail.example.com", "mail.example.com", AlignmentStrict) {
		t.Errorf("strict: an exact FQDN match must align")
	}
}

// mustAlign is AlignedMode over alignZone, failing the test on a DNS error.
func mustAlign(t *testing.T, auth, from string, mode AlignmentMode) bool {
	t.Helper()
	ok, err := AlignedMode(auth, from, mode, alignZone().lookup)
	if err != nil {
		t.Fatalf("AlignedMode(%q, %q, %v): %v", auth, from, mode, err)
	}
	return ok
}

// Issue #10: aspf=s applies strict alignment to the SPF-authenticated domain.
//
// checklist: DMARC-ALIGN-03
func TestAlignedModeStrictSPF(t *testing.T) {
	const record = "v=DMARC1; p=reject; aspf=s"
	const spfDomain = "bounce.example.com" // SPF-checked MAIL FROM domain
	const fromDomain = "example.com"       // header From, parent of the SPF domain

	if !aligned(t, spfDomain, fromDomain) {
		t.Fatalf("relaxed: AlignedMode(%q, %q) = false, want true (subdomain of From)", spfDomain, fromDomain)
	}
	if mode := mustParse(t, record).ASPF; mustAlign(t, spfDomain, fromDomain, mode) {
		t.Errorf("strict: AlignedMode(%q, %q, %v) = true, want false (aspf=s needs exact match)", spfDomain, fromDomain, mode)
	}
}

// Issue #10: with no adkim/aspf tag the mode defaults to relaxed.
//
// checklist: DMARC-ALIGN-02 DMARC-REC-10
func TestAlignedModeDefaultRelaxed(t *testing.T) {
	adkim := mustParse(t, "v=DMARC1; p=reject").ADKIM
	cases := []struct {
		auth, from string
		want       bool
	}{
		{"em.example.test", "mail.example.test", true},
		{"mail.example.test", "example.test", true},
		{"evil-example.test", "example.test", false},
	}
	for _, c := range cases {
		if got := mustAlign(t, c.auth, c.from, adkim); got != c.want {
			t.Errorf("AlignedMode(%q, %q, relaxed) = %v, want %v", c.auth, c.from, got, c.want)
		}
	}
}

// TestAlignedRejectsNonDomains checks that strings that are not DNS names
// never align, not even with themselves, in either mode, and send no query.
//
// checklist: DMARC-ALIGN-01
func TestAlignedRejectsNonDomains(t *testing.T) {
	z := alignZone()
	for _, s := range []string{"..", ".example.com", "a..b", "exa mple.com", "a/b.com", strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 127) + "com", strings.Repeat("ü", 1<<19) + ".com"} {
		for _, mode := range []AlignmentMode{AlignmentRelaxed, AlignmentStrict} {
			if ok, err := AlignedMode(s, s, mode, z.lookup); ok || err != nil {
				t.Errorf("AlignedMode(%q, %q, %v) = %v, %v; want false", s, s, mode, ok, err)
			}
		}
	}
	if len(z.queried) != 0 {
		t.Errorf("queried %q", z.queried)
	}
	if s := strings.Repeat("a.", 125) + "com"; !aligned(t, s, s) {
		t.Errorf("a 253-character name must align with itself")
	}
	if AlignmentMode(7).String() != "AlignmentMode(7)" || AlignmentStrict.String() != "strict" || AlignmentRelaxed.String() != "relaxed" {
		t.Errorf("AlignmentMode.String")
	}
}
