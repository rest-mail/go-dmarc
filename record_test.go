package dmarc

import (
	"errors"
	"net"
	"strings"
	"testing"
)

func TestParsePolicy(t *testing.T) {
	cases := []struct{ record, want string }{
		{"v=DMARC1; p=reject; rua=mailto:agg@example.test", "reject"},
		{"v=DMARC1; p=quarantine; pct=50", "quarantine"},
		{"v=DMARC1; p=none", "none"},
		{"v=DMARC1; sp=reject", "none"}, // no p= tag -> default none
		{"", "none"},
	}
	for _, c := range cases {
		got, err := ParsePolicy(c.record)
		if err != nil {
			t.Errorf("ParsePolicy(%q) unexpected error: %v", c.record, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParsePolicy(%q) = %q, want %q", c.record, got, c.want)
		}
	}
}

// Issue #15: a p= value outside the RFC 7489 §6.3 set none/quarantine/reject,
// or a record that carries p= more than once, is malformed. ParsePolicy must
// reject it with an error instead of returning the raw value ("bogus") or a
// first-wins pick from the duplicate — either of which a caller would apply as
// the disposition. §6.6.3 treats a record with no valid p as if none were
// published, which the caller effects by declining to use it.
func TestParsePolicyRejectsInvalid(t *testing.T) {
	rejected := []string{
		"v=DMARC1; p=bogus",              // unrecognised value, previously returned raw
		"v=DMARC1; p=rejct",              // typo of a real value is still invalid
		"v=DMARC1; p=",                   // empty value
		"v=DMARC1; p=none; p=reject",     // duplicate p= (first-wins previously)
		"v=DMARC1; p=reject; p=reject",   // duplicate even with identical values
		"v=DMARC1; P=none; p=quarantine", // duplicate is case-insensitive on the tag name
	}
	for _, record := range rejected {
		if got, err := ParsePolicy(record); err == nil {
			t.Errorf("ParsePolicy(%q) = %q, nil; want an invalid/duplicate error", record, got)
		}
	}

	// A valid value must still parse cleanly (the fix must not over-reject).
	if got, err := ParsePolicy("v=DMARC1; p=reject"); err != nil || got != "reject" {
		t.Errorf("ParsePolicy(valid p=reject) = %q, %v; want reject, nil", got, err)
	}
}

// Issue #14: DMARC tag names are case-insensitive and the enumerated policy
// values none/quarantine/reject are matched case-insensitively (RFC 7489
// §6.3/§6.4 ABNF). A case-sensitive parser silently drops the policy of an
// otherwise-valid record: "P=reject" fails the "p=" prefix test and defaults to
// "none", while "p=REJECT" is returned verbatim so a downstream `== "reject"`
// comparison misses it and the reject policy is not enforced. ParsePolicy must
// recognise the tag regardless of case and normalise the value to lower case.
func TestParsePolicyCaseInsensitive(t *testing.T) {
	cases := []struct{ record, want string }{
		{"v=DMARC1; P=reject", "reject"},         // uppercase tag name
		{"v=DMARC1; p=REJECT", "reject"},         // uppercase value normalised
		{"v=DMARC1; P=Reject", "reject"},         // mixed case, both
		{"v=DMARC1; P=Quarantine", "quarantine"}, // mixed-case quarantine
		{"v=DMARC1; P=NONE", "none"},             // uppercase none
		{"v=dmarc1; p=reject", "reject"},         // lowercase still works
		{"v=DMARC1; p = reject", "reject"},       // WSP around '=' per ABNF
		{"v=DMARC1; sp=reject", "none"},          // sp= is not p=; default none
	}
	for _, c := range cases {
		got, err := ParsePolicy(c.record)
		if err != nil {
			t.Errorf("ParsePolicy(%q) unexpected error: %v", c.record, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParsePolicy(%q) = %q, want %q", c.record, got, c.want)
		}
	}
}

// Issue #11: pct= (RFC 7489 §6.3) sets the percentage of failing messages the
// requested policy is applied to for a staged rollout. It must be parsed and
// exposed (default 100 when absent) so a receiver can sample rather than always
// enforcing at 100%; a value outside 0–100, or a non-integer, is a malformed
// record and is rejected.
func TestParsePct(t *testing.T) {
	valid := []struct {
		record string
		want   int
	}{
		{"v=DMARC1; p=reject; pct=25", 25},
		{"v=DMARC1; p=quarantine; pct=0", 0}, // monitor-only staged rollout
		{"v=DMARC1; p=reject; pct=100", 100}, // explicit full enforcement
		{"v=DMARC1; p=reject", 100},          // absent -> default 100
		{"v=DMARC1; p=reject; pct= 50 ", 50}, // whitespace around the value tolerated
		{"v=DMARC1; p=reject; PCT=25", 25},   // issue #14: tag name is case-insensitive
		{"", 100},                            // empty record -> default 100
	}
	for _, c := range valid {
		got, err := ParsePct(c.record)
		if err != nil {
			t.Errorf("ParsePct(%q) unexpected error: %v", c.record, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParsePct(%q) = %d, want %d", c.record, got, c.want)
		}
	}

	rejected := []string{
		"v=DMARC1; p=reject; pct=101", // above range
		"v=DMARC1; p=reject; pct=-1",  // below range
		"v=DMARC1; p=reject; pct=200",
		"v=DMARC1; p=reject; pct=fifty", // non-integer
		"v=DMARC1; p=reject; pct=",      // empty value
	}
	for _, record := range rejected {
		if got, err := ParsePct(record); err == nil {
			t.Errorf("ParsePct(%q) = %d, nil; want an out-of-range/invalid error", record, got)
		}
	}
}

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

// Issue #10: adkim= / aspf= (RFC 7489 §6.3) select the DKIM and SPF
// identifier-alignment mode — "r" relaxed (the default) or "s" strict. A parser
// that never reads the tags leaves every record relaxed, so a domain that
// publishes strict alignment to defend against a hostile delegated subdomain
// (§10.4) is silently given relaxed semantics. The tag name and value are
// case-insensitive, whitespace around "=" is tolerated, and any value other than
// "s" (including an absent tag or an unknown value) degrades to the relaxed
// default.
func TestParseAlignmentMode(t *testing.T) {
	cases := []struct {
		record      string
		adkim, aspf AlignmentMode
	}{
		{"v=DMARC1; p=reject", AlignmentRelaxed, AlignmentRelaxed}, // absent -> relaxed default
		{"v=DMARC1; p=reject; adkim=r; aspf=r", AlignmentRelaxed, AlignmentRelaxed},
		{"v=DMARC1; p=reject; adkim=s", AlignmentStrict, AlignmentRelaxed}, // aspf still defaults relaxed
		{"v=DMARC1; p=reject; aspf=s", AlignmentRelaxed, AlignmentStrict},
		{"v=DMARC1; p=reject; adkim=s; aspf=s", AlignmentStrict, AlignmentStrict},
		{"v=DMARC1; p=reject; ADKIM=S; ASPF=S", AlignmentStrict, AlignmentStrict}, // case-insensitive name and value
		{"v=DMARC1; p=reject; adkim = s", AlignmentStrict, AlignmentRelaxed},      // WSP around '=' per ABNF
		{"v=DMARC1; p=reject; adkim=x", AlignmentRelaxed, AlignmentRelaxed},       // unknown value -> relaxed default
		{"", AlignmentRelaxed, AlignmentRelaxed},
	}
	for _, c := range cases {
		if got := ParseADKIM(c.record); got != c.adkim {
			t.Errorf("ParseADKIM(%q) = %v, want %v", c.record, got, c.adkim)
		}
		if got := ParseASPF(c.record); got != c.aspf {
			t.Errorf("ParseASPF(%q) = %v, want %v", c.record, got, c.aspf)
		}
	}
}

// Issue #10: AlignedMode must honour the alignment mode. Under strict alignment
// the identifier domain must be an exact FQDN match with the From domain, so a
// delegated subdomain that aligns under relaxed must NOT align under strict.
// This is the reported defect: adkim=s was ignored, so a DKIM signature with
// d=example.com was reported aligned for a From of mail.example.com even though
// the domain opted into strict alignment specifically to reject it.
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
	if mode := ParseADKIM(record); AlignedMode(dkimDomain, fromDomain, mode, nil) {
		t.Errorf("strict: AlignedMode(%q, %q, %v) = true, want false (adkim=s needs exact match)", dkimDomain, fromDomain, mode)
	}
	// An exact match still aligns under strict.
	if !AlignedMode("mail.example.com", "mail.example.com", AlignmentStrict, nil) {
		t.Errorf("strict: an exact FQDN match must align")
	}
}

// Issue #10: aspf=s applies strict alignment to the SPF-authenticated domain.
func TestAlignedModeStrictSPF(t *testing.T) {
	const record = "v=DMARC1; p=reject; aspf=s"
	const spfDomain = "bounce.example.com" // SPF-checked MAIL FROM domain
	const fromDomain = "example.com"       // header From, parent of the SPF domain

	if !AlignedMode(spfDomain, fromDomain, AlignmentRelaxed, nil) {
		t.Fatalf("relaxed: AlignedMode(%q, %q) = false, want true (subdomain of From)", spfDomain, fromDomain)
	}
	if mode := ParseASPF(record); AlignedMode(spfDomain, fromDomain, mode, nil) {
		t.Errorf("strict: AlignedMode(%q, %q, %v) = true, want false (aspf=s needs exact match)", spfDomain, fromDomain, mode)
	}
}

// Issue #10: with no adkim/aspf tag the mode defaults to relaxed, so AlignedMode
// is identical to Aligned/AlignedOrg — existing behaviour is unchanged for
// records that do not opt into strict alignment.
func TestAlignedModeDefaultRelaxed(t *testing.T) {
	const record = "v=DMARC1; p=reject" // no adkim/aspf
	adkim := ParseADKIM(record)         // AlignmentRelaxed
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

// Issue #10: Discover must surface the record's alignment modes so a caller that
// only has the discovered Policy can request the right (possibly strict)
// alignment. A zero Policy (no record) reports the relaxed default.
func TestDiscoverExposesAlignmentMode(t *testing.T) {
	resolver := func(string) ([]string, error) {
		return []string{"v=DMARC1; p=reject; adkim=s; aspf=r"}, nil
	}
	pol, err := Discover("example.test", resolver, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pol.ADKIM != AlignmentStrict {
		t.Errorf("Policy.ADKIM = %v, want strict", pol.ADKIM)
	}
	if pol.ASPF != AlignmentRelaxed {
		t.Errorf("Policy.ASPF = %v, want relaxed", pol.ASPF)
	}
}

func TestLookup(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		resolver := func(name string) ([]string, error) {
			if name != "_dmarc.example.test" {
				t.Fatalf("unexpected lookup name %q", name)
			}
			return []string{"v=spf1 -all", "v=DMARC1; p=reject"}, nil
		}
		rec, err := Lookup("example.test", resolver)
		if err != nil {
			t.Fatal(err)
		}
		if rec != "v=DMARC1; p=reject" {
			t.Errorf("got %q", rec)
		}
	})

	t.Run("no DMARC record", func(t *testing.T) {
		resolver := func(string) ([]string, error) { return []string{"v=spf1 -all"}, nil }
		rec, err := Lookup("example.test", resolver)
		if err != nil {
			t.Fatalf("no-record must not be an error: %v", err)
		}
		if rec != "" {
			t.Errorf("expected empty record, got %q", rec)
		}
	})

	// Issue #12: RFC 7489 §6.6.3 step 5 — if more than one record at the name
	// begins with v=DMARC1, the set is ambiguous and discarded, so the domain is
	// treated as publishing no usable policy. Returning the first record would
	// make the applied policy depend on non-deterministic DNS ordering.
	t.Run("multiple DMARC records are discarded (no policy)", func(t *testing.T) {
		resolver := func(string) ([]string, error) {
			return []string{"v=DMARC1; p=none", "v=DMARC1; p=reject"}, nil
		}
		rec, err := Lookup("example.test", resolver)
		if err != nil {
			t.Fatalf("multiple records is no-policy, not an error: %v", err)
		}
		if rec != "" {
			t.Errorf("expected empty record for an ambiguous multi-record set, got %q", rec)
		}
	})

	// Non-DMARC TXT records at the name are ignored, so exactly one v=DMARC1
	// record alongside unrelated TXT records is still a usable single policy.
	t.Run("one DMARC record among non-DMARC TXT records still applies", func(t *testing.T) {
		resolver := func(string) ([]string, error) {
			return []string{"v=spf1 -all", "v=DMARC1; p=reject", "google-site-verification=abc"}, nil
		}
		rec, err := Lookup("example.test", resolver)
		if err != nil {
			t.Fatal(err)
		}
		if rec != "v=DMARC1; p=reject" {
			t.Errorf("got %q, want the single DMARC record", rec)
		}
	})

	t.Run("resolver error", func(t *testing.T) {
		wantErr := errors.New("dns timeout")
		resolver := func(string) ([]string, error) { return nil, wantErr }
		if _, err := Lookup("example.test", resolver); !errors.Is(err, wantErr) {
			t.Errorf("expected resolver error to propagate, got %v", err)
		}
	})

	// Issue #8: net.LookupTXT returns a *net.DNSError with IsNotFound for a name
	// that does not exist, which is the common case for a domain that simply
	// publishes no DMARC record. That is "no policy" (RFC 7489 §6.6.3), not a
	// lookup failure, and must map to the documented ("", nil).
	t.Run("NXDOMAIN is no-record, not an error", func(t *testing.T) {
		resolver := func(string) ([]string, error) {
			return nil, &net.DNSError{Err: "no such host", Name: "_dmarc.example.test", IsNotFound: true}
		}
		rec, err := Lookup("example.test", resolver)
		if err != nil {
			t.Fatalf("NXDOMAIN must not be an error: %v", err)
		}
		if rec != "" {
			t.Errorf("expected empty record, got %q", rec)
		}
	})

	// A transient failure (SERVFAIL/timeout) is NOT not-found: the caller must be
	// able to tell it apart from no-record so it does not fail open, so it must
	// still surface as an error (temperror).
	t.Run("transient DNS failure surfaces as error", func(t *testing.T) {
		tempErr := &net.DNSError{Err: "server misbehaving", Name: "_dmarc.example.test", IsTemporary: true}
		resolver := func(string) ([]string, error) { return nil, tempErr }
		rec, err := Lookup("example.test", resolver)
		if err == nil {
			t.Fatalf("transient DNS failure must surface as an error, got record %q", rec)
		}
		if !errors.Is(err, tempErr) {
			t.Errorf("expected the transient error to propagate, got %v", err)
		}
	})

	// Issue #13: the v=DMARC1 version tag must match as a complete token per
	// RFC 7489 §6.3 (v is the first tag and its value is exactly "DMARC1") and
	// the §6.4 ABNF (dmarc-version = "v" *WSP "=" *WSP "DMARC1"). A raw prefix
	// match was simultaneously too lax and too strict: it accepted "v=DMARC10"
	// (a distinct, longer token) as a DMARC record, and rejected ABNF-legal
	// forms with whitespace around "=" and a case-insensitive tag name/value.
	// Both defects are exercised in this one test.
	t.Run("version tag matches DMARC1 as a complete token (issue #13)", func(t *testing.T) {
		cases := []struct {
			name   string
			record string
			// want is the Lookup result: the record itself when it is recognized
			// as a DMARC record, or "" when it must be ignored as non-DMARC.
			want string
		}{
			// Too lax: DMARC10 / DMARC1x are different, longer tokens, not the
			// DMARC1 version, so a domain publishing only such a record has no
			// policy.
			{"rejects v=DMARC10", "v=DMARC10; p=none", ""},
			{"rejects v=DMARC1x", "v=DMARC1x; p=none", ""},
			// Too strict: an uppercase tag name, whitespace around "=" and before
			// the separator, and a case-insensitive value are all ABNF-legal and
			// must be accepted.
			{"accepts uppercase tag with WSP before separator", "V=DMARC1 ; p=none", "V=DMARC1 ; p=none"},
			{"accepts whitespace around =", "v = DMARC1; p=none", "v = DMARC1; p=none"},
			{"accepts case-insensitive value", "v=dmarc1; p=none", "v=dmarc1; p=none"},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				resolver := func(string) ([]string, error) { return []string{c.record}, nil }
				rec, err := Lookup("example.test", resolver)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if rec != c.want {
					t.Errorf("Lookup with record %q = %q, want %q", c.record, rec, c.want)
				}
			})
		}
	})
}
