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
		if got := ParsePolicy(c.record); got != c.want {
			t.Errorf("ParsePolicy(%q) = %q, want %q", c.record, got, c.want)
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
}
