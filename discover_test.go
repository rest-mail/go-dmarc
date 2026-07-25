package dmarc

import (
	"errors"
	"net"
	"testing"
)

func TestDefaultOrgDomain(t *testing.T) {
	cases := []struct{ in, want string }{
		{"example.test", "example.test"},
		{"sub.example.test", "example.test"},
		{"a.b.c.example.test", "example.test"},
		{"EXAMPLE.TEST", "example.test"},
		{"example.test.", "example.test"},
		{"localhost", "localhost"},
		{"", ""},
	}
	for _, c := range cases {
		if got := DefaultOrgDomain(c.in); got != c.want {
			t.Errorf("DefaultOrgDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDiscover(t *testing.T) {
	// The organizational domain publishes a record whose subdomain policy (sp=)
	// differs from its own policy (p=), so we can tell which one was applied.
	orgResolver := func(name string) ([]string, error) {
		switch name {
		case "_dmarc.example.test":
			return []string{"v=DMARC1; p=reject; sp=quarantine; rua=mailto:agg@example.test"}, nil
		default:
			return []string{"v=spf1 -all"}, nil // no DMARC record anywhere else
		}
	}

	t.Run("exact record applies p=", func(t *testing.T) {
		p, err := Discover("example.test", orgResolver, nil)
		if err != nil {
			t.Fatal(err)
		}
		if p.Record == "" || p.ViaOrgDomain {
			t.Fatalf("expected an exact (non-fallback) match, got %+v", p)
		}
		if p.Domain != "example.test" {
			t.Errorf("Domain = %q, want example.test", p.Domain)
		}
		if p.Requested != "reject" {
			t.Errorf("Requested = %q, want reject (p=)", p.Requested)
		}
	})

	// This is the bug in issue #5: a subdomain with no _dmarc record must fall
	// back to the organizational domain and apply its subdomain policy.
	t.Run("subdomain falls back to org and applies sp=", func(t *testing.T) {
		p, err := Discover("sub.example.test", orgResolver, nil)
		if err != nil {
			t.Fatal(err)
		}
		if p.Record == "" {
			t.Fatal("no policy found for subdomain: DMARC silently not applied (org-domain fallback missing)")
		}
		if !p.ViaOrgDomain {
			t.Error("ViaOrgDomain = false, want true")
		}
		if p.Domain != "example.test" {
			t.Errorf("Domain = %q, want example.test", p.Domain)
		}
		if p.Requested != "quarantine" {
			t.Errorf("Requested = %q, want quarantine (sp=)", p.Requested)
		}
	})

	t.Run("subdomain fallback with no sp= applies p=", func(t *testing.T) {
		resolver := func(name string) ([]string, error) {
			if name == "_dmarc.example.test" {
				return []string{"v=DMARC1; p=reject"}, nil
			}
			return nil, nil
		}
		p, err := Discover("deep.mail.example.test", resolver, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !p.ViaOrgDomain || p.Requested != "reject" {
			t.Errorf("got %+v, want fallback with Requested=reject", p)
		}
	})

	// Issue #11: the discovered policy must carry the record's pct= so a caller
	// can honour a staged rollout instead of enforcing at 100%. Both the exact
	// match and the org-domain fallback expose it; an absent pct= defaults to 100.
	t.Run("exposes pct from an exact record", func(t *testing.T) {
		resolver := func(string) ([]string, error) {
			return []string{"v=DMARC1; p=reject; pct=25"}, nil
		}
		p, err := Discover("example.test", resolver, nil)
		if err != nil {
			t.Fatal(err)
		}
		if p.Pct != 25 {
			t.Errorf("Pct = %d, want 25", p.Pct)
		}
	})

	t.Run("pct defaults to 100 when absent", func(t *testing.T) {
		p, err := Discover("example.test", orgResolver, nil)
		if err != nil {
			t.Fatal(err)
		}
		if p.Pct != 100 {
			t.Errorf("Pct = %d, want 100 (default)", p.Pct)
		}
	})

	t.Run("org-domain fallback exposes pct", func(t *testing.T) {
		resolver := func(name string) ([]string, error) {
			if name == "_dmarc.example.test" {
				return []string{"v=DMARC1; p=reject; sp=quarantine; pct=10"}, nil
			}
			return nil, nil
		}
		p, err := Discover("sub.example.test", resolver, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !p.ViaOrgDomain || p.Pct != 10 {
			t.Errorf("got %+v, want fallback with Pct=10", p)
		}
	})

	t.Run("malformed pct is rejected", func(t *testing.T) {
		resolver := func(string) ([]string, error) {
			return []string{"v=DMARC1; p=reject; pct=150"}, nil
		}
		if _, err := Discover("example.test", resolver, nil); err == nil {
			t.Error("expected an out-of-range pct to surface as an error")
		}
	})

	t.Run("no record anywhere", func(t *testing.T) {
		resolver := func(string) ([]string, error) { return []string{"v=spf1 -all"}, nil }
		p, err := Discover("sub.nodmarc.test", resolver, nil)
		if err != nil {
			t.Fatal(err)
		}
		if p.Record != "" || p.ViaOrgDomain || p.Requested != "none" {
			t.Errorf("got %+v, want empty record / Requested=none", p)
		}
	})

	// Issue #12: RFC 7489 §6.6.3 step 5 — a name publishing more than one
	// v=DMARC1 record has an ambiguous set that is discarded, and discovery
	// terminates with no policy. Because the queried set is non-empty (step 3
	// only falls back to the organizational domain on an *empty* set), this must
	// NOT fall back, even when the org domain publishes a usable policy.
	t.Run("multiple records at the queried domain yield no policy without falling back", func(t *testing.T) {
		resolver := func(name string) ([]string, error) {
			switch name {
			case "_dmarc.sub.example.test":
				return []string{"v=DMARC1; p=reject", "v=DMARC1; p=none"}, nil
			case "_dmarc.example.test":
				return []string{"v=DMARC1; p=reject; sp=quarantine"}, nil
			default:
				return nil, nil
			}
		}
		p, err := Discover("sub.example.test", resolver, nil)
		if err != nil {
			t.Fatalf("ambiguous multi-record set is no-policy, not an error: %v", err)
		}
		if p.Record != "" || p.ViaOrgDomain || p.Requested != "none" {
			t.Errorf("got %+v, want empty record / Requested=none / no org fallback", p)
		}
	})

	// Multiple records at the organizational domain reached through the fallback
	// are likewise discarded: the subdomain ends up with no policy.
	t.Run("multiple records at the org domain yield no policy", func(t *testing.T) {
		resolver := func(name string) ([]string, error) {
			if name == "_dmarc.example.test" {
				return []string{"v=DMARC1; p=reject; sp=quarantine", "v=DMARC1; p=none"}, nil
			}
			return nil, nil // the subdomain itself publishes nothing
		}
		p, err := Discover("sub.example.test", resolver, nil)
		if err != nil {
			t.Fatalf("ambiguous org-domain set is no-policy, not an error: %v", err)
		}
		if p.Record != "" || p.ViaOrgDomain || p.Requested != "none" {
			t.Errorf("got %+v, want empty record / Requested=none", p)
		}
	})

	t.Run("resolver error propagates", func(t *testing.T) {
		wantErr := errors.New("dns timeout")
		resolver := func(string) ([]string, error) { return nil, wantErr }
		if _, err := Discover("sub.example.test", resolver, nil); !errors.Is(err, wantErr) {
			t.Errorf("expected resolver error to propagate, got %v", err)
		}
	})

	// Issue #8: an NXDOMAIN at every name (the usual case for a domain with no
	// DMARC anywhere) must be reported as "no policy", not an error, all the way
	// through the org-domain fallback.
	t.Run("NXDOMAIN everywhere is no policy, not an error", func(t *testing.T) {
		nx := func(string) ([]string, error) {
			return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
		}
		p, err := Discover("sub.nodmarc.test", nx, nil)
		if err != nil {
			t.Fatalf("NXDOMAIN must not surface as an error: %v", err)
		}
		if p.Record != "" || p.ViaOrgDomain || p.Requested != "none" {
			t.Errorf("got %+v, want empty record / Requested=none", p)
		}
	})

	// An NXDOMAIN on the exact subdomain must not short-circuit discovery: the
	// org-domain fallback (issue #5 / PR #17) still has to run and apply sp=.
	t.Run("NXDOMAIN subdomain still falls back to org and applies sp=", func(t *testing.T) {
		resolver := func(name string) ([]string, error) {
			if name == "_dmarc.example.test" {
				return []string{"v=DMARC1; p=reject; sp=quarantine"}, nil
			}
			return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
		}
		p, err := Discover("sub.example.test", resolver, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !p.ViaOrgDomain || p.Domain != "example.test" || p.Requested != "quarantine" {
			t.Errorf("got %+v, want fallback to example.test with Requested=quarantine", p)
		}
	})

	// A transient failure must not be swallowed by the fallback: it has to
	// propagate so the caller can retry instead of failing open.
	t.Run("transient DNS failure propagates through discovery", func(t *testing.T) {
		tempErr := &net.DNSError{Err: "server misbehaving", IsTemporary: true}
		resolver := func(string) ([]string, error) { return nil, tempErr }
		if _, err := Discover("sub.example.test", resolver, nil); !errors.Is(err, tempErr) {
			t.Errorf("expected transient error to propagate, got %v", err)
		}
	})

	// A caller with a real public suffix list plugs it in; the fallback must use
	// the org domain the injected function returns, not the two-label default.
	t.Run("injected org-domain func is honoured", func(t *testing.T) {
		resolver := func(name string) ([]string, error) {
			if name == "_dmarc.example.co.test" {
				return []string{"v=DMARC1; p=reject; sp=reject"}, nil
			}
			return nil, nil
		}
		org := func(string) string { return "example.co.test" }
		p, err := Discover("sub.example.co.test", resolver, org)
		if err != nil {
			t.Fatal(err)
		}
		if !p.ViaOrgDomain || p.Domain != "example.co.test" || p.Requested != "reject" {
			t.Errorf("got %+v, want fallback to example.co.test with Requested=reject", p)
		}
	})
}
