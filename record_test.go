package dmarc

import (
	"errors"
	"net"
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
	}
	for _, c := range cases {
		if got := Aligned(c.auth, c.from); got != c.want {
			t.Errorf("Aligned(%q, %q) = %v, want %v", c.auth, c.from, got, c.want)
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
