package dmarc

import (
	"errors"
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
}
