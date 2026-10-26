package dmarc

import (
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
)

// zone is a fake DNS: the TXT records at each name, the errors some names
// answer with, and every name asked for, in order.
type zone struct {
	records map[string][]string
	errs    map[string]error
	queried []string
}

func (z *zone) lookup(name string) ([]string, error) {
	z.queried = append(z.queried, name)
	if err := z.errs[name]; err != nil {
		return nil, err
	}
	return z.records[name], nil
}

// dmarcZone serves one DMARC record at _dmarc.<domain> for each domain given.
func dmarcZone(records map[string]string) *zone {
	z := &zone{records: map[string][]string{}}
	for domain, rec := range records {
		z.records["_dmarc."+domain] = []string{rec}
	}
	return z
}

// Issue #14: the subdomain policy tag (sp=) shares the case-insensitivity rules
// of p= — the tag name matches regardless of case and the enumerated value is
// normalised to lower case, so an org record like "v=DMARC1; p=reject;
// SP=Quarantine" applies "quarantine" to subdomains rather than silently
// dropping the sp= tag and falling back to p=.
//
// checklist: DMARC-DISC-10 DMARC-REC-17 DMARC-REC-09
func TestDiscoverSubdomainPolicyCaseInsensitive(t *testing.T) {
	cases := []struct{ record, want string }{
		{"v=DMARC1; p=reject; SP=quarantine", "quarantine"}, // uppercase tag name
		{"v=DMARC1; p=reject; sp=QUARANTINE", "quarantine"}, // uppercase value normalised
		{"v=DMARC1; p=reject; Sp=Reject", "reject"},         // mixed case, both
		{"v=DMARC1; P=Reject", "reject"},                    // no sp= -> falls back to p= (also case-insensitive)
		{"v=DMARC1; p=reject; sp=none", "none"},             // lowercase still works
	}
	for _, c := range cases {
		z := dmarcZone(map[string]string{"example.test": c.record})
		p, err := Discover("sub.example.test", z.lookup, nil)
		if err != nil || !p.Inherited || p.Requested != c.want {
			t.Errorf("Discover with org record %q = %+v, %v; want Requested %q", c.record, p, err, c.want)
		}
	}
}

// TestDiscover checks policy discovery (RFC 9989 §4.10.1): the Author
// Domain's own record, else the record the DNS Tree Walk finds above it, with
// no record, several records, NXDOMAIN and DNS errors.
//
// checklist: DMARC-DISC-02 DMARC-DISC-03 DMARC-DISC-08 DMARC-DISC-09 DMARC-DISC-10 DMARC-REC-09
func TestDiscover(t *testing.T) {
	t.Run("the Author Domain's record applies p=, with one query", func(t *testing.T) {
		z := dmarcZone(map[string]string{"example.test": "v=DMARC1; p=reject; sp=none", "test": "v=DMARC1; p=none"})
		p, err := Discover("example.test", z.lookup, nil)
		if err != nil || p.Domain != "example.test" || p.Requested != "reject" || p.Applied != "reject" || p.Inherited || p.PSD {
			t.Errorf("Discover = %+v, %v", p, err)
		}
		if !reflect.DeepEqual(z.queried, []string{"_dmarc.example.test"}) {
			t.Errorf("queried %q", z.queried)
		}
	})

	t.Run("a subdomain gets the record above it, and its sp=", func(t *testing.T) {
		z := dmarcZone(map[string]string{"example.test": "v=DMARC1; p=reject; sp=quarantine"})
		p, err := Discover("mail.example.test", z.lookup, nil)
		if err != nil || p.Domain != "example.test" || p.Requested != "quarantine" || !p.Inherited || p.Raw != "v=DMARC1; p=reject; sp=quarantine" {
			t.Errorf("Discover = %+v, %v", p, err)
		}
		if want := []string{"_dmarc.mail.example.test", "_dmarc.example.test", "_dmarc.test"}; !reflect.DeepEqual(z.queried, want) {
			t.Errorf("queried %q, want %q", z.queried, want)
		}
	})

	t.Run("with no sp= a subdomain gets p=", func(t *testing.T) {
		z := dmarcZone(map[string]string{"example.test": "v=DMARC1; p=reject"})
		if p, err := Discover("a.b.example.test", z.lookup, nil); err != nil || p.Requested != "reject" || !p.Inherited {
			t.Errorf("Discover = %+v, %v", p, err)
		}
	})

	t.Run("exposes the alignment modes", func(t *testing.T) {
		z := dmarcZone(map[string]string{"example.test": "v=DMARC1; p=reject; adkim=s; aspf=r"})
		p, err := Discover("example.test", z.lookup, nil)
		if err != nil || p.Record.ADKIM != AlignmentStrict || p.Record.ASPF != AlignmentRelaxed {
			t.Errorf("Discover = %+v, %v", p, err)
		}
	})

	t.Run("no record anywhere is no policy", func(t *testing.T) {
		z := &zone{records: map[string][]string{"_dmarc.mail.example.test": {"v=spf1 -all"}}}
		p, err := Discover("mail.example.test", z.lookup, nil)
		if err != nil || p.Raw != "" || p.Requested != "none" || p.Applied != "none" || p.Inherited {
			t.Errorf("Discover = %+v, %v", p, err)
		}
		if want := []string{"_dmarc.mail.example.test", "_dmarc.example.test", "_dmarc.test"}; !reflect.DeepEqual(z.queried, want) {
			t.Errorf("queried %q, want %q", z.queried, want)
		}
	})

	t.Run("several records at the Author Domain are none, so the walk goes on", func(t *testing.T) {
		z := &zone{records: map[string][]string{
			"_dmarc.mail.example.test": {"v=DMARC1; p=none", "v=DMARC1; p=reject"},
			"_dmarc.example.test":      {"v=DMARC1; p=quarantine"},
		}}
		p, err := Discover("mail.example.test", z.lookup, nil)
		if err != nil || p.Domain != "example.test" || p.Requested != "quarantine" {
			t.Errorf("Discover = %+v, %v", p, err)
		}
	})

	t.Run("several records above are none too", func(t *testing.T) {
		z := &zone{records: map[string][]string{"_dmarc.example.test": {"v=DMARC1; p=none", "v=DMARC1; p=reject"}}}
		if p, err := Discover("mail.example.test", z.lookup, nil); err != nil || p.Raw != "" || p.Requested != "none" {
			t.Errorf("Discover = %+v, %v", p, err)
		}
	})

	t.Run("NXDOMAIN is no record, and the walk goes on", func(t *testing.T) {
		nx := &net.DNSError{Err: "no such host", IsNotFound: true}
		z := dmarcZone(map[string]string{"example.test": "v=DMARC1; p=reject; sp=quarantine"})
		z.errs = map[string]error{"_dmarc.mail.example.test": nx, "_dmarc.test": nx}
		if p, err := Discover("mail.example.test", z.lookup, nil); err != nil || p.Requested != "quarantine" {
			t.Errorf("Discover = %+v, %v", p, err)
		}
		z = &zone{errs: map[string]error{"_dmarc.example.test": nx, "_dmarc.test": nx}}
		if p, err := Discover("example.test", z.lookup, nil); err != nil || p.Raw != "" || p.Requested != "none" {
			t.Errorf("NXDOMAIN everywhere: Discover = %+v, %v", p, err)
		}
	})

	t.Run("a DNS error is returned, at the Author Domain or above it", func(t *testing.T) {
		temp := &net.DNSError{Err: "server misbehaving", IsTemporary: true}
		for _, name := range []string{"_dmarc.mail.example.test", "_dmarc.example.test", "_dmarc.test"} {
			z := dmarcZone(nil)
			z.errs = map[string]error{name: temp}
			if _, err := Discover("mail.example.test", z.lookup, nil); !errors.Is(err, temp) {
				t.Errorf("an error at %s: Discover error = %v, want %v", name, err, temp)
			}
		}
	})
}

// TestDiscoverTreeWalk checks the DNS Tree Walk (RFC 9989 §4.10): it starts
// at the Author Domain's parent, or at its last seven labels when it has more
// than eight, so no discovery sends more than eight queries, and it stops at
// a record with psd=y or psd=n.
//
// checklist: DMARC-DISC-04 DMARC-DISC-05 DMARC-DISC-20
func TestDiscoverTreeWalk(t *testing.T) {
	// The example of §4.10: thirteen labels, eight queries.
	z := dmarcZone(nil)
	if _, err := Discover("a.b.c.d.e.f.g.h.i.j.mail.example.com", z.lookup, nil); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"_dmarc.a.b.c.d.e.f.g.h.i.j.mail.example.com",
		"_dmarc.g.h.i.j.mail.example.com",
		"_dmarc.h.i.j.mail.example.com",
		"_dmarc.i.j.mail.example.com",
		"_dmarc.j.mail.example.com",
		"_dmarc.mail.example.com",
		"_dmarc.example.com",
		"_dmarc.com",
	}
	if !reflect.DeepEqual(z.queried, want) {
		t.Errorf("queried %q\nwant %q", z.queried, want)
	}

	for labels := 1; labels <= 20; labels++ {
		z := dmarcZone(nil)
		domain := strings.Repeat("x.", labels-1) + "test"
		if _, err := Discover(domain, z.lookup, nil); err != nil {
			t.Fatal(err)
		}
		want := min(labels, 8)
		if len(z.queried) != want {
			t.Errorf("%d labels: %d queries %q, want %d", labels, len(z.queried), z.queried, want)
		}
		if last := z.queried[len(z.queried)-1]; last != "_dmarc.test" {
			t.Errorf("%d labels: the walk ended at %s, not the last label", labels, last)
		}
	}

	// A record with psd=n or psd=y stops the walk; one with psd=u does not.
	for psd, wantQueries := range map[string]int{"n": 2, "y": 2, "u": 4} {
		z := dmarcZone(map[string]string{"b.example.test": "v=DMARC1; p=reject; psd=" + psd})
		if _, err := Discover("a.b.example.test", z.lookup, nil); err != nil {
			t.Fatal(err)
		}
		if len(z.queried) != wantQueries {
			t.Errorf("psd=%s: queried %q, want %d queries", psd, z.queried, wantQueries)
		}
	}
}

// TestDiscoverOrganizationalDomainOrPSD checks which record above the Author
// Domain applies (RFC 9989 §4.10.1, §4.10.2): its Organizational Domain's,
// and when that publishes none, its Public Suffix Domain's.
//
// checklist: DMARC-DISC-19 DMARC-ORG-01
func TestDiscoverOrganizationalDomainOrPSD(t *testing.T) {
	cases := []struct {
		name    string
		records map[string]string
		domain  string
		psd     bool
	}{
		{"the fewest labels", map[string]string{"mail.example.com": "v=DMARC1; p=none", "example.com": "v=DMARC1; p=reject"}, "example.com", false},
		{"psd=n names the Organizational Domain", map[string]string{"mail.example.com": "v=DMARC1; p=reject; psd=n", "example.com": "v=DMARC1; p=none"}, "mail.example.com", false},
		{"one label below psd=y, which publishes", map[string]string{"example.com": "v=DMARC1; p=reject", "com": "v=DMARC1; p=none; psd=y"}, "example.com", false},
		{"one label below psd=y, which publishes none: the PSD's", map[string]string{"com": "v=DMARC1; p=reject; psd=y"}, "com", true},
		{"the PSD's, over a record below the Organizational Domain", map[string]string{"mail.example.com": "v=DMARC1; p=none", "com": "v=DMARC1; p=reject; psd=y"}, "com", true},
	}
	for _, c := range cases {
		z := dmarcZone(c.records)
		p, err := Discover("a.mail.example.com", z.lookup, nil)
		if err != nil || p.Domain != c.domain || p.PSD != c.psd || !p.Inherited || p.Requested != "reject" {
			t.Errorf("%s: Discover = %+v, %v; want the record of %s (PSD %v)", c.name, p, err, c.domain, c.psd)
		}
	}
	// A PSD record applies to a domain directly below it, which is its own
	// Organizational Domain and publishes nothing.
	z := dmarcZone(map[string]string{"com": "v=DMARC1; p=reject; psd=y"})
	if p, err := Discover("example.com", z.lookup, nil); err != nil || p.Domain != "com" || !p.PSD {
		t.Errorf("Discover(example.com) = %+v, %v; want the PSD's record", p, err)
	}
}

// TestDiscoverNonExistentPolicy checks np= (RFC 9989 §4.7, §4.10.1): an
// inherited record gives a subdomain that does not exist its np=, one that
// exists its sp=, and either p= without them; exists is asked only when it
// matters, and its error is returned.
//
// checklist: DMARC-REC-19 DMARC-DISC-10
func TestDiscoverNonExistentPolicy(t *testing.T) {
	exists := func(ok bool, err error) (ExistsFunc, *[]string) {
		var asked []string
		return func(d string) (bool, error) { asked = append(asked, d); return ok, err }, &asked
	}
	cases := []struct {
		record string
		exists bool
		want   string
		asks   bool
	}{
		{"v=DMARC1; p=none; sp=quarantine; np=reject", false, "reject", true},
		{"v=DMARC1; p=none; sp=quarantine; np=reject", true, "quarantine", true},
		{"v=DMARC1; p=none; np=reject", true, "none", true},
		{"v=DMARC1; p=none; sp=quarantine", false, "quarantine", false},
		{"v=DMARC1; p=reject", false, "reject", false},
	}
	for _, c := range cases {
		z := dmarcZone(map[string]string{"example.test": c.record})
		f, asked := exists(c.exists, nil)
		p, err := Discover("nx.example.test", z.lookup, f)
		if err != nil || p.Requested != c.want {
			t.Errorf("%q, exists %v: Discover = %+v, %v; want %s", c.record, c.exists, p, err, c.want)
		}
		if c.asks != (len(*asked) == 1) || c.asks && (*asked)[0] != "nx.example.test" {
			t.Errorf("%q: exists was asked %q", c.record, *asked)
		}
	}

	// The Author Domain's own record is its p=, and exists is not asked.
	z := dmarcZone(map[string]string{"example.test": "v=DMARC1; p=quarantine; np=reject"})
	f, asked := exists(false, nil)
	if p, err := Discover("example.test", z.lookup, f); err != nil || p.Requested != "quarantine" || len(*asked) != 0 {
		t.Errorf("own record: Discover = %+v, %v, asked %q", p, err, *asked)
	}
	// With no exists, the Author Domain is taken to exist.
	z = dmarcZone(map[string]string{"example.test": "v=DMARC1; p=none; sp=quarantine; np=reject"})
	if p, err := Discover("nx.example.test", z.lookup, nil); err != nil || p.Requested != "quarantine" {
		t.Errorf("nil exists: Discover = %+v, %v", p, err)
	}
	temp := errors.New("timeout")
	f, _ = exists(false, temp)
	if _, err := Discover("nx.example.test", z.lookup, f); !errors.Is(err, temp) {
		t.Errorf("exists error: Discover error = %v, want %v", err, temp)
	}
}

// TestDiscoverTestMode checks t=y (RFC 9989 §4.7): the policy is applied one
// level lower, reject as quarantine and quarantine as none, and none is
// unaffected; the requested policy is kept for reports.
//
// checklist: DMARC-REC-21 DMARC-POL-01
func TestDiscoverTestMode(t *testing.T) {
	cases := []struct{ record, requested, applied string }{
		{"v=DMARC1; p=reject; t=y", "reject", "quarantine"},
		{"v=DMARC1; p=quarantine; t=y", "quarantine", "none"},
		{"v=DMARC1; p=none; t=y", "none", "none"},
		{"v=DMARC1; p=reject; t=n", "reject", "reject"},
		{"v=DMARC1; p=reject", "reject", "reject"},
	}
	for _, c := range cases {
		z := dmarcZone(map[string]string{"example.test": c.record})
		p, err := Discover("example.test", z.lookup, nil)
		if err != nil || p.Requested != c.requested || p.Applied != c.applied {
			t.Errorf("%q: Discover = %+v, %v; want requested %s, applied %s", c.record, p, err, c.requested, c.applied)
		}
	}
	// An inherited policy is lowered the same way.
	z := dmarcZone(map[string]string{"example.test": "v=DMARC1; p=none; sp=reject; t=y"})
	if p, err := Discover("mail.example.test", z.lookup, nil); err != nil || p.Requested != "reject" || p.Applied != "quarantine" {
		t.Errorf("inherited: Discover = %+v, %v", p, err)
	}
}

// TestDiscoverInvalidPolicy checks §4.10.1: a record with no valid p=, or an
// invalid sp= or np=, requests "none" when it names a valid rua= URI, so
// reports still flow, and leaves DMARC unapplied otherwise. Neither is an
// error (v0.3.0 returned one, which a caller could not tell from a DNS
// failure).
//
// checklist: DMARC-DISC-06 DMARC-DISC-07
func TestDiscoverInvalidPolicy(t *testing.T) {
	cases := []struct {
		domain, record string
		applies        bool
	}{
		{"example.test", "v=DMARC1; p=bogus; rua=mailto:agg@example.test", true},
		{"example.test", "v=DMARC1; p=reject; sp=bogus; rua=mailto:agg@example.test", true},
		{"example.test", "v=DMARC1; p=reject; np=bogus; rua=mailto:agg@example.test", true},
		{"example.test", "v=DMARC1; rua=mailto:agg@example.test", true},
		{"sub.example.test", "v=DMARC1; p=reject; sp=bogus; rua=mailto:agg@example.test", true},
		{"example.test", "v=DMARC1; p=bogus", false},
		{"example.test", "v=DMARC1; p=none; p=reject", false},
		{"sub.example.test", "v=DMARC1; p=reject; sp=bogus", false},
		{"sub.example.test", "v=DMARC1; p=reject; np=bogus", false},
	}
	for _, c := range cases {
		z := dmarcZone(map[string]string{"example.test": c.record})
		p, err := Discover(c.domain, z.lookup, nil)
		if err != nil || p.Requested != "none" || p.Applied != "none" || (p.Raw != "") != c.applies {
			t.Errorf("Discover(%q) with %q = %+v, %v; want Requested none, applies %v", c.domain, c.record, p, err, c.applies)
		}
		if c.applies && len(p.Record.RUA) != 1 {
			t.Errorf("Discover(%q) with %q lost the rua= URI: %+v", c.domain, c.record, p.Record)
		}
	}
}

// TestDiscoverDomainForm checks that the Author Domain is queried as an
// A-label, lower case and without the root dot, and that a string that is
// not a domain sends no query.
//
// checklist: DMARC-DISC-01
func TestDiscoverDomainForm(t *testing.T) {
	z := dmarcZone(nil)
	if p, err := Discover("Mail.Bücher.Example.", z.lookup, nil); err != nil || p.Raw != "" {
		t.Fatalf("Discover = %+v, %v", p, err)
	}
	want := []string{"_dmarc.mail.xn--bcher-kva.example", "_dmarc.xn--bcher-kva.example", "_dmarc.example"}
	if !reflect.DeepEqual(z.queried, want) {
		t.Errorf("queried %q, want %q", z.queried, want)
	}

	z.queried = nil
	for _, d := range []string{"", ".", "..", "a..example.test", "exa mple.test", "a@example.test", strings.Repeat("a", 64) + ".test"} {
		if p, err := Discover(d, z.lookup, nil); err != nil || p.Raw != "" || p.Requested != "none" {
			t.Errorf("Discover(%q) = %+v, %v", d, p, err)
		}
	}
	if len(z.queried) != 0 {
		t.Errorf("queried %q for non-domains", z.queried)
	}
}
