package dmarc

import (
	"reflect"
	"strings"
	"testing"
)

// The examples of RFC 9989 Appendix B as tests.

// TestRFC9989RecordExamples parses the records of RFC 9989 Appendix B.2,
// including B.2.5's two aggregate URIs and test mode. The records are given
// as their zone files publish them: several character-strings, which DNS
// returns joined.
//
// checklist: DMARC-URI-01 DMARC-URI-05 DMARC-REC-06 DMARC-REC-21
func TestRFC9989RecordExamples(t *testing.T) {
	defaults := func(r Record) Record {
		r.PSD, r.ADKIM, r.ASPF, r.FailureOptions = "u", AlignmentRelaxed, AlignmentRelaxed, []string{"0"}
		return r
	}
	cases := []struct {
		name    string
		strings []string
		want    Record
	}{
		{"B.2.1", []string{"v=DMARC1; p=none; ", "rua=mailto:dmarc-feedback@example.com"},
			defaults(Record{Policy: "none", RUA: []string{"mailto:dmarc-feedback@example.com"}})},
		{"B.2.2", []string{"v=DMARC1; p=none; ", "rua=mailto:dmarc-feedback@example.com; ", "ruf=mailto:auth-reports@example.com"},
			defaults(Record{Policy: "none", RUA: []string{"mailto:dmarc-feedback@example.com"},
				RUF: []string{"mailto:auth-reports@example.com"}})},
		{"B.2.3", []string{"v=DMARC1; p=none; ", "rua=mailto:dmarc-feedback@example.com; ", "ruf=mailto:auth-reports@thirdparty.example.net"},
			defaults(Record{Policy: "none", RUA: []string{"mailto:dmarc-feedback@example.com"},
				RUF: []string{"mailto:auth-reports@thirdparty.example.net"}})},
		{"B.2.5, testing", []string{"v=DMARC1; p=quarantine; ", "rua=mailto:dmarc-feedback@example.com,", "mailto:tld-test@thirdparty.example.net; ", "t=y"},
			func() Record {
				r := defaults(Record{Policy: "quarantine", RUA: []string{"mailto:dmarc-feedback@example.com", "mailto:tld-test@thirdparty.example.net"}})
				r.Testing = true
				return r
			}()},
		{"B.2.5, enforcing", []string{"v=DMARC1; p=reject; ", "rua=mailto:dmarc-feedback@example.com,", "mailto:tld-test@thirdparty.example.net"},
			defaults(Record{Policy: "reject", RUA: []string{"mailto:dmarc-feedback@example.com", "mailto:tld-test@thirdparty.example.net"}})},
	}
	for _, c := range cases {
		got, err := ParseRecord(strings.Join(c.strings, ""))
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %+v, %v\nwant %+v", c.name, got, err, c.want)
		}
	}
}

// TestRFC9989AlignmentExamples runs the examples of RFC 9989 Appendix B.1 and
// §4.4's table through AlignedMode in both modes, with example.com, example.net
// and sample.net each publishing a record.
//
// checklist: DMARC-ALIGN-02 DMARC-ALIGN-03
func TestRFC9989AlignmentExamples(t *testing.T) {
	z := dmarcZone(map[string]string{
		"example.com": "v=DMARC1; p=none",
		"example.net": "v=DMARC1; p=none",
		"sample.net":  "v=DMARC1; p=none",
	})
	cases := []struct {
		name            string
		auth, from      string
		relaxed, strict bool
	}{
		{"B.1.1 example 1 (SPF, identical)", "example.com", "example.com", true, true},
		{"B.1.1 example 2 (SPF, child)", "child.example.com", "example.com", true, false},
		{"B.1.1 example 3 (SPF, not aligned)", "example.net", "child.example.com", false, false},
		{"B.1.2 example 1 (DKIM, identical)", "example.com", "example.com", true, true},
		{"B.1.2 example 2 (DKIM, parent)", "example.com", "child.example.com", true, false},
		{"B.1.2 example 3 (DKIM, not aligned)", "example.net", "child.example.com", false, false},
		{"§4.4 table, relaxed", "foo.example.com", "news.example.com", true, false},
		{"§4.4 table, strict", "news.example.com", "news.example.com", true, true},
		{"§4.4 table, none", "foo.example.net", "news.example.com", false, false},
		{"d=com", "com", "news.example.com", false, false},
	}
	for _, c := range cases {
		for mode, want := range map[AlignmentMode]bool{AlignmentRelaxed: c.relaxed, AlignmentStrict: c.strict} {
			if got, err := AlignedMode(c.auth, c.from, mode, z.lookup); err != nil || got != want {
				t.Errorf("%s: %v = %v, %v; want %v", c.name, mode, got, err, want)
			}
		}
	}
}

// TestRFC9989TreeWalkExamples follows RFC 9989 Appendix B.4: the
// Organizational Domains of an Author Domain, its RFC5321.MailFrom domain and
// a DKIM-Authenticated Identifier, the queries each Tree Walk sends, the
// alignments they give and the record that applies.
//
// checklist: DMARC-DISC-04 DMARC-DISC-05 DMARC-ORG-01 DMARC-ALIGN-02 DMARC-DISC-19
func TestRFC9989TreeWalkExamples(t *testing.T) {
	t.Run("B.4.1 simple", func(t *testing.T) {
		z := dmarcZone(map[string]string{"example.com": "v=DMARC1; p=reject", "signing.example.com": "v=DMARC1; p=none"})
		if org, err := OrgDomain("example.com", z.lookup); err != nil || org != "example.com" {
			t.Errorf("OrgDomain(example.com) = %q, %v", org, err)
		}
		if want := []string{"_dmarc.example.com", "_dmarc.com"}; !reflect.DeepEqual(z.queried, want) {
			t.Errorf("queried %q, want %q", z.queried, want)
		}
		z.queried = nil
		if org, err := OrgDomain("signing.example.com", z.lookup); err != nil || org != "example.com" {
			t.Errorf("OrgDomain(signing.example.com) = %q, %v", org, err)
		}
		if want := []string{"_dmarc.signing.example.com", "_dmarc.example.com", "_dmarc.com"}; !reflect.DeepEqual(z.queried, want) {
			t.Errorf("queried %q, want %q", z.queried, want)
		}
		if ok, err := AlignedMode("signing.example.com", "example.com", AlignmentRelaxed, z.lookup); !ok || err != nil {
			t.Errorf("DKIM not aligned: %v, %v", ok, err)
		}
		if p, err := Discover("example.com", z.lookup, nil); err != nil || p.Domain != "example.com" || p.Inherited {
			t.Errorf("Discover = %+v, %v; want the Author Domain's own record", p, err)
		}
	})

	t.Run("B.4.2 deep", func(t *testing.T) {
		const author = "a.b.c.d.e.f.g.h.i.j.k.example.com"
		z := dmarcZone(map[string]string{"example.com": "v=DMARC1; p=reject", "signing.example.com": "v=DMARC1; p=none"})
		if org, err := OrgDomain(author, z.lookup); err != nil || org != "example.com" {
			t.Errorf("OrgDomain = %q, %v", org, err)
		}
		want := []string{"_dmarc.a.b.c.d.e.f.g.h.i.j.k.example.com", "_dmarc.g.h.i.j.k.example.com",
			"_dmarc.h.i.j.k.example.com", "_dmarc.i.j.k.example.com", "_dmarc.j.k.example.com",
			"_dmarc.k.example.com", "_dmarc.example.com", "_dmarc.com"}
		if !reflect.DeepEqual(z.queried, want) {
			t.Errorf("queried %q\nwant %q", z.queried, want)
		}
		for _, id := range []string{"example.com", "signing.example.com"} {
			if ok, err := AlignedMode(id, author, AlignmentRelaxed, z.lookup); !ok || err != nil {
				t.Errorf("%s not aligned: %v, %v", id, ok, err)
			}
		}
		z.queried = nil
		if p, err := Discover(author, z.lookup, nil); err != nil || p.Domain != "example.com" || !p.Inherited {
			t.Errorf("Discover = %+v, %v; want example.com's record", p, err)
		}
		if !reflect.DeepEqual(z.queried, want) {
			t.Errorf("Discover queried %q\nwant %q", z.queried, want)
		}
	})

	t.Run("B.4.3 PSD", func(t *testing.T) {
		z := dmarcZone(map[string]string{"giant.bank.example": "v=DMARC1; p=reject", "bank.example": "v=DMARC1; p=none; psd=y"})
		for domain, want := range map[string]string{
			"giant.bank.example":      "giant.bank.example",
			"mail.giant.bank.example": "giant.bank.example",
			"mail.mega.bank.example":  "mega.bank.example",
		} {
			z.queried = nil
			if org, err := OrgDomain(domain, z.lookup); err != nil || org != want {
				t.Errorf("OrgDomain(%s) = %q, %v; want %s", domain, org, err, want)
			}
			if last := z.queried[len(z.queried)-1]; last != "_dmarc.bank.example" {
				t.Errorf("OrgDomain(%s): the walk went on past the psd=y record to %s", domain, last)
			}
		}
		if ok, err := AlignedMode("mail.giant.bank.example", "giant.bank.example", AlignmentRelaxed, z.lookup); !ok || err != nil {
			t.Errorf("SPF not aligned: %v, %v", ok, err)
		}
		if ok, err := AlignedMode("mail.mega.bank.example", "giant.bank.example", AlignmentRelaxed, z.lookup); ok || err != nil {
			t.Errorf("DKIM aligned: %v, %v", ok, err)
		}
		if p, err := Discover("giant.bank.example", z.lookup, nil); err != nil || p.Domain != "giant.bank.example" || p.Requested != "reject" {
			t.Errorf("Discover = %+v, %v; want giant.bank.example's own record", p, err)
		}
	})
}

// TestRFC9989ThirdPartyExample checks the external destinations of RFC 9989
// Appendix B.2.3 and B.2.4: failure reports for example.com may go to
// thirdparty.example.net once it publishes v=DMARC1 at
// example.com._report._dmarc.thirdparty.example.net, and not before; its
// ruf= there overrides the address; and RFC 7489 §7.1's blue.example.com and
// red.example.net example likewise.
//
// checklist: DMARC-EXT-01 DMARC-EXT-03 DMARC-EXT-04
func TestRFC9989ThirdPartyExample(t *testing.T) {
	rec := mustParse(t, "v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com; ruf=mailto:auth-reports@thirdparty.example.net")
	z := dmarcZone(map[string]string{"example.com": "v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com"})
	z.records["example.com._report._dmarc.thirdparty.example.net"] = []string{"v=DMARC1;"}
	got, err := AuthorizeReportURIs("example.com", "ruf", rec.RUF, z.lookup)
	if err != nil || !reflect.DeepEqual(got, rec.RUF) {
		t.Errorf("ruf: got %+v, %v; want %+v", got, err, rec.RUF)
	}
	if got, err := AuthorizeReportURIs("example.com", "rua", rec.RUA, z.lookup); err != nil || !reflect.DeepEqual(got, rec.RUA) {
		t.Errorf("rua inside the Organizational Domain: got %+v, %v", got, err)
	}
	var asked []string
	for _, q := range z.queried {
		if strings.Contains(q, "._report.") {
			asked = append(asked, q)
		}
	}
	if want := []string{"example.com._report._dmarc.thirdparty.example.net"}; !reflect.DeepEqual(asked, want) {
		t.Errorf("asked %q, want %q", asked, want)
	}

	// B.2.4: the third party's ruf= replaces the address.
	z.records["example.com._report._dmarc.thirdparty.example.net"] = []string{
		"v=DMARC1; rua=mailto:aggregate-reports@thirdparty.example.net; ruf=mailto:failure-reports@thirdparty.example.net"}
	if got, err := AuthorizeReportURIs("example.com", "ruf", rec.RUF, z.lookup); err != nil ||
		!reflect.DeepEqual(got, []string{"mailto:failure-reports@thirdparty.example.net"}) {
		t.Errorf("override: got %+v, %v", got, err)
	}

	// Before the third party publishes its record, the URI is ignored.
	delete(z.records, "example.com._report._dmarc.thirdparty.example.net")
	if got, err := AuthorizeReportURIs("example.com", "ruf", rec.RUF, z.lookup); err != nil || len(got) != 0 {
		t.Errorf("unauthorized: got %+v, %v; want none", got, err)
	}

	// RFC 7489 §7.1's example.
	blue := mustParse(t, "v=DMARC1; p=none; rua=mailto:reports@red.example.net")
	z = dmarcZone(nil)
	z.records["blue.example.com._report._dmarc.red.example.net"] = []string{"v=DMARC1"}
	if got, err := AuthorizeReportURIs("blue.example.com", "rua", blue.RUA, z.lookup); err != nil || !reflect.DeepEqual(got, blue.RUA) {
		t.Errorf("blue/red: got %+v, %v", got, err)
	}
}
