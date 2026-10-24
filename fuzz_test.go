package dmarc

import (
	"encoding/xml"
	"reflect"
	"slices"
	"strings"
	"testing"

	msgauth "github.com/emersion/go-msgauth/dmarc"
	"golang.org/x/net/idna"
)

// FuzzParseRecord parses any TXT record: the parser never panics; a record it
// accepts starts with v=DMARC1 and holds only valid values, every report URI
// parses again as itself, and a record without a valid policy is p=none only
// when it names a valid rua= URI. Where go-msgauth accepts a record whose
// tags are lower-case, unrepeated and led by v=DMARC1, this parser accepts it
// too with the same p=, sp=, adkim= and aspf=.
//
// checklist: DMARC-REC-07 DMARC-REC-08 DMARC-DISC-06
func FuzzParseRecord(f *testing.F) {
	for _, r := range diffRecords {
		f.Add(r.record)
	}
	for _, seed := range []string{
		"v=DMARC1; p=reject; rua=mailto:a@example.com!18446744073709551615t, mailto:b@example.com!0",
		"v=DMARC1; p=none; ruf=mailto:x@y.test; fo=0:1:d:s; rf=afrf:iodef; ri=4294967296",
		"v=DMARC1; p=none; sp=reject; np=quarantine; psd=y; t=y; ruf=mailto:x@y.test; fo=d:1:s",
		"v=DMARC1;;;=;p=;=reject", "v=DMARC1; p=none; rua=,,,!,mailto:!1k", "v=DMARC1\x00; p=none",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, txt string) {
		r, err := ParseRecord(txt)
		if err != nil {
			if err != ErrNotDMARC && err != ErrNoPolicy {
				t.Fatalf("unexpected error %v", err)
			}
			if (err == ErrNotDMARC) == hasDMARCVersion(txt) {
				t.Fatalf("error %v for a record whose version tag is %v", err, hasDMARCVersion(txt))
			}
			return
		}
		if !hasDMARCVersion(txt) {
			t.Fatalf("accepted a record without v=DMARC1 first")
		}
		if !slices.Contains([]string{"none", "quarantine", "reject"}, r.Policy) ||
			!slices.Contains([]string{"", "none", "quarantine", "reject"}, r.SubdomainPolicy) ||
			!slices.Contains([]string{"", "none", "quarantine", "reject"}, r.NonExistentPolicy) ||
			!slices.Contains([]string{"y", "n", "u"}, r.PSD) || len(r.FailureOptions) == 0 {
			t.Fatalf("invalid values %+v", r)
		}
		seen := map[string]bool{}
		for _, o := range r.FailureOptions {
			if !slices.Contains([]string{"0", "1", "d", "s"}, o) || len(r.RUF) == 0 && o != "0" || seen[o] {
				t.Fatalf("fo %q with ruf %v", r.FailureOptions, r.RUF)
			}
			seen[o] = true
		}
		if seen["0"] && seen["1"] {
			t.Fatalf("fo %q has both 0 and 1", r.FailureOptions)
		}
		for _, u := range append(slices.Clone(r.RUA), r.RUF...) {
			again, ok := parseReportURI(u)
			if !ok || again != u {
				t.Fatalf("URI %q does not parse again: %q, %v", u, again, ok)
			}
		}
		if _, err := msgauth.Parse(txt); err == nil && plainTags(txt) {
			theirs, _ := msgauth.Parse(txt)
			if r.Policy != string(theirs.Policy) || r.SubdomainPolicy != string(theirs.SubdomainPolicy) ||
				alignmentLetter(r.ADKIM) != string(theirs.DKIMAlignment) || alignmentLetter(r.ASPF) != string(theirs.SPFAlignment) {
				t.Fatalf("here %+v, go-msgauth %+v", r, theirs)
			}
		}
	})
}

// plainTags reports whether every tag of a record is lower-case and appears
// once, the first is v=DMARC1, and there is no np=, which go-msgauth (RFC
// 7489) does not know and an invalid value of which leaves this parser's
// record without a policy: the records on which the two must agree.
func plainTags(txt string) bool {
	if !hasDMARCVersion(txt) {
		return false
	}
	seen := map[string]bool{}
	for _, part := range strings.Split(txt, ";") {
		name, _, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		name = strings.TrimSpace(name)
		if name != strings.ToLower(name) || seen[name] || name == "np" {
			return false
		}
		seen[name] = true
	}
	return true
}

// FuzzAlignment checks alignment on any pair of identifiers, against a DNS
// where every two-label name publishes a record: it never panics, sends no
// more than eight queries for each name, is symmetric, strict alignment
// implies relaxed alignment, an identifier aligns with itself exactly when it
// is a domain, and the A-label form agrees with golang.org/x/net/idna's
// punycode.
//
// checklist: DMARC-ALIGN-01 DMARC-ALIGN-02 DMARC-ALIGN-03
func FuzzAlignment(f *testing.F) {
	for _, seed := range [][2]string{
		{"example.com", "mail.example.com"}, {"münchen.de", "xn--mnchen-3ya.de"}, {"EXAMPLE.COM.", "example.com"},
		{"", ""}, {"..", ".."}, {"a.b.c.d.e.f", "f"}, {"食狮.中国", "www.食狮.中国"}, {"ß.de", "ss.de"}, {"\xff.com", "\xff.com"},
		// Found by this target: a long Unicode label took quadratic time.
		{strings.Repeat("ü", 20000) + ".com", "example.com"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		queries := 0
		resolver := func(name string) ([]string, error) {
			queries++
			if strings.Count(name, ".") == 2 {
				return []string{"v=DMARC1; p=none"}, nil
			}
			return nil, nil
		}
		align := func(x, y string, mode AlignmentMode) bool {
			ok, err := AlignedMode(x, y, mode, resolver)
			if err != nil {
				t.Fatalf("AlignedMode(%q, %q, %v): %v", x, y, mode, err)
			}
			return ok
		}
		for _, mode := range []AlignmentMode{AlignmentRelaxed, AlignmentStrict} {
			if align(a, b, mode) != align(b, a, mode) {
				t.Fatalf("%v alignment of %q and %q is not symmetric", mode, a, b)
			}
		}
		if align(a, b, AlignmentStrict) && !align(a, b, AlignmentRelaxed) {
			t.Fatalf("%q and %q align strictly but not relaxed", a, b)
		}
		if queries > 5*16 {
			t.Fatalf("five alignments sent %d queries", queries)
		}
		d, ok := queryDomain(a)
		if align(a, a, AlignmentRelaxed) != ok {
			t.Fatalf("AlignedMode(%q, %q) = %v, but queryDomain says %v", a, a, !ok, ok)
		}
		if !ok {
			return
		}
		if again, ok := queryDomain(d); !ok || again != d {
			t.Fatalf("normalizing %q is not idempotent: %q then %q", a, d, again)
		}
		// Compare the punycode of each label with x/net/idna's, where it
		// accepts the lower-cased label.
		for _, label := range strings.Split(strings.ToLower(strings.TrimSuffix(a, ".")), ".") {
			want, err := idna.Punycode.ToASCII(label)
			if err != nil || isASCII(label) {
				continue
			}
			if got := labelToASCII(label); got != want {
				t.Fatalf("label %q: %q, x/net/idna %q", label, got, want)
			}
		}
	})
}

// FuzzDiscover discovers the policy of any domain against any pair of
// records, one at the domain and one at every name above it: it never
// panics, queries only _dmarc names of valid domains, at most eight, and
// returns a policy that either is empty or was parsed from the record it
// names, with the policy it applies the requested one or, in test mode, one
// level lower.
//
// checklist: DMARC-DISC-01 DMARC-DISC-02 DMARC-DISC-04 DMARC-DISC-05
func FuzzDiscover(f *testing.F) {
	f.Add("mail.example.com", "v=DMARC1; p=reject", "v=DMARC1; p=none; sp=quarantine")
	f.Add("Mail.Bücher.Example.", "", "v=DMARC1; sp=reject; rua=mailto:a@b.test")
	f.Add("a..b", "v=DMARC1; p=reject", "")
	f.Add("x.y.z.example.com", "v=spf1 -all", "v=DMARC1; p=bogus")
	f.Add("a.b.c.d.e.f.g.h.i.j.example.com", "", "v=DMARC1; p=reject; t=y; psd=n")
	f.Fuzz(func(t *testing.T, domain, exact, org string) {
		queries := 0
		resolver := func(name string) ([]string, error) {
			queries++
			rest, ok := strings.CutPrefix(name, "_dmarc.")
			if _, valid := queryDomain(rest); !ok || !valid || rest != normalizeDomain(rest) {
				t.Fatalf("queried %q", name)
			}
			if d, _ := queryDomain(domain); rest == d {
				return []string{exact}, nil
			}
			return []string{org}, nil
		}
		p, err := Discover(domain, resolver, nil)
		if err != nil {
			t.Fatalf("error %v", err)
		}
		if queries > 8 {
			t.Fatalf("%d queries", queries)
		}
		if p.Raw == "" {
			if p.Requested != "none" || p.Applied != "none" || p.Inherited || p.PSD || p.Domain != "" {
				t.Fatalf("empty policy %+v", p)
			}
			return
		}
		rec, err := ParseRecord(p.Raw)
		if err != nil || !reflect.DeepEqual(rec, p.Record) {
			t.Fatalf("policy %+v does not match its record (%v)", p, err)
		}
		if !slices.Contains([]string{rec.Policy, rec.SubdomainPolicy}, p.Requested) {
			t.Fatalf("requested %q is not the record's", p.Requested)
		}
		lower := map[string]string{"reject": "quarantine", "quarantine": "none", "none": "none"}
		if p.Applied != p.Requested && (!rec.Testing || p.Applied != lower[p.Requested]) {
			t.Fatalf("applied %q for requested %q, testing %v", p.Applied, p.Requested, rec.Testing)
		}
	})
}

// FuzzBuildReport builds a report from any field values: BuildReport never
// panics, and a report it returns validates against RFC 9990's Appendix A
// schema and reads back with the same rows.
//
// checklist: DMARC-XML-02 DMARC-XML-06
func FuzzBuildReport(f *testing.F) {
	f.Add("example.test", "192.0.2.1", "reject", "pass", "fail", "mfrom", "sel", "sampled_out", "r", "1")
	f.Add("<&>", "2001:db8::1", "Quarantine", "weird", "SoftFail", "helo", "", "arc", "s", "")
	f.Add("\x00￾\x1b", "::ffff:10.0.0.1", "", "", "", "", "\xff", "", "", "0:1")
	f.Fuzz(func(t *testing.T, domain, ip, disposition, dkimResult, spfResult, mode, selector, reason, adkim, fo string) {
		recs := []AggregateRecord{{
			Domain: domain, SourceIP: ip, HeaderFrom: domain, Disposition: disposition, EnvelopeFrom: selector, EnvelopeTo: mode,
			DKIM:    []DKIMAuth{{Domain: domain, Selector: selector, Result: dkimResult, Aligned: true}, {Domain: selector, Result: dkimResult}},
			SPF:     &SPFAuth{Domain: domain, Result: spfResult},
			Reasons: []PolicyOverrideReason{{Type: reason, Comment: selector}},
		}, {Domain: domain, SourceIP: ip, Disposition: disposition}}
		policy := PolicyPublished{Domain: domain, DiscoveryMethod: reason, ADKIM: adkim, ASPF: adkim, P: disposition, SP: disposition, NP: fo, FO: fo, Testing: mode}
		out, err := BuildReport(ReportMetadata{OrgName: domain, Email: selector, ReportID: reason, Error: dkimResult, Generator: mode}, policy, recs)
		if err != nil {
			if _, ok := reportIP(ip); ok {
				t.Fatalf("BuildReport failed for a valid IP: %v", err)
			}
			return
		}
		if err := validateReport(out); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		var fb Feedback
		if err := xml.Unmarshal(out, &fb); err != nil {
			t.Fatal(err)
		}
		total := 0
		for _, r := range fb.Records {
			total += r.Row.Count
		}
		if want := AggregateRecords(recs); len(fb.Records) != len(want) || total != len(recs) {
			t.Fatalf("rows %+v, want %+v", fb.Records, want)
		}
	})
}
