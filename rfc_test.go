package dmarc

import (
	"bufio"
	"math"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/publicsuffix"
)

// The examples of RFC 7489 Appendix B, and the Public Suffix List's own test
// cases, as tests.

// TestRFC7489RecordExamples parses the records of RFC 7489 Appendix B.2,
// including B.2.4's two aggregate URIs, one with a 10m size limit. The
// records are given as their zone files publish them: several
// character-strings, which DNS returns joined.
//
// checklist: DMARC-URI-01 DMARC-URI-02 DMARC-URI-05 DMARC-REC-06
func TestRFC7489RecordExamples(t *testing.T) {
	const max = math.MaxUint64
	defaults := func(r Record) Record {
		r.ADKIM, r.ASPF, r.Pct, r.ReportInterval = AlignmentRelaxed, AlignmentRelaxed, 100, 86400
		r.FailureOptions, r.ReportFormats = []string{"0"}, []string{"afrf"}
		return r
	}
	cases := []struct {
		name    string
		strings []string
		want    Record
	}{
		{"B.2.1", []string{"v=DMARC1; p=none; ", "rua=mailto:dmarc-feedback@example.com"},
			defaults(Record{Policy: "none", RUA: []ReportURI{{"mailto:dmarc-feedback@example.com", max}}})},
		{"B.2.2", []string{"v=DMARC1; p=none; ", "rua=mailto:dmarc-feedback@example.com; ", "ruf=mailto:auth-reports@example.com"},
			defaults(Record{Policy: "none", RUA: []ReportURI{{"mailto:dmarc-feedback@example.com", max}},
				RUF: []ReportURI{{"mailto:auth-reports@example.com", max}}})},
		{"B.2.3", []string{"v=DMARC1; p=none; ", "rua=mailto:dmarc-feedback@example.com; ", "ruf=mailto:auth-reports@thirdparty.example.net"},
			defaults(Record{Policy: "none", RUA: []ReportURI{{"mailto:dmarc-feedback@example.com", max}},
				RUF: []ReportURI{{"mailto:auth-reports@thirdparty.example.net", max}}})},
		{"B.2.4", []string{"v=DMARC1; p=quarantine; ", "rua=mailto:dmarc-feedback@example.com,", "mailto:tld-test@thirdparty.example.net!10m; ", "pct=25"},
			func() Record {
				r := defaults(Record{Policy: "quarantine", RUA: []ReportURI{
					{"mailto:dmarc-feedback@example.com", max}, {"mailto:tld-test@thirdparty.example.net", 10 << 20}}})
				r.Pct = 25
				return r
			}()},
		{"B.3.1", []string{"v=DMARC1; p=reject; aspf=r;", " rua=mailto:dmarc-feedback@example.com"},
			defaults(Record{Policy: "reject", RUA: []ReportURI{{"mailto:dmarc-feedback@example.com", max}}})},
	}
	for _, c := range cases {
		got, err := ParseRecord(strings.Join(c.strings, ""))
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %+v, %v\nwant %+v", c.name, got, err, c.want)
		}
	}
}

// TestRFC7489AlignmentExamples runs the examples of RFC 7489 Appendix B.1 and
// B.3.1 through AlignedMode in both modes.
//
// checklist: DMARC-ALIGN-02 DMARC-ALIGN-03
func TestRFC7489AlignmentExamples(t *testing.T) {
	cases := []struct {
		name            string
		auth, from      string
		relaxed, strict bool
	}{
		{"B.1.1 example 1 (SPF, identical)", "example.com", "example.com", true, true},
		{"B.1.1 example 2 (SPF, parent)", "child.example.com", "example.com", true, false},
		{"B.1.1 example 3 (SPF, not aligned)", "example.net", "child.example.com", false, false},
		{"B.1.2 example 1 (DKIM, identical)", "example.com", "example.com", true, true},
		{"B.1.2 example 2 (DKIM, parent)", "example.com", "child.example.com", true, false},
		{"B.1.2 example 3 (DKIM, not aligned)", "sample.net", "child.example.com", false, false},
		{"3.1.1 (d=example.com, From news.example.com)", "example.com", "news.example.com", true, false},
		{"3.1.1 (d=com never aligns)", "com", "news.example.com", false, false},
		{"3.1.2 (cbg.bounces.example.com)", "cbg.bounces.example.com", "example.com", true, false},
		{"B.3.1 (SPF mail.example.com)", "mail.example.com", "example.com", true, false},
		{"B.3.1 (DKIM example.com)", "example.com", "example.com", true, true},
	}
	for _, c := range cases {
		if got := AlignedMode(c.auth, c.from, AlignmentRelaxed, pslOrgDomain); got != c.relaxed {
			t.Errorf("%s: relaxed = %v, want %v", c.name, got, c.relaxed)
		}
		if got := AlignedMode(c.auth, c.from, AlignmentStrict, pslOrgDomain); got != c.strict {
			t.Errorf("%s: strict = %v, want %v", c.name, got, c.strict)
		}
	}
}

// TestRFC7489DiscoveryWalk follows RFC 7489 §6.6.3 for the domains of
// Appendix B.2: test.example.com publishes its own record (B.2.4), any other
// subdomain of example.com falls back to the Organizational Domain's record
// (B.2.1), and the queries go to exactly the names the RFC lists.
//
// checklist: DMARC-DISC-02 DMARC-DISC-04 DMARC-DISC-10
func TestRFC7489DiscoveryWalk(t *testing.T) {
	zone := map[string][]string{
		"_dmarc.example.com":      {"v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com"},
		"_dmarc.test.example.com": {"v=DMARC1; p=quarantine; rua=mailto:dmarc-feedback@example.com,mailto:tld-test@thirdparty.example.net!10m; pct=25"},
	}
	cases := []struct {
		from      string
		queries   []string
		domain    string
		requested string
		viaOrg    bool
	}{
		{"example.com", []string{"_dmarc.example.com"}, "example.com", "none", false},
		{"test.example.com", []string{"_dmarc.test.example.com"}, "test.example.com", "quarantine", false},
		{"a.b.example.com", []string{"_dmarc.a.b.example.com", "_dmarc.example.com"}, "example.com", "none", true},
		// The record at test.example.com is not the Organizational Domain's, so
		// a subdomain of it falls back to example.com, not to test.example.com
		// (§6.3: "sp" is ignored for records published on subdomains).
		{"x.test.example.com", []string{"_dmarc.x.test.example.com", "_dmarc.example.com"}, "example.com", "none", true},
	}
	for _, c := range cases {
		var queries []string
		resolver := func(name string) ([]string, error) {
			queries = append(queries, name)
			return zone[name], nil
		}
		p, err := Discover(c.from, resolver, pslOrgDomain)
		if err != nil {
			t.Fatalf("%s: %v", c.from, err)
		}
		if !reflect.DeepEqual(queries, c.queries) || p.Domain != c.domain || p.Requested != c.requested || p.ViaOrgDomain != c.viaOrg {
			t.Errorf("%s: queries %q, got %+v; want queries %q, domain %s, requested %s, via org %v",
				c.from, queries, p, c.queries, c.domain, c.requested, c.viaOrg)
		}
	}
}

// TestRFC7489ThirdPartyExample checks the external destinations of RFC 7489
// §7.1 and Appendix B.2.3: reports for example.com may go to
// thirdparty.example.net once it publishes v=DMARC1 at
// example.com._report._dmarc.thirdparty.example.net, and not before; §7.1's
// blue.example.com and red.example.net example likewise.
//
// checklist: DMARC-EXT-01 DMARC-EXT-03
func TestRFC7489ThirdPartyExample(t *testing.T) {
	rec := mustParse(t, "v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com; ruf=mailto:auth-reports@thirdparty.example.net")
	var queries []string
	authorized := map[string][]string{"example.com._report._dmarc.thirdparty.example.net": {"v=DMARC1"}}
	resolver := func(name string) ([]string, error) {
		queries = append(queries, name)
		return authorized[name], nil
	}
	got, err := AuthorizeReportURIs("example.com", "ruf", rec.RUF, resolver, pslOrgDomain)
	if err != nil || !reflect.DeepEqual(got, rec.RUF) {
		t.Errorf("ruf: got %+v, %v; want %+v", got, err, rec.RUF)
	}
	if got, err := AuthorizeReportURIs("example.com", "rua", rec.RUA, resolver, pslOrgDomain); err != nil || !reflect.DeepEqual(got, rec.RUA) {
		t.Errorf("rua inside the Organizational Domain: got %+v, %v", got, err)
	}
	if want := []string{"example.com._report._dmarc.thirdparty.example.net"}; !reflect.DeepEqual(queries, want) {
		t.Errorf("queries %q, want %q", queries, want)
	}

	// Before the third party publishes its record, the URI is ignored.
	authorized = nil
	if got, err := AuthorizeReportURIs("example.com", "ruf", rec.RUF, resolver, pslOrgDomain); err != nil || len(got) != 0 {
		t.Errorf("unauthorized: got %+v, %v; want none", got, err)
	}

	// §7.1's own example.
	blue := mustParse(t, "v=DMARC1; p=none; rua=mailto:reports@red.example.net")
	queries = nil
	authorized = map[string][]string{"blue.example.com._report._dmarc.red.example.net": {"v=DMARC1"}}
	if got, err := AuthorizeReportURIs("blue.example.com", "rua", blue.RUA, resolver, pslOrgDomain); err != nil || !reflect.DeepEqual(got, blue.RUA) {
		t.Errorf("blue/red: got %+v, %v", got, err)
	}
	if want := []string{"blue.example.com._report._dmarc.red.example.net"}; !reflect.DeepEqual(queries, want) {
		t.Errorf("blue/red queries %q, want %q", queries, want)
	}
}

// pslOrgDomain is an OrgDomainFunc backed by the Public Suffix List of
// golang.org/x/net/publicsuffix (a test-only dependency): the public suffix
// plus one label, or "" for a public suffix itself.
func pslOrgDomain(domain string) string {
	org, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return ""
	}
	return org
}

// pslCase is one checkPublicSuffix line of the PSL's test file.
type pslCase struct {
	input, org string // org is "" for null
}

var checkPublicSuffixLine = regexp.MustCompile(`^checkPublicSuffix\((null|'[^']*'), (null|'[^']*')\);$`)

// readPSLCases reads testdata/psl/test_psl.txt, the Public Suffix List's own
// test cases (public domain), skipping the null input.
func readPSLCases(t *testing.T) []pslCase {
	t.Helper()
	f, err := os.Open("testdata/psl/test_psl.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var cases []pslCase
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		m := checkPublicSuffixLine.FindStringSubmatch(strings.TrimSpace(sc.Text()))
		if m == nil || m[1] == "null" {
			continue
		}
		c := pslCase{input: strings.Trim(m[1], "'")}
		if m[2] != "null" {
			c.org = strings.Trim(m[2], "'")
		}
		cases = append(cases, c)
	}
	if len(cases) < 75 {
		t.Fatalf("read only %d cases from test_psl.txt", len(cases))
	}
	return cases
}

// TestPSLOrgDomains runs the Public Suffix List's test cases through the
// organizational-domain logic with a PSL-backed OrgDomainFunc: the hook gets
// names in the A-label form the cases expect (mixed case and U-labels
// included); a name whose Organizational Domain the PSL gives aligns with it
// and with its siblings, and finds that domain's policy by the §6.6.3
// fallback; and two names under a public suffix never align. It also records
// where the registry-free DefaultOrgDomain gets these cases wrong.
//
// checklist: DMARC-ORG-01 DMARC-ALIGN-04 DMARC-DISC-04
func TestPSLOrgDomains(t *testing.T) {
	var heuristicWrong []string
	for _, c := range readPSLCases(t) {
		input := normalizeDomain(c.input)
		want := normalizeDomain(c.org)
		if strings.HasPrefix(c.input, ".") {
			// A leading dot is not a domain: it never aligns and sends no query.
			if AlignedOrg(c.input, c.input, pslOrgDomain) {
				t.Errorf("%q aligns with itself", c.input)
			}
			continue
		}
		if got := pslOrgDomain(input); got != want {
			t.Errorf("org domain of %q (%q) = %q, want %q", c.input, input, got, want)
		}
		if want == "" {
			// A public suffix has no Organizational Domain: two registrations
			// under it are different organizations.
			if AlignedOrg("a."+c.input, "b."+c.input, pslOrgDomain) {
				t.Errorf("a.%s and b.%s align, but %s is a public suffix", c.input, c.input, c.input)
			}
			if AlignedOrg("a."+c.input, "b."+c.input, nil) {
				heuristicWrong = append(heuristicWrong, c.input)
			}
			continue
		}
		if !AlignedOrg(c.input, c.org, pslOrgDomain) || !AlignedOrg("x."+c.org, "y."+c.org, pslOrgDomain) {
			t.Errorf("%q does not align with %q or its siblings", c.input, c.org)
		}
		if input != want {
			resolver := func(name string) ([]string, error) {
				if name == "_dmarc."+want {
					return []string{"v=DMARC1; p=reject"}, nil
				}
				return nil, nil
			}
			p, err := Discover(c.input, resolver, pslOrgDomain)
			if err != nil || !p.ViaOrgDomain || p.Domain != want || p.Requested != "reject" {
				t.Errorf("Discover(%q) = %+v, %v; want the policy of %s", c.input, p, err, want)
			}
		}
	}
	// The two-label heuristic treats every two-label public suffix in the
	// list as an organization, so registrations under it falsely align.
	for _, suffix := range []string{"uk.com", "ac.jp", "kyoto.jp", "ak.us", "xn--55qx5d.cn", "公司.cn"} {
		if !slices.Contains(heuristicWrong, suffix) {
			t.Errorf("DefaultOrgDomain now handles %s; update the README and this test", suffix)
		}
	}
}
