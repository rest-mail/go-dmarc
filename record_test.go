package dmarc

import (
	"errors"
	"math"
	"net"
	"reflect"
	"testing"
)

// mustParse parses a record that must be valid.
func mustParse(t testing.TB, record string) Record {
	t.Helper()
	r, err := ParseRecord(record)
	if err != nil {
		t.Fatalf("ParseRecord(%q): %v", record, err)
	}
	return r
}

// TestParseRecordDefaults checks the default of every tag a minimal record
// omits.
//
// checklist: DMARC-REC-11 DMARC-REC-13 DMARC-REC-16 DMARC-REC-10
func TestParseRecordDefaults(t *testing.T) {
	got := mustParse(t, "v=DMARC1; p=reject")
	want := Record{
		Policy:         "reject",
		ADKIM:          AlignmentRelaxed,
		ASPF:           AlignmentRelaxed,
		Pct:            100,
		FailureOptions: []string{"0"},
		ReportFormats:  []string{"afrf"},
		ReportInterval: 86400,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

// TestParseRecordVersion checks that v=DMARC1 must be the first tag, with its
// value matched exactly, or the record is not a DMARC record.
//
// checklist: DMARC-REC-02 DMARC-REC-03
func TestParseRecordVersion(t *testing.T) {
	for _, rec := range []string{"v=DMARC1; p=none", "V=DMARC1;p=none", "v = DMARC1 ;p=none", "v=DMARC1\t; p=none"} {
		if _, err := ParseRecord(rec); err != nil {
			t.Errorf("ParseRecord(%q): %v", rec, err)
		}
	}
	for _, rec := range []string{"", "p=none", "p=none; v=DMARC1", "v=DMARC2; p=none", "v=dmarc1; p=none",
		"v=DMARC10; p=none", "v=DMARC; p=none", "v=spf1 -all", "v DMARC1; p=none", "vv=DMARC1; p=none"} {
		if _, err := ParseRecord(rec); !errors.Is(err, ErrNotDMARC) {
			t.Errorf("ParseRecord(%q) error = %v, want ErrNotDMARC", rec, err)
		}
	}
}

// TestParseRecordSyntax checks the tag-list syntax: whitespace around "=" and
// ";", tags in any order after v=, an optional trailing ";", empty parts and
// unknown tags ignored.
//
// checklist: DMARC-REC-05 DMARC-REC-06
func TestParseRecordSyntax(t *testing.T) {
	want := mustParse(t, "v=DMARC1; p=quarantine; sp=reject; adkim=s; pct=50; rua=mailto:a@example.test")
	for _, rec := range []string{
		"v=DMARC1;p=quarantine;sp=reject;adkim=s;pct=50;rua=mailto:a@example.test",
		"v=DMARC1 ;  p = quarantine ;\tsp=reject; adkim =s ; pct= 50; rua=mailto:a@example.test;",
		"v=DMARC1; rua=mailto:a@example.test; pct=50; adkim=s; sp=reject; p=quarantine",
		"v=DMARC1; p=quarantine; ; sp=reject;; adkim=s; pct=50; rua=mailto:a@example.test; x=1; future=yes; junk",
	} {
		if got := mustParse(t, rec); !reflect.DeepEqual(got, want) {
			t.Errorf("ParseRecord(%q) = %+v, want %+v", rec, got, want)
		}
	}
}

// TestParseRecordPolicy checks p= and sp= and the §6.6.3 step 6 rule for a
// record without a valid policy: p=none when it names a valid rua= URI, and
// no DMARC otherwise.
//
// checklist: DMARC-REC-08 DMARC-DISC-06 DMARC-DISC-07
func TestParseRecordPolicy(t *testing.T) {
	cases := []struct{ record, p, sp string }{
		{"v=DMARC1; p=none", "none", ""},
		{"v=DMARC1; p=quarantine", "quarantine", ""},
		{"v=DMARC1; p=reject; sp=none", "reject", "none"},
		{"v=DMARC1; p=none; sp=quarantine", "none", "quarantine"},
		// No valid policy, but a valid rua=: read as p=none.
		{"v=DMARC1; rua=mailto:a@example.test", "none", ""},
		{"v=DMARC1; p=bogus; rua=mailto:a@example.test", "none", ""},
		{"v=DMARC1; p=reject; sp=bogus; rua=mailto:a@example.test", "none", ""},
		{"v=DMARC1; p=reject; p=reject; rua=mailto:a@example.test", "none", ""},
		{"v=DMARC1; p=reject; sp=none; sp=none; rua=mailto:a@example.test", "none", ""},
	}
	for _, c := range cases {
		r := mustParse(t, c.record)
		if r.Policy != c.p || r.SubdomainPolicy != c.sp {
			t.Errorf("ParseRecord(%q) p=%q sp=%q, want p=%q sp=%q", c.record, r.Policy, r.SubdomainPolicy, c.p, c.sp)
		}
	}
	// No valid policy and no valid rua=: DMARC does not apply.
	for _, rec := range []string{"v=DMARC1", "v=DMARC1;", "v=DMARC1; p=", "v=DMARC1; p=bogus", "v=DMARC1; p=rejct",
		"v=DMARC1; p=reject; sp=bogus", "v=DMARC1; p=none; p=reject", "v=DMARC1; p=bogus; rua=nonsense",
		"v=DMARC1; sp=reject", "v=DMARC1; p=bogus; ruf=mailto:a@example.test"} {
		if r, err := ParseRecord(rec); !errors.Is(err, ErrNoPolicy) {
			t.Errorf("ParseRecord(%q) = %+v, %v; want ErrNoPolicy", rec, r, err)
		}
	}
}

// TestParsePolicy checks the p=-only shortcut the server uses.
//
// checklist: DMARC-REC-08 DMARC-DISC-06 DMARC-DISC-07
func TestParsePolicy(t *testing.T) {
	cases := []struct{ record, want string }{
		{"v=DMARC1; p=reject; rua=mailto:agg@example.test", "reject"},
		{"v=DMARC1; p=quarantine; pct=50", "quarantine"},
		{"v=DMARC1; P=Reject", "reject"},
		{"v=DMARC1; sp=reject; rua=mailto:agg@example.test", "none"},
	}
	for _, c := range cases {
		if got, err := ParsePolicy(c.record); err != nil || got != c.want {
			t.Errorf("ParsePolicy(%q) = %q, %v; want %q", c.record, got, err, c.want)
		}
	}
	for _, rec := range []string{"", "v=DMARC1; p=bogus", "v=DMARC1; p=none; p=reject", "v=dmarc1; p=reject"} {
		if got, err := ParsePolicy(rec); err == nil {
			t.Errorf("ParsePolicy(%q) = %q, nil; want an error", rec, got)
		}
	}
}

// TestParseRecordCaseInsensitive checks that tag names and the enumerated
// values match in any case, as the ABNF's quoted strings do, while URIs keep
// their case.
//
// checklist: DMARC-REC-17
func TestParseRecordCaseInsensitive(t *testing.T) {
	r := mustParse(t, "V=DMARC1; P=Reject; SP=QUARANTINE; ADKIM=S; Aspf=S; PCT=10; FO=D:S; RF=AFRF; RI=3600; RUF=mailto:Fail@Example.test; RUA=MailTo:Agg@Example.test!10M")
	want := Record{
		Policy: "reject", SubdomainPolicy: "quarantine", ADKIM: AlignmentStrict, ASPF: AlignmentStrict, Pct: 10,
		FailureOptions: []string{"d", "s"}, ReportFormats: []string{"afrf"}, ReportInterval: 3600,
		RUA: []ReportURI{{URI: "MailTo:Agg@Example.test", MaxSize: 10 << 20}},
		RUF: []ReportURI{{URI: "mailto:Fail@Example.test", MaxSize: math.MaxUint64}},
	}
	if !reflect.DeepEqual(r, want) {
		t.Errorf("got %+v\nwant %+v", r, want)
	}
}

// TestParseRecordAlignmentModes checks adkim= and aspf=: s is strict, r and
// anything else relaxed.
//
// checklist: DMARC-REC-10 DMARC-REC-07
func TestParseRecordAlignmentModes(t *testing.T) {
	cases := []struct {
		record     string
		adkim, spf AlignmentMode
	}{
		{"v=DMARC1; p=reject", AlignmentRelaxed, AlignmentRelaxed},
		{"v=DMARC1; p=reject; adkim=r; aspf=r", AlignmentRelaxed, AlignmentRelaxed},
		{"v=DMARC1; p=reject; adkim=s", AlignmentStrict, AlignmentRelaxed},
		{"v=DMARC1; p=reject; aspf=s", AlignmentRelaxed, AlignmentStrict},
		{"v=DMARC1; p=reject; adkim = s; aspf=s", AlignmentStrict, AlignmentStrict},
		{"v=DMARC1; p=reject; adkim=x; aspf=strict", AlignmentRelaxed, AlignmentRelaxed},
	}
	for _, c := range cases {
		r := mustParse(t, c.record)
		if r.ADKIM != c.adkim || r.ASPF != c.spf {
			t.Errorf("ParseRecord(%q) adkim=%v aspf=%v, want %v %v", c.record, r.ADKIM, r.ASPF, c.adkim, c.spf)
		}
	}
}

// TestParseRecordPct checks pct=: one to three digits up to 100, or the
// default of 100.
//
// checklist: DMARC-REC-11 DMARC-REC-07
func TestParseRecordPct(t *testing.T) {
	cases := []struct {
		value string
		want  int
	}{
		{"25", 25}, {"0", 0}, {"100", 100}, {" 50 ", 50}, {"050", 50}, {"007", 7},
		{"101", 100}, {"200", 100}, {"-1", 100}, {"+5", 100}, {"fifty", 100}, {"", 100}, {"0050", 100}, {"5.5", 100},
	}
	for _, c := range cases {
		rec := "v=DMARC1; p=reject; pct=" + c.value
		if got := mustParse(t, rec).Pct; got != c.want {
			t.Errorf("ParseRecord(%q).Pct = %d, want %d", rec, got, c.want)
		}
	}
}

// TestParseRecordInvalidTagsDefault checks that a syntax error in an optional
// tag takes its default and leaves the rest of the record, and the policy,
// alone. (v0.3.0 refused such a record; a typo in pct= then switched a
// domain's reject policy off.)
//
// checklist: DMARC-REC-07
func TestParseRecordInvalidTagsDefault(t *testing.T) {
	got := mustParse(t, "v=DMARC1; p=reject; adkim=x; aspf=; pct=150; fo=2; rf=xml; ri=-5; ruf=mailto:f@example.test")
	want := Record{
		Policy: "reject", ADKIM: AlignmentRelaxed, ASPF: AlignmentRelaxed, Pct: 100,
		FailureOptions: []string{"0"}, ReportFormats: []string{"afrf"}, ReportInterval: 86400,
		RUF: []ReportURI{{URI: "mailto:f@example.test", MaxSize: math.MaxUint64}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

// TestParseRecordDuplicateTags checks that a repeated tag is a syntax error:
// its values are discarded, so a repeated optional tag takes its default and
// a repeated p= leaves no valid policy.
//
// checklist: DMARC-REC-18
func TestParseRecordDuplicateTags(t *testing.T) {
	r := mustParse(t, "v=DMARC1; p=reject; pct=10; pct=20; adkim=s; ADKIM=s")
	if r.Pct != 100 || r.ADKIM != AlignmentRelaxed || r.Policy != "reject" {
		t.Errorf("got %+v, want pct 100, adkim relaxed, p reject", r)
	}
	if _, err := ParseRecord("v=DMARC1; p=reject; P=reject"); !errors.Is(err, ErrNoPolicy) {
		t.Errorf("a repeated p= must leave no policy, got %v", err)
	}
}

// TestParseRecordFailureOptions checks fo=: a colon-separated list of 0, 1, d
// and s, "0" by default, and ignored when the record has no ruf=.
//
// checklist: DMARC-REC-12 DMARC-REC-13 DMARC-REC-07
func TestParseRecordFailureOptions(t *testing.T) {
	const ruf = "; ruf=mailto:f@example.test"
	cases := []struct {
		record string
		want   []string
	}{
		{"v=DMARC1; p=none" + ruf, []string{"0"}},
		{"v=DMARC1; p=none; fo=1" + ruf, []string{"1"}},
		{"v=DMARC1; p=none; fo=0:1:d:s" + ruf, []string{"0", "1", "d", "s"}},
		{"v=DMARC1; p=none; fo= d : s " + ruf, []string{"d", "s"}},
		{"v=DMARC1; p=none; fo=1:x" + ruf, []string{"0"}},
		{"v=DMARC1; p=none; fo=" + ruf, []string{"0"}},
		{"v=DMARC1; p=none; fo=1", []string{"0"}},
		{"v=DMARC1; p=none; fo=1; ruf=nonsense", []string{"0"}},
	}
	for _, c := range cases {
		if got := mustParse(t, c.record).FailureOptions; !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParseRecord(%q).FailureOptions = %q, want %q", c.record, got, c.want)
		}
	}
}

// TestParseRecordReportFormats checks rf=: only the registered afrf format is
// kept, and the default is afrf.
//
// checklist: DMARC-REC-14
func TestParseRecordReportFormats(t *testing.T) {
	for _, v := range []string{"afrf", "AFRF", "iodef:afrf", "iodef", "", "afrf:afrf"} {
		got := mustParse(t, "v=DMARC1; p=none; rf="+v).ReportFormats
		want := []string{"afrf"}
		if v == "afrf:afrf" {
			want = []string{"afrf", "afrf"}
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("rf=%s: ReportFormats = %q, want %q", v, got, want)
		}
	}
}

// TestParseRecordReportInterval checks ri=: an unsigned 32-bit number of
// seconds, 86400 by default.
//
// checklist: DMARC-REC-16 DMARC-REC-07
func TestParseRecordReportInterval(t *testing.T) {
	cases := []struct {
		value string
		want  uint32
	}{{"3600", 3600}, {"0", 0}, {"4294967295", 4294967295}, {"4294967296", 86400}, {"-1", 86400}, {"1h", 86400}, {"", 86400}}
	for _, c := range cases {
		if got := mustParse(t, "v=DMARC1; p=none; ri="+c.value).ReportInterval; got != c.want {
			t.Errorf("ri=%s: ReportInterval = %d, want %d", c.value, got, c.want)
		}
	}
}

// TestParseReportURIs checks rua= and ruf=: comma-separated URIs in order,
// each with an optional "!" size limit in powers of two, invalid ones left
// out.
//
// checklist: DMARC-URI-01 DMARC-URI-02 DMARC-URI-03 DMARC-URI-04 DMARC-URI-05
func TestParseReportURIs(t *testing.T) {
	const max = math.MaxUint64
	cases := []struct {
		value string
		want  []ReportURI
	}{
		{"mailto:a@example.test", []ReportURI{{"mailto:a@example.test", max}}},
		{"mailto:a@example.test,mailto:b@example.test, mailto:c@example.test ,https://r.example.test/x",
			[]ReportURI{{"mailto:a@example.test", max}, {"mailto:b@example.test", max}, {"mailto:c@example.test", max}, {"https://r.example.test/x", max}}},
		{"mailto:a@example.test!100", []ReportURI{{"mailto:a@example.test", 100}}},
		{"mailto:a@example.test!10k", []ReportURI{{"mailto:a@example.test", 10 << 10}}},
		{"mailto:a@example.test!50m", []ReportURI{{"mailto:a@example.test", 50 << 20}}},
		{"mailto:a@example.test!2g", []ReportURI{{"mailto:a@example.test", 2 << 30}}},
		{"mailto:a@example.test!1T", []ReportURI{{"mailto:a@example.test", 1 << 40}}},
		{"mailto:a@example.test!0", []ReportURI{{"mailto:a@example.test", 0}}},
		{"mailto:a@example.test!18446744073709551615", []ReportURI{{"mailto:a@example.test", max}}},
		{"mailto:a@example.test!18446744073709551615k", []ReportURI{{"mailto:a@example.test", max}}},
		// A size that does not fit in 64 bits, or is not a number, makes the
		// URI invalid, and so does an unencoded "!" in it.
		{"mailto:a@example.test!18446744073709551616", nil},
		{"mailto:a@example.test!", nil},
		{"mailto:a@example.test!10x", nil},
		{"mailto:a@example.test!k", nil},
		{"mailto:a!b@example.test!10", nil},
		// An encoded comma or "!" belongs to the URI.
		{"mailto:a%2Cb@example.test,mailto:c%21d@example.test!1k",
			[]ReportURI{{"mailto:a%2Cb@example.test", max}, {"mailto:c%21d@example.test", 1 << 10}}},
		// Not URIs: no scheme, nothing after it, whitespace or control
		// characters inside, a bad scheme.
		{"a@example.test,mailto:,mailto:a b@example.test,mailto:a\x00@example.test,1x:a@example.test,,", nil},
		{"", nil},
	}
	for _, c := range cases {
		got := mustParse(t, "v=DMARC1; p=none; rua="+c.value).RUA
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("rua=%q: got %+v, want %+v", c.value, got, c.want)
		}
	}
}

// TestLookup checks the raw record lookup: non-DMARC TXT records are
// discarded, several DMARC records are no policy, NXDOMAIN is no policy, and a
// transient DNS error is an error.
//
// checklist: DMARC-DISC-03 DMARC-DISC-05 DMARC-DISC-08 DMARC-DISC-09 DMARC-REC-02 DMARC-REC-03
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
	// the §6.4 ABNF (dmarc-version = "v" *WSP "=" *WSP %x44 %x4d %x41 %x52 %x43
	// %x31). The value is case-sensitive: §6.3 says it "MUST match precisely".
	t.Run("version tag matches DMARC1 exactly", func(t *testing.T) {
		cases := []struct {
			name   string
			record string
			// want is the Lookup result: the record itself when it is recognized
			// as a DMARC record, or "" when it must be ignored as non-DMARC.
			want string
		}{
			{"rejects v=DMARC10", "v=DMARC10; p=none", ""},
			{"rejects v=DMARC1x", "v=DMARC1x; p=none", ""},
			{"rejects a lower-case value", "v=dmarc1; p=none", ""},
			{"rejects v= after another tag", "p=none; v=DMARC1", ""},
			{"accepts uppercase tag with WSP before separator", "V=DMARC1 ; p=none", "V=DMARC1 ; p=none"},
			{"accepts whitespace around =", "v = DMARC1; p=none", "v = DMARC1; p=none"},
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

	t.Run("queries the A-label form, and nothing for a non-domain", func(t *testing.T) {
		var queried []string
		resolver := func(name string) ([]string, error) {
			queried = append(queried, name)
			return nil, nil
		}
		for _, d := range []string{"Bücher.Example.", "", "a..b", "exa mple.test"} {
			if rec, err := Lookup(d, resolver); rec != "" || err != nil {
				t.Errorf("Lookup(%q) = %q, %v", d, rec, err)
			}
		}
		if len(queried) != 1 || queried[0] != "_dmarc.xn--bcher-kva.example" {
			t.Errorf("queried %q, want only _dmarc.xn--bcher-kva.example", queried)
		}
	})
}

// TestNilResolverUsesSystemDNS checks that a nil resolver stands for the
// system's (net.LookupTXT), here replaced by a fake so no query leaves the
// machine.
//
// checklist: DMARC-DISC-02
func TestNilResolverUsesSystemDNS(t *testing.T) {
	saved := systemResolver
	defer func() { systemResolver = saved }()
	var queried []string
	systemResolver = func(name string) ([]string, error) {
		queried = append(queried, name)
		return []string{"v=DMARC1; p=reject"}, nil
	}
	if rec, err := Lookup("example.test", nil); err != nil || rec != "v=DMARC1; p=reject" {
		t.Errorf("Lookup = %q, %v", rec, err)
	}
	if p, err := Discover("example.test", nil, nil); err != nil || p.Requested != "reject" {
		t.Errorf("Discover = %+v, %v", p, err)
	}
	if got, err := AuthorizeReportURIs("example.test", "rua", uris("mailto:a@other.test"), nil, nil); err != nil || len(got) != 1 {
		t.Errorf("AuthorizeReportURIs = %+v, %v", got, err)
	}
	want := []string{"_dmarc.example.test", "_dmarc.example.test", "example.test._report._dmarc.other.test"}
	if !reflect.DeepEqual(queried, want) {
		t.Errorf("queried %q, want %q", queried, want)
	}
}
