package dmarc

import (
	"errors"
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
// checklist: DMARC-REC-13 DMARC-REC-10 DMARC-REC-20 DMARC-REC-21
func TestParseRecordDefaults(t *testing.T) {
	got := mustParse(t, "v=DMARC1; p=reject")
	want := Record{
		Policy:         "reject",
		PSD:            "u",
		ADKIM:          AlignmentRelaxed,
		ASPF:           AlignmentRelaxed,
		FailureOptions: []string{"0"},
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
	want := mustParse(t, "v=DMARC1; p=quarantine; sp=reject; np=reject; adkim=s; rua=mailto:a@example.test")
	for _, rec := range []string{
		"v=DMARC1;p=quarantine;sp=reject;np=reject;adkim=s;rua=mailto:a@example.test",
		"v=DMARC1 ;  p = quarantine ;\tsp=reject; np= reject; adkim =s ; rua=mailto:a@example.test;",
		"v=DMARC1; rua=mailto:a@example.test; adkim=s; np=reject; sp=reject; p=quarantine",
		"v=DMARC1; p=quarantine; ; sp=reject;; np=reject; adkim=s; rua=mailto:a@example.test; x=1; future=yes; junk",
	} {
		if got := mustParse(t, rec); !reflect.DeepEqual(got, want) {
			t.Errorf("ParseRecord(%q) = %+v, want %+v", rec, got, want)
		}
	}
}

// TestParseRecordRemovedTags checks that pct=, rf= and ri=, which RFC 9989
// removed, are unknown tags now: whatever they hold, the record reads as if
// they were absent.
//
// checklist: DMARC-REC-11 DMARC-REC-05
func TestParseRecordRemovedTags(t *testing.T) {
	want := mustParse(t, "v=DMARC1; p=reject; ruf=mailto:f@example.test")
	for _, rec := range []string{
		"v=DMARC1; p=reject; pct=0; ruf=mailto:f@example.test",
		"v=DMARC1; p=reject; pct=50; rf=afrf; ri=3600; ruf=mailto:f@example.test",
		"v=DMARC1; p=reject; pct=bogus; rf=iodef; ri=-1; ruf=mailto:f@example.test",
		"v=DMARC1; p=reject; pct=10; pct=20; ruf=mailto:f@example.test",
	} {
		if got := mustParse(t, rec); !reflect.DeepEqual(got, want) {
			t.Errorf("ParseRecord(%q) = %+v, want %+v", rec, got, want)
		}
	}
}

// TestParseRecordPolicy checks p=, sp= and np= and the §4.10.1 rule for a
// record without a valid policy: p=none when it names a valid rua= URI, and
// no DMARC otherwise.
//
// checklist: DMARC-REC-08 DMARC-REC-19 DMARC-DISC-06 DMARC-DISC-07
func TestParseRecordPolicy(t *testing.T) {
	cases := []struct{ record, p, sp, np string }{
		{"v=DMARC1; p=none", "none", "", ""},
		{"v=DMARC1; p=quarantine", "quarantine", "", ""},
		{"v=DMARC1; p=reject; sp=none", "reject", "none", ""},
		{"v=DMARC1; p=none; sp=quarantine", "none", "quarantine", ""},
		{"v=DMARC1; p=none; np=reject", "none", "", "reject"},
		{"v=DMARC1; p=none; sp=quarantine; np=reject", "none", "quarantine", "reject"},
		// No valid policy, but a valid rua=: read as p=none.
		{"v=DMARC1; rua=mailto:a@example.test", "none", "", ""},
		{"v=DMARC1; p=bogus; rua=mailto:a@example.test", "none", "", ""},
		{"v=DMARC1; p=reject; sp=bogus; rua=mailto:a@example.test", "none", "", ""},
		{"v=DMARC1; p=reject; np=bogus; rua=mailto:a@example.test", "none", "", ""},
		{"v=DMARC1; p=reject; np=; rua=mailto:a@example.test", "none", "", ""},
		{"v=DMARC1; p=reject; p=reject; rua=mailto:a@example.test", "none", "", ""},
		{"v=DMARC1; p=reject; sp=none; sp=none; rua=mailto:a@example.test", "none", "", ""},
		{"v=DMARC1; p=reject; np=none; np=none; rua=mailto:a@example.test", "none", "", ""},
	}
	for _, c := range cases {
		r := mustParse(t, c.record)
		if r.Policy != c.p || r.SubdomainPolicy != c.sp || r.NonExistentPolicy != c.np {
			t.Errorf("ParseRecord(%q) p=%q sp=%q np=%q, want p=%q sp=%q np=%q", c.record,
				r.Policy, r.SubdomainPolicy, r.NonExistentPolicy, c.p, c.sp, c.np)
		}
	}
	// No valid policy and no valid rua=: DMARC does not apply.
	for _, rec := range []string{"v=DMARC1", "v=DMARC1;", "v=DMARC1; p=", "v=DMARC1; p=bogus", "v=DMARC1; p=rejct",
		"v=DMARC1; p=reject; sp=bogus", "v=DMARC1; p=reject; np=bogus", "v=DMARC1; p=none; p=reject",
		"v=DMARC1; p=bogus; rua=nonsense", "v=DMARC1; sp=reject", "v=DMARC1; np=reject",
		"v=DMARC1; p=bogus; ruf=mailto:a@example.test"} {
		if r, err := ParseRecord(rec); !errors.Is(err, ErrNoPolicy) {
			t.Errorf("ParseRecord(%q) = %+v, %v; want ErrNoPolicy", rec, r, err)
		}
	}
}

// TestParsePolicy checks the p=-only shortcut.
//
// checklist: DMARC-REC-08 DMARC-DISC-06 DMARC-DISC-07
func TestParsePolicy(t *testing.T) {
	cases := []struct{ record, want string }{
		{"v=DMARC1; p=reject; rua=mailto:agg@example.test", "reject"},
		{"v=DMARC1; p=quarantine; t=y", "quarantine"},
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
	r := mustParse(t, "V=DMARC1; P=Reject; SP=QUARANTINE; NP=Reject; PSD=N; T=Y; ADKIM=S; Aspf=S; FO=D:S; RUF=mailto:Fail@Example.test; RUA=MailTo:Agg@Example.test!10M")
	want := Record{
		Policy: "reject", SubdomainPolicy: "quarantine", NonExistentPolicy: "reject", PSD: "n", Testing: true,
		ADKIM: AlignmentStrict, ASPF: AlignmentStrict, FailureOptions: []string{"d", "s"},
		RUA: []string{"MailTo:Agg@Example.test"},
		RUF: []string{"mailto:Fail@Example.test"},
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

// TestParseRecordPSD checks psd=: y, n or the default u, an invalid or
// repeated value taking the default.
//
// checklist: DMARC-REC-20 DMARC-REC-07
func TestParseRecordPSD(t *testing.T) {
	for value, want := range map[string]string{"y": "y", "n": "n", "u": "u", "Y": "y", " n ": "n", "": "u", "yes": "u", "x": "u"} {
		if got := mustParse(t, "v=DMARC1; p=none; psd="+value).PSD; got != want {
			t.Errorf("psd=%q: PSD = %q, want %q", value, got, want)
		}
	}
	if got := mustParse(t, "v=DMARC1; p=none; psd=y; psd=y").PSD; got != "u" {
		t.Errorf("a repeated psd= reads as %q, want the default u", got)
	}
}

// TestParseRecordTestMode checks t=: y asks for test mode, and n, the
// default, and anything else do not.
//
// checklist: DMARC-REC-21 DMARC-REC-07
func TestParseRecordTestMode(t *testing.T) {
	for value, want := range map[string]bool{"y": true, "Y": true, " y ": true, "n": false, "": false, "yes": false, "1": false} {
		if got := mustParse(t, "v=DMARC1; p=reject; t="+value).Testing; got != want {
			t.Errorf("t=%q: Testing = %v, want %v", value, got, want)
		}
	}
}

// TestParseRecordInvalidTagsDefault checks that a syntax error in an optional
// tag takes its default and leaves the rest of the record, and the policy,
// alone. (v0.3.0 refused such a record; a typo in an optional tag then
// switched a domain's reject policy off.)
//
// checklist: DMARC-REC-07
func TestParseRecordInvalidTagsDefault(t *testing.T) {
	got := mustParse(t, "v=DMARC1; p=reject; adkim=x; aspf=; psd=maybe; t=sometimes; fo=2; ruf=mailto:f@example.test")
	want := Record{
		Policy: "reject", PSD: "u", ADKIM: AlignmentRelaxed, ASPF: AlignmentRelaxed,
		FailureOptions: []string{"0"}, RUF: []string{"mailto:f@example.test"},
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
	r := mustParse(t, "v=DMARC1; p=reject; t=y; t=y; adkim=s; ADKIM=s")
	if r.Testing || r.ADKIM != AlignmentRelaxed || r.Policy != "reject" {
		t.Errorf("got %+v, want no test mode, adkim relaxed, p reject", r)
	}
	if _, err := ParseRecord("v=DMARC1; p=reject; P=reject"); !errors.Is(err, ErrNoPolicy) {
		t.Errorf("a repeated p= must leave no policy, got %v", err)
	}
}

// TestParseRecordFailureOptions checks fo=: "0" or "1", which exclude each
// other, and "d" and "s", each at most once, "0" by default, and ignored
// when the record has no ruf=.
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
		{"v=DMARC1; p=none; fo=0:d:s" + ruf, []string{"0", "d", "s"}},
		{"v=DMARC1; p=none; fo=d:1:s" + ruf, []string{"d", "1", "s"}},
		{"v=DMARC1; p=none; fo= d : s " + ruf, []string{"d", "s"}},
		{"v=DMARC1; p=none; fo=0:1" + ruf, []string{"0"}},
		{"v=DMARC1; p=none; fo=1:0:d" + ruf, []string{"0"}},
		{"v=DMARC1; p=none; fo=d:d" + ruf, []string{"0"}},
		{"v=DMARC1; p=none; fo=1:s:s" + ruf, []string{"0"}},
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

// TestParseReportURIs checks rua= and ruf=: comma-separated URIs in order,
// the obsolete "!" size limit checked for its syntax and dropped, and invalid
// URIs left out.
//
// checklist: DMARC-URI-01 DMARC-URI-02 DMARC-URI-04 DMARC-URI-05
func TestParseReportURIs(t *testing.T) {
	cases := []struct {
		value string
		want  []string
	}{
		{"mailto:a@example.test", []string{"mailto:a@example.test"}},
		{"mailto:a@example.test,mailto:b@example.test, mailto:c@example.test ,https://r.example.test/x",
			[]string{"mailto:a@example.test", "mailto:b@example.test", "mailto:c@example.test", "https://r.example.test/x"}},
		// The obsolete size limit is dropped, whatever its size.
		{"mailto:a@example.test!100", []string{"mailto:a@example.test"}},
		{"mailto:a@example.test!10k", []string{"mailto:a@example.test"}},
		{"mailto:a@example.test!50m,mailto:b@example.test!2G", []string{"mailto:a@example.test", "mailto:b@example.test"}},
		{"mailto:a@example.test!1T", []string{"mailto:a@example.test"}},
		{"mailto:a@example.test!0", []string{"mailto:a@example.test"}},
		{"mailto:a@example.test!18446744073709551616", []string{"mailto:a@example.test"}},
		// A "!" not followed by a size makes the URI invalid, and so does an
		// unencoded "!" in it.
		{"mailto:a@example.test!", nil},
		{"mailto:a@example.test!10x", nil},
		{"mailto:a@example.test!k", nil},
		{"mailto:a!b@example.test!10", nil},
		// An encoded comma or "!" belongs to the URI.
		{"mailto:a%2Cb@example.test,mailto:c%21d@example.test!1k",
			[]string{"mailto:a%2Cb@example.test", "mailto:c%21d@example.test"}},
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
// checklist: DMARC-DISC-03 DMARC-DISC-08 DMARC-DISC-09 DMARC-REC-02 DMARC-REC-03
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

	// Issue #12: RFC 9989 §4.10 step 2 — if more than one record at the name
	// begins with v=DMARC1, they are all discarded, so the name publishes no
	// usable policy. Returning the first record would make the applied policy
	// depend on non-deterministic DNS ordering.
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
	// publishes no DMARC record. That is "no policy" (RFC 9989 §4.10.1), not a
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
	// RFC 9989 §4.7 (v is the first tag and its value is exactly "DMARC1") and
	// the §4.8 ABNF (dmarc-version = "v" equals %s"DMARC1"). The value is
	// case-sensitive: §4.7 says "The tag value is case sensitive".
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
		if name == "_dmarc.example.test" || name == "example.test._report._dmarc.other.test" {
			return []string{"v=DMARC1; p=reject"}, nil
		}
		return nil, nil
	}
	if rec, err := Lookup("example.test", nil); err != nil || rec != "v=DMARC1; p=reject" {
		t.Errorf("Lookup = %q, %v", rec, err)
	}
	if p, err := Discover("example.test", nil, nil); err != nil || p.Requested != "reject" {
		t.Errorf("Discover = %+v, %v", p, err)
	}
	if got, err := AuthorizeReportURIs("example.test", "rua", []string{"mailto:a@other.test"}, nil); err != nil || len(got) != 1 {
		t.Errorf("AuthorizeReportURIs = %+v, %v", got, err)
	}
	// Lookup and Discover each ask once; the destination check walks the tree
	// for both domains, which have different Organizational Domains, and then
	// asks the destination.
	want := []string{"_dmarc.example.test", "_dmarc.example.test",
		"_dmarc.example.test", "_dmarc.test", "_dmarc.other.test", "_dmarc.test",
		"example.test._report._dmarc.other.test"}
	if !reflect.DeepEqual(queried, want) {
		t.Errorf("queried %q, want %q", queried, want)
	}
}
