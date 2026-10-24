package dmarc

import (
	"strings"
	"testing"

	msgauth "github.com/emersion/go-msgauth/dmarc"
)

// The differential tests check the record parser against another
// implementation, github.com/emersion/go-msgauth/dmarc (MIT). go-msgauth is a
// test-only dependency; the library does not import it.
//
// go-msgauth implements RFC 7489, and is stricter than it in some places and
// looser in others; this parser follows RFC 9989, which removed pct=, rf= and
// ri= and added np=, psd= and t=. Where the two disagree on purpose,
// diffRecords says why; everywhere else a record one accepts the other must
// accept with the same p=, sp=, adkim=, aspf=, fo=, rua= and ruf=.

var diffRecords = []struct {
	record string
	// divergence is "" when both parsers must agree, or why they do not.
	divergence string
}{
	{"v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com", ""},
	{"v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com; ruf=mailto:auth-reports@thirdparty.example.net", ""},
	{"v=DMARC1; p=quarantine; rua=mailto:dmarc-feedback@example.com,mailto:tld-test@thirdparty.example.net!10m; pct=25", ""},
	{"v=DMARC1; p=reject; aspf=r; rua=mailto:dmarc-feedback@example.com", ""},
	{"v=DMARC1; p=quarantine; sp=reject; adkim=s; aspf=s; pct=0; fo=1:d:s; rf=afrf; ri=3600; rua=mailto:a@example.com,mailto:b@example.net!10m; ruf=mailto:c@example.org", ""},
	{"v=DMARC1; p=reject; np=quarantine; psd=n; t=y", ""},
	{"v = DMARC1 ;  p = none ;\tsp = quarantine ; adkim = r ;", ""},
	{"v=DMARC1;p=reject;pct=100;", ""},
	{"v=DMARC1; p=none; fo=1; ruf=mailto:f@example.com", ""},
	{"v=DMARC1; p=none; unknown=tag; x-future=1", ""},
	{"v=DMARC1; p=reject; pct=007", ""},
	{"v=DMARC10; p=none", ""},
	{"v=DMARC2; p=none", ""},
	{"v=spf1 -all", ""},
	{"v=DMARC1; p=rejct", ""},
	{"v=DMARC1; p=reject; sp=bogus", ""},
	{"v=dmarc1; p=reject", ""}, // v=DMARC1 is case sensitive (RFC 9989 §4.7); v0.3.0 took it
	{"", ""},

	{"v=DMARC1; p=REJECT", "go-msgauth matches values case-sensitively; RFC 9989's ABNF quotes them, which makes them case-insensitive"},
	{"V=DMARC1; P=reject", "go-msgauth matches tag names case-sensitively; the ABNF's quoted tag names are case-insensitive"},
	{"v=DMARC1; p=reject; pct=150", "go-msgauth refuses the record; pct= is no longer a DMARC tag (RFC 9989), so it is ignored"},
	{"v=DMARC1; p=reject; adkim=x", "go-msgauth refuses the record; RFC 9989 §4.8 says a syntax error takes the default (relaxed)"},
	{"v=DMARC1; p=reject; fo=2; ruf=mailto:f@example.com", "go-msgauth refuses the record; RFC 9989 §4.8 says a syntax error takes the default (fo=0)"},
	{"v=DMARC1; p=none; fo=0:1; ruf=mailto:f@example.com", "go-msgauth takes both; RFC 9989's dmarc-fo makes 0 and 1 exclusive, so the list takes the default"},
	{"v=DMARC1; p=reject; rf=iodef", "go-msgauth refuses the record; rf= is no longer a DMARC tag (RFC 9989), so it is ignored"},
	{"v=DMARC1; p=reject; ri=0", "go-msgauth refuses ri=0; ri= is no longer a DMARC tag (RFC 9989), so it is ignored"},
	{"v=DMARC1; p=reject; junk", "go-msgauth refuses a part without '='; a syntax error is ignored (RFC 9989 §4.8)"},
	{"v=DMARC1; rua=mailto:a@example.com", "go-msgauth needs p=; RFC 9989 §4.10.1 reads a record without one, but with a valid rua=, as p=none"},
	{"v=DMARC1; p=bogus; rua=mailto:a@example.com", "go-msgauth refuses an invalid p=; RFC 9989 §4.10.1 reads it as p=none when rua= is valid"},
	{"v=DMARC1; p=reject; np=bogus; rua=mailto:a@example.com", "go-msgauth does not know np=; RFC 9989 §4.10.1 reads a record with an invalid np= as p=none when rua= is valid"},
	{"p=reject; v=DMARC1", "go-msgauth takes v= anywhere; RFC 9989 §4.7 says it MUST be the first tag"},
	{"v=DMARC1; p=none; p=reject", "go-msgauth lets the last of a repeated tag win; a repeated tag is a syntax error (RFC 6376 §3.2)"},
	{"v=DMARC1; p=none; rua=mailto:r%C3%ABports@example.com", "go-msgauth keeps an internationalized report address; RFC 8616 §6 says rua= and ruf= addresses are conventional"},
}

// TestDifferentialRecords parses each record of diffRecords with both
// parsers. Where they must agree, they accept and reject the same records and
// read the same values; where they diverge, the divergence is real (so the
// list stays honest).
//
// checklist: DMARC-REC-06 DMARC-REC-08 DMARC-REC-10 DMARC-REC-11 DMARC-EAI-03
func TestDifferentialRecords(t *testing.T) {
	for _, c := range diffRecords {
		mine, err := ParseRecord(c.record)
		theirs, theirErr := msgauth.Parse(c.record)
		agree := (err == nil) == (theirErr == nil)
		if agree && err == nil {
			if diff := compareMsgauth(mine, theirs); diff != "" {
				agree = false
				if c.divergence == "" {
					t.Errorf("%q: %s", c.record, diff)
				}
			}
		}
		switch {
		case c.divergence == "" && !agree:
			t.Errorf("%q: here %+v, %v; go-msgauth %+v, %v", c.record, mine, err, theirs, theirErr)
		case c.divergence != "" && agree:
			t.Errorf("%q: listed as a divergence (%s) but both parsers agree", c.record, c.divergence)
		}
	}
}

// compareMsgauth returns how a record go-msgauth accepted differs from ours,
// or "" when every value agrees.
func compareMsgauth(mine Record, theirs *msgauth.Record) string {
	var diffs []string
	check := func(name string, ok bool) {
		if !ok {
			diffs = append(diffs, name)
		}
	}
	check("p", mine.Policy == string(theirs.Policy))
	check("sp", mine.SubdomainPolicy == string(theirs.SubdomainPolicy))
	check("adkim", alignmentLetter(mine.ADKIM) == string(theirs.DKIMAlignment))
	check("aspf", alignmentLetter(mine.ASPF) == string(theirs.SPFAlignment))
	if len(mine.RUF) > 0 && theirs.FailureOptions != 0 {
		var fo msgauth.FailureOptions
		for _, o := range mine.FailureOptions {
			fo |= map[string]msgauth.FailureOptions{"0": msgauth.FailureAll, "1": msgauth.FailureAny, "d": msgauth.FailureDKIM, "s": msgauth.FailureSPF}[o]
		}
		check("fo", fo == theirs.FailureOptions)
	}
	check("rua", sameURIs(mine.RUA, theirs.ReportURIAggregate))
	check("ruf", sameURIs(mine.RUF, theirs.ReportURIFailure))
	if len(diffs) == 0 {
		return ""
	}
	return "values differ: " + strings.Join(diffs, ", ")
}

// sameURIs compares our URIs with go-msgauth's, which keep the "!" size limit
// in the string.
func sameURIs(mine []string, theirs []string) bool {
	if len(mine) != len(theirs) {
		return false
	}
	for i, u := range theirs {
		if uri, _, _ := strings.Cut(u, "!"); uri != mine[i] {
			return false
		}
	}
	return true
}
