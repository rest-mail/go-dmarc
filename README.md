# go-dmarc

[![CI](https://github.com/rest-mail/go-dmarc/actions/workflows/ci.yml/badge.svg)](https://github.com/rest-mail/go-dmarc/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/rest-mail/go-dmarc.svg)](https://pkg.go.dev/github.com/rest-mail/go-dmarc)
[![Go Report Card](https://goreportcard.com/badge/github.com/rest-mail/go-dmarc)](https://goreportcard.com/report/github.com/rest-mail/go-dmarc)

The receiver side of DMARC ([RFC 7489](https://www.rfc-editor.org/rfc/rfc7489))
for Go, from the [REST Mail](https://rest-mail.com) project: policy lookup and
parsing, identifier alignment, and aggregate (rua) report generation. Standard
library only, no external dependencies.

It is checked item by item against the RFC in [CHECKLIST.md](CHECKLIST.md).
RFC 7489 has since been obsoleted by DMARCbis (RFCs 9989, 9990 and 9991, May
2026); the checklist says why it still follows RFC 7489 and where DMARCbis
differs.

## About

DMARC (Domain-based Message Authentication, Reporting, and Conformance) lets the
owner of a From domain publish, at `_dmarc.<domain>`, how receivers should treat
mail that is not authenticated as coming from that domain. A receiver checks
whether a passing SPF or DKIM identifier **aligns** with the From domain; if
neither does, it applies the domain's published policy — `none`, `quarantine`,
or `reject` — and later reports what it observed back to the domain owner.

This package holds no storage or scheduling state. A mail pipeline consults the
policy and alignment primitives per message and records the outcomes however it
likes; a reporter later hands a slice of neutral `AggregateRecord` values to
`BuildReport` to emit the RFC 7489 aggregate-report document.

## Features

- **Record parsing** — `ParseRecord` reads every RFC 7489 tag (`p`, `sp`,
  `adkim`, `aspf`, `pct`, `fo`, `rf`, `ri`, `rua`, `ruf`) into a `Record`, with
  defaults for the tags a record omits or gets wrong, and report URIs with their
  `!` size limits. `ParsePolicy` reads only `p=`.
- **Policy discovery** — `Discover` resolves a From domain's policy with the
  RFC 7489 §6.6.3 organizational-domain fallback (a subdomain with no record of
  its own inherits the org domain's `sp=`/`p=`), and handles a record without a
  valid policy as §6.6.3 step 6 says. `Lookup` fetches a single
  `_dmarc.<domain>` TXT record. Domains are looked up as A-labels.
- **Identifier alignment** — `AlignedMode` evaluates relaxed or strict
  alignment (RFC 7489 §3.1) under the record's `adkim=`/`aspf=` mode;
  `AlignedOrg` and `Aligned` are its relaxed forms.
- **Aggregate reporting** — `AggregateRecords` groups per-message evaluations
  into report rows, `BuildReport` marshals an aggregate report that validates
  against RFC 7489's Appendix C schema (with policy-override reasons such as
  `sampled_out`), `NewPolicyPublished` describes the discovered policy, and
  `Gzip` compresses the report for the `application/gzip` attachment (§7.2.1).
- **External report destinations** — `AuthorizeReportURIs` performs the §7.1
  check that a `rua=`/`ruf=` address outside the domain agreed to receive its
  reports, including the destination's override.
- **Injectable DNS & org-domain** — `Lookup`/`Discover` take a `TXTResolver`
  (its signature matches `net.LookupTXT`) for tests and custom lookups, and
  `Discover` takes an `OrgDomainFunc` for organizational-domain derivation
  (`nil` uses system DNS and the built-in heuristic respectively).
- **Zero external dependencies** — standard library only (the tests use
  go-msgauth and golang.org/x/net; the library does not). Organizational-domain
  derivation defaults to a registry-free heuristic (`DefaultOrgDomain`) that
  takes the last two labels, which is **wrong under multi-label public
  suffixes**: it treats `co.uk` as an organization, so `attacker.co.uk` aligns
  with `victim.co.uk`. Pass a Public Suffix List-backed `OrgDomainFunc` (e.g.
  wrapping `golang.org/x/net/publicsuffix`) wherever that matters:

  ```go
  func orgDomain(domain string) string {
  	org, err := publicsuffix.EffectiveTLDPlusOne(domain)
  	if err != nil {
  		return "" // a public suffix has no Organizational Domain
  	}
  	return org
  }
  ```

## Install

```sh
go get github.com/rest-mail/go-dmarc
```

## Quickstart

Parse a published DMARC record and decide the disposition for one message. A
message passes DMARC only when a passing authenticated identifier (SPF
`smtp.mailfrom` or a verified DKIM `d=`) also *aligns* with the From domain; when
none does, the receiver applies the published policy.

```go
package main

import (
	"fmt"

	"github.com/rest-mail/go-dmarc"
)

func main() {
	// The record published at _dmarc.example.com. In production, discover the
	// policy with dmarc.Discover("example.com", nil, nil) (which also handles the
	// organizational-domain fallback for subdomains); a literal keeps this DNS-free.
	record := "v=DMARC1; p=reject; adkim=r; aspf=r; rua=mailto:agg@example.com"
	policy, err := dmarc.ParsePolicy(record) // "none" | "quarantine" | "reject"
	if err != nil {
		panic(err) // a malformed or duplicated p= value is an unusable record
	}

	// SPF authenticated the envelope sender's domain, but it is an unrelated
	// bulk-sender domain that does not align with the From domain.
	fromDomain := "example.com"
	spfDomain, spfPass := "bounce.marketing.net", true

	dmarcPass := spfPass && dmarc.Aligned(spfDomain, fromDomain)

	disposition := "none"
	if !dmarcPass {
		disposition = policy // apply the published policy to unauthenticated mail
	}
	fmt.Printf("dmarc=%v disposition=%s\n", dmarcPass, disposition)
	// Prints: dmarc=false disposition=reject
}
```

## Aggregate reports

Collect one `AggregateRecord` per evaluated message, then marshal them into the
RFC 7489 aggregate-report document and gzip it for delivery:

```go
meta := dmarc.ReportMetadata{
	OrgName:   "reporter.example",
	Email:     "dmarc@reporter.example",
	ReportID:  "1784700000.example.com@reporter.example",
	DateRange: dmarc.DateRange{Begin: begin, End: end},
}
policy := dmarc.NewPolicyPublished(discovered) // from dmarc.Discover

xmlBytes, err := dmarc.BuildReport(meta, policy, records) // records []dmarc.AggregateRecord
if err != nil {
	panic(err)
}
gz, err := dmarc.Gzip(xmlBytes)
if err != nil {
	panic(err)
}
_ = gz // attach as application/gzip
```

`BuildReport` calls `AggregateRecords` for you (identical rows are summed into a
`count`); call `AggregateRecords` directly if you want the grouped rows without
marshalling. A mechanism counts as passing DMARC only when it both passed *and*
aligned, so `PolicyEvaluated` reflects the DMARC-aligned result, not the raw
SPF/DKIM verdict.

## Choices the RFC leaves open

Where RFC 7489 leaves a detail to the implementation, this package takes the
simplest secure option:

- **Tag names and enumerated values** match in any case (`P=Reject`), as the
  ABNF's quoted strings do, but `v=DMARC1`'s value must be upper case: §6.3
  says it "MUST match precisely".
- **`p=` may come anywhere after `v=`**. §6.3 asks publishers to put it
  second, but refusing records that do not would switch their policy off.
- **A tag with a syntax error, or a repeated tag, takes its default.** A
  repeated or invalid `p=` (or an invalid `sp=`) leaves the record without a
  policy, which §6.6.3 step 6 then settles: `p=none` when `rua=` names a valid
  URI, no DMARC otherwise.
- **A report URI** must be absolute (have a scheme) and contain no whitespace;
  its size limit must fit in 64 bits. Invalid URIs are left out of the list.
- **A domain** must be at most 253 characters of labels of 1 to 63 letters,
  digits, hyphens or underscores, after lower-casing and conversion of
  U-labels to A-labels. Anything else has no policy (no DNS query is sent) and
  never aligns.
- **In a report**, an unknown result or disposition becomes `none`, an
  unknown override reason `other` (keeping its text in the comment), a record
  with no SPF result gets one of `none` for its envelope domain, and IPv6
  source addresses are written in full, as the schema's pattern requires. A
  report with no records, or a source address that is not an IP address, is
  refused.
- **The report's root element** has no XML namespace. The schema names one,
  but no generator in use sets it, and RFC 9990's new schema has a different
  one.

## Testing

```sh
go test -race ./...                 # all tests, no network
go run ./internal/checklist         # CHECKLIST.md and the tests agree
go test -run='^$' -fuzz='^FuzzParseRecord$' -fuzztime=30s .
python3 -m unittest discover -s .github/tests   # what CI passes the shared proof
```

CI runs these through go-spf's reusable
[`rfc-verification.yml`](https://github.com/rest-mail/go-spf/blob/7d291c08d310b9c62afc287e75a534a39150fafb/.github/workflows/rfc-verification.yml),
pinned to that commit; the required `Build & Test` check passes only when it
and the workflow fixtures in [`.github/tests`](.github/tests) both succeed.
CI also fails below 95% statement coverage; the lines left uncovered on
purpose are listed, each with a reason, in [COVERAGE.md](COVERAGE.md). The fuzz
targets are `FuzzParseRecord` (any TXT record, compared with go-msgauth where
both must agree), `FuzzAlignment` (alignment is symmetric, strict implies
relaxed, and the A-labels match golang.org/x/net/idna's punycode),
`FuzzDiscover` (discovery against any records) and `FuzzBuildReport` (any
report validates against the schema); CI runs each for 30 seconds. Their seeds
are in the targets, and inputs that once failed are kept there or in
`testdata/fuzz`.

The RFC's own examples are tests: the records of Appendix B.2 (including the
two report URIs and size limit of B.2.4), the alignment examples of B.1 and
B.3.1, the discovery walk for B.2's domains, and the third-party destination
of B.2.3 and §7.1. Every report shape is validated against the Appendix C
schema, which `schema_test.go` encodes. The Public Suffix List's own test
cases ([`testdata/psl`](testdata/psl), public domain) run through alignment
and discovery with a PSL-backed `OrgDomainFunc`. Differential tests check the
record parser against [go-msgauth](https://github.com/emersion/go-msgauth)
(MIT), listing each place where the two disagree on purpose and why. go-msgauth
and golang.org/x/net are test-only dependencies; the library does not import
them.

### The RFC checklist

[CHECKLIST.md](CHECKLIST.md) lists the RFC's requirements item by item, and a
small program, [`internal/checklist`](internal/checklist/main.go), checks it
against the tests in CI. It is the same program as
[go-spf](https://github.com/rest-mail/go-spf)'s and
[go-dkim](https://github.com/rest-mail/go-dkim)'s; other `go-*` libraries can
copy both.

The checklist is a Markdown file holding one or more tables whose header is
exactly:

```markdown
| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DMARC-REC-03 | 6.3 | MUST | v= is the first tag; a record that starts with another tag is ignored. | `TestParseRecordVersion` |
| DMARC-AGG-08 | 7.2.1 | SHOULD | Use a secure transport. | n/a: the library sends nothing. |
```

- **ID** is unique, upper case, and ends in a number: a prefix for the RFC, an
  area, and a sequence number (`DMARC-REC-03`).
- **Section** is the RFC section (or sections) the requirement comes from.
- **Level** is the RFC 2119 keyword it carries (`MUST`, `MUST NOT`, `SHOULD`,
  `SHOULD NOT`, `RECOMMENDED`, `NOT RECOMMENDED`, `MAY`, ...), or `Normative`
  for normative text without a keyword.
- **Requirement** says what is required, in one line (no `|`).
- **Tests** lists the test functions that cover it, separated by commas, or
  says `n/a:` and why it does not apply.

Each test names the items it covers in its doc comment:

```go
// TestParseRecordVersion checks that v=DMARC1 must be the first tag, with its
// value matched exactly, or the record is not a DMARC record.
//
// checklist: DMARC-REC-02 DMARC-REC-03
func TestParseRecordVersion(t *testing.T) {
```

`go run ./internal/checklist [-file CHECKLIST.md] [package dir ...]` scans the
`_test.go` files of the given package directories (default `.`) and fails when:

- an ID is used twice, or a row is malformed;
- an item names no test and is not marked `n/a`;
- an item lists a test that does not exist, or that does not name the item;
- a test names an item that does not exist, is `n/a`, or does not list it;
- a `Test` or `Fuzz` function names no item (`Example` functions may).

## Documentation

Full API reference:
[pkg.go.dev/github.com/rest-mail/go-dmarc](https://pkg.go.dev/github.com/rest-mail/go-dmarc).

## Changelog

Recent releases — see [CHANGELOG.md](CHANGELOG.md) for the complete history.

- **Unreleased** — breaking: `ParseRecord` and `Record` replace `ParsePct`/`ParseADKIM`/`ParseASPF`, and `Policy` carries the parsed `Record`; invalid optional tags take their defaults and an invalid policy follows §6.6.3 step 6 instead of erroring; `v=DMARC1` is case-sensitive; reports validate against Appendix C (`sp`, `pct`, `fo`, an `spf` result and full IPv6 always written) with override reasons; adds `AuthorizeReportURIs` (§7.1); fixes a quadratic punycode slowdown on long domains; an RFC checklist, a 95% coverage gate, fuzzing and differential tests.
- **v0.3.0** (2026-07-25) — breaking: `ParsePolicy`/`ParsePct` now return errors (invalid `p=`/`pct=` rejected); adds strict-alignment mode (`AlignmentMode`, ADKIM/ASPF) + RFC 7489 App C `rua` XML fixes.
- **v0.2.0** (2026-07-25) — breaking: `AggregateRecord` carries per-identifier `DKIM`/`SPF` auth slices; adds `Discover` with organizational-domain fallback and PSL-backed `AlignedOrg`.
- **v0.1.1** (2026-07-23) — module renamed to `github.com/rest-mail/go-dmarc`.
- **v0.1.0** (2026-07-23) — initial release: DMARC (RFC 7489) policy lookup/parsing, identifier alignment, and aggregate (`rua`) report XML, standard library only.

## License

[MIT](LICENSE) © 2026 rest-mail
