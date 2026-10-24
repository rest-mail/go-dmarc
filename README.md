# go-dmarc

[![CI](https://github.com/rest-mail/go-dmarc/actions/workflows/ci.yml/badge.svg)](https://github.com/rest-mail/go-dmarc/actions/workflows/ci.yml)
[![Coverage gate: >=95%](https://img.shields.io/badge/coverage%20gate-%3E%3D95%25-brightgreen)](COVERAGE.md)
[![Checklist: 82/106 mapped](https://img.shields.io/badge/checklist-82%2F106%20mapped-blue)](CHECKLIST.md)
[![Go Reference](https://pkg.go.dev/badge/github.com/rest-mail/go-dmarc.svg)](https://pkg.go.dev/github.com/rest-mail/go-dmarc)
[![Go Report Card](https://goreportcard.com/badge/github.com/rest-mail/go-dmarc)](https://goreportcard.com/report/github.com/rest-mail/go-dmarc)

The receiver side of DMARC ([RFC 9989](https://www.rfc-editor.org/rfc/rfc9989))
for Go, from the [REST Mail](https://rest-mail.com) project: policy lookup and
parsing with the DNS Tree Walk, identifier alignment, and aggregate (rua)
report generation ([RFC 9990](https://www.rfc-editor.org/rfc/rfc9990)).
Standard library only, no external dependencies.

It is checked item by item against the RFCs in [CHECKLIST.md](CHECKLIST.md).
RFC 9989 and RFC 9990 (May 2026) obsolete RFC 7489; the checklist says what
changed.

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
`BuildReport` to emit the aggregate-report document.

## Features

- **Record parsing** — `ParseRecord` reads every RFC 9989 tag (`p`, `sp`,
  `np`, `psd`, `t`, `adkim`, `aspf`, `fo`, `rua`, `ruf`) into a `Record`, with
  defaults for the tags a record omits or gets wrong. The tags RFC 9989
  removed (`pct`, `rf`, `ri`) are ignored like any unknown tag, and so is the
  obsolete `!` size limit of a report URI. `ParsePolicy` reads only `p=`.
- **Policy discovery** — `Discover` finds an Author Domain's policy (RFC 9989
  §4.10.1): its own record, or else, by the DNS Tree Walk (§4.10), its
  Organizational Domain's or its Public Suffix Domain's, whose `sp=` applies
  (or `np=` when the domain does not exist, asked through an `ExistsFunc`).
  `Policy.Requested` is the policy published and `Policy.Applied` the one to
  apply, one level lower in test mode (`t=y`). `Lookup` fetches a single
  `_dmarc.<domain>` TXT record. Domains are looked up as A-labels, and no
  walk sends more than eight queries.
- **Identifier alignment** — `AlignedMode` evaluates relaxed or strict
  alignment (RFC 9989 §4.4) under the record's `adkim=`/`aspf=` mode;
  `OrgDomain` finds the Organizational Domain relaxed alignment compares
  (§4.10.2), from DNS rather than a Public Suffix List.
- **Aggregate reporting** — `AggregateRecords` groups per-message evaluations
  into report rows, `BuildReport` marshals an aggregate report that validates
  against RFC 9990's Appendix A schema, in its namespace (with policy-override
  reasons), `NewPolicyPublished` describes the discovered policy, `Gzip`
  compresses the report for the `application/gzip` attachment, and
  `ReportFilename` and `ReportSubject` name the attachment and the message
  (§3.5.2).
- **External report destinations** — `AuthorizeReportURIs` performs the check
  that a `rua=`/`ruf=` address outside the domain's Organizational Domain
  agreed to receive its reports, including the destination's override.
- **Injectable DNS** — every function that queries DNS takes a `TXTResolver`
  (its signature matches `net.LookupTXT`, and `nil` uses it) for tests and
  custom lookups.
- **Zero external dependencies** — standard library only (the tests use
  go-msgauth and golang.org/x/net; the library does not).

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
	// policy with dmarc.Discover("example.com", nil, nil) (which also walks the
	// DNS tree for subdomains); a literal keeps this DNS-free.
	record := "v=DMARC1; p=reject; adkim=r; aspf=r; rua=mailto:agg@example.com"
	policy, err := dmarc.ParsePolicy(record) // "none" | "quarantine" | "reject"
	if err != nil {
		panic(err) // a malformed or duplicated p= value is an unusable record
	}

	// SPF authenticated the envelope sender's domain, but it is an unrelated
	// bulk-sender domain that does not align with the From domain.
	fromDomain := "example.com"
	spfDomain, spfPass := "bounce.marketing.net", true

	// Relaxed alignment compares Organizational Domains, which a DNS Tree Walk
	// finds; pass nil for system DNS.
	aligned, err := dmarc.AlignedMode(spfDomain, fromDomain, dmarc.AlignmentRelaxed, nil)
	if err != nil {
		panic(err) // a DNS failure: the policy cannot be applied (RFC 9989 §5.3.6)
	}
	dmarcPass := spfPass && aligned

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
aggregate-report document and gzip it for delivery:

```go
meta := dmarc.ReportMetadata{
	OrgName:   "reporter.example",
	Email:     "dmarc@reporter.example",
	ReportID:  "1784700000.example.com@reporter.example",
	DateRange: dmarc.DateRange{Begin: begin, End: end},
	Generator: "my-mta 1.0",
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
// Attach gz as application/gzip under this name, in a message with this Subject.
name, _ := dmarc.ReportFilename("reporter.example", policy.Domain, meta.DateRange, "", true)
subject, _ := dmarc.ReportSubject(policy.Domain, "reporter.example", meta.ReportID)
```

`BuildReport` calls `AggregateRecords` for you (identical rows are summed into a
`count`); call `AggregateRecords` directly if you want the grouped rows without
marshalling. A mechanism counts as passing DMARC only when it both passed *and*
aligned, so `PolicyEvaluated` reflects the DMARC-aligned result, not the raw
SPF/DKIM verdict.

## Choices the RFC leaves open

Where RFC 9989 leaves a detail to the implementation, this package takes the
simplest secure option:

- **Tag names and enumerated values** match in any case (`P=Reject`), as the
  ABNF's quoted strings do, but `v=DMARC1`'s value must be upper case: §4.7
  says it "is case sensitive".
- **A tag with a syntax error, or a repeated tag, takes its default.** A
  repeated or invalid `p=` (or an invalid `sp=` or `np=`) leaves the record
  without a policy, which §4.10.1 then settles: `p=none` when `rua=` names a
  valid URI, no DMARC otherwise. A record without a valid policy still counts
  in the Tree Walk, so its `psd=` decides the Organizational Domain.
- **A report URI** must be absolute (have a scheme) and contain no whitespace,
  and an obsolete size limit after it must be digits with an optional unit;
  the limit itself is dropped. Invalid URIs are left out of the list.
- **Whether a domain exists** for `np=` is the caller's to say: `Discover`
  asks its `ExistsFunc` only when the record that applies has `np=`, and with
  none takes the domain to exist.
- **A DNS error** during discovery or alignment is returned, so the caller
  decides whether to fail open or closed (§4.10.1, §5.3.6).
- **A domain** must be at most 253 characters of labels of 1 to 63 letters,
  digits, hyphens or underscores, after lower-casing and conversion of
  U-labels to A-labels. Anything else has no policy (no DNS query is sent) and
  never aligns.
- **In a report**, an unknown result or disposition becomes `none`, an
  unknown override reason `other` (keeping its text in the comment, as RFC
  7489's `forwarded` and `sampled_out` do), each value of policy_published
  the caller leaves empty takes its default, and a record SPF did not check
  has no `spf` result. A report with no records, or a source address that is
  not an IP address, is refused.

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
relaxed, the Tree Walks stay within their queries, and the A-labels match
golang.org/x/net/idna's punycode), `FuzzDiscover` (discovery against any
records, in at most eight queries) and `FuzzBuildReport` (any report validates
against the schema); CI runs each for 30 seconds. Their seeds
are in the targets, and inputs that once failed are kept there or in
`testdata/fuzz`.

The coverage badge shows the enforced minimum; measured statement coverage
is printed in each CI run's **Verify RFC** log. The checklist badge counts
requirements mapped to tests over all checklist rows, including the 24
`n/a` rows with documented reasons. CI checks the badge against the actual
checklist and its test mappings. The CI badge reports whether verification
passed.

RFC 9989's own examples are tests: the records of Appendix B.2 (including
B.2.5's two report URIs and test mode), the alignment examples of B.1 and
§4.4, the three Tree Walks of B.4 (with the queries each sends), and the
third-party destination and override of B.2.3 and B.2.4. Every report shape is
validated against RFC 9990's Appendix A schema, namespace included, which
`schema_test.go` encodes. Differential tests check the record parser against
[go-msgauth](https://github.com/emersion/go-msgauth) (MIT, RFC 7489), listing
each place where the two disagree on purpose and why. go-msgauth and
golang.org/x/net are test-only dependencies; the library does not import
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

- **Unreleased** — breaking: DMARCbis. The receiver side follows RFC 9989: the DNS Tree Walk finds the Organizational Domain (`OrgDomain`) and the policy (`Discover`, with the PSD's record and `np=`), `AlignedMode` and `AuthorizeReportURIs` take a resolver, `t=` test mode gives `Policy.Applied`, and `pct=`, `rf=`, `ri=` and URI size limits are ignored. Aggregate reports follow RFC 9990 (namespace, `np`, `testing`, `discovery_method`, one MAIL FROM `spf`, `ReportFilename`, `ReportSubject`).
- **v0.4.1** (2026-10-22) — breaking: `ParseRecord` and `Record` replace `ParsePct`/`ParseADKIM`/`ParseASPF`, and `Policy` carries the parsed `Record`; invalid optional tags take their defaults and an invalid policy follows §6.6.3 step 6 instead of erroring; `v=DMARC1` is case-sensitive; reports validate against Appendix C (`sp`, `pct`, `fo`, an `spf` result and full IPv6 always written) with override reasons; adds `AuthorizeReportURIs` (§7.1); fixes a quadratic punycode slowdown on long domains; an RFC checklist, a 95% coverage gate, fuzzing and differential tests.
- **v0.3.0** (2026-07-25) — breaking: `ParsePolicy`/`ParsePct` now return errors (invalid `p=`/`pct=` rejected); adds strict-alignment mode (`AlignmentMode`, ADKIM/ASPF) + RFC 7489 App C `rua` XML fixes.
- **v0.2.0** (2026-07-25) — breaking: `AggregateRecord` carries per-identifier `DKIM`/`SPF` auth slices; adds `Discover` with organizational-domain fallback and PSL-backed `AlignedOrg`.
- **v0.1.1** (2026-07-23) — module renamed to `github.com/rest-mail/go-dmarc`.
- **v0.1.0** (2026-07-23) — initial release: DMARC (RFC 7489) policy lookup/parsing, identifier alignment, and aggregate (`rua`) report XML, standard library only.

## License

[MIT](LICENSE) © 2026 rest-mail
