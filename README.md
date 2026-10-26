# go-dmarc

[![CI](https://github.com/rest-mail/go-dmarc/actions/workflows/ci.yml/badge.svg)](https://github.com/rest-mail/go-dmarc/actions/workflows/ci.yml)
[![Coverage gate: >=95%](https://img.shields.io/badge/coverage%20gate-%3E%3D95%25-brightgreen)](COVERAGE.md)
[![Checklist: 82/106 mapped](https://img.shields.io/badge/checklist-82%2F106%20mapped-blue)](CHECKLIST.md)
[![Go Reference](https://pkg.go.dev/badge/github.com/rest-mail/go-dmarc.svg)](https://pkg.go.dev/github.com/rest-mail/go-dmarc/pkg/dmarc)
[![Go Report Card](https://goreportcard.com/badge/github.com/rest-mail/go-dmarc)](https://goreportcard.com/report/github.com/rest-mail/go-dmarc)

The receiver side of DMARC ([RFC 9989]) for Go, from the
[REST Mail](https://rest-mail.com) project: policy discovery with the DNS Tree
Walk, record parsing, identifier alignment, and aggregate report generation
([RFC 9990]). Standard library only: no external dependencies.

DMARC lets the owner of a From domain publish, at `_dmarc.<domain>`, how
receivers should treat mail that is not authenticated as coming from that
domain. A receiver checks whether a passing SPF or DKIM identifier **aligns**
with the From domain; if neither does, it weighs the domain's published policy
(`none`, `quarantine` or `reject`), and later reports what it saw back to the
domain owner.

The package holds no storage or scheduling state. A mail pipeline asks it for
the policy and the alignment of each message and records the outcomes however
it likes; a reporter later hands a slice of `AggregateRecord` values to
`BuildReport` to produce the report. RFC 9989 and RFC 9990 (May 2026) obsolete
RFC 7489; [CHECKLIST.md](CHECKLIST.md) says what changed.

## Contents

- [Install](#install)
- [Packages](#packages)
- [Quick start](#quick-start): [evaluate one message](#evaluate-one-message), [aggregate reports](#aggregate-reports)
- [Features](#features): [choices the RFC leaves open](#choices-the-rfc-leaves-open)
- [What the library does and what the host must do](#what-the-library-does-and-what-the-host-must-do)
- [RFC conformance](#rfc-conformance): [the checklist](#the-rfc-checklist), [what it does not do](#what-it-does-not-do), [badges and coverage](#badges-and-coverage)
- [Changelog](#changelog)
- [Licence](#licence)

## Install

```sh
go get github.com/rest-mail/go-dmarc@latest
```

The module declares go 1.25. go-msgauth and golang.org/x/net appear in
`go.mod` for the tests only; the library does not import them.

## Packages

| Import path | What it holds |
|-------------|---------------|
| `github.com/rest-mail/go-dmarc/pkg/dmarc` | Public API. Policy: `Discover`, `Policy`, `ExistsFunc`, `Lookup`, `ParseRecord`, `Record`, `ParsePolicy`, `ErrNotDMARC` and `ErrNoPolicy`. Alignment: `AlignedMode`, `AlignmentMode` and `OrgDomain`. Reports: `AggregateRecord`, `AggregateRecords`, `BuildReport`, `NewPolicyPublished`, `Gzip`, `ReportFilename`, `ReportSubject`, `AuthorizeReportURIs`, `Namespace` and the report's XML types. DNS: `TXTResolver`. |
| `pkg/dmarc/internal/dnsname` | Internal DNS-name validation, A-label normalization and punycode. |
| `pkg/dmarc/internal/recordgrammar` | Internal tag grammar and report URI parsing. |
| `pkg/dmarc/internal/reportcodec` | Internal RFC 9990 value normalization and attachment identifier validation. |

Policy evaluation and aggregate reporting keep their public API in `pkg/dmarc`.
They share focused internal helpers; callers use the same names and signatures.

Upgrading from v0.5 or earlier: the root package is gone. Import
`github.com/rest-mail/go-dmarc/pkg/dmarc` instead; every name is unchanged.
[CHANGELOG.md](CHANGELOG.md#060---2026-10-26) has the table.

## Quick start

### Evaluate one message

A message passes DMARC only when a passing authenticated identifier (SPF
`smtp.mailfrom` or a verified DKIM `d=`) also aligns with the From domain. When
none does, the receiver weighs the published policy.

```go
package main

import (
	"fmt"
	"log"

	"github.com/rest-mail/go-dmarc/pkg/dmarc"
)

func main() {
	// The domain of the message's From field, and what the SPF and DKIM
	// verifiers found. A nil resolver uses system DNS.
	fromDomain := "example.com"
	spfDomain, spfPass := "bounce.marketing.net", true

	policy, err := dmarc.Discover(fromDomain, nil, nil)
	if err != nil {
		log.Fatal(err) // a DNS failure: the policy cannot be applied (RFC 9989 §5.3.6)
	}
	if policy.Raw == "" {
		fmt.Println("no DMARC policy")
		return
	}

	aligned, err := dmarc.AlignedMode(spfDomain, fromDomain, policy.Record.ASPF, nil)
	if err != nil {
		log.Fatal(err)
	}
	if spfPass && aligned {
		fmt.Println("dmarc=pass")
		return
	}
	// No aligned identifier passed. Applied is the published policy, one
	// level lower in test mode (t=y); local policy has the final say (§5.4).
	fmt.Println("dmarc=fail policy=" + policy.Applied)
}
```

`Example` in [`pkg/dmarc/example_test.go`](pkg/dmarc/example_test.go) runs
the same decision against an injected resolver, with no DNS.

### Aggregate reports

Collect one `AggregateRecord` per evaluated message, then marshal them into the
report and gzip it for delivery:

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
	log.Fatal(err)
}
gz, err := dmarc.Gzip(xmlBytes)
if err != nil {
	log.Fatal(err)
}
// Attach gz as application/gzip under this name, in a message with this Subject.
name, _ := dmarc.ReportFilename("reporter.example", policy.Domain, meta.DateRange, "", true)
subject, _ := dmarc.ReportSubject(policy.Domain, "reporter.example", meta.ReportID)
```

`BuildReport` calls `AggregateRecords` for you (identical rows are summed into a
`count`); call `AggregateRecords` directly for the grouped rows without the
XML. A mechanism counts as passing DMARC only when it both passed and aligned,
so `PolicyEvaluated` holds the DMARC result, not the raw SPF or DKIM verdict.
`Example_aggregateReport` in the same file runs this end to end.

## Features

| Area | RFC | API |
|------|-----|-----|
| Record parsing | RFC 9989 §4.7, §4.8 | `ParseRecord` reads every tag (`p`, `sp`, `np`, `psd`, `t`, `adkim`, `aspf`, `fo`, `rua`, `ruf`) into a `Record`, with defaults for the tags a record omits or gets wrong. `ParsePolicy` reads only `p=`. |
| Policy discovery | RFC 9989 §4.10, §4.10.1 | `Discover` finds an Author Domain's own record, or by the DNS Tree Walk its Organizational Domain's or its Public Suffix Domain's, whose `sp=` applies (`np=` when the domain does not exist). `Policy.Requested` is the published policy and `Policy.Applied` the one to apply. `Lookup` fetches one `_dmarc.<domain>` record. |
| Organizational Domain | RFC 9989 §4.10.2 | `OrgDomain` finds it from the DNS, not from a Public Suffix List. |
| Identifier alignment | RFC 9989 §4.4 | `AlignedMode` compares under relaxed or strict mode (`adkim=`, `aspf=`). |
| Aggregate reports | RFC 9990 §3 | `AggregateRecords` groups evaluations into rows; `BuildReport` writes a report that validates against RFC 9990's Appendix A schema, in its namespace, with policy-override reasons; `NewPolicyPublished` describes the discovered policy; `Gzip`, `ReportFilename` and `ReportSubject` prepare the attachment and the message (§3.5.2). |
| External destinations | RFC 9990 §4 | `AuthorizeReportURIs` checks that a `rua=` or `ruf=` address outside the domain's Organizational Domain agreed to receive its reports, and applies the destination's override. |
| Internationalized names | RFC 8616 §6 | Domains are looked up and compared as A-labels; `rua=` and `ruf=` addresses must be conventional. |
| Injectable DNS | | Every function that queries DNS takes a `TXTResolver`, whose signature matches `net.LookupTXT`; `nil` uses it. |

The tags RFC 9989 removed (`pct`, `rf`, `ri`) are ignored like any unknown
tag, and so is the obsolete `!` size limit of a report URI. No Tree Walk sends
more than eight queries.

### Choices the RFC leaves open

Where RFC 9989 leaves a detail to the implementation, the package takes the
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

## What the library does and what the host must do

Each area below says what go-dmarc handles and what stays with the host, the
mail system that calls it. The [checklist](CHECKLIST.md) records these
boundaries row by row.

### Policy and alignment

The library:

- Finds the policy that applies to an Author Domain, by the Tree Walk when the
  domain publishes none, and lowers it one level in test mode.
- Discards several records at one name and walks on, and treats a record
  without a valid policy as RFC 9989 §4.10.1 says.
- Decides whether an authenticated domain aligns with the From domain, in the
  record's mode.
- Returns every DNS error to the caller.

The host:

- Extracts the Author Domain from the message's From field. The library takes
  a domain, not a message.
- Runs SPF and DKIM verification ([go-spf](https://github.com/rest-mail/go-spf),
  [go-dkim](https://github.com/rest-mail/go-dkim) or others) and passes their
  domains and results.
- Says whether a domain exists, through an `ExistsFunc`, when `np=` matters.
- Decides the disposition. RFC 9989 forbids rejecting mail on `p=reject`
  alone; the library reports the policy, it does not apply it.
- Writes the Authentication-Results header field.

### Aggregate reports

The library:

- Groups evaluations into rows, orders and caps each row's DKIM results
  (§3.1.3), and writes the XML document, valid against the schema.
- Compresses the document and builds the attachment's file name and the
  message's Subject.
- Checks that an external `rua=` destination agreed to receive reports.

The host:

- Stores evaluations, chooses the reporting period, the Report-ID and the
  grouping into one report per policy domain.
- Builds the report message, signs it so it passes DMARC, and sends it over a
  secure transport, at least once every 24 hours.
- Calls `AuthorizeReportURIs` before sending to an external destination.

## RFC conformance

### The RFC checklist

[CHECKLIST.md](CHECKLIST.md) lists the requirements of RFC 9989 and RFC 9990
item by item, with the RFC 8616 rows for internationalized names, and a small
program, [`internal/checklist`](internal/checklist/main.go), checks it against
the tests in CI. It is the same program as the other `go-*` libraries'. Rows
that belong to the host, or that the library does not meet, are `n/a` with the
reason.

The checklist is a Markdown file holding one or more tables whose header is
exactly:

```markdown
| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DMARC-REC-03 | 4.7 | MUST | v= is the first tag; a record that starts with another tag is ignored. | `TestParseRecordVersion`, `TestLookup` |
| DMARC-AGG-08 | RFC 9990 3.5 | SHOULD | Use a secure transport. | n/a: the library sends nothing. |
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

```sh
go run ./internal/checklist pkg/dmarc pkg/dmarc/internal/dnsname pkg/dmarc/internal/recordgrammar pkg/dmarc/internal/reportcodec
```

RFC 9989's own examples are tests: the records of Appendix B.2 (including
B.2.5's two report URIs and test mode), the alignment examples of B.1 and
§4.4, the three Tree Walks of B.4 (with the queries each sends), and the
third-party destination and override of B.2.3 and B.2.4. Every report shape is
validated against RFC 9990's Appendix A schema, namespace included, which
`pkg/dmarc/schema_test.go` encodes. Differential tests check the record parser
against [go-msgauth](https://github.com/emersion/go-msgauth) (MIT, RFC 7489),
listing each place where the two disagree on purpose and why.

### What it does not do

Some gaps are deliberate, and go-dmarc will not fill them. Others are planned,
each with an issue. The checklist records every one as an `n/a` row with its
reason.

#### Not supported, by design

| Area | What go-dmarc does | Why |
|------|--------------------|-----|
| Mail and SMTP | Sends no mail and speaks no SMTP: no report delivery, no rejection during the SMTP transaction. | Delivery, retries and transport security belong to the host's mail system, which already has them. |
| Messages | Takes domains and results, not messages: no From parsing, no SPF evaluation, no DKIM verification, no Authentication-Results field. | Those are separate standards with their own libraries; a DMARC library that parsed mail would duplicate them. |
| Disposition | Reports the requested and applied policy; never decides what happens to a message. | RFC 9989 makes the disposition local policy and forbids rejecting on `p=reject` alone. |
| State | No storage of evaluations and no report scheduling. | The host already has a database and a scheduler; the library stays a set of pure functions over DNS. |
| Public Suffix List | Not used: the Organizational Domain comes from the DNS Tree Walk. | RFC 9989 replaced the list with the Tree Walk. |
| `pct=`, `rf=`, `ri=` and URI size limits | Ignored. | RFC 9989 removed them. |
| Full IDNA2008 mapping | U-labels are lower-cased and converted to A-labels, without NFC normalisation or special folds such as `ß`. | It would need Unicode tables, and matters only for deliberately unusual spellings. |

#### Not planned

| Area | What go-dmarc does |
|------|--------------------|
| Reading reports | Writes aggregate reports but does not parse them: the Report Consumer side is out of scope. |
| Report extensions (RFC 9990 §3.2) | Writes none. |

#### Planned

| Gap | Issue |
|-----|-------|
| Failure reports (RFC 9991): `ruf=` and `fo=` are parsed, but no report is built. | [#43](https://github.com/rest-mail/go-dmarc/issues/43) |

### Badges and coverage

The coverage badge shows the floor CI enforces, not a measured figure; each CI
run prints the measured statement coverage in its **Verify RFC** log. The
lines left uncovered on purpose are listed, each with a reason, in
[COVERAGE.md](COVERAGE.md). The checklist badge counts requirements mapped to
tests over all checklist rows, including the 24 `n/a` rows. `TestReadmeChecklistBadge`
in `internal/checklist` checks it against the checklist and its test mappings,
and the workflow fixtures check the coverage badge.

CI runs the proof through go-spf's reusable
[`rfc-verification.yml`](https://github.com/rest-mail/go-spf/blob/2409e76ef1e501e0222e6c25a0c7a6202de1051b/.github/workflows/rfc-verification.yml),
pinned to that commit: build, vet, golangci-lint, race tests with at least 95%
statement coverage across packages (`-coverpkg=./...`), the checklist, and
30 seconds of each fuzz target. The required `Build & Test` check passes only
when it and the workflow fixtures in
[`.github/tests`](.github/tests) both succeed. To run the same locally:

```sh
go test -race -coverpkg=./... ./...        # all tests, coverage across packages
go run ./internal/checklist pkg/dmarc pkg/dmarc/internal/dnsname \
  pkg/dmarc/internal/recordgrammar pkg/dmarc/internal/reportcodec
go test -run='^$' -fuzz='^FuzzParseRecord$' -fuzztime=30s ./pkg/dmarc
python3 -m unittest discover -s .github/tests   # what CI passes the shared proof
```

Four fuzz targets run in CI: `FuzzParseRecord` (any TXT record, compared with
go-msgauth where both must agree), `FuzzAlignment` (alignment is symmetric,
strict implies relaxed, the Tree Walks stay within their queries, and the
A-labels match golang.org/x/net/idna's punycode), `FuzzDiscover` (discovery
against any records, in at most eight queries) and `FuzzBuildReport` (any
report validates against the schema). Their seeds are in the targets, and
inputs that once failed are kept there or in `testdata/fuzz`.

## Changelog

Recent releases; see [CHANGELOG.md](CHANGELOG.md) for the complete history.

### v0.6.1 (2026-10-26)

DNS names, record grammar and report codecs move into internal packages; the
public API is unchanged. CI's pinned RFC proof measures coverage across
packages with `-coverpkg`.

### v0.6.0 (2026-10-26)

The library moves to `pkg/dmarc` (breaking: import
`github.com/rest-mail/go-dmarc/pkg/dmarc`; every name is unchanged).

### v0.5.0 (2026-10-24)

DMARCbis (breaking). The receiver follows RFC 9989: the DNS Tree Walk finds the
Organizational Domain (`OrgDomain`) and the policy (`Discover`, with the Public
Suffix Domain's record and `np=`), `AlignedMode` and `AuthorizeReportURIs` take
a resolver, `t=` test mode gives `Policy.Applied`, and `pct=`, `rf=`, `ri=` and
URI size limits are ignored. Aggregate reports follow RFC 9990.

### v0.4.1 (2026-10-22)

Internationalized `rua=` and `ruf=` addresses are refused (RFC 8616 §6), and
more checklist rows are proved by tests.

### v0.4.0 (2026-10-17)

Checked against RFC 7489 (breaking): `ParseRecord` and `Record` replace the
single-tag parsers, invalid optional tags take their defaults, reports
validate against the schema with override reasons, and `AuthorizeReportURIs`
checks external destinations. An RFC checklist, a 95% coverage gate, fuzzing
and differential tests. CHANGELOG.md records it under 0.4.1.

### v0.3.0 (2026-07-25)

`ParsePolicy` returns an error for an invalid `p=` (breaking). Strict
alignment.

### v0.2.0 (2026-07-25)

`AggregateRecord` carries DKIM and SPF results per identifier (breaking).
`Discover` falls back to the Organizational Domain.

### v0.1.1 (2026-07-23)

The module is `github.com/rest-mail/go-dmarc`.

### v0.1.0 (2026-07-23)

Policy lookup and parsing, identifier alignment and aggregate report XML
(RFC 7489).

## Licence

[MIT](LICENSE) © 2026 rest-mail

[RFC 9989]: https://www.rfc-editor.org/rfc/rfc9989
[RFC 9990]: https://www.rfc-editor.org/rfc/rfc9990
