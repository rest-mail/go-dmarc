# go-dmarc

[![CI](https://github.com/rest-mail/go-dmarc/actions/workflows/ci.yml/badge.svg)](https://github.com/rest-mail/go-dmarc/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/rest-mail/go-dmarc.svg)](https://pkg.go.dev/github.com/rest-mail/go-dmarc)
[![Go Report Card](https://goreportcard.com/badge/github.com/rest-mail/go-dmarc)](https://goreportcard.com/report/github.com/rest-mail/go-dmarc)

The receiver side of DMARC ([RFC 7489](https://www.rfc-editor.org/rfc/rfc7489))
for Go — policy lookup and parsing, identifier alignment, and aggregate (rua)
report generation. Standard library only, no external dependencies.

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

- **Policy discovery** — `Discover` resolves a From domain's policy with the
  RFC 7489 §6.6.3 organizational-domain fallback (a subdomain with no record of
  its own inherits the org domain's `sp=`/`p=`) and exposes the record's `pct=`
  sampling rate on `Policy.Pct`; `Lookup` fetches a single `_dmarc.<domain>` TXT
  record, `ParsePolicy` reads its `p=` tag (validated against
  `none`/`quarantine`/`reject`; an unrecognised or duplicated value is a
  malformed record, not a raw pass-through), and `ParsePct` reads its `pct=` tag
  (0–100, default 100) so a staged rollout can be applied to a sample of failing
  messages rather than always at 100% (§6.6.4).
- **Identifier alignment** — `Aligned` implements DMARC relaxed alignment
  (RFC 7489 §3.1) between an authenticated domain and the From domain, and
  `AlignedMode` honours a record's `adkim=`/`aspf=` mode (`ParseADKIM`/
  `ParseASPF`, also on `Policy.ADKIM`/`Policy.ASPF`) so strict alignment
  (§6.3, §10.4) can require an exact FQDN match.
- **Aggregate reporting** — `AggregateRecords` groups per-message evaluations
  into report rows, `BuildReport` marshals the RFC 7489 aggregate-report XML, and
  `Gzip` compresses it for the `application/gzip` attachment (§7.2.1).
- **Injectable DNS & org-domain** — `Lookup`/`Discover` take a `TXTResolver`
  (its signature matches `net.LookupTXT`) for tests and custom lookups, and
  `Discover` takes an `OrgDomainFunc` for organizational-domain derivation
  (`nil` uses system DNS and the built-in heuristic respectively).
- **Zero external dependencies** — standard library only. Organizational-domain
  derivation defaults to a registry-free heuristic (`DefaultOrgDomain`); pass a
  Public Suffix List-backed `OrgDomainFunc` (e.g. wrapping
  `golang.org/x/net/publicsuffix`) when you need multi-label public suffixes.

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
policy := dmarc.PolicyPublished{Domain: "example.com", ADKIM: "r", ASPF: "r", P: "reject", PCT: 100}

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

## Documentation

Full API reference:
[pkg.go.dev/github.com/rest-mail/go-dmarc](https://pkg.go.dev/github.com/rest-mail/go-dmarc).

## Changelog

Recent releases — see [CHANGELOG.md](CHANGELOG.md) for the complete history.

- **v0.3.0** (2026-07-25) — breaking: `ParsePolicy`/`ParsePct` now return errors (invalid `p=`/`pct=` rejected); adds strict-alignment mode (`AlignmentMode`, ADKIM/ASPF) + RFC 7489 App C `rua` XML fixes.
- **v0.2.0** (2026-07-25) — breaking: `AggregateRecord` carries per-identifier `DKIM`/`SPF` auth slices; adds `Discover` with organizational-domain fallback and PSL-backed `AlignedOrg`.
- **v0.1.1** (2026-07-23) — module renamed to `github.com/rest-mail/go-dmarc`.
- **v0.1.0** (2026-07-23) — initial release: DMARC (RFC 7489) policy lookup/parsing, identifier alignment, and aggregate (`rua`) report XML, standard library only.

## License

[MIT](LICENSE) © 2026 rest-mail
