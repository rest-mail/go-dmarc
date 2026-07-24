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

- **Policy discovery** — `Lookup` fetches the `_dmarc.<domain>` TXT record and
  `ParsePolicy` reads its requested policy (`p=`).
- **Identifier alignment** — `Aligned` implements DMARC relaxed alignment
  (RFC 7489 §3.1) between an authenticated domain and the From domain.
- **Aggregate reporting** — `AggregateRecords` groups per-message evaluations
  into report rows, `BuildReport` marshals the RFC 7489 aggregate-report XML, and
  `Gzip` compresses it for the `application/gzip` attachment (§7.2.1).
- **Injectable DNS** — `Lookup` takes a `TXTResolver` (its signature matches
  `net.LookupTXT`) for tests and custom lookups, or `nil` for system DNS.
- **Zero external dependencies** — standard library only.

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
	// The record published at _dmarc.example.com. In production this comes from
	// dmarc.Lookup("example.com", nil); a literal keeps the example DNS-free.
	record := "v=DMARC1; p=reject; adkim=r; aspf=r; rua=mailto:agg@example.com"
	policy := dmarc.ParsePolicy(record) // "none" | "quarantine" | "reject"

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

## License

[MIT](LICENSE) © 2026 rest-mail
