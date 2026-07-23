# dmarc

[![CI](https://github.com/rest-mail/dmarc/actions/workflows/ci.yml/badge.svg)](https://github.com/rest-mail/dmarc/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/rest-mail/dmarc.svg)](https://pkg.go.dev/github.com/rest-mail/dmarc)

The receiver side of DMARC ([RFC 7489](https://www.rfc-editor.org/rfc/rfc7489))
for Go, with zero external dependencies (standard library only): policy lookup
and parsing, identifier alignment, and aggregate (rua) report XML generation.

The package holds no storage or scheduling state. A mail pipeline consults the
policy/alignment primitives per message and records the outcomes however it
likes; a reporter later hands a slice of neutral `AggregateRecord` values to
`BuildReport` to emit the RFC 7489 aggregate-report document.

- **`Lookup` / `ParsePolicy`** — fetch the `_dmarc.<domain>` TXT record and read
  its published policy (`p=`). `Lookup` takes an injectable `TXTResolver` (its
  signature matches `net.LookupTXT`), or `nil` for system DNS.
- **`Aligned`** — DMARC relaxed identifier alignment (RFC 7489 §3.1) between an
  authenticated domain (from SPF `smtp.mailfrom` or a DKIM signature's `d=`) and
  the From domain.
- **`AggregateRecords` / `BuildReport` / `Gzip`** — group per-message
  evaluations into report rows and marshal the aggregate-report XML, ready to be
  gzipped and attached per RFC 7489 §7.2.1.

## Install

```sh
go get github.com/rest-mail/dmarc
```

## Evaluate a message

```go
record, err := dmarc.Lookup("example.com", nil)
if err != nil || record == "" {
	// No DMARC record (or lookup failed): DMARC does not apply.
	return
}
policy := dmarc.ParsePolicy(record) // "none" | "quarantine" | "reject"

// authDomain comes from an SPF smtp.mailfrom or a verified DKIM d=.
aligned := dmarc.Aligned(authDomain, "example.com")
if !aligned && policy == "reject" {
	// reject per published policy
}
```

## Build an aggregate report

```go
meta := dmarc.ReportMetadata{
	OrgName:   "reporter.example",
	Email:     "dmarc-reports@reporter.example",
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

## License

[MIT](LICENSE) © 2026 rest-mail
