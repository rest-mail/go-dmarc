# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Note: pre-1.0, breaking changes may ship in a minor release.

## [Unreleased]

go-dmarc now meets the standard of rest-mail/rest-mail-server#374: an RFC
7489 checklist checked in CI, a 95% coverage gate, fuzzing, the RFC's examples
as tests, and differential tests against go-msgauth. Writing the checklist
and fuzzing found the bugs fixed below. The module is v0.x and its only user
is REST Mail's server, so where compatibility would cost anything this is a
clean break. The checklist follows RFC 7489, although DMARCbis (RFC 9989, 9990
and 9991) obsoleted it in May 2026; CHECKLIST.md says why and where they
differ.

### Breaking

- **`ParseRecord` and `Record` replace `ParsePct`, `ParseADKIM` and
  `ParseASPF`.** `ParseRecord` reads every tag (`p`, `sp`, `adkim`, `aspf`,
  `pct`, `fo`, `rf`, `ri`, `rua`, `ruf`) with its default, and the report URIs
  with their size limits (`ReportURI`). It returns `ErrNotDMARC` for a record
  that does not start with `v=DMARC1`, and `ErrNoPolicy` for one with no valid
  policy and no valid `rua=` (RFC 7489 §6.6.3 step 6).
- **`Policy` carries the parsed record.** `Policy.Record` is now the
  `Record`, `Policy.Raw` the TXT string (what `Policy.Record` used to be), and
  `Policy.Pct`, `Policy.ADKIM` and `Policy.ASPF` moved to `Policy.Record`.
- **A record with an invalid optional tag is no longer refused.** A `pct=`,
  `adkim=`, `aspf=`, `fo=`, `rf=` or `ri=` with a syntax error, or a repeated
  tag, takes its default, as §6.3 says it should; `Discover` used to return an
  error for a bad `pct=`, which a caller could not tell from a DNS failure, so
  a typo switched off a domain's `p=reject`.
- **A record without a valid policy follows §6.6.3 step 6.** A missing,
  invalid or repeated `p=`, or an invalid `sp=`, reads as `p=none` when the
  record names a valid `rua=` URI (so its reports still flow), and leaves DMARC
  unapplied otherwise. `Discover` no longer returns an error for it, and
  `ParsePolicy` returns `none` or an error accordingly (a record without `p=`
  or `rua=` used to read as `none`; it is now `ErrNoPolicy`).
- **`v=DMARC1` is matched exactly.** `v=dmarc1` is not a DMARC record, as §6.3
  ("MUST match precisely") and the ABNF's `%x44 %x4d ...` require; v0.3.0
  accepted it.
- **`BuildReport` refuses** a report with no records, and a record whose
  `SourceIP` is not an IP address, both of which the schema forbids.
- **`PolicyPublished` always writes `sp`, `pct` and `fo`**, which the schema
  requires: an empty `SP` is written as `P`, an empty `FO` as `0`, and `PCT`
  as given (it used to be left out when 0). It gains the `FO` field.

### Added

- README coverage-gate and RFC checklist badges, checked in CI against the
  enforced coverage minimum and the checklist's actual test mappings.
- `AuthorizeReportURIs`, the §7.1 check that a `rua=` or `ruf=` address
  outside the domain's Organizational Domain agreed to receive its reports
  (a `v=DMARC1` record at `<domain>._report._dmarc.<host>`), with the
  destination's override.
- `NewPolicyPublished`, which fills `policy_published` from a discovered
  `Policy`.
- Policy-override reasons: `AggregateRecord.Reasons` and
  `PolicyEvaluated.Reasons` report why a disposition differs from the
  published policy (`sampled_out`, `forwarded`, `trusted_forwarder`,
  `mailing_list`, `local_policy`, `other`), as RFC 7489 §6 asks.
- `CHECKLIST.md`, which maps every receiver and reporter requirement of RFC
  7489 to its tests (95 items: 62 tested, 33 not applicable with a reason),
  and `internal/checklist`, copied from go-spf and go-dkim, which checks the
  two agree in CI.
- A CI gate at 95% statement coverage (99.3% now), with `COVERAGE.md` listing
  what is left uncovered and why.
- Four fuzz targets, each run for 30 seconds in CI: record parsing (compared
  with go-msgauth), alignment (compared with golang.org/x/net/idna's
  punycode), policy discovery, and report building (validated against the
  schema).
- Tests from the RFC: the records of Appendix B.2, the alignment examples of
  B.1 and B.3.1, the discovery walk for B.2's domains, the third-party
  destinations of B.2.3 and §7.1, and every report shape validated against
  the Appendix C schema. The Public Suffix List's own test cases run through
  alignment and discovery with a PSL-backed `OrgDomainFunc`.
- Differential tests against `github.com/emersion/go-msgauth/dmarc` (MIT,
  test-only), which list each place the two parsers disagree on purpose.
  golang.org/x/net is also a test-only dependency; the library still imports
  only the standard library.

### Fixed

Found by writing the checklist and by fuzzing:

- **A long Unicode domain took quadratic time.** Punycode encoding is
  quadratic in a label's length, and nothing bounded it: a 16,000-character
  From domain took 1.5 s in `Aligned`, a megabyte minutes. A name longer than
  a DNS name can be is now refused before it is encoded. (Found by
  `FuzzAlignment`.)
- **Domains were queried as given.** `Discover` and `Lookup` sent a U-label,
  an upper-case name or one with a root dot to the resolver as it was; they
  now query the A-label (§6.6.1), and send nothing for a string that is not a
  domain. A root dot also made `Discover` query the same domain twice.
- **Strings that are not domains aligned with themselves**: `Aligned("..",
  "..")` was true.
- **An invalid `sp=` was ignored for the domain's own policy**, and `p=` was
  applied; §6.6.3 step 6 covers an invalid `sp=` too.
- **The aggregate report did not validate against Appendix C**: `sp`, `pct`
  and `fo` were left out of `policy_published`, a message without an SPF
  result had no `spf` element, compressed IPv6 addresses do not match the
  schema's pattern, and an `adkim`/`aspf` value other than `r` or `s` was
  written as given.
- An `OrgDomainFunc` result was used as given; it is now normalized, and one
  that is not a domain counts as none.

## [0.3.0] - 2026-07-25

### Breaking

- **`ParsePolicy` now returns `(string, error)`.** A record whose `p=` (or
  `sp=`) value is not one of `none`, `quarantine`, or `reject`, or that repeats
  the tag, is rejected with an error instead of having its raw value returned;
  per RFC 7489 §6.6.3 such a record is treated as publishing no policy rather
  than applying an unintended disposition. Callers must handle the returned
  error (the unexported subdomain-policy parser changed the same way).
- **`ParsePct` returns `(int, error)`.** The new `pct=` reader rejects a value
  outside the range 0–100, or one that is not an integer, as a malformed record
  rather than applying it.
- **Strict alignment.** `adkim=` / `aspf=` (RFC 7489 §6.3) are now parsed with
  the new **`ParseADKIM`** / **`ParseASPF`** functions into the new
  **`AlignmentMode`** type (`AlignmentRelaxed` — the default — or
  `AlignmentStrict`), and **`Policy.ADKIM`** / **`Policy.ASPF`** expose the modes
  from `Discover`. The new **`AlignedMode`** evaluates alignment under a given
  mode: strict requires an exact FQDN match (the §10.4 mitigation against a
  hostile delegated subdomain), while relaxed is unchanged from `AlignedOrg`.
  `Aligned` and `AlignedOrg` keep their relaxed semantics, so records without
  the tags behave exactly as before.

### Added

- **`pct=` sampling rate.** `Discover` now reads the `pct=` tag (RFC 7489 §6.3)
  and exposes it on the new **`Policy.Pct`** field (0–100, defaulting to 100
  when the tag is absent), so a receiver can apply the requested policy to a
  random sample of failing messages for a staged rollout (§6.6.4) instead of
  enforcing it at 100%. **`ParsePct`** parses the tag directly.

### Fixed

- **Multiple DMARC records are now discarded rather than resolved first-wins.**
  A name that publishes more than one `v=DMARC1` record is an ambiguous set (RFC
  7489 §6.6.3 step 5): `Lookup` returns no record and `Discover` returns a
  no-policy result without falling back to the organizational domain, instead of
  non-deterministically selecting whichever record the resolver happened to list
  first. A single record, and non-DMARC TXT records at the name, behave as
  before.
- **Aggregate (`rua`) report XML is now valid per RFC 7489 Appendix C.** The
  report emits the required `envelope_from` and `spf` `scope` elements,
  normalises result and disposition values to their closed enumerations
  (defaulting unknown or empty values to `none`), and groups rows by the
  normalised results, so a validating report consumer accepts the document.
- **The `v=DMARC1` version tag is matched as a complete token.** Longer tokens
  such as `v=DMARC10` or `v=DMARC1x` are no longer accepted as DMARC records,
  while ABNF-legal forms with whitespace around `=` and a mixed-case tag
  name/value (`V=DMARC1`, `v = DMARC1`) are now recognised.
- **Alignment inputs are sanitised before comparison** (RFC 7489 §3.1): an empty
  identifier never aligns, a trailing root dot is stripped, and each label is
  lower-cased and folded to its ASCII (`xn--` punycode) form so a Unicode domain
  and its encoded equivalent compare as one name. This closes a false DMARC pass
  on unnormalised or empty identifiers.
- **Tag names and enumerated policy values are matched case-insensitively** (RFC
  7489 §6.3/§6.4). A record such as `P=reject` or `p=REJECT` is now parsed and
  enforced correctly instead of silently defaulting to `none` or slipping past a
  downstream `== "reject"` comparison.

## [0.2.0] - 2026-07-25

### Breaking

- **`AggregateRecord` now carries authentication results as slices instead of
  scalars.** The four fields `DKIMResult string`, `DKIMAligned bool`,
  `SPFResult string`, and `SPFAligned bool` are removed and replaced by two
  slice fields:

  ```go
  DKIM []DKIMAuth
  SPF  []SPFAuth
  ```

  Each element carries its own authenticating domain — a DKIM signature's `d=`
  domain (and optional `s=` selector), or an SPF check's checked domain and
  `mfrom`/`helo` scope — alongside its `Result` and `Aligned` flag. This lets a
  report name the domain that actually authenticated a message rather than
  repeating the header-From domain, and supports multiple DKIM signatures per
  message. A message with no DKIM signature now emits no `<dkim>` element in
  `auth_results`.

  Migration: replace the old scalar assignment

  ```go
  dmarc.AggregateRecord{ /* … */ DKIMResult: "pass", DKIMAligned: true, SPFResult: "fail", SPFAligned: false }
  ```

  with the per-identifier slices

  ```go
  dmarc.AggregateRecord{ /* … */
      DKIM: []dmarc.DKIMAuth{{Domain: "example.com", Selector: "s1", Result: "pass", Aligned: true}},
      SPF:  []dmarc.SPFAuth{{Domain: "bounce.example.net", Scope: "mfrom", Result: "fail", Aligned: false}},
  }
  ```

### Added

- **`Discover`** performs full DMARC policy discovery, including the RFC 7489
  §6.6.3 Organizational-Domain fallback: a subdomain that publishes no record of
  its own now inherits its organizational domain's subdomain policy (`sp=`, or
  `p=` when `sp=` is absent). It returns a new **`Policy`** value that reports the
  supplying `Domain`, raw `Record`, `Requested` policy, and whether it was found
  `ViaOrgDomain`.
- **`DKIMAuth`** and **`SPFAuth`** types describe a single identifier's
  authentication result (domain, selector/scope, result, alignment) for the
  `auth_results` section.
- **`AlignedOrg`** and the **`OrgDomainFunc`** hook allow injecting a Public
  Suffix List-backed organizational-domain derivation for correct alignment
  under multi-label public suffixes (e.g. `co.uk`). **`DefaultOrgDomain`** is the
  registry-free default; `Aligned` is now `AlignedOrg` with that default hook.
- Report XML: `DKIMResult` gained a `selector` element and `SPFResult` gained a
  `scope` element (both `omitempty`).

### Fixed

- Relaxed alignment now compares **organizational domains** rather than raw DNS
  suffixes. Sibling subdomains (e.g. `em.example.com` and `mail.example.com`)
  correctly align, while lookalikes (`evil-example.com`) and domains that are
  themselves public suffixes no longer do.
- **`Lookup`** treats an NXDOMAIN result (the name does not exist) as "no DMARC
  record" — it returns `("", nil)` per RFC 7489 §6.6.3 — instead of surfacing it
  as a lookup error. Genuine transient failures (SERVFAIL, timeout, and other
  non-not-found DNS errors) still return an error so callers do not fail open.
- Aggregate reports record the actual authenticating domain(s) in `auth_results`
  instead of repeating the header-From domain.

## [0.1.1] - 2026-07-23

### Changed

- Module renamed to `github.com/rest-mail/go-dmarc`.

## [0.1.0] - 2026-07-23

### Added

- Initial release: DMARC (RFC 7489) policy lookup and parsing, identifier
  alignment, and aggregate (`rua`) report XML generation, depending only on the
  Go standard library.
