# Changelog

All notable changes to go-dmarc are documented here. This project follows
[Semantic Versioning](https://semver.org). While the major version is `0`, a
minor bump may include breaking changes.

## [Unreleased]

## [0.3.0] - 2026-07-25

### BREAKING CHANGES

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

## v0.2.0

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

## v0.1.1

- Module renamed to `github.com/rest-mail/go-dmarc`.

## v0.1.0

- Initial release: DMARC (RFC 7489) policy lookup and parsing, identifier
  alignment, and aggregate (`rua`) report XML generation, depending only on the
  Go standard library.
