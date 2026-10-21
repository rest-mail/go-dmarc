# RFC 7489 checklist

Every requirement [RFC 7489](https://www.rfc-editor.org/rfc/rfc7489) places on
a DMARC receiver (policy discovery and evaluation) and on a report generator
(aggregate reports, failure reports and their destinations), item by item,
with the tests that cover it. The list takes in every MUST, MUST NOT, SHOULD,
SHOULD NOT, RECOMMENDED and REQUIRED that applies to a receiver or a reporter,
the MAYs the library implements, and the normative behaviour that carries no
keyword (level "Normative"), such as the record grammar of §6.4 and the
report schema of Appendix C. Requirements on Domain Owners publishing records
are left out unless a receiver must act on them. A section number alone is
RFC 7489's; the others are named.

An item that does not apply to a library (because it is the receiver's
policy, or the library sends no mail, say) says "n/a" and why. CI checks this
file against the tests with `go run ./internal/checklist`; the format is
described in the [README](README.md#the-rfc-checklist).

## Which RFC: 7489, not yet DMARCbis

In May 2026 RFC 7489 was obsoleted by DMARCbis:
[RFC 9989](https://www.rfc-editor.org/rfc/rfc9989) (the protocol),
[RFC 9990](https://www.rfc-editor.org/rfc/rfc9990) (aggregate reports) and
[RFC 9991](https://www.rfc-editor.org/rfc/rfc9991) (failure reports). This
checklist still follows RFC 7489, because RFC 7489 is what the library
implements and what senders' records and report consumers expect today;
moving to DMARCbis is a change of protocol, not a fix, and is left for its
own release. Where DMARCbis differs, receivers that follow RFC 7489 stay
interoperable (DMARCbis keeps `v=DMARC1` and every tag's syntax), with these
differences:

| Area | RFC 7489 (this library) | DMARCbis |
|------|-------------------------|----------|
| Organizational Domain (DMARC-ORG-01, DMARC-DISC-04) | The Public Suffix List, through an `OrgDomainFunc`. | A DNS Tree Walk up the From domain's labels (RFC 9989 §4.10), with no list. |
| Tags | `pct`, `rf`, `ri` are read (DMARC-REC-11, -14, -16). | `pct`, `rf` and `ri` are removed; `np` (non-existent subdomains), `psd` and `t` (test mode) are added. They are ignored here as unknown tags (DMARC-REC-05). |
| `p=` | Required; a record without one is read as `p=none` when `rua=` is valid (DMARC-DISC-06). | Optional; a missing or invalid `p=` is read as `p=none`. The order rule for `v` and `p` is gone (see DMARC-REC-04). |
| Report URIs | A `!` size limit is honoured (DMARC-URI-02). | The size limit is removed. |
| Aggregate report | The Appendix C schema, no namespace (DMARC-XML-02). | A new schema in the `urn:ietf:params:xml:ns:dmarc-2.0` namespace, with `np`, `testing`, `discovery_method` and `generator`. |
| Failure reports | Not generated (DMARC-FAIL). | Moved to RFC 9991; still not generated. |

## Records (§6.1, §6.3, §6.4)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DMARC-REC-01 | 6.1 | MUST | Concatenate the character-strings of a TXT record, in order, before parsing it. | n/a: a TXTResolver returns each record as one string; net.LookupTXT, the default, joins the character-strings, and a resolver passed in must do the same. |
| DMARC-REC-02 | 6.3, 6.4 | MUST | v= is DMARC1, matched exactly (upper case); a record whose v= differs or is absent is ignored. | `TestParseRecordVersion`, `TestLookup` |
| DMARC-REC-03 | 6.3 | MUST | v= is the first tag; a record that starts with another tag is ignored. | `TestParseRecordVersion`, `TestLookup` |
| DMARC-REC-04 | 6.3, 6.4 | MUST | v and p are present and appear in that order. | n/a: a requirement on the record's publisher. A receiver taking p= only in second place would drop the policy of records such as "v=DMARC1; rua=...; p=reject", so the parser takes p= anywhere after v=, as RFC 9989 does (`TestParseRecordSyntax`). |
| DMARC-REC-05 | 6.3 | MUST | Ignore unknown tags. | `TestParseRecordSyntax` |
| DMARC-REC-06 | 6.4 | Normative | Tags after v= come in any order, with optional whitespace around "=" and ";" and an optional final ";". | `TestParseRecordSyntax`, `TestRFC7489RecordExamples`, `TestDifferentialRecords` |
| DMARC-REC-07 | 6.3 | SHOULD | Discard a syntax error in the rest of the record in favour of the tag's default, or ignore it. | `TestParseRecordInvalidTagsDefault`, `TestParseRecordAlignmentModes`, `TestParseRecordPct`, `TestParseRecordFailureOptions`, `TestParseRecordReportInterval`, `FuzzParseRecord` |
| DMARC-REC-08 | 6.3, 6.4 | Normative | p= is none, quarantine or reject. | `TestParseRecordPolicy`, `TestParsePolicy`, `TestDifferentialRecords`, `FuzzParseRecord` |
| DMARC-REC-09 | 6.3 | MUST | When sp= is absent, apply p= to subdomains. | `TestDiscover`, `TestDiscoverSubdomainPolicyCaseInsensitive` |
| DMARC-REC-10 | 6.3, 6.4 | Normative | adkim= and aspf= are r (relaxed, the default) or s (strict). | `TestParseRecordDefaults`, `TestParseRecordAlignmentModes`, `TestAlignedModeDefaultRelaxed`, `TestDifferentialRecords` |
| DMARC-REC-11 | 6.3, 6.4 | Normative | pct= is an integer of one to three digits from 0 to 100; 100 by default. | `TestParseRecordDefaults`, `TestParseRecordPct`, `TestDifferentialRecords` |
| DMARC-REC-12 | 6.3 | MUST | Ignore fo= when the record has no ruf=. | `TestParseRecordFailureOptions` |
| DMARC-REC-13 | 6.3, 6.4 | Normative | fo= is a colon-separated list of 0, 1, d and s; "0" by default. | `TestParseRecordDefaults`, `TestParseRecordFailureOptions` |
| DMARC-REC-14 | 6.3 | SHOULD | Ignore an rf= value that is not a registered failure-report format (only afrf is). | `TestParseRecordReportFormats` |
| DMARC-REC-15 | 6.3 | MUST | Support the AFRF failure-report format. | n/a: the library generates no failure reports (see DMARC-FAIL). |
| DMARC-REC-16 | 6.3, 6.4 | Normative | ri= is a 32-bit unsigned number of seconds; 86400 by default. | `TestParseRecordDefaults`, `TestParseRecordReportInterval` |
| DMARC-REC-17 | 6.4 | Normative | Tag names and the enumerated values are case-insensitive, as the ABNF's quoted strings are. | `TestParseRecordCaseInsensitive`, `TestDiscoverSubdomainPolicyCaseInsensitive` |
| DMARC-REC-18 | 6.3; RFC 6376 3.2 | MUST NOT | A tag appears more than once; a repeated tag is a syntax error and its values are discarded. | `TestParseRecordDuplicateTags` |

## Report URIs (§6.2, §6.3, §6.4)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DMARC-URI-01 | 6.2, 6.3 | Normative | rua= and ruf= are comma-separated lists of URIs, kept in the order published. | `TestParseReportURIs`, `TestRFC7489RecordExamples` |
| DMARC-URI-02 | 6.2, 6.4 | Normative | A URI may end in "!" and a size, with an optional k, m, g or t unit counted in powers of two. | `TestParseReportURIs`, `TestRFC7489RecordExamples` |
| DMARC-URI-03 | 6.4 | MUST | The size fits in an unsigned 64-bit integer; a URI whose size does not is invalid. | `TestParseReportURIs` |
| DMARC-URI-04 | 6.3, 6.4 | MUST | A comma or "!" inside a URI is percent-encoded, so an unencoded one ends the URI. | `TestParseReportURIs` |
| DMARC-URI-05 | 6.2 | MUST | Support at least two report URIs. | `TestParseReportURIs`, `TestRFC7489RecordExamples` |
| DMARC-URI-06 | 6.3 | MUST | Implement mailto: report URIs, i.e. sending reports by mail. | n/a: the library sends no mail. It parses mailto: URIs and finds their host for §7.1 (DMARC-EXT-01); the caller sends. |
| DMARC-URI-07 | 6.3 | MUST | Ignore report URIs the receiver does not support. | n/a: the caller knows which schemes it sends to; the library keeps every valid URI. |
| DMARC-URI-08 | 6.3 | MUST NOT | Generate aggregate reports for a domain whose record has no rua=. | `TestNoRUANoAggregateDestinations` |
| DMARC-URI-09 | 6.3 | MUST NOT | Generate failure reports for a domain whose record has no ruf=. | n/a: the library generates no failure reports. |

## Policy discovery (§6.6.1 to §6.6.3)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DMARC-DISC-01 | 6.6.1 | Normative | Convert a UTF-8 From domain to an A-label before looking it up; a string that is not a domain has no policy. | `TestDiscoverDomainForm`, `FuzzDiscover` |
| DMARC-DISC-02 | 6.6.3 | MUST | Query _dmarc.<From domain> first. | `TestDiscover`, `TestRFC7489DiscoveryWalk`, `TestNilResolverUsesSystemDNS`, `FuzzDiscover` |
| DMARC-DISC-03 | 6.6.3 | Normative | Discard the TXT records that do not start with v=DMARC1. | `TestLookup`, `TestDiscover` |
| DMARC-DISC-04 | 6.6.3 | MUST | When no record is left, query _dmarc.<Organizational Domain>, if that differs. | `TestDiscover`, `TestRFC7489DiscoveryWalk`, `TestPSLOrgDomains`, `TestDefaultOrgDomain`, `FuzzDiscover` |
| DMARC-DISC-05 | 6.6.3 | Normative | With several records (or none) left, end discovery with no policy, without falling back. | `TestDiscover`, `TestLookup` |
| DMARC-DISC-06 | 6.6.3 | SHOULD | A record with no valid p=, or an invalid sp=, but a valid rua= URI is read as p=none. | `TestDiscoverInvalidPolicy`, `TestParseRecordPolicy`, `TestParsePolicy`, `FuzzParseRecord` |
| DMARC-DISC-07 | 6.6.3 | Normative | Such a record without a valid rua= URI: DMARC is not applied to the message. | `TestDiscoverInvalidPolicy`, `TestParseRecordPolicy`, `TestParsePolicy` |
| DMARC-DISC-08 | 6.6.3 | SHOULD NOT | Apply DMARC when no record exists; a name that does not exist is no policy, not an error. | `TestDiscover`, `TestLookup` |
| DMARC-DISC-09 | 6.6.3 | Normative | DNS errors are the receiver's to handle: they are returned, apart from no policy, so it can fail open or closed. | `TestDiscover`, `TestLookup` |
| DMARC-DISC-10 | 6.3, 6.6.3 | Normative | A record found at the Organizational Domain gives a subdomain its sp= (or p=). | `TestDiscover`, `TestDiscoverSubdomainPolicyCaseInsensitive`, `TestRFC7489DiscoveryWalk` |
| DMARC-DISC-11 | 6.6.1 | Normative | Messages with no, several or a group From domain are handled outside DMARC. | `TestDiscoverWithoutOneFromDomain` |
| DMARC-DISC-12 | 6.6.2 | MUST | DKIM results include each signature's d=, and SPF results the domain checked. | `TestAuthResults_ReportsAuthenticatingDomains` |
| DMARC-DISC-13 | 6.6.2 | SHOULD NOT | Use heuristics such as best-guess SPF for a domain that publishes no SPF or DKIM. | n/a: the caller runs SPF and DKIM. |
| DMARC-DISC-14 | 6.6.2 | Normative | When no aligned identifier passes and one failed temporarily, the policy cannot be applied. | n/a: the caller combines the SPF and DKIM results. |
| DMARC-DISC-15 | 6.6.1; RFC 1035 2.3.4 | Normative | A domain name is at most 253 characters of labels of at most 63; a longer input is not a domain and is refused before it is punycode-encoded. | `TestLongNamesRefusedQuickly` |

## Identifier alignment and the Organizational Domain (§3)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DMARC-ALIGN-01 | 3.1, 6.6.1 | Normative | Compare domains case-insensitively, as A-labels, without the root dot; an empty identifier, or one that is not a domain, never aligns. | `TestAligned`, `TestAlignedSanitizesInputs`, `TestAlignedRejectsNonDomains`, `FuzzAlignment` |
| DMARC-ALIGN-02 | 3.1.1, 3.1.2 | Normative | Relaxed alignment: the two Organizational Domains are equal. | `TestAligned`, `TestAlignedOrg`, `TestAlignedModeDefaultRelaxed`, `TestRFC7489AlignmentExamples`, `FuzzAlignment` |
| DMARC-ALIGN-03 | 3.1.1, 3.1.2 | Normative | Strict alignment: the two domains are the same FQDN. | `TestAlignedModeStrictDKIM`, `TestAlignedModeStrictSPF`, `TestRFC7489AlignmentExamples`, `FuzzAlignment` |
| DMARC-ALIGN-04 | 3.1.1 | Normative | A domain that is a public suffix (d=com) never aligns. | `TestAlignedOrg`, `TestPSLOrgDomains` |
| DMARC-ALIGN-05 | 3.1.1, 6.6.2 | Normative | DMARC passes when any DKIM signature or SPF check passed for an aligned identifier, and fails otherwise. | `TestEvaluated_RequiresPassAndAlign`, `TestPolicyEvaluatedAnySignature` |
| DMARC-ORG-01 | 3.2 | Normative | The Organizational Domain is the longest public suffix matching the domain plus one more label. | `TestPSLOrgDomains` |

## Applying the policy (§6, §6.6.4, §6.7)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DMARC-POL-01 | 6.6.4 | MUST NOT | Enact p= or sp= on more than pct= percent of the messages it covers. | n/a: the caller decides each message's fate; Record.Pct is the rate (§6.3's random sampling suits). |
| DMARC-POL-02 | 6.6.4 | SHOULD | Treat a message sampled out of a reject policy as quarantine, and one sampled out of quarantine normally. | n/a: the caller's disposition. |
| DMARC-POL-03 | 6 | SHOULD | Report a deviation from the published policy, and why, in the aggregate report's PolicyOverride reason. | `TestBuildReportOverrideReasons` |
| DMARC-POL-04 | 6.7 | SHOULD NOT | Let a discovered p=none change how mail is handled. | n/a: the caller's disposition. |
| DMARC-POL-05 | 6.7 | MUST | Encode the domain recorded in Authentication-Results as an A-label. | n/a: the library writes no header fields. |
| DMARC-POL-06 | 6.3 | SHOULD | Reject during the SMTP transaction. | n/a: the library speaks no SMTP. |
| DMARC-POL-07 | 6.6.4 | MUST | Include every message's data in reports, whatever pct= says. | `TestAggregateRecords_GroupsAndCounts` |

## Verifying external destinations (§7.1)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DMARC-EXT-01 | 7.1 | Normative | A report URI whose host's Organizational Domain differs from the policy's is checked at <policy domain, as an A-label>._report._dmarc.<host>. | `TestAuthorizeReportURIs`, `TestRFC7489ThirdPartyExample` |
| DMARC-EXT-02 | 7.1 | MUST | A confirming record starts with v=DMARC1; other records are discarded. | `TestAuthorizeReportURIs` |
| DMARC-EXT-03 | 7.1 | MUST | Ignore a URI whose external destination is not confirmed. | `TestAuthorizeReportURIs`, `TestRFC7489ThirdPartyExample` |
| DMARC-EXT-04 | 7.1 | Normative | A rua= or ruf= in the confirming record replaces the URI. | `TestAuthorizeReportURIs` |
| DMARC-EXT-05 | 7.1 | MUST | An overriding URI uses the same destination host; otherwise neither it nor the original is used. | `TestAuthorizeReportURIs` |
| DMARC-EXT-06 | 7.1 | MAY | A temporary DNS error lets the caller try the check again later. | `TestAuthorizeReportURIs` |

## Aggregate reports (§7.2)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DMARC-AGG-01 | 7.2 | SHOULD | Include the DMARC policy discovered and applied. | `TestBuildReportPolicyPublished` |
| DMARC-AGG-02 | 7.2 | SHOULD | Include the disposition, the identifiers SPF and DKIM evaluated with their results, and whether each was aligned. | `TestAuthResults_ReportsAuthenticatingDomains`, `TestBuildReport_SchemaConformance` |
| DMARC-AGG-03 | 7.2 | SHOULD | Report each subdomain's mail apart from the Organizational Domain's. | `TestAggregateRecordsSeparatesSubdomains` |
| DMARC-AGG-04 | 7.2 | SHOULD | Include the policy requested and the policy applied, if they differ. | `TestBuildReportOverrideReasons` |
| DMARC-AGG-05 | 7.2 | SHOULD | Count all messages received, even those other filters block. | `TestAggregateRecords_GroupsAndCounts` |
| DMARC-AGG-06 | 7.2 | SHOULD | Keep reporting periods on hour boundaries (daily ones starting at 00:00 UTC). | n/a: the caller chooses the period (DateRange). |
| DMARC-AGG-07 | 6.3 | MUST | Provide daily reports, and SHOULD hourly ones when ri= asks. | n/a: scheduling is the caller's; Record.ReportInterval is the requested interval. |
| DMARC-AGG-08 | 7.2.1 | SHOULD | Use a secure transport. | n/a: the library sends nothing. |
| DMARC-AGG-09 | 7.2.1 | MUST | Try the URIs in order, skip those whose size limit the report exceeds, and attempt every other one. | `TestRUADeliveryOrderAndLimits`, `ExampleReportURI_delivery` |
| DMARC-AGG-10 | 7.2.1, 7.2.2 | SHOULD | When no URI can take the report, send a short error report. | n/a: the library sends nothing. |
| DMARC-AGG-11 | 7.2.1.1 | MUST | Send the report as a MIME message with the XML in one part. | n/a: the caller builds the message. |
| DMARC-AGG-12 | 7.2.1.1 | SHOULD | Compress the XML with gzip (application/gzip). | `TestGzip_RoundTrip` |
| DMARC-AGG-13 | 7.2.1.1 | MUST | Name the file with the extension xml, or xml.gz when compressed. | n/a: the caller builds the message. |
| DMARC-AGG-14 | 7.2.1.1 | MUST | Send report mail that passes DMARC with an aligned identifier. | n/a: the caller signs and sends the message. |
| DMARC-AGG-15 | 7.2.1.1 | SHOULD | Give the report's Subject the form of the ABNF. | n/a: the caller builds the message. |
| DMARC-AGG-16 | 7.2.2 | MUST | Format an error report per MIME, with a text/plain part of field-value pairs, and send it to every mailto: URI. | n/a: the library sends nothing. |
| DMARC-AGG-17 | 6.3 | MUST NOT | Apply pct= to DMARC report mail. | n/a: the caller handles mail. |

## The report schema (Appendix C)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DMARC-XML-01 | C | MUST | The report's version is 1.0. | `TestBuildReport_ValidXML` |
| DMARC-XML-02 | C | Normative | The report validates against the Appendix C schema: its elements, their order, how often each occurs, and their types. | `TestReportValidatesAgainstAppendixC`, `TestBuildReport_GoldenXML`, `FuzzBuildReport` |
| DMARC-XML-03 | C | Normative | policy_published has domain, p, sp, pct and fo, and adkim and aspf as r or s when present. | `TestBuildReportPolicyPublished`, `TestBuildReport_GoldenXML` |
| DMARC-XML-04 | C | Normative | Each record's auth_results has at least one spf result. | `TestBuildReportAlwaysHasSPF` |
| DMARC-XML-05 | C | Normative | auth_results has a dkim result per signature, and none for an unsigned message. | `TestBuildReport_OmitsDKIMWhenUnsigned`, `TestAuthResults_OmitsDKIMWhenUnsigned` |
| DMARC-XML-06 | C | Normative | Dispositions, DMARC results, DKIM and SPF results and SPF scopes take only their enumerated values. | `TestBuildReport_SchemaConformance`, `TestReportValidatesAgainstAppendixC`, `FuzzBuildReport` |
| DMARC-XML-07 | C | Normative | source_ip matches the IPAddress pattern: a dotted quad, or an IPv6 address in eight groups. | `TestBuildReportSourceIP` |
| DMARC-XML-08 | C | Normative | A report has at least one record. | `TestBuildReportNeedsRecords` |
| DMARC-XML-09 | C | Normative | A policy override reason's type is a PolicyOverrideType. | `TestBuildReportOverrideReasons` |
| DMARC-XML-10 | C | Normative | identifiers has envelope_from and header_from. | `TestBuildReport_SchemaConformance` |

## Failure reports (§7.3)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DMARC-FAIL-01 | 7.3 | SHOULD | Include the URIs of the message that failed. | n/a: failure reports are not supported yet; the library builds aggregate reports only. |
| DMARC-FAIL-02 | 7.3 | SHOULD | Include as much of the message and its header as reasonable. | n/a: failure reports are not supported yet. |
| DMARC-FAIL-03 | 7.3 | MUST | Attempt delivery to each selected ruf= URI. | n/a: failure reports are not supported yet. |
| DMARC-FAIL-04 | 7.3.1 | REQUIRED | Include the Identity-Alignment field. | n/a: failure reports are not supported yet. |
| DMARC-FAIL-05 | 7.3.1 | REQUIRED | Include DKIM-Domain, DKIM-Identity and DKIM-Selector when the message was signed. | n/a: failure reports are not supported yet. |
| DMARC-FAIL-06 | 7.3.1 | REQUIRED | Include SPF-DNS. | n/a: failure reports are not supported yet. |
| DMARC-FAIL-07 | 6.3 | MUST | Follow the format rf= names. | n/a: failure reports are not supported yet. |
