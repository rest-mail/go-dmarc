# RFC 9989 checklist

An inventory of [RFC 9989](https://www.rfc-editor.org/rfc/rfc9989)
requirements on a DMARC Mail Receiver (the record, policy discovery, the DNS
Tree Walk, identifier alignment and applying the policy), and of the RFC 7489
requirements on a report generator (aggregate reports, failure reports and
their destinations) that the library still implements, item by item, with the
tests that cover it. The list tracks MUST, MUST NOT, SHOULD, SHOULD NOT,
RECOMMENDED and REQUIRED obligations on receivers and reporters, the MAYs the
library implements, and the normative behaviour that carries no keyword (level
"Normative"), such as the record grammar of §4.8 and the Tree Walk of §4.10.
Requirements on Domain Owners publishing records are left out unless a
receiver must act on them. A section number alone is RFC 9989's; the others
are named.

An item that does not apply to a library (because it is the receiver's
policy, or the library sends no mail, say) says "n/a" and why. CI checks this
file against the tests with `go run ./internal/checklist`; the format is
described in the [README](README.md#the-rfc-checklist).

## Which RFC: RFC 9989 for the receiver, RFC 7489 for reports so far

In May 2026 RFC 7489 was obsoleted by DMARCbis:
[RFC 9989](https://www.rfc-editor.org/rfc/rfc9989) (the protocol),
[RFC 9990](https://www.rfc-editor.org/rfc/rfc9990) (aggregate reports) and
[RFC 9991](https://www.rfc-editor.org/rfc/rfc9991) (failure reports). The
receiver side follows RFC 9989. Aggregate reports, and the check of their
external destinations, still follow RFC 7489 §7 and Appendix C, until they
move to RFC 9990 in the same release. What changed for a receiver:

| Area | RFC 7489 (before) | RFC 9989 (now) |
|------|-------------------|----------------|
| Organizational Domain (DMARC-ORG-01) | The Public Suffix List, through an `OrgDomainFunc`. | A DNS Tree Walk up the domain's labels (§4.10), with no list: `OrgDomain`. |
| Policy discovery (DMARC-DISC-04, -19) | The From domain, then its Organizational Domain. | The Author Domain, then the Tree Walk: its Organizational Domain, then its Public Suffix Domain. |
| Several records at one name (DMARC-DISC-03) | End discovery with no policy. | Discard them all, and walk on. |
| Tags | `pct`, `rf`, `ri` are read. | `pct`, `rf` and `ri` are removed, so ignored as unknown tags (DMARC-REC-11); `np` (non-existent subdomains), `psd` and `t` (test mode) are added (DMARC-REC-19 to -21). |
| `fo=` (DMARC-REC-13) | Any list of 0, 1, d and s. | 0 and 1 exclude each other, and d and s appear at most once. |
| Report URIs (DMARC-URI-02) | A `!` size limit is honoured. | The size limit is obsolete and ignored. |

## Section audit (2026-10-24)

Reviewed RFC 9989 §§1–11 and Appendices A–C, including their subsections,
for Mail Receiver obligations. This records the audit scope, not a claim that
caller-owned behavior is implemented by the library. Failure reports remain
unsupported by owner decision; this audit adds no such feature.

| Sections audited | Result |
|------------------|--------|
| 1–3 | Introduction, requirements and terminology; §3.2.13's non-existent domain is NXDOMAIN (DMARC-REC-19, `ExistsFunc`). |
| 4.1–4.4 | Overview and identifier alignment: ALIGN rows. |
| 4.5–4.8 | The record: REC and URI rows. |
| 4.9 | Flow diagram; no obligations. |
| 4.10, 4.10.1, 4.10.2 | The DNS Tree Walk, policy discovery and the Organizational Domain: DISC and ORG rows. |
| 5.1, 5.2 | Domain Owner and PSO actions; obligations on publishers only. |
| 5.3.1–5.3.9 | Mail Receiver actions: DISC-01, -11, -12, -14, -16 to -18; AGG-07. |
| 5.4 | Policy enforcement: POL rows. |
| 6 | Feedback is RFC 9990's. |
| 7.1–7.6 | Other topics; §7.4's receiver obligations are POL-14 and POL-15. |
| 8–11 | Minimum implementations (Domain Owner side), privacy, IANA and security considerations; no further receiver obligations a library can meet. |
| A–C | Design notes, examples and changes; Appendix B's examples are tests (`rfc_test.go`), Appendix A.6's test mode is DMARC-REC-21. |

## Records (§4.5, §4.7, §4.8)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DMARC-REC-01 | 4.5 | MUST | Concatenate the character-strings of a TXT record, in order, before parsing it. | `TestRFC9989TXTCharacterStrings` |
| DMARC-REC-02 | 4.7, 4.8 | MUST | v= is DMARC1, matched exactly (upper case); a record whose v= differs or is absent is ignored. | `TestParseRecordVersion`, `TestLookup` |
| DMARC-REC-03 | 4.7 | MUST | v= is the first tag; a record that starts with another tag is ignored. | `TestParseRecordVersion`, `TestLookup` |
| DMARC-REC-05 | 4.7, 4.8 | MUST | Ignore unknown tags. | `TestParseRecordSyntax`, `TestParseRecordRemovedTags` |
| DMARC-REC-06 | 4.8 | Normative | Tags after v= come in any order, with optional whitespace around "=" and ";" and an optional final ";". | `TestParseRecordSyntax`, `TestRFC9989RecordExamples`, `TestDifferentialRecords` |
| DMARC-REC-07 | 4.8 | MUST | Discard a syntax error in the rest of the record in favour of the tag's default, or ignore it. | `TestParseRecordInvalidTagsDefault`, `TestParseRecordAlignmentModes`, `TestParseRecordPSD`, `TestParseRecordTestMode`, `TestParseRecordFailureOptions`, `FuzzParseRecord` |
| DMARC-REC-08 | 4.7, 4.8 | Normative | p= is none, quarantine or reject. | `TestParseRecordPolicy`, `TestParsePolicy`, `TestDifferentialRecords`, `FuzzParseRecord` |
| DMARC-REC-09 | 4.7 | MUST | When sp= is absent (and np= absent or not applicable), apply p= to subdomains. | `TestDiscover`, `TestDiscoverSubdomainPolicyCaseInsensitive` |
| DMARC-REC-10 | 4.7, 4.8 | Normative | adkim= and aspf= are r (relaxed, the default) or s (strict). | `TestParseRecordDefaults`, `TestParseRecordAlignmentModes`, `TestAlignedModeDefaultRelaxed`, `TestDifferentialRecords` |
| DMARC-REC-11 | 4.7; C.5.2 | Normative | pct=, rf= and ri= are no longer DMARC tags: whatever they hold, they are ignored like any unknown tag. | `TestParseRecordRemovedTags`, `TestDifferentialRecords` |
| DMARC-REC-12 | 4.7 | MUST | Ignore fo= when the record has no ruf=. | `TestParseRecordFailureOptions` |
| DMARC-REC-13 | 4.7, 4.8 | Normative | fo= is 0 or 1, which exclude each other, and d and s, each at most once; "0" by default. | `TestParseRecordDefaults`, `TestParseRecordFailureOptions` |
| DMARC-REC-17 | 4.8 | Normative | Tag names and the enumerated values are case-insensitive, as the ABNF's quoted strings are. | `TestParseRecordCaseInsensitive`, `TestDiscoverSubdomainPolicyCaseInsensitive` |
| DMARC-REC-18 | 4.8; RFC 6376 3.2 | MUST NOT | A tag appears more than once; a repeated tag is a syntax error and its values are discarded. | `TestParseRecordDuplicateTags` |
| DMARC-REC-19 | 4.7 | MUST | np= is a policy for subdomains that do not exist; when it is absent, sp= (or else p=) applies to them. | `TestParseRecordPolicy`, `TestDiscoverNonExistentPolicy` |
| DMARC-REC-20 | 4.7, 4.8 | Normative | psd= is y, n or u; u by default. | `TestParseRecordDefaults`, `TestParseRecordPSD` |
| DMARC-REC-21 | 4.7, 4.8; A.6 | Normative | t= is y or n, n by default; t=y asks for the policy to be applied one level lower (quarantine for reject, none for quarantine), and does not affect none. | `TestParseRecordDefaults`, `TestParseRecordTestMode`, `TestDiscoverTestMode`, `TestRFC9989RecordExamples` |

DMARC-REC-01 is proved through the real `net.LookupTXT` path, with DNS wire
responses containing several character-strings per record and several distinct
records. Custom `TXTResolver` implementations must preserve that contract.

## Report URIs (§4.6, §4.7, §4.8)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DMARC-URI-01 | 4.6, 4.8 | Normative | rua= and ruf= are comma-separated lists of URIs, kept in the order published. | `TestParseReportURIs`, `TestRFC9989RecordExamples` |
| DMARC-URI-02 | 4.8 | Normative | A URI may end in the obsolete "!" size limit, which is checked for its syntax and ignored. | `TestParseReportURIs` |
| DMARC-URI-04 | 4.8 | MUST | A comma or "!" inside a URI is percent-encoded, so an unencoded one ends the URI. | `TestParseReportURIs` |
| DMARC-URI-05 | 4.6 | SHOULD | Send a report to each listed URI: every valid URI is kept. | `TestParseReportURIs`, `TestRFC9989RecordExamples`, `TestRUADeliveryOrder` |
| DMARC-URI-06 | 4.7 | MUST | Implement mailto: report URIs, i.e. sending reports by mail. | n/a: the library sends no mail. It parses mailto: URIs and finds their host for §7.1 (DMARC-EXT-01); the caller sends. |
| DMARC-URI-07 | 4.7 | MUST | Ignore report URIs the receiver does not support. | n/a: the caller knows which schemes it sends to; the library keeps every valid URI. |
| DMARC-URI-08 | 4.7 | MUST NOT | Generate aggregate reports for a domain whose record has no rua=. | `TestNoRUANoAggregateDestinations` |
| DMARC-URI-09 | 4.7 | MUST NOT | Generate failure reports for a domain whose record has no ruf=. | n/a: the library generates no failure reports. |

## Policy discovery and the DNS Tree Walk (§4.10, §4.10.1, §5.3)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DMARC-DISC-01 | 5.3.1 | MUST | Convert a U-label Author Domain to an A-label before processing it; a string that is not a domain has no policy. | `TestDiscoverDomainForm`, `FuzzDiscover` |
| DMARC-DISC-02 | 4.10.1 | Normative | Query _dmarc.<Author Domain> first; a single record there is the one that applies. | `TestDiscover`, `TestNilResolverUsesSystemDNS`, `FuzzDiscover` |
| DMARC-DISC-03 | 4.10 | Normative | Discard the TXT records that do not start with v=DMARC1; several records at one name are all discarded. | `TestLookup`, `TestDiscover` |
| DMARC-DISC-04 | 4.10, 4.10.1 | Normative | With no record at the Author Domain, walk up the tree: from its parent, or, when it has more than eight labels, from its last seven, one label at a time to the last. | `TestDiscoverTreeWalk`, `TestRFC9989TreeWalkExamples`, `FuzzDiscover` |
| DMARC-DISC-05 | 4.10 | Normative | No Tree Walk sends more than eight queries. | `TestDiscoverTreeWalk`, `TestRFC9989TreeWalkExamples`, `FuzzDiscover` |
| DMARC-DISC-06 | 4.10.1 | MUST | A record with no valid p=, or an invalid sp= or np=, but a valid rua= URI is read as p=none. | `TestDiscoverInvalidPolicy`, `TestParseRecordPolicy`, `TestParsePolicy`, `FuzzParseRecord` |
| DMARC-DISC-07 | 4.10.1 | Normative | Such a record without a valid rua= URI: DMARC is not applied to the message. | `TestDiscoverInvalidPolicy`, `TestParseRecordPolicy`, `TestParsePolicy` |
| DMARC-DISC-08 | 4.10.1 | MUST NOT | Apply DMARC when the walk finds no record; a name that does not exist is no record, not an error. | `TestDiscover`, `TestLookup` |
| DMARC-DISC-09 | 4.10.1 | Normative | DNS errors are the receiver's to handle: they are returned, apart from no record, so it can fail open or closed. | `TestDiscover`, `TestLookup` |
| DMARC-DISC-10 | 4.10.1 | Normative | The record of the Organizational Domain or PSD gives a subdomain its sp= if it exists and its np= if it does not, each falling back to p=. | `TestDiscover`, `TestDiscoverSubdomainPolicyCaseInsensitive`, `TestDiscoverNonExistentPolicy` |
| DMARC-DISC-11 | 5.3.1 | Normative | With no From domain, or several, DMARC validation is not possible. | `TestDiscoverWithoutOneFromDomain` |
| DMARC-DISC-12 | 5.3.3 | MUST | DKIM results include each signature's d= (and s=), and SPF results the domain checked. | `TestAuthResults_ReportsAuthenticatingDomains` |
| DMARC-DISC-14 | 5.3.6 | Normative | When a DNS query DMARC needs fails, the message neither passes nor fails, and the policy cannot be applied. | n/a: the caller combines the SPF and DKIM results; Discover and AlignedMode return the DNS error for it to act on. |
| DMARC-DISC-15 | 5.3.1; RFC 1035 2.3.4 | Normative | A domain name is at most 253 characters of labels of at most 63; a longer input is not a domain and is refused before it is punycode-encoded. | `TestLongNamesRefusedQuickly` |
| DMARC-DISC-16 | 5.3.1 | Normative | Extract the Author Domain from the message's RFC5322.From field. | n/a: the caller parses the message and supplies the extracted domain to Discover; the library accepts a domain, not a message or From header. |
| DMARC-DISC-17 | 5.3.3 | Normative | Perform DKIM signature verification for the Authenticated Identifiers. | n/a: the caller runs a DKIM verifier and passes its results and signing domains; the library does not verify signatures. |
| DMARC-DISC-18 | 5.3.3 | Normative | Perform SPF validation for the Authenticated Identifiers. | n/a: the caller runs an SPF evaluator and passes its results and checked domains; the library does not evaluate SPF records. |
| DMARC-DISC-19 | 4.10.1 | Normative | The record that applies is the Author Domain's, else its Organizational Domain's, else its PSD's. | `TestDiscoverOrganizationalDomainOrPSD`, `TestRFC9989TreeWalkExamples` |
| DMARC-DISC-20 | 4.10 | Normative | A Tree Walk stops at a single record with psd=y or psd=n. | `TestDiscoverTreeWalk` |

## Identifier alignment and the Organizational Domain (§4.4, §4.10.2)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DMARC-ALIGN-01 | 4.4, 5.3.1 | Normative | Compare domains case-insensitively, as A-labels, without the root dot; an empty identifier, or one that is not a domain, never aligns. | `TestAligned`, `TestAlignedSanitizesInputs`, `TestAlignedRejectsNonDomains`, `FuzzAlignment` |
| DMARC-ALIGN-02 | 4.4 | Normative | Relaxed alignment: the two Organizational Domains are equal. | `TestAligned`, `TestAlignedModeTreeWalk`, `TestAlignedModeDefaultRelaxed`, `TestRFC9989AlignmentExamples`, `TestRFC9989TreeWalkExamples`, `FuzzAlignment` |
| DMARC-ALIGN-03 | 4.4 | Normative | Strict alignment: the two domains are the same FQDN. | `TestAlignedModeStrictDKIM`, `TestAlignedModeStrictSPF`, `TestRFC9989AlignmentExamples`, `FuzzAlignment` |
| DMARC-ALIGN-04 | 4.10.2 | Normative | A public suffix with no record of its own (d=com) is its own Organizational Domain, so it aligns with no other domain. | `TestAlignedModeTreeWalk` |
| DMARC-ALIGN-05 | 4.4.1, 5.3.5 | Normative | DMARC passes when any DKIM signature or SPF check passed for an aligned identifier, and fails otherwise. | `TestEvaluated_RequiresPassAndAlign`, `TestPolicyEvaluatedAnySignature` |
| DMARC-ORG-01 | 4.10.2 | Normative | Of the names a Tree Walk found records at, longest first, the Organizational Domain is the first with psd=n, or the name one label below the first with psd=y (but not the domain's own), else the one with the fewest labels, else the domain itself. | `TestOrgDomain`, `TestDiscoverOrganizationalDomainOrPSD`, `TestRFC9989TreeWalkExamples` |
| DMARC-ORG-02 | 4.10.2 | Normative | The Tree Walk for an Authenticated Identifier or the Author Domain starts at that domain. | `TestOrgDomain`, `TestAlignedModeTreeWalk` |

## Applying the policy (§4.7, §5.4, §7.4)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DMARC-POL-01 | 4.7; A.6 | Normative | In test mode (t=y), apply the policy one level lower, and report the policy requested. | `TestDiscoverTestMode` |
| DMARC-POL-03 | 5.4 | SHOULD | Report a deviation from the published policy, and why, in the aggregate report's PolicyOverride reason. | `TestBuildReportOverrideReasons` |
| DMARC-POL-04 | 5.4 | MUST NOT | Let a discovered p=none change how mail is handled. | n/a: the caller's disposition. |
| DMARC-POL-06 | 5.3 | Normative | Apply DMARC during the SMTP transaction when policies at Enforcement are honoured. | n/a: the library speaks no SMTP. |
| DMARC-POL-08 | 5.3.6 | Normative | Handle mail that fails DMARC by local policy, which may take the published policy into account. | n/a: the caller decides message disposition; the library discovers the requested and applied policy only. |
| DMARC-POL-11 | 5.4 | SHOULD | Add Authentication-Results, and especially when delivering mail that fails DMARC. | n/a: the caller constructs message headers; the library writes no Authentication-Results field. |
| DMARC-POL-14 | 5.4, 7.4 | MUST NOT | Reject mail solely because of a published p=reject; use other knowledge and analysis too. | n/a: the caller's disposition; the library reports the published policy. |
| DMARC-POL-15 | 7.4 | MUST | Without other knowledge and analysis, treat mail failing a p=reject policy as if the policy were p=quarantine. | n/a: the caller's disposition. |

## Verifying external destinations (RFC 7489 §7.1)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DMARC-EXT-01 | RFC 7489 7.1 | Normative | A report URI whose host's Organizational Domain differs from the policy's is checked at <policy domain, as an A-label>._report._dmarc.<host>. | `TestAuthorizeReportURIs`, `TestRFC9989ThirdPartyExample` |
| DMARC-EXT-02 | RFC 7489 7.1 | MUST | A confirming record starts with v=DMARC1; other records are discarded. | `TestAuthorizeReportURIs` |
| DMARC-EXT-03 | RFC 7489 7.1 | MUST | Ignore a URI whose external destination is not confirmed. | `TestAuthorizeReportURIs`, `TestRFC9989ThirdPartyExample` |
| DMARC-EXT-04 | RFC 7489 7.1 | Normative | A rua= or ruf= in the confirming record replaces the URI. | `TestAuthorizeReportURIs`, `TestRFC9989ThirdPartyExample` |
| DMARC-EXT-05 | RFC 7489 7.1 | MUST | An overriding URI uses the same destination host; otherwise neither it nor the original is used. | `TestAuthorizeReportURIs` |
| DMARC-EXT-06 | RFC 7489 7.1 | MAY | A temporary DNS error lets the caller try the check again later. | `TestAuthorizeReportURIs` |
| DMARC-EXT-07 | RFC 7489 12.5 | SHOULD | Use the external-reporting verification mechanism of §7.1. | n/a: the caller must invoke AuthorizeReportURIs before external delivery; BuildReport constructs XML without sending or choosing destinations. |

## Aggregate reports (RFC 7489 §7.2)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DMARC-AGG-01 | RFC 7489 7.2 | SHOULD | Include the DMARC policy discovered and applied. | `TestBuildReportPolicyPublished` |
| DMARC-AGG-02 | RFC 7489 7.2 | SHOULD | Include the disposition, the identifiers SPF and DKIM evaluated with their results, and whether each was aligned. | `TestAuthResults_ReportsAuthenticatingDomains`, `TestBuildReport_SchemaConformance` |
| DMARC-AGG-03 | RFC 7489 7.2 | SHOULD | Report each subdomain's mail apart from the Organizational Domain's. | `TestAggregateRecordsSeparatesSubdomains` |
| DMARC-AGG-04 | RFC 7489 7.2 | SHOULD | Include the policy requested and the policy applied, if they differ. | `TestBuildReportOverrideReasons` |
| DMARC-AGG-05 | RFC 7489 7.2 | SHOULD | Count all messages received, even those other filters block. | `TestAggregateRecords_GroupsAndCounts`, `TestBuildReportSamplingKeepsAllMessages` |
| DMARC-AGG-06 | RFC 7489 7.2 | SHOULD | Keep reporting periods on hour boundaries (daily ones starting at 00:00 UTC). | n/a: the caller chooses the period (DateRange). |
| DMARC-AGG-07 | 5.3.8 | SHOULD | Generate and send aggregate reports at least once every 24 hours. | n/a: scheduling is the caller's. |
| DMARC-AGG-08 | RFC 7489 7.2.1 | SHOULD | Use a secure transport. | n/a: the library sends nothing. |
| DMARC-AGG-09 | 4.6 | SHOULD | Send the report to each listed URI, in the order published. | `TestRUADeliveryOrder`, `ExampleRecord_rua` |
| DMARC-AGG-10 | RFC 7489 7.2.1, 7.2.2 | SHOULD | When no URI can take the report, send a short error report. | n/a: the library sends nothing. |
| DMARC-AGG-11 | RFC 7489 7.2.1.1 | MUST | Send the report as a MIME message with the XML in one part. | n/a: the caller builds the message. |
| DMARC-AGG-12 | RFC 7489 7.2.1.1 | SHOULD | Compress the XML with gzip (application/gzip). | `TestGzip_RoundTrip` |
| DMARC-AGG-13 | RFC 7489 7.2.1.1 | MUST | Name the file with the extension xml, or xml.gz when compressed. | n/a: the caller builds the message. |
| DMARC-AGG-14 | RFC 7489 7.2.1.1 | MUST | Send report mail that passes DMARC with an aligned identifier. | n/a: the caller signs and sends the message. |
| DMARC-AGG-15 | RFC 7489 7.2.1.1 | SHOULD | Give the report's Subject the form of the ABNF. | n/a: the caller builds the message. |
| DMARC-AGG-16 | RFC 7489 7.2.2 | MUST | Format an error report per MIME, with a text/plain part of field-value pairs, and send it to every mailto: URI. | n/a: the library sends nothing. |
| DMARC-AGG-18 | RFC 7489 7.2.1.1 | SHOULD | Label compressed aggregate data application/gzip and uncompressed data text/xml. | n/a: the caller builds MIME parts and chooses their Content-Type; Gzip returns bytes only. |
| DMARC-AGG-19 | RFC 7489 7.2.1.1 | MUST | Encode the aggregate data as an XML file, including when it is gzip-compressed for delivery. | `TestAggregateAttachmentXML` |
| DMARC-AGG-20 | RFC 7489 7.2.2 | MUST | Set an error report's Report-Size to the actual number of bytes attempted on that transport. | n/a: the caller sends reports and constructs delivery-error messages; the library cannot observe transport encoding or attempted byte counts. |
| DMARC-AGG-21 | RFC 7489 7.2.2 | MUST | Generate separate delivery-error reports when attempted sizes differ between transports. | n/a: the caller tracks delivery attempts and constructs delivery-error messages. |
| DMARC-AGG-22 | RFC 7489 7.2.2 | MUST | Include Report-Date, Report-Domain, Report-ID, Report-Size, Submitter and Submitting-URI in the delivery-error report. | n/a: the caller constructs delivery-error MIME messages; the library builds successful aggregate-report XML only. |

## The report schema (RFC 7489 Appendix C)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DMARC-XML-01 | RFC 7489 C | MUST | The report's version is 1.0. | `TestBuildReport_ValidXML` |
| DMARC-XML-02 | RFC 7489 C | Normative | The report validates against the Appendix C schema: its elements, their order, how often each occurs, and their types. | `TestReportValidatesAgainstAppendixC`, `TestBuildReport_GoldenXML`, `FuzzBuildReport` |
| DMARC-XML-03 | RFC 7489 C | Normative | policy_published has domain, p, sp, pct and fo, and adkim and aspf as r or s when present. | `TestBuildReportPolicyPublished`, `TestBuildReport_GoldenXML` |
| DMARC-XML-04 | RFC 7489 C | Normative | Each record's auth_results has at least one spf result. | `TestBuildReportAlwaysHasSPF` |
| DMARC-XML-05 | RFC 7489 C | Normative | auth_results has a dkim result per signature, and none for an unsigned message. | `TestBuildReport_OmitsDKIMWhenUnsigned`, `TestAuthResults_OmitsDKIMWhenUnsigned` |
| DMARC-XML-06 | RFC 7489 C | Normative | Dispositions, DMARC results, DKIM and SPF results and SPF scopes take only their enumerated values. | `TestBuildReport_SchemaConformance`, `TestReportValidatesAgainstAppendixC`, `FuzzBuildReport` |
| DMARC-XML-07 | RFC 7489 C | Normative | source_ip matches the IPAddress pattern: a dotted quad, or an IPv6 address in eight groups. | `TestBuildReportSourceIP` |
| DMARC-XML-08 | RFC 7489 C | Normative | A report has at least one record. | `TestBuildReportNeedsRecords` |
| DMARC-XML-09 | RFC 7489 C | Normative | A policy override reason's type is a PolicyOverrideType. | `TestBuildReportOverrideReasons` |
| DMARC-XML-10 | RFC 7489 C | Normative | identifiers has envelope_from and header_from. | `TestBuildReport_SchemaConformance` |

## Failure reports (RFC 7489 §7.3)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DMARC-FAIL-01 | RFC 7489 7.3 | SHOULD | Include the URIs of the message that failed. | n/a: failure reports are not supported yet; the library builds aggregate reports only. |
| DMARC-FAIL-02 | RFC 7489 7.3 | SHOULD | Include as much of the message and its header as reasonable. | n/a: failure reports are not supported yet. |
| DMARC-FAIL-03 | RFC 7489 7.3 | MUST | Attempt delivery to each selected ruf= URI. | n/a: failure reports are not supported yet. |
| DMARC-FAIL-04 | RFC 7489 7.3.1 | REQUIRED | Include the Identity-Alignment field. | n/a: failure reports are not supported yet. |
| DMARC-FAIL-05 | RFC 7489 7.3.1 | REQUIRED | Include DKIM-Domain, DKIM-Identity and DKIM-Selector when the message was signed. | n/a: failure reports are not supported yet. |
| DMARC-FAIL-06 | RFC 7489 7.3.1 | REQUIRED | Include SPF-DNS. | n/a: failure reports are not supported yet. |

## Internationalized mail (RFC 8616 §6)

[RFC 8616](https://www.rfc-editor.org/rfc/rfc8616) §6 updates RFC 7489 for
internationalized (EAI, RFC 6530) mail. Its §3 states the principle the rows
apply: DNS stays ASCII, so a U-label in a header domain becomes an A-label
before lookup. RFC 8616 §§4–5 update SPF and DKIM and are not DMARC's.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DMARC-EAI-01 | RFC 8616 §6; 5.3.1 | Normative | Convert every U-label in the RFC5322.From domain to an A-label before further processing: policy lookup, the Organizational Domain and alignment. | `TestRFC8616ULabels` |
| DMARC-EAI-02 | RFC 8616 §6; RFC 7489 7.1 | Normative | Convert every U-label in the domains §7.1 handles to an A-label, including the policy domain in `<policy domain>._report._dmarc.<host>`. | `TestRFC8616ULabels` |
| DMARC-EAI-03 | RFC 8616 §6; 4.6 | Normative | rua= and ruf= addresses are conventional, never internationalized, because one record serves both kinds of mail: a mailto: URI naming a UTF-8 local part or a U-label domain, raw or percent-encoded, is not a valid report URI. | `TestRFC8616ConventionalReportAddresses`, `TestDifferentialRecords` |
