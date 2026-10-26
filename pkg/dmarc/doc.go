// Package dmarc implements the receiver side of DMARC (RFC 9989): looking up
// and parsing a domain's published policy with the DNS Tree Walk, evaluating
// identifier alignment, and generating aggregate (rua) report XML (RFC 9990).
// It depends only on the Go standard library.
//
// DMARC (Domain-based Message Authentication, Reporting, and Conformance) lets
// the owner of a From domain publish, at _dmarc.<domain>, how receivers should
// treat mail that is not authenticated as coming from that domain. A receiver
// checks whether a passing SPF or DKIM identifier aligns with the From domain;
// if neither does, it applies the domain's published policy (none, quarantine,
// or reject) and, later, reports what it saw back to the domain owner.
//
// The package is deliberately free of any storage or scheduling concerns. A
// caller records per-message evaluations however it likes, then hands a slice of
// neutral [AggregateRecord] values to [BuildReport] to produce the aggregate
// report.
//
// # Policy discovery and evaluation
//
// [Discover] performs policy discovery for an Author Domain (RFC 9989
// §4.10.1): its own record, or else, by the DNS Tree Walk (§4.10), the record
// of its Organizational Domain or its Public Suffix Domain, whose subdomain
// policy applies (sp=, np= for a domain that does not exist, else p=), one
// level lower in test mode (t=y). [ParseRecord] reads every tag of a record,
// with defaults for those it omits or gets wrong; [Lookup] is the lower-level
// primitive that fetches the raw record at exactly _dmarc.<domain>, and
// [ParsePolicy] reads only a record's p=. [AlignedMode] reports whether an
// authenticated domain — from an SPF smtp.mailfrom or a verified DKIM
// signature's d= — aligns with the From domain under the record's adkim= or
// aspf= mode, comparing the Organizational Domains [OrgDomain] finds:
//
//	policy, _ := dmarc.Discover("mail.example.com", nil, nil)
//	aligned, _ := dmarc.AlignedMode(dkimDomain, "mail.example.com", policy.Record.ADKIM, nil)
//	if !aligned && policy.Applied == "reject" {
//		// no aligned identifier passed: weigh the published policy (§5.4)
//	}
//
// The Organizational Domain comes from DNS, not from the Public Suffix List:
// the Tree Walk reads the records published above a domain, and a Public
// Suffix Domain that publishes one with psd=y marks itself.
//
// # Aggregate reporting
//
// A reporter collects one [AggregateRecord] per evaluated message, then calls
// [BuildReport] to marshal them into the RFC 9990 aggregate-report XML
// document, valid against the schema of its Appendix A; [NewPolicyPublished]
// describes the discovered policy. [AggregateRecords] performs the grouping
// (identical rows are summed into a count) and is called by [BuildReport], but
// is exported for callers that want the grouped rows directly. [Gzip]
// compresses the document for delivery as the application/gzip attachment,
// which [ReportFilename] names and whose message [ReportSubject] titles
// (RFC 9990 §3.5.2). Before sending to a rua= or ruf= address outside the
// domain's own Organizational Domain, [AuthorizeReportURIs] checks that the
// destination agreed to receive the reports (RFC 9990 §4).
package dmarc
