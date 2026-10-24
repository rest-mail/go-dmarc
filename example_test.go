package dmarc_test

import (
	"bytes"
	"fmt"

	"github.com/rest-mail/go-dmarc"
)

// Example parses a published DMARC record and decides the disposition for one
// message. A message passes DMARC only when a passing authenticated identifier
// (SPF smtp.mailfrom or a verified DKIM d=) also *aligns* with the From domain;
// when none does, the receiver applies the domain's published policy.
func Example() {
	// The record published at _dmarc.example.com. In production, discover the
	// policy with dmarc.Discover("example.com", nil, nil) (which also walks the
	// DNS tree for subdomains); a literal keeps this DNS-free.
	record := "v=DMARC1; p=reject; adkim=r; aspf=r; rua=mailto:agg@example.com"
	policy, err := dmarc.ParsePolicy(record) // requested policy for failures
	if err != nil {
		panic(err) // a malformed or duplicated p= value is an unusable record
	}

	// SPF authenticated the envelope sender's domain, but it is an unrelated
	// bulk-sender domain that does not align with the From domain.
	fromDomain := "example.com"
	spfDomain, spfPass := "bounce.marketing.net", true

	// Relaxed alignment compares Organizational Domains, which a DNS Tree Walk
	// finds; production callers pass nil for system DNS.
	resolver := func(name string) ([]string, error) {
		if name == "_dmarc.example.com" || name == "_dmarc.marketing.net" {
			return []string{"v=DMARC1; p=none"}, nil
		}
		return nil, nil
	}
	aligned, err := dmarc.AlignedMode(spfDomain, fromDomain, dmarc.AlignmentRelaxed, resolver)
	if err != nil {
		panic(err) // a DNS failure: the policy cannot be applied (RFC 9989 §5.3.6)
	}
	dmarcPass := spfPass && aligned

	disposition := "none"
	if !dmarcPass {
		disposition = policy // apply the published policy to unauthenticated mail
	}
	fmt.Printf("dmarc=%v disposition=%s\n", dmarcPass, disposition)
	// Output: dmarc=false disposition=reject
}

// ExampleDiscover shows the RFC 9989 §4.10 DNS Tree Walk: a subdomain that
// publishes no _dmarc record of its own inherits its Organizational Domain's
// subdomain policy (sp=, else p=). The resolver is injected to keep this
// DNS-free; production callers pass nil to use system DNS.
func ExampleDiscover() {
	resolver := func(name string) ([]string, error) {
		// Only the organizational domain publishes a record.
		if name == "_dmarc.example.com" {
			return []string{"v=DMARC1; p=reject; sp=quarantine"}, nil
		}
		return nil, nil
	}

	policy, err := dmarc.Discover("newsletter.example.com", resolver, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("inherited=%v from=%s apply=%s\n",
		policy.Inherited, policy.Domain, policy.Applied)
	// Output: inherited=true from=example.com apply=quarantine
}

// ExampleOrgDomain finds Organizational Domains under a Public Suffix Domain
// that says it is one (psd=y), as in RFC 9989 Appendix B.4.3.
func ExampleOrgDomain() {
	resolver := func(name string) ([]string, error) {
		switch name {
		case "_dmarc.giant.bank.example":
			return []string{"v=DMARC1; p=reject"}, nil
		case "_dmarc.bank.example":
			return []string{"v=DMARC1; p=none; psd=y"}, nil
		}
		return nil, nil
	}
	for _, domain := range []string{"giant.bank.example", "mail.giant.bank.example", "mail.mega.bank.example"} {
		org, err := dmarc.OrgDomain(domain, resolver)
		if err != nil {
			panic(err)
		}
		fmt.Println(domain, "->", org)
	}
	// Output:
	// giant.bank.example -> giant.bank.example
	// mail.giant.bank.example -> giant.bank.example
	// mail.mega.bank.example -> mega.bank.example
}

// Example_aggregateReport turns per-message evaluations into the RFC 7489
// aggregate-report XML and gzips it for delivery.
func Example_aggregateReport() {
	records := []dmarc.AggregateRecord{
		{
			Domain:      "example.com",
			SourceIP:    "192.0.2.10",
			HeaderFrom:  "example.com",
			Disposition: "reject",
			// SPF passed for the envelope-sender (bounce) domain, which does not
			// align with the From domain; auth_results reports that checked domain.
			SPF: []dmarc.SPFAuth{
				{Domain: "bounce.marketing.net", Scope: "mfrom", Result: "pass", Aligned: false},
			},
		},
	}
	meta := dmarc.ReportMetadata{
		OrgName:   "reporter.example",
		Email:     "dmarc@reporter.example",
		ReportID:  "1@reporter.example",
		DateRange: dmarc.DateRange{Begin: 1784700000, End: 1784786400},
	}
	policy := dmarc.PolicyPublished{Domain: "example.com", ADKIM: "r", ASPF: "r", P: "reject", PCT: 100}

	xmlBytes, err := dmarc.BuildReport(meta, policy, records)
	if err != nil {
		panic(err)
	}
	gz, err := dmarc.Gzip(xmlBytes)
	if err != nil {
		panic(err)
	}
	fmt.Printf("xml=%v rows=%d gzipped=%v\n",
		bytes.HasPrefix(xmlBytes, []byte("<?xml")),
		bytes.Count(xmlBytes, []byte("<record>")),
		len(gz) > 0)
	// Output: xml=true rows=1 gzipped=true
}

// ExampleParseRecord reads every tag of a record, here RFC 9989 Appendix
// B.2.5's, which asks for test mode: the omitted tags take their defaults.
func ExampleParseRecord() {
	rec, err := dmarc.ParseRecord("v=DMARC1; p=quarantine; rua=mailto:dmarc-feedback@example.com," +
		"mailto:tld-test@thirdparty.example.net; t=y")
	if err != nil {
		panic(err) // not a DMARC record, or one with no usable policy
	}
	fmt.Println(rec.Policy, rec.Testing, rec.ADKIM, rec.PSD)
	for _, uri := range rec.RUA {
		fmt.Println(uri)
	}
	// Output:
	// quarantine true relaxed u
	// mailto:dmarc-feedback@example.com
	// mailto:tld-test@thirdparty.example.net
}
