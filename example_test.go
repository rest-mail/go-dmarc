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
	// policy with dmarc.Discover("example.com", nil, nil) (which also handles the
	// organizational-domain fallback for subdomains); a literal keeps this DNS-free.
	record := "v=DMARC1; p=reject; adkim=r; aspf=r; rua=mailto:agg@example.com"
	policy, err := dmarc.ParsePolicy(record) // requested policy for failures
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
	// Output: dmarc=false disposition=reject
}

// ExampleDiscover shows the RFC 7489 §6.6.3 organizational-domain fallback: a
// subdomain that publishes no _dmarc record of its own inherits the org domain's
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
	fmt.Printf("via_org=%v from=%s apply=%s\n",
		policy.ViaOrgDomain, policy.Domain, policy.Requested)
	// Output: via_org=true from=example.com apply=quarantine
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
