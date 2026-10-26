package dmarc

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// The aggregate report schema of RFC 9990 Appendix A, written out as Go data
// so that validateReport can check a document against it without an XML
// schema library. Each complex type lists its child elements in the schema's
// order with their type and occurrences (maxOccurs -1 is "unbounded"); all
// marks an xs:all group, whose children may come in any order. Each simple
// type is an enumeration or a pattern, as in the schema. The schema's
// elementFormDefault is qualified, so every element must be in its target
// namespace, urn:ietf:params:xml:ns:dmarc-2.0. The langAttrString elements
// are strings with an optional lang attribute, which BuildReport never
// writes, and source_ip, an xs:string in the schema, must be the IPv4address
// or IPv6address of RFC 3986 §3.2.2 that §3.1.1.8 says it is.

type schemaElement struct {
	name     string
	typ      string
	min, max int
}

type schemaComplexType struct {
	all      bool
	elements []schemaElement
}

func one(name, typ string) schemaElement      { return schemaElement{name, typ, 1, 1} }
func optional(name, typ string) schemaElement { return schemaElement{name, typ, 0, 1} }

var appendixAComplexTypes = map[string]schemaComplexType{
	"feedback": {elements: []schemaElement{
		optional("version", "xs:decimal"),
		one("report_metadata", "ReportMetadataType"),
		one("policy_published", "PolicyPublishedType"),
		optional("extension", "ExtensionType"),
		{"record", "RecordType", 1, -1},
	}},
	"DateRangeType": {all: true, elements: []schemaElement{one("begin", "xs:integer"), one("end", "xs:integer")}},
	"ReportMetadataType": {all: true, elements: []schemaElement{
		one("org_name", "xs:string"),
		one("email", "xs:string"),
		optional("extra_contact_info", "xs:string"),
		one("report_id", "xs:string"),
		one("date_range", "DateRangeType"),
		optional("error", "xs:string"),
		optional("generator", "xs:string"),
	}},
	"PolicyPublishedType": {all: true, elements: []schemaElement{
		one("domain", "xs:string"),
		one("p", "DispositionType"),
		optional("sp", "DispositionType"),
		optional("np", "DispositionType"),
		optional("adkim", "AlignmentType"),
		optional("aspf", "AlignmentType"),
		optional("discovery_method", "DiscoveryType"),
		optional("fo", "xs:string"),
		optional("testing", "TestingType"),
	}},
	"PolicyOverrideReason": {all: true, elements: []schemaElement{
		one("type", "PolicyOverrideType"),
		optional("comment", "xs:string"),
	}},
	"PolicyEvaluatedType": {elements: []schemaElement{
		one("disposition", "ActionDispositionType"),
		one("dkim", "DMARCResultType"),
		one("spf", "DMARCResultType"),
		{"reason", "PolicyOverrideReason", 0, -1},
	}},
	"RowType": {all: true, elements: []schemaElement{
		one("source_ip", "RFC3986IP"),
		one("count", "xs:integer"),
		one("policy_evaluated", "PolicyEvaluatedType"),
	}},
	"IdentifierType": {all: true, elements: []schemaElement{
		one("header_from", "xs:string"),
		optional("envelope_from", "xs:string"),
		optional("envelope_to", "xs:string"),
	}},
	"DKIMAuthResultType": {all: true, elements: []schemaElement{
		one("domain", "xs:string"),
		one("selector", "xs:string"),
		one("result", "DKIMResultType"),
		optional("human_result", "xs:string"),
	}},
	"SPFAuthResultType": {all: true, elements: []schemaElement{
		one("domain", "xs:string"),
		optional("scope", "SPFDomainScope"),
		one("result", "SPFResultType"),
		optional("human_result", "xs:string"),
	}},
	"AuthResultType": {elements: []schemaElement{
		{"dkim", "DKIMAuthResultType", 0, -1},
		optional("spf", "SPFAuthResultType"),
	}},
	"RecordType": {elements: []schemaElement{
		one("row", "RowType"),
		one("identifiers", "IdentifierType"),
		one("auth_results", "AuthResultType"),
	}},
	"ExtensionType": {elements: nil},
}

var appendixAEnumerations = map[string][]string{
	"AlignmentType":         {"r", "s"},
	"DispositionType":       {"none", "quarantine", "reject"},
	"ActionDispositionType": {"none", "pass", "quarantine", "reject"},
	"DiscoveryType":         {"psl", "treewalk"},
	"TestingType":           {"n", "y"},
	"DMARCResultType":       {"pass", "fail"},
	"PolicyOverrideType":    {"local_policy", "mailing_list", "other", "policy_test_mode", "trusted_forwarder"},
	"DKIMResultType":        {"none", "pass", "fail", "policy", "neutral", "temperror", "permerror"},
	"SPFDomainScope":        {"mfrom"},
	"SPFResultType":         {"none", "pass", "fail", "softfail", "policy", "neutral", "temperror", "permerror"},
}

// appendixAPatterns are the built-in xs:integer and xs:decimal lexical forms,
// anchored as XML Schema patterns are.
var appendixAPatterns = map[string]*regexp.Regexp{
	"xs:integer": regexp.MustCompile(`^[+-]?[0-9]+$`),
	"xs:decimal": regexp.MustCompile(`^[+-]?([0-9]+(\.[0-9]*)?|\.[0-9]+)$`),
}

// xmlNode is a parsed element: its name and namespace, its child elements,
// and its text.
type xmlNode struct {
	name, space string
	children    []*xmlNode
	text        strings.Builder
}

// parseXMLTree reads a document into a tree of elements.
func parseXMLTree(doc []byte) (*xmlNode, error) {
	dec := xml.NewDecoder(bytes.NewReader(doc))
	var stack []*xmlNode
	var root *xmlNode
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch tok := tok.(type) {
		case xml.StartElement:
			n := &xmlNode{name: tok.Name.Local, space: tok.Name.Space}
			if len(stack) == 0 {
				if root != nil {
					return nil, fmt.Errorf("second root element <%s>", n.name)
				}
				root = n
			} else {
				parent := stack[len(stack)-1]
				parent.children = append(parent.children, n)
			}
			stack = append(stack, n)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].text.Write(tok)
			}
		}
	}
	if root == nil {
		return nil, fmt.Errorf("no root element")
	}
	return root, nil
}

// validateReport checks an aggregate report document against the Appendix A
// schema and returns the first violation it finds.
func validateReport(doc []byte) error {
	root, err := parseXMLTree(doc)
	if err != nil {
		return err
	}
	if root.name != "feedback" {
		return fmt.Errorf("root element is <%s>, want <feedback>", root.name)
	}
	return validateNode(root, "feedback", "feedback")
}

func validateNode(n *xmlNode, typ, path string) error {
	if n.space != Namespace {
		return fmt.Errorf("%s: <%s> is in namespace %q, want %q", path, n.name, n.space, Namespace)
	}
	ct, complex := appendixAComplexTypes[typ]
	if !complex {
		if len(n.children) > 0 {
			return fmt.Errorf("%s: simple type %s has child elements", path, typ)
		}
		return validateSimple(n.text.String(), typ, path)
	}
	if strings.TrimSpace(n.text.String()) != "" {
		return fmt.Errorf("%s: text %q in complex type %s", path, n.text.String(), typ)
	}
	if ct.all {
		counts := map[string]int{}
		for _, c := range n.children {
			e, ok := findElement(ct.elements, c.name)
			if !ok {
				return fmt.Errorf("%s: unexpected element <%s>", path, c.name)
			}
			counts[c.name]++
			if err := validateNode(c, e.typ, path+"/"+c.name); err != nil {
				return err
			}
		}
		for _, e := range ct.elements {
			if counts[e.name] < e.min || counts[e.name] > e.max {
				return fmt.Errorf("%s: <%s> occurs %d times, want %d to %d", path, e.name, counts[e.name], e.min, e.max)
			}
		}
		return nil
	}
	i := 0
	for _, e := range ct.elements {
		count := 0
		for i < len(n.children) && n.children[i].name == e.name && (e.max < 0 || count < e.max) {
			if err := validateNode(n.children[i], e.typ, path+"/"+e.name); err != nil {
				return err
			}
			count++
			i++
		}
		if count < e.min {
			return fmt.Errorf("%s: <%s> occurs %d times, want at least %d (in sequence)", path, e.name, count, e.min)
		}
	}
	if i < len(n.children) {
		return fmt.Errorf("%s: unexpected element <%s> (out of sequence)", path, n.children[i].name)
	}
	return nil
}

func validateSimple(text, typ, path string) error {
	if typ == "xs:string" {
		return nil
	}
	if typ == "RFC3986IP" {
		if ip, err := netip.ParseAddr(text); err != nil || ip.Zone() != "" || ip.Is4In6() {
			return fmt.Errorf("%s: %q is not an RFC 3986 IPv4address or IPv6address", path, text)
		}
		return nil
	}
	if enum, ok := appendixAEnumerations[typ]; ok {
		if !slices.Contains(enum, text) {
			return fmt.Errorf("%s: %q is not a %s %q", path, text, typ, enum)
		}
		return nil
	}
	re, ok := appendixAPatterns[typ]
	if !ok {
		return fmt.Errorf("%s: unknown type %s", path, typ)
	}
	value := text
	if strings.HasPrefix(typ, "xs:") {
		value = strings.TrimSpace(text) // the built-in numeric types collapse whitespace
	}
	if !re.MatchString(value) {
		return fmt.Errorf("%s: %q does not match %s", path, text, typ)
	}
	return nil
}

func findElement(elements []schemaElement, name string) (schemaElement, bool) {
	for _, e := range elements {
		if e.name == name {
			return e, true
		}
	}
	return schemaElement{}, false
}
