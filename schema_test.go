package dmarc

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
)

// The aggregate report schema of RFC 7489 Appendix C, written out as Go data
// so that validateReport can check a document against it without an XML
// schema library. Each complex type lists its child elements in the schema's
// order with their type and occurrences (maxOccurs -1 is "unbounded"); all
// marks an xs:all group, whose children may come in any order. Each simple
// type is an enumeration or a pattern, as in the schema. Namespaces are not
// checked: the schema names a target namespace but no report generator puts
// its elements in it, and neither does BuildReport.

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

var appendixCComplexTypes = map[string]schemaComplexType{
	"feedback": {elements: []schemaElement{
		one("version", "xs:decimal"),
		one("report_metadata", "ReportMetadataType"),
		one("policy_published", "PolicyPublishedType"),
		{"record", "RecordType", 1, -1},
	}},
	"DateRangeType": {all: true, elements: []schemaElement{one("begin", "xs:integer"), one("end", "xs:integer")}},
	"ReportMetadataType": {elements: []schemaElement{
		one("org_name", "xs:string"),
		one("email", "xs:string"),
		optional("extra_contact_info", "xs:string"),
		one("report_id", "xs:string"),
		one("date_range", "DateRangeType"),
		{"error", "xs:string", 0, -1},
	}},
	"PolicyPublishedType": {all: true, elements: []schemaElement{
		one("domain", "xs:string"),
		optional("adkim", "AlignmentType"),
		optional("aspf", "AlignmentType"),
		one("p", "DispositionType"),
		one("sp", "DispositionType"),
		one("pct", "xs:integer"),
		one("fo", "xs:string"),
	}},
	"PolicyOverrideReason": {all: true, elements: []schemaElement{
		one("type", "PolicyOverrideType"),
		optional("comment", "xs:string"),
	}},
	"PolicyEvaluatedType": {elements: []schemaElement{
		one("disposition", "DispositionType"),
		one("dkim", "DMARCResultType"),
		one("spf", "DMARCResultType"),
		{"reason", "PolicyOverrideReason", 0, -1},
	}},
	"RowType": {all: true, elements: []schemaElement{
		one("source_ip", "IPAddress"),
		one("count", "xs:integer"),
		one("policy_evaluated", "PolicyEvaluatedType"),
	}},
	"IdentifierType": {all: true, elements: []schemaElement{
		optional("envelope_to", "xs:string"),
		one("envelope_from", "xs:string"),
		one("header_from", "xs:string"),
	}},
	"DKIMAuthResultType": {all: true, elements: []schemaElement{
		one("domain", "xs:string"),
		optional("selector", "xs:string"),
		one("result", "DKIMResultType"),
		optional("human_result", "xs:string"),
	}},
	"SPFAuthResultType": {all: true, elements: []schemaElement{
		one("domain", "xs:string"),
		one("scope", "SPFDomainScope"),
		one("result", "SPFResultType"),
	}},
	"AuthResultType": {elements: []schemaElement{
		{"dkim", "DKIMAuthResultType", 0, -1},
		{"spf", "SPFAuthResultType", 1, -1},
	}},
	"RecordType": {elements: []schemaElement{
		one("row", "RowType"),
		one("identifiers", "IdentifierType"),
		one("auth_results", "AuthResultType"),
	}},
}

var appendixCEnumerations = map[string][]string{
	"AlignmentType":      {"r", "s"},
	"DispositionType":    {"none", "quarantine", "reject"},
	"DMARCResultType":    {"pass", "fail"},
	"PolicyOverrideType": {"forwarded", "sampled_out", "trusted_forwarder", "mailing_list", "local_policy", "other"},
	"DKIMResultType":     {"none", "pass", "fail", "policy", "neutral", "temperror", "permerror"},
	"SPFDomainScope":     {"helo", "mfrom"},
	"SPFResultType":      {"none", "neutral", "pass", "fail", "softfail", "temperror", "permerror"},
}

// appendixCPatterns are the schema's patterns, anchored as XML Schema
// patterns are; the built-in xs:integer and xs:decimal lexical forms are here
// too. IPAddress is the schema's own pattern, character for character.
var appendixCPatterns = map[string]*regexp.Regexp{
	"IPAddress":  regexp.MustCompile(`^(?:((1?[0-9]?[0-9]|2[0-4][0-9]|25[0-5]).){3}(1?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])|([A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4})$`),
	"xs:integer": regexp.MustCompile(`^[+-]?[0-9]+$`),
	"xs:decimal": regexp.MustCompile(`^[+-]?([0-9]+(\.[0-9]*)?|\.[0-9]+)$`),
}

// xmlNode is a parsed element: its name, its child elements, and its text.
type xmlNode struct {
	name     string
	children []*xmlNode
	text     strings.Builder
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
			n := &xmlNode{name: tok.Name.Local}
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

// validateReport checks an aggregate report document against the Appendix C
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
	ct, complex := appendixCComplexTypes[typ]
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
	if enum, ok := appendixCEnumerations[typ]; ok {
		if !slices.Contains(enum, text) {
			return fmt.Errorf("%s: %q is not a %s %q", path, text, typ, enum)
		}
		return nil
	}
	re, ok := appendixCPatterns[typ]
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
