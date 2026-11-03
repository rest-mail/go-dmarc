package dmarc

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rest-mail/go-dmarc/pkg/dmarc/internal/dnsname"
	"github.com/rest-mail/go-dmarc/pkg/dmarc/internal/reportcodec"
)

// FailureReportsDue says which failure reports a record's fo= tag asks for
// (RFC 9989 §4.7). DMARC is an RFC 9991 report, the one [BuildFailureReport]
// builds; DKIM and SPF are the mechanism-specific reports of RFC 6651 and
// RFC 6652, which the library does not build (RFC 9991 §3 leaves them to the
// receiver).
type FailureReportsDue struct {
	DMARC bool // fo=0 or fo=1 matched
	DKIM  bool // fo=d matched
	SPF   bool // fo=s matched
}

// Any reports whether any failure report is due.
func (d FailureReportsDue) Any() bool { return d.DMARC || d.DKIM || d.SPF }

// FailureReportsFor decides from a record's fo= options which failure
// reports a message calls for (RFC 9989 §4.7), given the message's DKIM
// signatures and SPF result as an [AggregateRecord] carries them:
//
//   - 0 (the default): a DMARC report when neither DKIM nor SPF produced an
//     aligned pass, that is when the message failed DMARC.
//   - 1: a DMARC report when either of them did not produce an aligned pass.
//     An unsigned message, or one whose SPF was not checked, has no aligned
//     pass from that mechanism.
//   - d: a DKIM report when any signature failed evaluation (a result other
//     than pass or none), aligned or not.
//   - s: an SPF report when SPF failed (fail, softfail, temperror or
//     permerror), aligned or not.
//
// Nothing is due when the record has no ruf= URI: fo= is then ignored and
// failure reports MUST NOT be generated (RFC 9989 §4.7). Nothing is due for a
// record with psd=y either: report generators MUST NOT consider its ruf= tag
// (RFC 9991 §2). The decision only says what the Domain Owner asked for;
// whether to send any report at all, and the rate limit RFC 9991 §2 requires,
// stay with the caller.
func FailureReportsFor(rec Record, dkim []DKIMAuth, spf *SPFAuth) FailureReportsDue {
	if len(rec.RUF) == 0 || strings.EqualFold(rec.PSD, "y") {
		return FailureReportsDue{}
	}
	dkimAligned := dmarcDKIM(dkim) == "pass"
	spfAligned := dmarcSPF(spf) == "pass"
	var due FailureReportsDue
	for _, o := range rec.FailureOptions {
		switch strings.ToLower(o) {
		case "0":
			due.DMARC = due.DMARC || !dkimAligned && !spfAligned
		case "1":
			due.DMARC = due.DMARC || !dkimAligned || !spfAligned
		case "d":
			for _, d := range dkim {
				if r := reportcodec.NormalizeDKIMResult(d.Result); r != "pass" && r != "none" {
					due.DKIM = true
				}
			}
		case "s":
			if spf != nil {
				switch reportcodec.NormalizeSPFResult(spf.Result) {
				case "fail", "softfail", "temperror", "permerror":
					due.SPF = true
				}
			}
		}
	}
	return due
}

// IdentityAlignment returns the value of the Identity-Alignment field of a
// DMARC failure report (RFC 9991 §4 item 2): "dkim", "spf" or "dkim, spf" for
// the mechanisms that did not authenticate an identity aligned with the From
// domain, or "none" when both did. A mechanism that was not attempted (no
// signature, SPF not checked) authenticated no aligned identity, so it is
// listed.
func IdentityAlignment(dkim []DKIMAuth, spf *SPFAuth) string {
	var failed []string
	if dmarcDKIM(dkim) != "pass" {
		failed = append(failed, "dkim")
	}
	if dmarcSPF(spf) != "pass" {
		failed = append(failed, "spf")
	}
	if len(failed) == 0 {
		return "none"
	}
	return strings.Join(failed, ", ")
}

// FailureReportURIs returns the ruf= URIs of a discovered policy that failure
// reports may go to: none when the record has no ruf= (RFC 9989 §4.7) or has
// psd=y (RFC 9991 §2), and otherwise the URIs that pass the external
// destination check of RFC 9990 §4 with "ruf" in place of "rua" (RFC 9991 §5),
// as [AuthorizeReportURIs] returns them.
//
// The obsolete "!" size limit a URI may carry was already dropped by
// [ParseRecord]: RFC 9989 §4.8 tells reporters to ignore it. A reporter that
// wants to bound the size of its reports sets [FailureReport.MaxOriginalSize].
func FailureReportURIs(p Policy, resolver TXTResolver) ([]string, error) {
	if len(p.Record.RUF) == 0 || strings.EqualFold(p.Record.PSD, "y") {
		return nil, nil
	}
	return AuthorizeReportURIs(p.Domain, "ruf", p.Record.RUF, resolver)
}

// ReportMailbox returns the address a mailto: report URI sends to: its first
// address, percent-decoded, without the query. It returns false for another
// scheme or a mailto: URI without an address.
func ReportMailbox(uri string) (string, bool) {
	u, err := url.Parse(uri)
	if err != nil || !strings.EqualFold(u.Scheme, "mailto") {
		return "", false
	}
	addr, _, _ := strings.Cut(u.Opaque, "?")
	addr, _, _ = strings.Cut(addr, ",")
	if addr, err = url.PathUnescape(addr); err != nil || !strings.Contains(addr, "@") {
		return "", false
	}
	return addr, true
}

// SPFDNS is one SPF record used to reach an SPF result, for the SPF-DNS field
// (RFC 6591 §3.2.6, §4).
type SPFDNS struct {
	Domain string // the name the record was retrieved from
	Record string // the record's text, e.g. "v=spf1 -all"
}

// HeaderRedactor rewrites one header field of the reported message, or of the
// Original-Mail-From and Original-Rcpt-To report fields, before it goes into a
// failure report. name is the field name as written; value is everything after
// the colon, folding included. It returns the new value and whether to keep
// the field at all. RFC 6590 describes the redaction it is meant for.
type HeaderRedactor func(name, value string) (string, bool)

// FailureReport is what [BuildFailureReport] needs to build one RFC 9991
// failure report: the reporter's details, the message's DMARC evaluation, and
// the original message.
type FailureReport struct {
	// From, To and Date are the report message's own header fields: the
	// reporter's address, the destination (see [ReportMailbox]) and the time
	// the report is made. MessageID is its Message-ID, angle brackets
	// included, and is left out when empty. All but MessageID are required.
	From      string
	To        string
	Date      time.Time
	MessageID string

	// UserAgent names the generating software and its version (RFC 5965
	// §3.1), e.g. "rest-mail/1.4". Required.
	UserAgent string
	// ReportingMTA is the name of the MTA making the report (optional).
	ReportingMTA string

	// AuthenticationResults is the value of the report's single
	// Authentication-Results field (RFC 6591 §3.1): the DMARC result only,
	// e.g. "mx.example.net; dmarc=fail header.from=example.com". Required.
	AuthenticationResults string
	// ReportedDomain is the From domain the report is about, which RFC 6591
	// §3.1 requires when known. Required.
	ReportedDomain string
	// DKIM and SPF are the message's results, as for an [AggregateRecord].
	// They give the Identity-Alignment field, and the DKIM-Domain,
	// DKIM-Identity and DKIM-Selector fields of the first aligned signature
	// that did not pass (RFC 9991 §4 item 1).
	DKIM []DKIMAuth
	SPF  *SPFAuth
	// SPFDNS lists the SPF records used to reach the SPF result. It is
	// required when an aligned SPF identity failed (RFC 9991 §4 item 1), and
	// written as one SPF-DNS field each.
	SPFDNS []SPFDNS
	// DeliveryResult is delivered, spam, policy, reject or other (RFC 6591
	// §3.2.2), or "" to leave the field out.
	DeliveryResult string

	// The SMTP transaction, all optional; RFC 6591 §3.1 recommends the
	// envelope ID, MAIL FROM and source IP when known.
	OriginalEnvelopeID string
	OriginalMailFrom   string
	OriginalRcptTo     []string
	ArrivalDate        time.Time
	SourceIP           string
	SourcePort         int // RFC 6692; 0 leaves it out
	// Incidents is the number of similar failures this report stands for
	// (RFC 5965 §3.2; RFC 9991 §8.1 encourages grouping). 0 or 1 leaves the
	// field out: one incident.
	Incidents uint32

	// Message is the original message, header and body, as received.
	Message []byte
	// IncludeBody puts the whole message in the report as message/rfc822.
	// When false, the default, only its header goes in, as
	// text/rfc822-headers: RFC 9991 §7 asks reporters to minimise what they
	// expose.
	IncludeBody bool
	// MaxOriginalSize bounds the third part in octets. A whole message that
	// would exceed it is reported by its header alone, and a header that
	// still exceeds it is an error. 0 means no limit.
	MaxOriginalSize int
	// RedactHeader, when set, rewrites or drops each header field of the
	// original message and the Original-Mail-From and Original-Rcpt-To
	// fields. See [RedactLocalParts].
	RedactHeader HeaderRedactor
	// RedactBody, when set, rewrites the body of a message reported with
	// IncludeBody.
	RedactBody func(body []byte) []byte

	// Boundary is the multipart boundary; "" picks a random one.
	Boundary string
}

// BuildFailureReport builds an RFC 9991 DMARC failure report: an RFC 5965
// feedback report, a multipart/report message of report-type
// feedback-report, with
//
//  1. a text/plain part describing the report;
//  2. a message/feedback-report part with Feedback-Type auth-failure (RFC
//     6591), Auth-Failure dmarc, and the Identity-Alignment, DKIM-* and
//     SPF-DNS fields of RFC 9991 §4;
//  3. the original message as message/rfc822, or its header block as
//     text/rfc822-headers, after redaction.
//
// It returns the whole report message, header included, with CRLF line
// endings, ready for the caller to send; the library sends nothing. Its
// Subject is the original message's (RFC 5965 §2 item f). It returns an error
// for a missing required value, a field value that is not one line of ASCII,
// an original message without a header, or a third part over
// MaxOriginalSize.
//
// Whether to send a report is the caller's: see [FailureReportsFor],
// [FailureReportURIs], and the privacy considerations of RFC 9991 §7, which
// lead many receivers to send none at all.
func BuildFailureReport(r FailureReport) ([]byte, error) {
	switch {
	case r.From == "" || r.To == "":
		return nil, errors.New("dmarc: a failure report needs From and To")
	case r.Date.IsZero():
		return nil, errors.New("dmarc: a failure report needs a Date")
	case r.UserAgent == "":
		return nil, errors.New("dmarc: a failure report needs a User-Agent")
	case r.AuthenticationResults == "":
		return nil, errors.New("dmarc: a failure report needs the DMARC Authentication-Results")
	}
	domain, ok := dnsname.QueryDomain(r.ReportedDomain)
	if !ok {
		return nil, fmt.Errorf("dmarc: reported domain %q is not a domain name", r.ReportedDomain)
	}
	header, body, ok := splitMessage(r.Message)
	if !ok {
		return nil, errors.New("dmarc: the original message has no header")
	}
	fields := parseHeader(header)

	feedback, err := feedbackFields(r, domain)
	if err != nil {
		return nil, err
	}
	original, originalType := originalPart(r, fields, body)
	if r.MaxOriginalSize > 0 && len(original) > r.MaxOriginalSize && originalType == "message/rfc822" {
		original, originalType = originalPart(FailureReport{RedactHeader: r.RedactHeader}, fields, nil)
	}
	if r.MaxOriginalSize > 0 && len(original) > r.MaxOriginalSize {
		return nil, fmt.Errorf("dmarc: the original header is %d octets, over the %d allowed", len(original), r.MaxOriginalSize)
	}

	human := "This is a DMARC failure report for an email message"
	if r.SourceIP != "" {
		human += " received from IP " + r.SourceIP
	}
	if !r.ArrivalDate.IsZero() {
		human += " on " + r.ArrivalDate.Format(time.RFC1123Z)
	}
	human += ".\r\nThe message failed to authenticate an identity aligned with the\r\n" +
		"From domain " + domain + " (Identity-Alignment: " + IdentityAlignment(r.DKIM, r.SPF) + ").\r\n"

	boundary := r.Boundary
	if boundary == "" {
		var b [12]byte
		_, _ = rand.Read(b[:])
		boundary = "=_dmarc_" + hex.EncodeToString(b[:])
	}
	for _, part := range [][]byte{[]byte(human), feedback, original} {
		if bytes.Contains(part, []byte("--"+boundary)) {
			return nil, errors.New("dmarc: the boundary appears in the report")
		}
	}

	var out bytes.Buffer
	for _, f := range []struct{ name, value string }{
		{"From", r.From}, {"To", r.To}, {"Date", r.Date.Format(time.RFC1123Z)},
		{"Subject", subjectOf(fields)}, {"Message-ID", r.MessageID},
	} {
		if f.value == "" {
			continue
		}
		if f.name != "Subject" && !oneLine(f.value, false) {
			return nil, fmt.Errorf("dmarc: %s is not one line", f.name)
		}
		out.WriteString(f.name + ":" + leadSpace(f.value) + "\r\n")
	}
	out.WriteString("MIME-Version: 1.0\r\n")
	out.WriteString("Content-Type: multipart/report; report-type=feedback-report;\r\n\tboundary=\"" + boundary + "\"\r\n\r\n")
	out.WriteString("This is a MIME-formatted message.\r\n")
	writePart := func(contentType string, content []byte) {
		out.WriteString("\r\n--" + boundary + "\r\n")
		out.WriteString("Content-Type: " + contentType + "\r\n")
		out.WriteString("Content-Transfer-Encoding: " + transferEncoding(content) + "\r\n\r\n")
		out.Write(content)
	}
	writePart("text/plain; charset=us-ascii", []byte(human))
	writePart("message/feedback-report", feedback)
	writePart(originalType, original)
	out.WriteString("\r\n--" + boundary + "--\r\n")
	return out.Bytes(), nil
}

// feedbackFields writes the message/feedback-report part.
func feedbackFields(r FailureReport, domain string) ([]byte, error) {
	var b bytes.Buffer
	var bad string
	add := func(name, value string) {
		if value == "" {
			return
		}
		if !oneLine(value, true) && bad == "" {
			bad = name
		}
		b.WriteString(name + ": " + value + "\r\n")
	}
	add("Feedback-Type", "auth-failure")
	add("User-Agent", r.UserAgent)
	add("Version", "1")
	add("Auth-Failure", "dmarc")
	add("Authentication-Results", r.AuthenticationResults)
	add("Identity-Alignment", IdentityAlignment(r.DKIM, r.SPF))
	switch dr := strings.ToLower(r.DeliveryResult); dr {
	case "", "delivered", "spam", "policy", "reject", "other":
		add("Delivery-Result", dr)
	default:
		return nil, fmt.Errorf("dmarc: delivery result %q is not one of RFC 6591's", r.DeliveryResult)
	}
	for _, d := range r.DKIM {
		if d.Aligned && reportcodec.NormalizeDKIMResult(d.Result) != "pass" {
			identity := d.Identity
			if identity == "" {
				identity = "@" + d.Domain // the i= default (RFC 6376 §3.5)
			}
			add("DKIM-Domain", d.Domain)
			add("DKIM-Identity", identity)
			add("DKIM-Selector", d.Selector)
			break
		}
	}
	if r.SPF != nil && r.SPF.Aligned && reportcodec.NormalizeSPFResult(r.SPF.Result) != "pass" {
		if len(r.SPFDNS) == 0 {
			return nil, errors.New("dmarc: an aligned SPF failure needs its SPF-DNS records")
		}
		for _, s := range r.SPFDNS {
			add("SPF-DNS", "txt : "+s.Domain+" : "+strconv.Quote(s.Record))
		}
	}
	add("Original-Envelope-Id", r.OriginalEnvelopeID)
	add("Original-Mail-From", redactField(r.RedactHeader, "Original-Mail-From", r.OriginalMailFrom))
	for _, rcpt := range r.OriginalRcptTo {
		add("Original-Rcpt-To", redactField(r.RedactHeader, "Original-Rcpt-To", rcpt))
	}
	if !r.ArrivalDate.IsZero() {
		add("Arrival-Date", r.ArrivalDate.Format(time.RFC1123Z))
	}
	add("Reporting-MTA", r.ReportingMTA)
	if r.SourceIP != "" {
		ip, err := netip.ParseAddr(r.SourceIP)
		if err != nil || ip.Zone() != "" {
			return nil, fmt.Errorf("dmarc: source IP %q is not an IP address", r.SourceIP)
		}
		ip = ip.Unmap()
		if ip.Is4() {
			add("Source-IP", ip.String())
		} else {
			add("Source-IP", "IPv6:"+ip.String()) // RFC 5321 §4.1.3
		}
	}
	if r.SourcePort > 0 {
		add("Source-Port", strconv.Itoa(r.SourcePort))
	}
	if r.Incidents > 1 {
		add("Incidents", strconv.FormatUint(uint64(r.Incidents), 10))
	}
	add("Reported-Domain", domain)
	if bad != "" {
		return nil, fmt.Errorf("dmarc: %s is not one line of ASCII", bad)
	}
	return b.Bytes(), nil
}

// redactField applies the redactor to a report field, dropping it when the
// redactor says so.
func redactField(redact HeaderRedactor, name, value string) string {
	if redact == nil || value == "" {
		return value
	}
	v, keep := redact(name, " "+value)
	if !keep {
		return ""
	}
	return strings.TrimSpace(v)
}

// headerField is one field of the original header: its name and everything
// after the colon, folding kept.
type headerField struct{ name, value string }

// originalPart builds the third MIME part.
func originalPart(r FailureReport, fields []headerField, body []byte) ([]byte, string) {
	var b bytes.Buffer
	for _, f := range fields {
		value := f.value
		if r.RedactHeader != nil {
			var keep bool
			if value, keep = r.RedactHeader(f.name, value); !keep {
				continue
			}
		}
		b.WriteString(f.name + ":" + value + "\r\n")
	}
	if !r.IncludeBody {
		return b.Bytes(), "text/rfc822-headers"
	}
	if r.RedactBody != nil {
		body = r.RedactBody(body)
	}
	b.WriteString("\r\n")
	b.Write(crlf(body))
	return b.Bytes(), "message/rfc822"
}

// splitMessage splits a message at the empty line that ends its header. A
// message with no empty line is all header.
func splitMessage(msg []byte) (header, body []byte, ok bool) {
	msg = crlf(msg)
	if len(msg) == 0 || msg[0] == '\r' {
		return nil, nil, false
	}
	if i := bytes.Index(msg, []byte("\r\n\r\n")); i >= 0 {
		return msg[:i+2], msg[i+4:], true
	}
	if !bytes.HasSuffix(msg, []byte("\r\n")) {
		msg = append(msg, '\r', '\n')
	}
	return msg, nil, true
}

// parseHeader splits a CRLF header block into fields, keeping each field's
// folding. A line that is neither a field nor a continuation is dropped.
func parseHeader(header []byte) []headerField {
	var fields []headerField
	for _, line := range strings.Split(strings.TrimSuffix(string(header), "\r\n"), "\r\n") {
		if (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) && len(fields) > 0 {
			fields[len(fields)-1].value += "\r\n" + line
			continue
		}
		name, value, found := strings.Cut(line, ":")
		if !found || name == "" || strings.ContainsAny(name, " \t") {
			continue
		}
		fields = append(fields, headerField{name, value})
	}
	return fields
}

// crlf turns bare LF and bare CR line endings into CRLF.
func crlf(b []byte) []byte {
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	b = bytes.ReplaceAll(b, []byte("\r"), []byte("\n"))
	return bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n"))
}

// subjectOf returns the original Subject field's value, folding kept.
func subjectOf(fields []headerField) string {
	for _, f := range fields {
		if strings.EqualFold(f.name, "Subject") {
			return f.value
		}
	}
	return ""
}

// leadSpace makes a field value start with the space after the colon.
func leadSpace(v string) string {
	if strings.HasPrefix(v, " ") || strings.HasPrefix(v, "\t") {
		return v
	}
	return " " + v
}

// oneLine reports whether a value has no CR or LF, and, when ascii is set,
// only printable ASCII and tabs (RFC 5965 §6: the report part is 7bit).
func oneLine(v string, ascii bool) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '\r' || c == '\n' || c == 0 || ascii && (c > 126 || c < 32 && c != '\t') {
			return false
		}
	}
	return true
}

// transferEncoding is 7bit for ASCII content and 8bit otherwise.
func transferEncoding(b []byte) string {
	for _, c := range b {
		if c > 127 {
			return "8bit"
		}
	}
	return "7bit"
}

// addrSpec matches the local part and "@" of an address in a header value:
// a dot-atom or a quoted string followed by "@" and a domain.
var addrSpec = regexp.MustCompile(`("(?:[^"\\\r\n]|\\.)*"|[A-Za-z0-9!#$%&'*+/=?^_` + "`" + `{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_` + "`" + `{|}~-]+)*)@([A-Za-z0-9])`)

// RedactLocalParts returns a [HeaderRedactor] that replaces the local part of
// every address in a header value with a token derived from it and secret,
// as RFC 6590 §4 suggests and RFC 9991 Appendix A illustrates: the same local
// part always gives the same token under one secret, so a Report Consumer can
// still match addresses across reports without learning them. Domains are
// kept, so alignment stays visible. Keep secret private and change it
// whenever the tokens should stop matching.
//
// "=" may appear in a local part, but in a header value it more often ends a
// tag, as in DKIM-Signature's i=user@example.com or Authentication-Results'
// header.i=@example.com. So only the text after the last "=" of an unquoted
// local part is replaced: the tag names stay, an empty identity stays empty,
// and an SRS address keeps its hash and domain but loses the original local
// part.
func RedactLocalParts(secret []byte) HeaderRedactor {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return func(_, value string) (string, bool) {
		return addrSpec.ReplaceAllStringFunc(value, func(m string) string {
			at := strings.LastIndexByte(m, '@')
			prefix, local := "", m[:at]
			if i := strings.LastIndexByte(local, '='); i >= 0 && !strings.HasPrefix(local, `"`) {
				prefix, local = local[:i+1], local[i+1:]
			}
			if local == "" {
				return m
			}
			mac := hmac.New(sha256.New, secret)
			mac.Write([]byte(local))
			return prefix + strings.ToLower(enc.EncodeToString(mac.Sum(nil)[:5])) + m[at:]
		}), true
	}
}
