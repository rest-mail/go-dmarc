package dnsname

import (
	"strings"
	"testing"
	"time"
)

// TestLongNamesRefusedQuickly checks that a name too long to be a DNS name is
// refused before it is punycode-encoded, whose time is quadratic in the
// label's length: a megabyte of Unicode in a From domain once took minutes.
//
// checklist: DMARC-DISC-15
func TestLongNamesRefusedQuickly(t *testing.T) {
	long := strings.Repeat("ü", 1<<19) + ".com"
	start := time.Now()
	if _, ok := QueryDomain(long); ok {
		t.Error("an over-long name was accepted")
	}
	if _, ok := QueryDomain(strings.Repeat("ü", 255)); ok {
		t.Error("a 255-code-point name is a domain")
	}
	if got := labelToASCII(strings.Repeat("ü", 64)); got != strings.Repeat("ü", 64) {
		t.Errorf("a 64-code-point label was encoded to %q", got)
	}
	if got := labelToASCII(strings.Repeat("ü", 63)); !strings.HasPrefix(got, "xn--") {
		t.Errorf("a 63-code-point label encodes to %q", got)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
}
