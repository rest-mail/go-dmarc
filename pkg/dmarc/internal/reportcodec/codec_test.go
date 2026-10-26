package reportcodec

import "testing"

// TestEvaluated_RequiresPassAndAlign checks that a mechanism counts for DMARC only when it passed and aligned.
//
// checklist: DMARC-ALIGN-05 DMARC-XML-13
func TestEvaluated_RequiresPassAndAlign(t *testing.T) {
	if Evaluated("pass", false) != "fail" {
		t.Error("pass-but-unaligned must evaluate to fail")
	}
	if Evaluated("pass", true) != "pass" {
		t.Error("pass+aligned must evaluate to pass")
	}
	if Evaluated("fail", true) != "fail" {
		t.Error("fail must evaluate to fail")
	}
}
