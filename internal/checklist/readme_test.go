package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Check the real mappings before counting them: a row naming a missing test
// must never contribute to a green README badge.
func TestReadmeChecklistBadge(t *testing.T) {
	root := filepath.Join("..", "..")
	file := filepath.Join(root, "CHECKLIST.md")
	// The audited producer measures statements across packages with -coverpkg;
	// its coverage_total still rejects totals outside 95..100.
	const auditedProducer = "rest-mail/go-spf/.github/workflows/rfc-verification.yml@2409e76ef1e501e0222e6c25a0c7a6202de1051b"
	workflow, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(workflow), "uses: "+auditedProducer+"\n") {
		t.Fatal("coverage gate needs re-audit: RFC producer changed")
	}
	args := []string{"-file", file}
	for _, line := range strings.Split(string(workflow), "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "checklist-dirs: '"); ok {
			var dirs []string
			if err := json.Unmarshal([]byte(strings.TrimSuffix(value, "'")), &dirs); err != nil {
				t.Fatal(err)
			}
			for _, dir := range dirs {
				args = append(args, filepath.Join(root, dir))
			}
		}
	}
	if len(args) == 2 {
		t.Fatal("CI checklist-dirs names no package directory")
	}
	var out bytes.Buffer
	if code := run(args, &out, &out); code != 0 {
		t.Fatalf("invalid checklist (exit %d):\n%s", code, out.String())
	}
	items, err := parseChecklist(file, func(format string, args ...any) {
		t.Errorf(format, args...)
	})
	if err != nil {
		t.Fatal(err)
	}
	mapped := 0
	for _, it := range items {
		if !it.na {
			mapped++
		}
	}
	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("[![Checklist: %d/%d mapped](https://img.shields.io/badge/checklist-%d%%2F%d%%20mapped-blue)](CHECKLIST.md)",
		mapped, len(items), mapped, len(items))
	if !strings.Contains(string(readme), want) {
		t.Fatalf("stale or missing README checklist badge; want:\n%s", want)
	}
}
