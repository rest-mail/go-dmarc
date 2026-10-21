package main

import (
	"bytes"
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
	var out bytes.Buffer
	if code := run([]string{"-file", file, root}, &out, &out); code != 0 {
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
