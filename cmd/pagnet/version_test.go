package main

import (
	"bytes"
	"testing"
)

// TestVersionCommand pins the `pagnet version` output format: one line,
// "pagnet <version>". The version var is stamped at release-build time
// (-X main.version=$(VERSION)); in tests it is the "dev" default.
func TestVersionCommand(t *testing.T) {
	if version == "" {
		t.Fatal("version must be non-empty (stamped or the dev default)")
	}
	cmd := versionCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if want := "pagnet " + version + "\n"; buf.String() != want {
		t.Fatalf("version output = %q, want %q", buf.String(), want)
	}
}
