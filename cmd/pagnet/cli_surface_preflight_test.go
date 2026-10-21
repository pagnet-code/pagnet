//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDoctorToolStatusChecksInterpreterWithoutExecution(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	binary := filepath.Join(dir, "qwen")
	if err := os.WriteFile(binary, []byte("#!/usr/bin/env node\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if got := doctorToolStatus("qwen"); got != "runtime executable or interpreter unavailable" {
		t.Fatalf("missing interpreter reported as %q", got)
	}
	marker := filepath.Join(dir, "executed")
	if err := os.WriteFile(filepath.Join(dir, "node"), []byte("#!/bin/sh\nprintf executed > '"+marker+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if got := doctorToolStatus("qwen"); got != "found" {
		t.Fatalf("repaired interpreter reported as %q", got)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("doctor executed runtime")
	}
}
