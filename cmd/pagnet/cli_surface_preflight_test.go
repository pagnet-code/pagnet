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
	if got := doctorToolStatus("qwen", nil); got != "runtime executable or interpreter unavailable" {
		t.Fatalf("missing interpreter reported as %q", got)
	}
	marker := filepath.Join(dir, "executed")
	if err := os.WriteFile(filepath.Join(dir, "node"), []byte("#!/bin/sh\nprintf executed > '"+marker+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if got := doctorToolStatus("qwen", nil); got != "found" {
		t.Fatalf("repaired interpreter reported as %q", got)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("doctor executed runtime")
	}
}

func TestDoctorToolStatusUsesConfiguredRuntimePath(t *testing.T) {
	wrapperDir := t.TempDir()
	withNode := t.TempDir()
	withoutNode := t.TempDir()
	if err := os.WriteFile(filepath.Join(wrapperDir, "qwen"), []byte("#!/usr/bin/env node\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(withNode, "node"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", wrapperDir+string(os.PathListSeparator)+withoutNode)
	if got := doctorToolStatus("qwen", []string{"PATH=" + withNode}); got != "found" {
		t.Fatalf("configured interpreter ignored: %q", got)
	}
	t.Setenv("PATH", wrapperDir+string(os.PathListSeparator)+withNode)
	if got := doctorToolStatus("qwen", []string{"PATH=" + withoutNode}); got != "runtime executable or interpreter unavailable" {
		t.Fatalf("inherited interpreter overrode configured PATH: %q", got)
	}
}
