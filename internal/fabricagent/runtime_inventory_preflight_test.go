//go:build !windows

package fabricagent

import (
	"context"
	"github.com/pagnet-code/pagnet/domain"
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeInventoryChecksInterpreterAndRepairsWithoutExecution(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	binary := filepath.Join(dir, "qwen")
	if err := os.WriteFile(binary, []byte("#!/usr/bin/env node\n"), 0700); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(t.TempDir(), "profiles.json")
	check := func(want bool) {
		t.Helper()
		rows, err := RuntimeInventory(context.Background(), profilePath)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if row.Runtime == domain.RuntimeQwenCode && row.Available != want {
				t.Fatalf("runtime availability = %v, want %v", row.Available, want)
			}
		}
	}
	check(false)
	marker := filepath.Join(dir, "executed")
	if err := os.WriteFile(filepath.Join(dir, "node"), []byte("#!/bin/sh\nprintf executed > '"+marker+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	check(true)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("inventory executed runtime")
	}
}
