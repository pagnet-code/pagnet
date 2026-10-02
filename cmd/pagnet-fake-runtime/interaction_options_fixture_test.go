package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
)

func TestPersistentInteractionOptionsInlineAndFile(t *testing.T) {
	raw := `[{"id":"allow","kind":"allow_once"},{"id":"deny","kind":"reject_once"}]`
	want := []domain.RuntimeInteractionOption{{ID: "allow", Kind: "allow_once"}, {ID: "deny", Kind: "reject_once"}}
	for _, file := range []bool{false, true} {
		t.Run(map[bool]string{false: "inline", true: "file"}[file], func(t *testing.T) {
			t.Setenv("PAGNET_FAKE_INTERACTION_OPTIONS", "")
			t.Setenv("PAGNET_FAKE_INTERACTION_OPTIONS_FILE", "")
			if file {
				p := filepath.Join(t.TempDir(), "options.json")
				if err := os.WriteFile(p, []byte(raw), 0600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("PAGNET_FAKE_INTERACTION_OPTIONS_FILE", p)
			} else {
				t.Setenv("PAGNET_FAKE_INTERACTION_OPTIONS", raw)
			}
			got, err := persistentInteractionOptions()
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("native observed options changed", err)
			}
		})
	}
}

func TestPersistentInteractionOptionsRejectInvalidAndOversize(t *testing.T) {
	for _, raw := range []string{`not JSON`, `[]`, `[{"id":"deny","kind":"reject"}]`, strings.Repeat(" ", maxFakeInteractionOptionsBytes+1)} {
		for _, file := range []bool{false, true} {
			t.Run(map[bool]string{false: "inline", true: "file"}[file], func(t *testing.T) {
				t.Setenv("PAGNET_FAKE_INTERACTION_OPTIONS", "")
				t.Setenv("PAGNET_FAKE_INTERACTION_OPTIONS_FILE", "")
				if file {
					p := filepath.Join(t.TempDir(), "options.json")
					if err := os.WriteFile(p, []byte(raw), 0600); err != nil {
						t.Fatal(err)
					}
					t.Setenv("PAGNET_FAKE_INTERACTION_OPTIONS_FILE", p)
				} else {
					t.Setenv("PAGNET_FAKE_INTERACTION_OPTIONS", raw)
				}
				if _, err := persistentInteractionOptions(); err == nil {
					t.Fatal("invalid native options accepted")
				}
			})
		}
	}
	t.Run("conflicting_sources", func(t *testing.T) {
		t.Setenv("PAGNET_FAKE_INTERACTION_OPTIONS", "[]")
		t.Setenv("PAGNET_FAKE_INTERACTION_OPTIONS_FILE", "unused")
		if _, err := persistentInteractionOptions(); err == nil {
			t.Fatal("conflicting sources accepted")
		}
	})
	t.Run("nonregular_file", func(t *testing.T) {
		t.Setenv("PAGNET_FAKE_INTERACTION_OPTIONS", "")
		t.Setenv("PAGNET_FAKE_INTERACTION_OPTIONS_FILE", t.TempDir())
		if _, err := persistentInteractionOptions(); err == nil {
			t.Fatal("nonregular source accepted")
		}
	})
}
