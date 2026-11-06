package main

import (
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/externalprofile"
	"github.com/pagnet-code/pagnet/internal/runtimeconnect"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExternalReceiveAsksRequiresPrivateProfile(t *testing.T) {
	cmd := mcpExternalCmd()
	cmd.SetArgs([]string{"--receive-asks"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "requires a private --profile") {
		t.Fatalf("receive without private profile: %v", err)
	}
}

func TestExternalRuntimeBindingRequiresPrivateInboundStdio(t *testing.T) {
	for _, args := range [][]string{
		{"--runtime-binding", "saved"},
		{"--runtime-binding", "saved", "--profile", "work"},
		{"--runtime-binding", "saved", "--profile", "work", "--receive-asks", "--listen", "127.0.0.1:9000"},
	} {
		cmd := mcpExternalCmd()
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "requires a private --profile, --receive-asks and stdio") {
			t.Fatalf("invalid runtime binding accepted: %v", err)
		}
	}
}

func TestExternalRuntimeBindingRejectsForeignOrForgedRecord(t *testing.T) {
	state := t.TempDir()
	name := "pagnet_external_" + strings.ReplaceAll(domain.NewID().String(), "-", "")
	tokenFile := filepath.Join(state, "token")
	if err := os.WriteFile(tokenFile, []byte("private-operator-test-token"), 0600); err != nil {
		t.Fatal(err)
	}
	valid := runtimeconnect.Binding{URL: "http://127.0.0.1:4170", Workspace: state, Session: "live", Client: "registered", Name: name, TokenFile: tokenFile, Profile: "work", AutoAnswer: true}
	for _, scenario := range []string{"valid", "foreign-profile", "foreign-name", "outbound-only", "public-record", "symlink-record", "missing-token", "relative-token", "public-token", "symlink-token", "traversal"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			binding := valid
			if scenario == "public-token" || scenario == "symlink-token" {
				binding.TokenFile = filepath.Join(dir, "operator-token")
				if err := os.WriteFile(binding.TokenFile, []byte("private-operator-test-token"), 0600); err != nil {
					t.Fatal(err)
				}
				if scenario == "public-token" {
					if err := os.Chmod(binding.TokenFile, 0644); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Rename(binding.TokenFile, binding.TokenFile+".real"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(binding.TokenFile+".real", binding.TokenFile); err != nil {
						t.Fatal(err)
					}
				}
			}
			switch scenario {
			case "foreign-profile":
				binding.Profile = "other"
			case "foreign-name":
				binding.Name = "pagnet_external_foreign"
			case "outbound-only":
				binding.AutoAnswer = false
			case "missing-token":
				binding.TokenFile = filepath.Join(state, "missing")
			case "relative-token":
				binding.TokenFile = "token"
			}
			path := filepath.Join(dir, "runtime-connections", name+".json")
			if err := externalprofile.SaveBinding(path, binding); err != nil {
				t.Fatal(err)
			}
			if scenario == "public-record" {
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "symlink-record" {
				if err := os.Rename(path, path+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".real", path); err != nil {
					t.Fatal(err)
				}
			}
			requested := name
			if scenario == "traversal" {
				requested = "../" + name
			}
			qwen, err := externalRuntimeBinding(dir, "work", requested)
			if scenario == "valid" {
				if err != nil || qwen == nil {
					t.Fatalf("valid binding refused: %v", err)
				}
			} else if err == nil {
				t.Fatal("unsafe runtime binding accepted")
			}
		})
	}
}

func TestRuntimeAutoAnswerRequiresAllowedSenders(t *testing.T) {
	state := t.TempDir()
	path, _ := externalprofile.Path(state, "work")
	p := externalprofile.Profile{Version: 1, Principal: domain.NewID().String(), Network: domain.NewID().String(), Server: "https://app.pagnet.dev", Credential: "pgn_epd_v1_unused"}
	if err := externalprofile.SaveNew(path, p); err != nil {
		t.Fatal(err)
	}
	cmd := mcpRuntimeConnectCmd()
	cmd.SetArgs([]string{"--state-dir", state, "--profile", "work", "--auto-answer", "--url", "http://127.0.0.1:1", "--workspace", state, "--session", "live", "--client-id", "registered", "--token-file", filepath.Join(state, "unused")})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--allow-from") {
		t.Fatalf("auto-answer without senders: %v", err)
	}
}
