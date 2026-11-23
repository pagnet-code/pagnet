package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/internal/textbridge"
	"github.com/pagnet-code/pagnet/internal/textbridge/provider"
	"github.com/pagnet-code/pagnet/sdk"
)

func TestTextBridgeCreateExplicitProjectContract(t *testing.T) {
	for _, role := range []string{"sender", "responder"} {
		t.Run(role, func(t *testing.T) {
			state := textBridgeTestDir(t)
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				_ = json.NewEncoder(w).Encode(map[string]string{"id": textBridgeTestService, "activationCredential": "pgn_act_v1_test"})
			}))
			defer server.Close()
			deps := textBridgeDependencies{owner: func() (*cliCtx, error) { return &cliCtx{base: server.URL, token: "owner-token"}, nil }, provider: func(c provider.Config) (textbridge.Provider, error) { return provider.New(c) }}
			connected := 0
			deps.senderConnect = func(context.Context, sdk.Config) (textBridgeSenderConnection, error) {
				connected++
				return nil, errors.New("unexpected foreground connection")
			}
			args := []string{"sender", "create", "--name", "owner sender"}
			if role == "responder" {
				key := filepath.Join(state, "key")
				if err := os.WriteFile(key, []byte("test-provider-key"), 0600); err != nil {
					t.Fatal(err)
				}
				args = []string{"enable", "--name", "owner responder", "--provider-origin", "https://provider.example", "--model", "fixed", "--key-file", key, "--calls-per-day", "2"}
			}
			args = append(args, "--project-contract", textbridge.OwnerTextProjectContract, "--state-dir", state)
			if _, err := textBridgeExecute(t, deps, args...); err != nil {
				t.Fatal(err)
			}
			dir, err := textbridge.ProfileDirectoryForRole(state, textBridgeTestService, role)
			if err != nil {
				t.Fatal(err)
			}
			p, err := textbridge.LoadProfile(dir, textBridgeTestService)
			if err != nil || p.ProjectContract != textbridge.OwnerTextProjectContract || requests != 1 {
				t.Fatalf("saved owner contract: %+v %v", p.ProjectContract, err)
			}
			if role == "sender" {
				if _, err := textBridgeSenderExecute(t, deps, "question", "sender", "ask", "--service", p.Service, "--project", textBridgeSenderProject, "--to", textBridgeSenderRecipient, "--state-dir", state); err == nil || !strings.Contains(err.Error(), "registration") || connected != 0 {
					t.Fatal("unregistered owner sender used foreground sharing transport")
				}
				store, err := textbridge.OpenSenderStore(dir, p)
				if err != nil {
					t.Fatal(err)
				}
				store.Close()
			} else {
				store, err := textbridge.OpenProfileLedger(dir, p)
				if err != nil {
					t.Fatal(err)
				}
				store.Close()
			}
			_, err = textBridgeExecute(t, deps, "register", "--service", textBridgeTestService, "--role", role, "--project-contract", textbridge.SharingProjectContract, "--state-dir", state)
			if err == nil || !strings.Contains(err.Error(), "saved project contract cannot change") || requests != 1 {
				t.Fatal("registration switched contract or reached owner API")
			}
		})
	}
}
func TestTextBridgeRejectsUnknownProjectContractBeforeWork(t *testing.T) {
	deps := textBridgeDependencies{owner: func() (*cliCtx, error) {
		t.Error("unknown contract reached owner authentication")
		return nil, errors.New("unexpected")
	}}
	for _, args := range [][]string{{"sender", "create", "--project-contract", "unknown"}, {"enable", "--project-contract", "unknown"}, {"register", "--project-contract", "unknown"}} {
		if _, err := textBridgeExecute(t, deps, args...); err == nil || !strings.Contains(err.Error(), "--project-contract") {
			t.Fatal("unknown contract accepted")
		}
	}
}
