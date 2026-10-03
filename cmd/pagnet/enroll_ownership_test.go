package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pagnet-code/pagnet/internal/accounts"
)

func enrollmentStateSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	entries := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			entries[rel+"/"] = ""
			return nil
		}
		data, err := os.ReadFile(path)
		entries[rel] = string(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func TestEnrollOwnershipRequestBoundary(t *testing.T) {
	for _, ownership := range []string{"", "personal", "organization"} {
		t.Run("scope="+ownership, func(t *testing.T) {
			withFileFallback(t)
			t.Setenv("PAGNET_ENROLL_TOKEN", "")
			t.Setenv("PAGNET_SERVER", "")
			var mintedBody map[string]any
			var enrollmentBody map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/" + tokenExchangePath:
					fmt.Fprintf(w, `{"credential":%q,"role":"admin","networkScope":"all"}`, testDeviceCredential)
				case "/api/v1/auth/me":
					fmt.Fprint(w, `{"kind":"user","isAdmin":true,"userId":"signed-in-user"}`)
				case "/api/v1/hosts/enrollment-tokens":
					if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+testDeviceCredential {
						t.Error("enrollment mint did not use authenticated POST")
					}
					if err := json.NewDecoder(r.Body).Decode(&mintedBody); err != nil {
						t.Error(err)
					}
					w.WriteHeader(http.StatusCreated)
					fmt.Fprint(w, `{"token":"one-time-enrollment"}`)
				case "/api/v1/hosts/enroll":
					if err := json.NewDecoder(r.Body).Decode(&enrollmentBody); err != nil {
						t.Error(err)
					}
					fmt.Fprint(w, `{"host":{"ID":"host-1"},"credential":"host-credential","rootsMode":"allow_list","allowedRoots":["/work"]}`)
				default:
					t.Errorf("unexpected HTTP request %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			previousServer, previousAccount, previousUserToken := serverURL, accountFlag, userToken
			serverURL, accountFlag, userToken = server.URL, "", testAccountToken
			t.Cleanup(func() { serverURL, accountFlag, userToken = previousServer, previousAccount, previousUserToken })
			root := t.TempDir()
			args := []string{"--state-dir", root, "--name", "test-host", "--roots", "/work"}
			if ownership != "" {
				args = append(args, "--ownership", ownership)
			}
			cmd := enrollCmd()
			cmd.SetArgs(args)
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			want := map[string]any{"name": "test-host", "allowedRoots": []any{"/work"}}
			if ownership != "" {
				want["ownershipScope"] = ownership
			}
			if !reflect.DeepEqual(mintedBody, want) {
				t.Fatalf("mint payload = %#v; want %#v", mintedBody, want)
			}
			if _, specified := enrollmentBody["ownershipScope"]; specified {
				t.Fatal("ownership was resent while consuming the authoritative enrollment token")
			}
			cfg, _, err := loadAccountConfig(root)
			if err != nil || cfg.HostID != "host-1" || cfg.Credential != "host-credential" {
				t.Fatalf("host enrollment was not saved: %v", err)
			}
		})
	}
}

func TestEnrollOwnershipRejectsBeforeAuthenticationOrStateChanges(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		envToken string
		enrolled bool
		wantErr  string
	}{
		{name: "invalid", args: []string{"--ownership", "shared"}, wantErr: "must be personal or organization"},
		{name: "explicit empty", args: []string{"--ownership", ""}, wantErr: "must be personal or organization"},
		{name: "token personal", args: []string{"--ownership", "personal", "--token", "one-time"}, wantErr: "already specifies ownership"},
		{name: "token organization", args: []string{"--ownership", "organization", "--token", "one-time"}, wantErr: "already specifies ownership"},
		{name: "environment token", args: []string{"--ownership", "personal"}, envToken: "one-time", wantErr: "already specifies ownership"},
		{name: "enrolled personal", args: []string{"--ownership", "personal"}, enrolled: true, wantErr: "Transfer ownership"},
		{name: "enrolled organization", args: []string{"--ownership", "organization"}, enrolled: true, wantErr: "Transfer ownership"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PAGNET_ENROLL_TOKEN", tc.envToken)
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				http.Error(w, "must not reach server", http.StatusInternalServerError)
			}))
			defer server.Close()
			previousServer, previousAccount, previousUserToken := serverURL, accountFlag, userToken
			serverURL, accountFlag, userToken = server.URL, "", testAccountToken
			t.Cleanup(func() { serverURL, accountFlag, userToken = previousServer, previousAccount, previousUserToken })
			root := t.TempDir()
			if tc.enrolled {
				if err := mergeConfigFile(accounts.ConfigDir(root, accounts.DefaultAccount), map[string]any{"hostId": "existing-host", "credential": "existing-credential", "serverUrl": server.URL}); err != nil {
					t.Fatal(err)
				}
				if err := accounts.SetCurrent(root, accounts.DefaultAccount); err != nil {
					t.Fatal(err)
				}
			}
			before := enrollmentStateSnapshot(t, root)
			cmd := enrollCmd()
			cmd.SetArgs(append([]string{"--state-dir", root}, tc.args...))
			if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v; want %q", err, tc.wantErr)
			}
			if requests.Load() != 0 {
				t.Fatalf("rejected enrollment made %d HTTP requests", requests.Load())
			}
			if after := enrollmentStateSnapshot(t, root); !reflect.DeepEqual(after, before) {
				t.Fatal("rejected enrollment changed local account state")
			}
		})
	}
}
