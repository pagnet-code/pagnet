package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/textbridge"
	"github.com/pagnet-code/pagnet/internal/textbridge/provider"
	"github.com/pagnet-code/pagnet/sdk"
)

func frozenSummaryCLI(t *testing.T, onCreate func(string)) (string, string, textBridgeDependencies, []string, *int) {
	t.Helper()
	state := textBridgeTestDir(t)
	key, source := filepath.Join(state, "key"), filepath.Join(state, "summary")
	for path, value := range map[string]string{key: "private-provider-key", source: "private frozen instructions"} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	calls := new(int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			switch r.URL.Path {
			case "/api/v1/auth/me":
				fmt.Fprint(w, `{"userId":"c9893a44-626b-4bbc-a7d3-547d6c996450","tenantId":"1b9131ea-8f1c-4373-bb2b-bb2a795afdf6"}`)
			case "/api/v1/principals/" + textBridgeTestService:
				fmt.Fprintf(w, `{"principal":{"ID":%q,"Kind":"service","OwnershipScope":"personal","OwnerUserID":"c9893a44-626b-4bbc-a7d3-547d6c996450","OwningTenantID":"1b9131ea-8f1c-4373-bb2b-bb2a795afdf6"},"canManage":true,"endpoints":[]}`, textBridgeTestService)
			case "/api/v1/sharing-projects/" + textBridgeTestService:
				fmt.Fprintf(w, `{"id":%q,"contractVersion":"sdk_project_v2","state":"enrolling","role":"issuer","issuerTenantId":"1b9131ea-8f1c-4373-bb2b-bb2a795afdf6","issuerPrincipalIds":[%q],"recipientPrincipalIds":["1b4ad328-57b4-438f-a472-b28eae11d730"]}`, textBridgeTestService, textBridgeTestService)
			default:
				http.NotFound(w, r)
			}
			return
		}
		*calls++
		if onCreate != nil {
			onCreate(state)
		}
		json.NewEncoder(w).Encode(map[string]string{"id": textBridgeTestService, "activationCredential": "pgn_act_v1_private-credential"})
	}))
	t.Cleanup(server.Close)
	deps := textBridgeDependencies{owner: func() (*cliCtx, error) {
		return &cliCtx{base: server.URL, token: "private-owner-token", reauth: true}, nil
	}, provider: func(c provider.Config) (textbridge.Provider, error) { return provider.New(c) }}
	if _, err := textBridgeExecute(t, deps, "frozen-summary", "reserve", "--name", "summary", "--state-dir", state); err != nil {
		t.Fatal(err)
	}
	*calls = 0
	args := []string{"frozen-summary", "approve", "--state-dir", state, "--service", textBridgeTestService, "--provider-origin", "https://provider.example", "--model", "fixed", "--key-file", key, "--calls-per-day", "2", "--frozen-summary-file", source, "--project", textBridgeTestService, "--expires-at", time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	return state, source, deps, args, calls
}

func TestFrozenSummaryCLIRejectsLocalInputBeforeCreation(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*testing.T, string, *[]string)
	}{
		{"missing source", func(t *testing.T, source string, args *[]string) { *args = append((*args)[:14], (*args)[16:]...) }},
		{"missing projects", func(t *testing.T, source string, args *[]string) { *args = append((*args)[:16], (*args)[18:]...) }},
		{"missing expiry", func(t *testing.T, source string, args *[]string) { *args = (*args)[:18] }},
		{"label without policy", func(t *testing.T, source string, args *[]string) {
			*args = append((*args)[:14], "--historical-source-label", "source")
		}},
		{"zero allowance", func(t *testing.T, source string, args *[]string) { *args = append(*args, "--calls-per-day", "0") }},
		{"sender role", func(t *testing.T, source string, args *[]string) { *args = append(*args, "--role", "sender") }},
		{"unknown service selection", func(t *testing.T, source string, args *[]string) {
			*args = append(*args, "--service", "7dda6309-8127-4c19-98a2-47e7470612b7")
		}},

		{"private source", func(t *testing.T, source string, args *[]string) {
			if err := os.Chmod(source, 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized source", func(t *testing.T, source string, args *[]string) {
			if err := os.WriteFile(source, bytes.Repeat([]byte("x"), textbridge.MaxFrozenSummaryBytes+1), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"malformed source", func(t *testing.T, source string, args *[]string) {
			if err := os.WriteFile(source, []byte{0xff}, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"invalid project", func(t *testing.T, source string, args *[]string) { *args = append(*args, "--project", "invalid") }},
		{"duplicate project", func(t *testing.T, source string, args *[]string) {
			*args = append(*args, "--project", textBridgeTestService)
		}},
		{"expired", func(t *testing.T, source string, args *[]string) {
			*args = append(*args, "--expires-at", time.Now().Add(-time.Hour).Format(time.RFC3339))
		}},
		{"invalid expiry", func(t *testing.T, source string, args *[]string) { *args = append(*args, "--expires-at", "tomorrow") }},
		{"wrong contract", func(t *testing.T, source string, args *[]string) {
			*args = append(*args, "--project-contract", textbridge.OwnerTextProjectContract)
		}},
		{"provider config", func(t *testing.T, source string, args *[]string) {
			*args = append(*args, "--provider-origin", "invalid")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, source, deps, args, calls := frozenSummaryCLI(t, nil)
			test.change(t, source, &args)
			if _, err := textBridgeExecute(t, deps, args...); err == nil || *calls != 0 {
				t.Fatalf("local failure created service: %v calls=%d", err, *calls)
			}
		})
	}
}

func TestFrozenSummaryCLISetupStatusAndLiveDisable(t *testing.T) {
	state, source, deps, args, calls := frozenSummaryCLI(t, func(state string) {
		if _, err := os.Lstat(filepath.Join(state, "text-bridge", textBridgeTestService, "profile.json")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("profile published before remote creation: %v", err)
		}
	})
	if _, err := textBridgeExecute(t, deps, args...); err != nil {
		t.Fatal(err)
	}
	if *calls != 0 {
		t.Fatal("unexpected creation count")
	}
	dir := filepath.Join(state, "text-bridge", textBridgeTestService)
	p, err := textbridge.LoadProfile(dir, textBridgeTestService)
	if err != nil || p.FrozenSummaryApprovalID == "" || p.ServiceRole() != "responder" {
		t.Fatalf("incomplete profile: %v", err)
	}
	a, err := textbridge.LoadFrozenSummaryApproval(dir, p.FrozenSummaryApprovalID)
	if err != nil || a.Instructions != "private frozen instructions" {
		t.Fatalf("approval missing: %v", err)
	}
	if err := os.WriteFile(source, []byte("changed source"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := textbridge.ResolveFrozenSummary(dir, a.ID, p, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p.KeyFile); err != nil {
		t.Fatal(err)
	}
	status, err := textBridgeExecute(t, deps, "frozen-summary", "status", "--service", p.Service, "--state-dir", state)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{a.Instructions, p.KeyFile, p.Fingerprint, a.KeyFingerprint, a.ContentDigest, p.Credential, p.ProviderOrigin, source} {
		if strings.Contains(status, secret) {
			t.Fatalf("status exposed private field")
		}
	}
	if !strings.Contains(status, a.ID) || !strings.Contains(status, `"Disabled":false`) {
		t.Fatalf("missing status: %s", status)
	}
	// An older strict decoder does not recognize the new selection field.
	raw, err := os.ReadFile(filepath.Join(dir, "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	var oldProfile struct {
		Service, Server, Credential, ProviderOrigin, Model, KeyFile, Fingerprint, ProjectContract, Role string
		Limits                                                                                          json.RawMessage
		Disabled                                                                                        bool
		Registration                                                                                    json.RawMessage
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&oldProfile); err == nil {
		t.Fatal("old decoder accepted selected profile")
	}
	unlock, err := textbridge.LockProfile(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := textBridgeExecute(t, deps, "frozen-summary", "disable", "--service", p.Service, "--state-dir", state); err != nil {
		t.Fatal(err)
	}
	p, err = textbridge.LoadProfile(dir, p.Service)
	if err != nil || !p.Disabled {
		t.Fatalf("profile not disabled: %v", err)
	}
	a, err = textbridge.LoadFrozenSummaryApproval(dir, a.ID)
	if err != nil || !a.Disabled {
		t.Fatalf("approval not disabled: %v", err)
	}
	if _, err := textBridgeExecute(t, deps, "frozen-summary", "disable", "--service", p.Service, "--state-dir", state); err != nil {
		t.Fatal(err)
	}
}

func TestFrozenSummaryCLIPartialSetupDoesNotPublishProfile(t *testing.T) {
	state, _, deps, args, calls := frozenSummaryCLI(t, nil)
	dir := filepath.Join(state, "text-bridge", textBridgeTestService)
	if err := os.WriteFile(filepath.Join(dir, "ledger"), []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := textBridgeExecute(t, deps, args...); err == nil || *calls != 0 {
		t.Fatalf("accepted existing runtime state: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "profile.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("published incomplete profile")
	}
}

func TestFrozenSummaryCLIRejectsExistingProfile(t *testing.T) {
	state, _, deps, args, _ := frozenSummaryCLI(t, nil)
	dir := filepath.Join(state, "text-bridge", textBridgeTestService)
	if err := os.WriteFile(filepath.Join(dir, "profile.json"), []byte("existing profile"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := textBridgeExecute(t, deps, args...); err == nil {
		t.Fatal("accepted existing profile")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "profile.json"))
	if err != nil || string(raw) != "existing profile" {
		t.Fatal("changed profile")
	}
}

func TestFrozenSummaryCLIReservationCancelAndRetry(t *testing.T) {
	state, _, deps, args, calls := frozenSummaryCLI(t, nil)
	dir := filepath.Join(state, "text-bridge", textBridgeTestService)
	r, err := loadFrozenSummaryReservation(dir, textBridgeTestService)
	if err != nil {
		t.Fatal(err)
	}
	status, err := textBridgeExecute(t, deps, "frozen-summary", "status", "--service", textBridgeTestService, "--state-dir", state)
	if err != nil || !strings.Contains(status, `"State":"reserved"`) {
		t.Fatalf("reservation status: %s %v", status, err)
	}
	if _, err := textBridgeExecute(t, deps, "frozen-summary", "reserve", "--name", "summary", "--request-id", r.RequestID, "--state-dir", state); err != nil || *calls != 0 {
		t.Fatalf("retry made request: %v", err)
	}
	unlock, err := textbridge.LockProfile(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := textBridgeExecute(t, deps, "frozen-summary", "disable", "--service", textBridgeTestService, "--state-dir", state); err != nil {
		t.Fatal(err)
	}
	unlock()
	if _, err := textBridgeExecute(t, deps, args...); err == nil {
		t.Fatal("approved cancelled reservation")
	}
}

func TestFrozenSummaryCLIInterruptedApprovalCannotRetry(t *testing.T) {
	state, _, deps, args, _ := frozenSummaryCLI(t, nil)
	dir := filepath.Join(state, "text-bridge", textBridgeTestService)
	r, err := loadFrozenSummaryReservation(dir, textBridgeTestService)
	if err != nil {
		t.Fatal(err)
	}
	r.Approving = true
	if err := textbridge.SavePrivateJSON(dir, "frozen-summary-reservation.json", r); err != nil {
		t.Fatal(err)
	}
	if _, err := textBridgeExecute(t, deps, args...); err == nil {
		t.Fatal("retried interrupted approval")
	}
	if _, err := os.Lstat(filepath.Join(dir, "profile.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("published profile")
	}
}

func TestFrozenSummaryCLIRejectsUnreservedService(t *testing.T) {
	state, _, deps, args, _ := frozenSummaryCLI(t, nil)
	dir := filepath.Join(state, "text-bridge", textBridgeTestService)
	if err := os.Remove(filepath.Join(dir, "frozen-summary-reservation.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := textBridgeExecute(t, deps, args...); err == nil {
		t.Fatal("approved unreserved service")
	}
}

func TestFrozenSummaryCLIUncertainCreationNeverRetries(t *testing.T) {
	state := textBridgeTestDir(t)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(http.StatusInternalServerError) }))
	defer server.Close()
	deps := textBridgeDependencies{owner: func() (*cliCtx, error) { return &cliCtx{base: server.URL, token: "owner"}, nil }}
	args := []string{"frozen-summary", "reserve", "--name", "summary", "--request-id", textBridgeTestService, "--state-dir", state}
	for i := 0; i < 2; i++ {
		if _, err := textBridgeExecute(t, deps, args...); err == nil {
			t.Fatal("uncertain creation succeeded")
		}
	}
	if calls != 1 {
		t.Fatalf("creation retried %d times", calls)
	}
}

func TestFrozenSummaryCLIGenericEnableRejectsPolicyFlags(t *testing.T) {
	for _, flag := range []string{"--frozen-summary-file", "--project", "--expires-at", "--historical-source-label"} {
		if _, err := textBridgeExecute(t, textBridgeDependencies{}, "enable", flag, "value"); err == nil {
			t.Fatalf("generic enable accepted %s", flag)
		}
	}
}

func TestFrozenSummaryCLIRemoteEnrollmentFailureIsTerminal(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(map[string]any, map[string]any)
	}{
		{"offline endpoint", func(detail, project map[string]any) { detail["endpoints"] = []any{map[string]any{"status": "offline"}} }},
		{"missing endpoints", func(detail, project map[string]any) { delete(detail, "endpoints") }},
		{"discovery only", func(detail, project map[string]any) { detail["discoveryOnly"] = true }},
		{"not manager", func(detail, project map[string]any) { detail["canManage"] = false }},
		{"wrong owner", func(detail, project map[string]any) {
			detail["principal"].(map[string]any)["OwnerUserID"] = "1b4ad328-57b4-438f-a472-b28eae11d730"
		}},
		{"not personal", func(detail, project map[string]any) {
			detail["principal"].(map[string]any)["OwnershipScope"] = "organization"
		}},
		{"not service", func(detail, project map[string]any) { detail["principal"].(map[string]any)["Kind"] = "agent" }},
		{"wrong tenant", func(detail, project map[string]any) {
			detail["principal"].(map[string]any)["OwningTenantID"] = "1b4ad328-57b4-438f-a472-b28eae11d730"
		}},
		{"active project", func(detail, project map[string]any) { project["state"] = "active" }},
		{"terminal project", func(detail, project map[string]any) { project["state"] = "revoked" }},
		{"wrong contract", func(detail, project map[string]any) { project["contractVersion"] = "sdk_project_v1" }},
		{"wrong roster side", func(detail, project map[string]any) { project["role"] = "recipient" }},
		{"missing service", func(detail, project map[string]any) { project["issuerPrincipalIds"] = []string{} }},
		{"duplicate service", func(detail, project map[string]any) {
			project["issuerPrincipalIds"] = []string{textBridgeTestService, textBridgeTestService}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			state, _, deps, args, _ := frozenSummaryCLI(t, nil)
			dir := filepath.Join(state, "text-bridge", textBridgeTestService)
			detail := map[string]any{"principal": map[string]any{"ID": textBridgeTestService, "Kind": "service", "OwnershipScope": "personal", "OwnerUserID": "c9893a44-626b-4bbc-a7d3-547d6c996450", "OwningTenantID": "1b9131ea-8f1c-4373-bb2b-bb2a795afdf6"}, "canManage": true, "endpoints": []any{}}
			project := map[string]any{"id": textBridgeTestService, "contractVersion": "sdk_project_v2", "state": "pending", "role": "issuer", "issuerTenantId": "1b9131ea-8f1c-4373-bb2b-bb2a795afdf6", "issuerPrincipalIds": []string{textBridgeTestService}, "recipientPrincipalIds": []string{"1b4ad328-57b4-438f-a472-b28eae11d730"}}
			test.change(detail, project)
			gets := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gets++
				files, err := os.ReadDir(filepath.Join(dir, "frozen-summaries"))
				if err != nil || len(files) == 0 {
					t.Error("remote check preceded durable approval")
				}
				if _, err := os.Lstat(filepath.Join(dir, "profile.json")); !errors.Is(err, os.ErrNotExist) {
					t.Error("remote check followed profile publication")
				}
				switch r.URL.Path {
				case "/api/v1/auth/me":
					fmt.Fprint(w, `{"userId":"c9893a44-626b-4bbc-a7d3-547d6c996450","tenantId":"1b9131ea-8f1c-4373-bb2b-bb2a795afdf6"}`)
				case "/api/v1/principals/" + textBridgeTestService:
					json.NewEncoder(w).Encode(detail)
				case "/api/v1/sharing-projects/" + textBridgeTestService:
					json.NewEncoder(w).Encode(project)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			r, err := loadFrozenSummaryReservation(dir, textBridgeTestService)
			if err != nil {
				t.Fatal(err)
			}
			r.Server = server.URL
			if err := textbridge.SavePrivateJSON(dir, "frozen-summary-reservation.json", r); err != nil {
				t.Fatal(err)
			}
			deps.owner = func() (*cliCtx, error) { return &cliCtx{base: server.URL, token: "owner"}, nil }
			if _, err := textBridgeExecute(t, deps, args...); err == nil {
				t.Fatal("unsafe enrollment approved")
			}
			if gets == 0 {
				t.Fatal("owner check not performed")
			}
			if _, err := os.Lstat(filepath.Join(dir, "profile.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("published unsafe profile")
			}
			if _, err := textBridgeExecute(t, deps, args...); err == nil {
				t.Fatal("retried terminal approval")
			}
			if _, err := textBridgeExecute(t, deps, "frozen-summary", "disable", "--service", textBridgeTestService, "--state-dir", state); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFrozenSummaryCLIDisableDuringBlockedOwnerCheck(t *testing.T) {
	state, _, deps, args, _ := frozenSummaryCLI(t, nil)
	originalOwner, err := deps.owner()
	if err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/me" {
			close(started)
			<-release
		}
		response, err := http.Get(originalOwner.base + r.URL.Path)
		if err != nil {
			http.Error(w, "failed", http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		w.WriteHeader(response.StatusCode)
		io.Copy(w, response.Body)
	}))
	defer server.Close()
	dir := filepath.Join(state, "text-bridge", textBridgeTestService)
	reservation, err := loadFrozenSummaryReservation(dir, textBridgeTestService)
	if err != nil {
		t.Fatal(err)
	}
	reservation.Server = server.URL
	if err := textbridge.SavePrivateJSON(dir, "frozen-summary-reservation.json", reservation); err != nil {
		t.Fatal(err)
	}
	deps.owner = func() (*cliCtx, error) { return &cliCtx{base: server.URL, token: "owner"}, nil }
	approvalDone := make(chan error, 1)
	go func() { _, err := textBridgeExecute(t, deps, args...); approvalDone <- err }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("owner check did not start")
	}
	disabled := make(chan error, 1)
	go func() {
		_, err := textBridgeExecute(t, deps, "frozen-summary", "disable", "--service", textBridgeTestService, "--state-dir", state)
		disabled <- err
	}()
	select {
	case err := <-disabled:
		if err != nil {
			close(release)
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		close(release)
		<-approvalDone
		t.Fatal("disable waited for remote owner check")
	}
	close(release)
	if err := <-approvalDone; err == nil || !strings.Contains(err.Error(), "activation incomplete") {
		t.Fatalf("cancelled approval activated: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "profile.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled approval published profile")
	}
}

func TestFrozenSummaryCLIReservedServiceCannotRun(t *testing.T) {
	state, _, deps, _, _ := frozenSummaryCLI(t, nil)
	connected := false
	deps.connect = func(context.Context, sdk.Config) (textBridgeConnection, error) {
		connected = true
		return nil, errors.New("unexpected connect")
	}
	if _, err := textBridgeExecute(t, deps, "run", "--service", textBridgeTestService, "--state-dir", state); err == nil || connected {
		t.Fatal("reserved service ran")
	}
}
