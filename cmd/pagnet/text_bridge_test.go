package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/textbridge"
	"github.com/pagnet-code/pagnet/internal/textbridge/ledger"
	"github.com/pagnet-code/pagnet/internal/textbridge/provider"
	"github.com/pagnet-code/pagnet/sdk"
)

const textBridgeTestService = "eb8a664b-f7b8-4712-a90e-670a20bf4e68"

func textBridgeTestDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func textBridgeExecute(t *testing.T, deps textBridgeDependencies, args ...string) (string, error) {
	t.Helper()
	cmd := textBridgeCmdWithDependencies(deps)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestTextBridgeEnableStatusDisable(t *testing.T) {
	state := textBridgeTestDir(t)
	key := filepath.Join(state, "provider-key")
	if err := os.WriteFile(key, []byte("provider-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/api/v1/service-recipes" || r.Header.Get("Authorization") != "Bearer owner-secret" {
			t.Errorf("unexpected owner request")
		}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 1 || body["name"] != "responder" {
			t.Errorf("unexpected recipe fields: %v", body)
		}
		json.NewEncoder(w).Encode(map[string]string{"id": textBridgeTestService, "activationCredential": "pgn_act_v1_activation-secret"})
	}))
	defer server.Close()
	connected := false
	deps := textBridgeDependencies{
		owner:    func() (*cliCtx, error) { return &cliCtx{base: server.URL, token: "owner-secret", reauth: true}, nil },
		provider: func(c provider.Config) (textbridge.Provider, error) { return provider.New(c) },
		connect: func(context.Context, sdk.Config) (textBridgeConnection, error) {
			connected = true
			return nil, errors.New("unexpected connect")
		},
	}
	out, err := textBridgeExecute(t, deps, "enable", "--name", "responder", "--provider-origin", "https://provider.example", "--model", "fixed", "--key-file", key, "--calls-per-day", "3", "--state-dir", state)
	if err != nil {
		t.Fatal(err)
	}
	if out != textBridgeTestService+"\n" || calls != 1 {
		t.Fatalf("unexpected output or count: %q %d", out, calls)
	}
	dir := filepath.Join(state, "text-bridge", textBridgeTestService)
	info, err := os.Stat(filepath.Join(dir, "profile.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("profile permissions: %v", err)
	}
	status, err := textBridgeExecute(t, deps, "status", "--service", textBridgeTestService, "--state-dir", state)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"provider-secret", "owner-secret", "activation-secret", key, "provider.example"} {
		if strings.Contains(status, secret) {
			t.Fatalf("status exposed private configuration")
		}
	}
	if !strings.Contains(status, `"CallsPerDay":3`) || !strings.Contains(status, `"MaxConcurrent":1`) {
		t.Fatalf("missing limits: %s", status)
	}
	if _, err := textBridgeExecute(t, deps, "disable", "--service", textBridgeTestService, "--state-dir", state); err != nil {
		t.Fatal(err)
	}
	p, err := textBridgeLoadProfile(dir, textBridgeTestService)
	if err != nil || !p.Disabled {
		t.Fatalf("disable profile: %v", err)
	}
	if _, err := textBridgeExecute(t, deps, "run", "--service", textBridgeTestService, "--state-dir", state); err == nil || connected {
		t.Fatal("disabled profile connected")
	}
	status, err = textBridgeExecute(t, deps, "status", "--service", textBridgeTestService, "--state-dir", state)
	if err != nil || !strings.Contains(status, `"Enabled":false`) {
		t.Fatalf("disable budget: %s %v", status, err)
	}
}

func TestTextBridgeCreationNoRetryOrSecretErrors(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusInternalServerError, http.StatusTemporaryRedirect} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			state := textBridgeTestDir(t)
			key := filepath.Join(state, "key")
			if err := os.WriteFile(key, []byte("provider-secret"), 0600); err != nil {
				t.Fatal(err)
			}
			calls := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Location", "/redirected")
				w.WriteHeader(code)
				w.Write([]byte("activation-secret provider-secret"))
			}))
			defer s.Close()
			deps := textBridgeDependencies{owner: func() (*cliCtx, error) { return &cliCtx{base: s.URL, token: "owner-secret", reauth: true}, nil }, provider: func(c provider.Config) (textbridge.Provider, error) { return provider.New(c) }}
			out, err := textBridgeExecute(t, deps, "enable", "--name", "responder", "--provider-origin", "https://provider.example", "--model", "fixed", "--key-file", key, "--calls-per-day", "1", "--state-dir", state)
			if err == nil || calls != 1 {
				t.Fatalf("creation retried or succeeded: %v %d", err, calls)
			}
			if strings.Contains(out+err.Error(), "secret") {
				t.Fatal("creation leaked response or credentials")
			}
		})
	}
}

func TestTextBridgePreflightBeforeOwnerRequest(t *testing.T) {
	state := textBridgeTestDir(t)
	key := filepath.Join(state, "key")
	if err := os.WriteFile(key, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}
	ownerCalled := false
	deps := textBridgeDependencies{owner: func() (*cliCtx, error) { ownerCalled = true; return nil, errors.New("unexpected owner") }, provider: func(c provider.Config) (textbridge.Provider, error) { return provider.New(c) }}
	_, err := textBridgeExecute(t, deps, "enable", "--name", "responder", "--provider-origin", "https://provider.example", "--model", "fixed", "--key-file", key, "--calls-per-day", "1", "--state-dir", state)
	if err == nil || ownerCalled {
		t.Fatal("insecure key passed preflight")
	}
}

func TestTextBridgeResolveRequiresExplicitAcceptance(t *testing.T) {
	_, err := textBridgeExecute(t, textBridgeDependencies{}, "resolve", "--service", textBridgeTestService, "--project", textBridgeTestService, "--ask", textBridgeTestService, "--abandon")
	if err == nil || !strings.Contains(err.Error(), "--accept-possible-charge") {
		t.Fatal("resolve accepted without charge acknowledgement")
	}
}

func textBridgeTestProfile(t *testing.T) (string, string, textBridgeProfile, *ledger.Store) {
	t.Helper()
	state := textBridgeTestDir(t)
	base, err := textBridgeBase(state)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, textBridgeTestService)
	if err := textBridgePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(state, "key")
	if err := os.WriteFile(key, []byte("provider-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	c := provider.Config{BaseURL: "https://provider.example", Model: "fixed", APIKey: "provider-secret"}
	p := textBridgeProfile{Service: textBridgeTestService, Server: "https://control.example", Credential: "pgn_act_v1_secret", ProviderOrigin: c.BaseURL, Model: c.Model, KeyFile: key, Fingerprint: textBridgeFingerprint(c), Limits: ledger.Limits{CallsPerDay: 2, MaxConcurrent: 1}}
	if err := textBridgeSaveProfile(dir, p); err != nil {
		t.Fatal(err)
	}
	s, err := ledger.Open(filepath.Join(dir, "ledger"), ledger.Binding{ServiceOrigin: p.Server, PrincipalID: p.Service}, p.Limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return state, dir, p, s
}

type textBridgeFakeConnection struct {
	textbridge.Transport
	identity sdk.Identity
	message  bool
	ready    bool
	closed   bool
	cancel   context.CancelFunc
	terminal chan struct{}
}

func (c *textBridgeFakeConnection) WhoAmI(context.Context) (*sdk.Identity, error) {
	return &c.identity, nil
}
func (c *textBridgeFakeConnection) OnSharingProjectMessage(func(context.Context, sdk.SharingProjectMessage) error) {
	c.message = true
}
func (c *textBridgeFakeConnection) OnSharingProjectReady(f func(string)) {
	c.ready = true
	f(textBridgeTestService)
	c.cancel()
}
func (c *textBridgeFakeConnection) Done() <-chan struct{} { return c.terminal }
func (c *textBridgeFakeConnection) Err() error            { return nil }
func (c *textBridgeFakeConnection) Close() error          { c.closed = true; return nil }

func TestTextBridgeRunBindsIdentityAndCancels(t *testing.T) {
	for _, valid := range []bool{true, false} {
		t.Run(map[bool]string{true: "service", false: "wrong identity"}[valid], func(t *testing.T) {
			_, dir, p, s := textBridgeTestProfile(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			conn := &textBridgeFakeConnection{identity: sdk.Identity{Kind: "service", PrincipalID: p.Service}, cancel: cancel, terminal: make(chan struct{})}
			if !valid {
				conn.identity.Kind = "agent"
			}
			deps := textBridgeDependencies{provider: func(c provider.Config) (textbridge.Provider, error) { return provider.New(c) }, connect: func(_ context.Context, c sdk.Config) (textBridgeConnection, error) {
				if c.ExpectedPrincipalID != p.Service || c.Credential != p.Credential || c.Server != p.Server || c.StateDir != filepath.Join(dir, "sdk") {
					t.Error("connection did not bind saved principal")
				}
				return conn, nil
			}}
			err := textBridgeRun(ctx, dir, p, s, deps, io.Discard)
			if valid && (err != nil || !conn.message || !conn.ready) {
				t.Fatalf("run callbacks/cancellation: %v", err)
			}
			if !valid && (err == nil || conn.message || conn.ready) {
				t.Fatal("wrong principal registered handlers")
			}
			if !conn.closed {
				t.Fatal("connection not closed")
			}
		})
	}
}

func TestTextBridgeResolvePreservesCharge(t *testing.T) {
	state, _, p, s := textBridgeTestProfile(t)
	wire := []byte("private wire")
	sum := sha256.Sum256(wire)
	job, err := s.Insert(context.Background(), textBridgeTestService, textBridgeTestService, ledger.Data{Header: []byte(`{"kind":"ASK"}`), PredecessorWire: wire, WireDigest: hex.EncodeToString(sum[:]), Input: []byte("private ASK"), ProviderConfigFingerprint: p.Fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ClaimProvider(context.Background(), job, time.Now()); err != nil {
		t.Fatal(err)
	}
	args := []string{"resolve", "--service", p.Service, "--project", textBridgeTestService, "--ask", textBridgeTestService, "--abandon", "--accept-possible-charge", "--state-dir", state}
	if _, err := textBridgeExecute(t, textBridgeDependencies{}, args...); err == nil {
		t.Fatal("enabled bridge resolved claim")
	}
	status, err := textBridgeExecute(t, textBridgeDependencies{}, "status", "--service", p.Service, "--state-dir", state)
	if err != nil || !strings.Contains(status, `"AskID":"`+textBridgeTestService+`"`) || strings.Contains(status, "private") {
		t.Fatalf("unknown claim status: %s %v", status, err)
	}
	if _, err := textBridgeExecute(t, textBridgeDependencies{}, "disable", "--service", p.Service, "--state-dir", state); err != nil {
		t.Fatal(err)
	}
	if _, err := textBridgeExecute(t, textBridgeDependencies{}, args...); err != nil {
		t.Fatal(err)
	}
	b, err := s.BudgetSnapshot(context.Background())
	if err != nil || b.Enabled || b.Used != 1 || len(b.Active) != 0 {
		t.Fatalf("resolved budget: %+v %v", b, err)
	}
	job, err = s.Get(context.Background(), textBridgeTestService, textBridgeTestService)
	if err != nil || job.Phase != ledger.Unknown {
		t.Fatalf("resolved job: %s %v", job.Phase, err)
	}
}

func TestTextBridgeRunRejectsChangedKey(t *testing.T) {
	_, dir, p, s := textBridgeTestProfile(t)
	if err := os.WriteFile(p.KeyFile, []byte("different-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	err := textBridgeRun(context.Background(), dir, p, s, textBridgeDependencies{}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "configuration changed") {
		t.Fatalf("changed key accepted: %v", err)
	}
}

func TestTextBridgeMissingLedgerFailsClosed(t *testing.T) {
	state, dir, p, s := textBridgeTestProfile(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(dir, "ledger")); err != nil {
		t.Fatal(err)
	}
	_, err := textBridgeExecute(t, textBridgeDependencies{}, "status", "--service", p.Service, "--state-dir", state)
	if err == nil || !strings.Contains(err.Error(), "ledger is missing") {
		t.Fatalf("missing ledger accepted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ledger")); !os.IsNotExist(err) {
		t.Fatal("status initialized replacement ledger")
	}
}

func TestTextBridgeCreatedServiceFailureIdentifiesService(t *testing.T) {
	state := textBridgeTestDir(t)
	key := filepath.Join(state, "key")
	if err := os.WriteFile(key, []byte("provider-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"id": textBridgeTestService, "activationCredential": "invalid-secret"})
	}))
	defer s.Close()
	deps := textBridgeDependencies{owner: func() (*cliCtx, error) { return &cliCtx{base: s.URL, token: "owner-secret"}, nil }, provider: func(c provider.Config) (textbridge.Provider, error) { return provider.New(c) }}
	_, err := textBridgeExecute(t, deps, "enable", "--name", "responder", "--provider-origin", "https://provider.example", "--model", "fixed", "--key-file", key, "--calls-per-day", "1", "--state-dir", state)
	if err == nil || !strings.Contains(err.Error(), textBridgeTestService) || !strings.Contains(err.Error(), "inspect this service") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("missing safe reconciliation instruction: %v", err)
	}
}

func TestTextBridgeBackgroundErrorsAreRedacted(t *testing.T) {
	var out bytes.Buffer
	textBridgeReportError(&out, errors.New("secret provider response with ASK contents"))
	if strings.Contains(out.String(), "secret") || strings.Contains(out.String(), "ASK") || !strings.Contains(out.String(), "inspect status") {
		t.Fatalf("unsafe background error: %s", out.String())
	}
}
