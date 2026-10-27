package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/internal/accounts"
	"github.com/pagnet-code/pagnet/internal/config"
	"github.com/pagnet-code/pagnet/internal/textbridge"
	"github.com/pagnet-code/pagnet/internal/textbridge/ledger"
	"github.com/pagnet-code/pagnet/internal/textbridge/provider"
	"github.com/pagnet-code/pagnet/internal/textbridge/sender"
	"github.com/pagnet-code/pagnet/sdk"
	"gopkg.in/yaml.v3"
)

const registerTestHost = "90ef464b-3467-44d7-a70c-91258ec310ee"
const registerTestTenant = "69870d20-f019-434f-ab0c-9737f5fa422c"
const registerTestOwner = "7a8ff027-ce44-438e-bbf6-e781ff9414b9"

type registerFixture struct {
	state, dir string
	p          textbridge.Profile
	owner      *cliCtx
	deps       textBridgeDependencies
	calls      int
	authCalls  int
	bodies     [][]byte
	ids        []string
	respond    func(http.ResponseWriter, *http.Request, textBridgeInstallation)
}

func newRegisterFixture(t *testing.T) *registerFixture {
	t.Helper()
	f := &registerFixture{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls++
		p, err := textbridge.LoadProfile(f.dir, f.p.Service)
		if err != nil {
			t.Errorf("pending profile: %v", err)
			w.WriteHeader(500)
			return
		}
		if p.Registration == nil || !p.Registration.Pending {
			t.Error("PUT preceded durable pending metadata")
			w.WriteHeader(500)
			return
		}
		info, err := os.Stat(filepath.Join(f.dir, "profile.json"))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Error("pending metadata is not private")
		}
		body, _ := io.ReadAll(r.Body)
		f.bodies = append(f.bodies, body)
		f.ids = append(f.ids, p.Registration.InstallationID)
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/sharing/text-services/installations/"+p.Registration.InstallationID {
			t.Error("incorrect installation request")
		}
		if r.Header.Get("Authorization") != "Bearer owner-secret" {
			t.Error("incorrect owner authentication")
		}
		var tuple map[string]any
		if json.Unmarshal(body, &tuple) != nil || len(tuple) != 4 || tuple["serviceId"] != f.p.Service || tuple["hostId"] != registerTestHost || tuple["role"] != f.p.ServiceRole() || tuple["profileVersion"] != float64(1) {
			t.Error("request disclosed fields outside immutable tuple")
		}
		v := textBridgeInstallation{ID: p.Registration.InstallationID, ServiceID: f.p.Service, HostID: registerTestHost, Role: f.p.ServiceRole(), ProfileVersion: 1, TenantID: registerTestTenant, OwnerUserID: registerTestOwner, Generation: 1, DesiredState: "enabled"}
		if f.respond != nil {
			f.respond(w, r, v)
			return
		}
		json.NewEncoder(w).Encode(v)
	}))
	t.Cleanup(server.Close)
	state, dir, p, old := textBridgeTestProfile(t)
	old.Close()
	if err := os.RemoveAll(filepath.Join(dir, "ledger")); err != nil {
		t.Fatal(err)
	}
	p.Server = server.URL
	if err := textbridge.SaveProfile(dir, p); err != nil {
		t.Fatal(err)
	}
	store, err := ledger.Open(filepath.Join(dir, "ledger"), ledger.Binding{ServiceOrigin: p.Server, PrincipalID: p.Service}, p.Limits)
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	f.state, f.dir, f.p = state, dir, p
	f.owner = &cliCtx{base: server.URL, stateDir: state, cfg: config.Daemon{ServerURL: server.URL, HostID: registerTestHost, Credential: "host-secret"}}
	f.persist(t)
	f.deps = textBridgeDependencies{
		registrationContext:      func() (*cliCtx, error) { return f.owner, nil },
		registrationAuthenticate: func(c *cliCtx) error { f.authCalls++; c.token = "owner-secret"; return nil },
	}
	if err := os.Remove(p.KeyFile); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *registerFixture) persist(t *testing.T) {
	t.Helper()
	raw, err := yaml.Marshal(map[string]string{"serverUrl": f.owner.cfg.ServerURL, "hostId": f.owner.cfg.HostID, "credential": f.owner.cfg.Credential})
	if err != nil {
		t.Fatal(err)
	}
	dir := accountConfigDir(f.owner.stateDir, f.owner.account)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func (f *registerFixture) run(t *testing.T) (string, error) {
	t.Helper()
	return textBridgeExecute(t, f.deps, "register", "--service", f.p.Service, "--state-dir", f.state)
}
func (f *registerFixture) load(t *testing.T) textbridge.Profile {
	t.Helper()
	p, err := textbridge.LoadProfile(f.dir, f.p.Service)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func (f *registerFixture) save(t *testing.T, p textbridge.Profile) {
	t.Helper()
	if err := textbridge.SaveProfile(f.dir, p); err != nil {
		t.Fatal(err)
	}
}
func registerOutputPrivate(t *testing.T, out string, err error) {
	t.Helper()
	if err != nil {
		out += err.Error()
	}
	for _, secret := range []string{"owner-secret", "host-secret", "pgn_act_v1_secret", "provider-secret", "https://provider.example"} {
		if strings.Contains(out, secret) {
			t.Fatal("registration output disclosed a secret")
		}
	}
}

func TestTextBridgeRegisterEnabledAndIdempotent(t *testing.T) {
	f := newRegisterFixture(t)
	for range 2 {
		out, err := f.run(t)
		registerOutputPrivate(t, out, err)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, "pending daemon verification") {
			t.Fatal("missing verification status")
		}
	}
	p := f.load(t)
	if p.Registration == nil || p.Registration.Pending || p.Registration.TenantID != registerTestTenant || p.Registration.OwnerUserID != registerTestOwner {
		t.Fatal("registration confirmation not saved")
	}
	if f.calls != 2 || f.ids[0] != f.ids[1] || !bytes.Equal(f.bodies[0], f.bodies[1]) {
		t.Fatal("explicit retry replaced immutable tuple")
	}
}

func TestTextBridgeRegisterRetryPending(t *testing.T) {
	for _, kind := range []string{"dropped response", "server failure", "crash before PUT", "context canceled"} {
		t.Run(kind, func(t *testing.T) {
			f := newRegisterFixture(t)
			if kind == "crash before PUT" {
				p := f.p
				p.Registration = &textbridge.ProfileRegistration{InstallationID: registerTestTenant, HostID: registerTestHost, Role: "responder", ProfileVersion: 1, Pending: true}
				f.save(t, p)
			} else {
				var cancel context.CancelFunc
				f.respond = func(w http.ResponseWriter, r *http.Request, v textBridgeInstallation) {
					switch kind {
					case "dropped response":
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						conn.Close()
					case "server failure":
						w.WriteHeader(500)
					case "context canceled":
						cancel()
						<-r.Context().Done()
					}
				}
				var out string
				var err error
				if kind == "context canceled" {
					cmd := textBridgeCmdWithDependencies(f.deps)
					var buf bytes.Buffer
					cmd.SetOut(&buf)
					cmd.SetErr(&buf)
					cmd.SilenceErrors = true
					cmd.SilenceUsage = true
					cmd.SetArgs([]string{"register", "--service", f.p.Service, "--state-dir", f.state})
					var ctx context.Context
					ctx, cancel = context.WithCancel(context.Background())
					defer cancel()
					err = cmd.ExecuteContext(ctx)
					out = buf.String()
				} else {
					out, err = f.run(t)
				}
				registerOutputPrivate(t, out, err)
				if err == nil {
					t.Fatal("uncertain request succeeded")
				}
			}
			pending := f.load(t)
			if pending.Registration == nil || !pending.Registration.Pending {
				t.Fatal("retry metadata missing")
			}
			id := pending.Registration.InstallationID
			f.respond = nil
			if _, err := f.run(t); err != nil {
				t.Fatal(err)
			}
			if f.load(t).Registration.InstallationID != id {
				t.Fatal("retry replaced installation")
			}
			if len(f.ids) == 2 && (f.ids[0] != f.ids[1] || !bytes.Equal(f.bodies[0], f.bodies[1])) {
				t.Fatal("retry changed request")
			}
		})
	}
}

func TestTextBridgeRegisterLocalRejections(t *testing.T) {
	for _, kind := range []string{"host", "server", "unenrolled", "principal", "worker", "disabled", "missing profile", "lock", "persisted host", "persisted server"} {
		t.Run(kind, func(t *testing.T) {
			f := newRegisterFixture(t)
			switch kind {
			case "host":
				p := f.p
				p.Registration = &textbridge.ProfileRegistration{InstallationID: registerTestTenant, HostID: registerTestOwner, Role: "responder", ProfileVersion: 1, Pending: true}
				f.save(t, p)
			case "server":
				f.owner.base = "https://elsewhere.example"
			case "unenrolled":
				f.owner.cfg.Credential = ""
			case "principal":
				f.owner.principal = true
			case "worker":
				home := textBridgeTestDir(t)
				t.Setenv("HOME", home)
				f.owner.stateDir = filepath.Join(home, ".pagnet", "workers", "worker")
				f.persist(t)
			case "disabled":
				p := f.p
				p.Disabled = true
				f.save(t, p)
			case "missing profile":
				if err := os.Remove(filepath.Join(f.dir, "profile.json")); err != nil {
					t.Fatal(err)
				}
			case "lock":
				unlock, err := textbridge.LockProfile(f.dir)
				if err != nil {
					t.Fatal(err)
				}
				defer unlock()
			case "persisted host":
				f.owner.cfg.HostID = registerTestOwner
			case "persisted server":
				f.owner.cfg.ServerURL = "https://elsewhere.example"
			}
			out, err := f.run(t)
			registerOutputPrivate(t, out, err)
			if err == nil || f.calls != 0 || f.authCalls != 0 {
				t.Fatal("local rejection authenticated, sent PUT, or succeeded")
			}
		})
	}
}

func TestTextBridgeRegisterResponseMismatch(t *testing.T) {
	for _, field := range []string{"tenant", "owner", "id", "service", "host", "role", "version"} {
		t.Run(field, func(t *testing.T) {
			f := newRegisterFixture(t)
			if _, err := f.run(t); err != nil {
				t.Fatal(err)
			}
			old := *f.load(t).Registration
			f.respond = func(w http.ResponseWriter, r *http.Request, v textBridgeInstallation) {
				switch field {
				case "tenant":
					v.TenantID = registerTestHost
				case "owner":
					v.OwnerUserID = registerTestHost
				case "id":
					v.ID = registerTestHost
				case "service":
					v.ServiceID = registerTestHost
				case "host":
					v.HostID = registerTestOwner
				case "role":
					v.Role = "other"
				case "version":
					v.ProfileVersion = 2
				}
				json.NewEncoder(w).Encode(v)
			}
			out, err := f.run(t)
			registerOutputPrivate(t, out, err)
			if err == nil {
				t.Fatal("mismatched response accepted")
			}
			got := *f.load(t).Registration
			old.Pending = true
			if got != old {
				t.Fatal("mismatched response changed confirmed pins")
			}
		})
	}
}

func TestTextBridgeRegisterRemoteDisabled(t *testing.T) {
	f := newRegisterFixture(t)
	f.respond = func(w http.ResponseWriter, r *http.Request, v textBridgeInstallation) {
		v.DesiredState = "disabled"
		json.NewEncoder(w).Encode(v)
	}
	if _, err := f.run(t); err != nil {
		t.Fatal(err)
	}
	p := f.load(t)
	if !p.Disabled || p.Registration.Pending || p.Registration.DesiredState != "disabled" {
		t.Fatal("remote disable not persisted")
	}
	store, err := textbridge.OpenProfileLedger(f.dir, p)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	budget, err := store.BudgetSnapshot(context.Background())
	if err != nil || budget.Enabled {
		t.Fatal("remote disable not applied to ledger")
	}
	if _, err := f.run(t); err == nil || f.calls != 1 {
		t.Fatal("disabled profile attempted replacement")
	}
}

func TestTextBridgeRegisterCrashStateBlocksRun(t *testing.T) {
	for _, state := range []string{"pending", "disabled"} {
		t.Run(state, func(t *testing.T) {
			f := newRegisterFixture(t)
			p := f.p
			p.Registration = &textbridge.ProfileRegistration{InstallationID: registerTestTenant, HostID: registerTestHost, Role: "responder", ProfileVersion: 1, Pending: true}
			if state == "disabled" {
				p.Registration.Pending = false
				p.Registration.TenantID = registerTestTenant
				p.Registration.OwnerUserID = registerTestOwner
				p.Registration.Generation = 1
				p.Registration.DesiredState = "disabled"
				f.respond = func(w http.ResponseWriter, r *http.Request, v textBridgeInstallation) {
					v.DesiredState = "disabled"
					json.NewEncoder(w).Encode(v)
				}
			}
			f.save(t, p)
			if err := os.WriteFile(p.KeyFile, []byte("provider-secret"), 0600); err != nil {
				t.Fatal(err)
			}
			providerCalled := false
			f.deps.provider = func(provider.Config) (textbridge.Provider, error) {
				providerCalled = true
				return nil, errors.New("unexpected provider initialization")
			}
			if _, err := textBridgeExecute(t, f.deps, "run", "--service", p.Service, "--state-dir", f.state); err == nil || providerCalled {
				t.Fatal("crash state permitted responder initialization")
			}
			if _, err := f.run(t); err != nil {
				t.Fatal(err)
			}
			if f.calls != 1 || f.load(t).Registration.InstallationID != p.Registration.InstallationID {
				t.Fatal("crash reconciliation replaced registration")
			}
		})
	}
}

func TestTextBridgeRegisterDefaultPreflightServerOverride(t *testing.T) {
	for _, mode := range []string{"server flag", "environment"} {
		t.Run(mode, func(t *testing.T) {
			withFileFallback(t)
			f := newRegisterFixture(t)
			home := textBridgeTestDir(t)
			t.Setenv("HOME", home)
			f.owner.stateDir = filepath.Join(home, ".pagnet")
			f.owner.account = "default"
			f.persist(t)
			if err := accounts.SetCurrent(f.owner.stateDir, f.owner.account); err != nil {
				t.Fatal(err)
			}
			if err := saveUserToken(accountConfigDir(f.owner.stateDir, f.owner.account), f.owner.account, f.p.Server, "owner-secret"); err != nil {
				t.Fatal(err)
			}
			wrongRequests := 0
			wrong := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { wrongRequests++; w.WriteHeader(500) }))
			defer wrong.Close()
			oldServer, oldAccount, oldToken, oldNI := serverURL, accountFlag, userToken, nonInteractive
			t.Cleanup(func() { serverURL, accountFlag, userToken, nonInteractive = oldServer, oldAccount, oldToken, oldNI })
			serverURL, accountFlag, userToken, nonInteractive = "", "", "", true
			t.Setenv("PAGNET_SERVER", "")
			if mode == "server flag" {
				serverURL = wrong.URL
			} else {
				t.Setenv("PAGNET_SERVER", wrong.URL)
			}
			cmd := textBridgeCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			cmd.SetArgs([]string{"register", "--service", f.p.Service, "--state-dir", f.state})
			err := cmd.Execute()
			registerOutputPrivate(t, out.String(), err)
			if err == nil || !strings.Contains(err.Error(), "different servers") {
				t.Fatalf("override did not fail enrollment preflight: %v", err)
			}
			if wrongRequests != 0 || f.calls != 0 {
				t.Fatal("server override sent HTTP before authentication preflight")
			}
		})
	}
}

func TestTextBridgeRegisterEncodedServerPaths(t *testing.T) {
	for _, source := range []string{"profile", "resolved", "config", "persisted"} {
		t.Run(source, func(t *testing.T) {
			f := newRegisterFixture(t)
			base := f.p.Server + "/base"
			for _, separator := range []string{"%2F", "%2f", "%5C", "%5c"} {
				t.Run(separator, func(t *testing.T) {
					f.owner.base, f.owner.cfg.ServerURL = base, base
					f.persist(t)
					profileServer := base
					encoded := base + separator
					switch source {
					case "profile":
						profileServer = encoded
					case "resolved":
						f.owner.base = encoded
					case "config":
						f.owner.cfg.ServerURL = encoded
					case "persisted":
						f.owner.cfg.ServerURL = encoded
						f.persist(t)
						f.owner.cfg.ServerURL = base
					}
					if _, err := textBridgeRegistrationAccount(f.owner, profileServer); err == nil {
						t.Fatal("encoded separator accepted as enrollment server")
					}
				})
			}
		})
	}
}

func TestTextBridgeRunBlocksPartialRemoteDisable(t *testing.T) {
	for _, state := range []string{"profile only", "ledger only", "both"} {
		t.Run(state, func(t *testing.T) {
			f := newRegisterFixture(t)
			p := f.p
			p.Registration = &textbridge.ProfileRegistration{InstallationID: registerTestTenant, HostID: registerTestHost, Role: "responder", ProfileVersion: 1, TenantID: registerTestTenant, OwnerUserID: registerTestOwner, Generation: 1, DesiredState: "enabled"}
			if state != "ledger only" {
				p.Disabled = true
				p.Registration.DesiredState = "disabled"
			}
			f.save(t, p)
			if state != "profile only" {
				store, err := textbridge.OpenProfileLedger(f.dir, p)
				if err != nil {
					t.Fatal(err)
				}
				if err = store.SetEnabled(context.Background(), false); err != nil {
					t.Fatal(err)
				}
				store.Close()
			}
			if err := os.WriteFile(p.KeyFile, []byte("provider-secret"), 0600); err != nil {
				t.Fatal(err)
			}
			f.deps.provider = func(provider.Config) (textbridge.Provider, error) {
				t.Fatal("partial disable initialized provider")
				return nil, errors.New("unexpected provider")
			}
			f.deps.connect = func(context.Context, sdk.Config) (textBridgeConnection, error) {
				t.Fatal("partial disable connected SDK")
				return nil, errors.New("unexpected SDK")
			}
			_, err := textBridgeExecute(t, f.deps, "run", "--service", p.Service, "--state-dir", f.state)
			if err == nil || !strings.Contains(err.Error(), "text bridge is disabled") {
				t.Fatal("partial durable disable allowed standalone run")
			}
		})
	}
}

func TestTextBridgeRegisterSenderWithoutProvider(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "enabled", true: "remote disable"}[disabled], func(t *testing.T) {
			f := newRegisterFixture(t)
			dir, err := textbridge.ProfileDirectoryForRole(f.state, f.p.Service, "sender")
			if err != nil {
				t.Fatal(err)
			}
			// Preserve an existing CLI profile containing only its connection tuple.
			legacy := textBridgeSenderProfile{Service: f.p.Service, Server: f.p.Server, Credential: f.p.Credential}
			if err := textbridge.SavePrivateJSON(dir, "profile.json", struct{ Service, Server, Credential string }{legacy.Service, legacy.Server, legacy.Credential}); err != nil {
				t.Fatal(err)
			}
			store, err := sender.Open(filepath.Join(dir, "operations"), sender.Binding{ServiceOrigin: legacy.Server, PrincipalID: legacy.Service})
			if err != nil {
				t.Fatal(err)
			}
			store.Close()
			f.dir = dir
			f.p = legacy
			f.p.Role = "sender"
			if disabled {
				f.respond = func(w http.ResponseWriter, _ *http.Request, v textBridgeInstallation) {
					v.DesiredState = "disabled"
					json.NewEncoder(w).Encode(v)
				}
			}
			out, err := textBridgeExecute(t, f.deps, "register", "--service", f.p.Service, "--role", "sender", "--state-dir", f.state)
			registerOutputPrivate(t, out, err)
			if err != nil {
				t.Fatal(err)
			}
			p := f.load(t)
			if p.ServiceRole() != "sender" || p.Registration.Role != "sender" || p.Registration.Pending || p.Disabled != disabled {
				t.Fatalf("sender registration: %+v", p.Registration)
			}
			store, err = textbridge.OpenSenderStore(dir, p)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			enabled, err := store.Enabled(context.Background())
			if err != nil || enabled == disabled {
				t.Fatalf("sender disable gate: %v %v", enabled, err)
			}
			if _, err := os.Stat(filepath.Join(dir, "ledger")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("sender initialized provider ledger")
			}
			if _, err := textBridgeSenderLoadProfile(dir, p.Service); err != nil {
				t.Fatal("registration broke CLI sender profile loading", err)
			}
		})
	}
}

func TestTextBridgeRegisterSenderRetryGuidancePreservesRole(t *testing.T) {
	f := newRegisterFixture(t)
	dir, err := textbridge.ProfileDirectoryForRole(f.state, f.p.Service, "sender")
	if err != nil {
		t.Fatal(err)
	}
	p := textbridge.Profile{Role: "sender", Service: f.p.Service, Server: f.p.Server, Credential: f.p.Credential}
	if err := textbridge.SaveProfile(dir, p); err != nil {
		t.Fatal(err)
	}
	store, err := sender.Open(filepath.Join(dir, "operations"), sender.Binding{ServiceOrigin: p.Server, PrincipalID: p.Service})
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	f.dir, f.p = dir, p
	f.respond = func(w http.ResponseWriter, _ *http.Request, _ textBridgeInstallation) { w.WriteHeader(500) }
	_, err = textBridgeExecute(t, f.deps, "register", "--service", p.Service, "--role", "sender", "--state-dir", f.state)
	if err == nil || !strings.Contains(err.Error(), "register --service "+p.Service+" --role sender") {
		t.Fatal("sender retry command omitted role", err)
	}
}
