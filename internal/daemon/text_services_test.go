//go:build unix

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/textbridge"
	"github.com/pagnet-code/pagnet/internal/textbridge/ledger"
	"github.com/pagnet-code/pagnet/sdk"
	"github.com/pagnet-code/pagnet/transport"
)

func textFixture(t *testing.T, handler http.HandlerFunc) (*textServiceSupervisor, *textServiceClient, string, textbridge.Profile, textServiceInstallation) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	p := transport.HostSessionPayload{TenantID: uuid.NewString(), AccountID: uuid.NewString(), HostID: uuid.NewString(), NativeAdmissionID: uuid.NewString(), RunnerID: uuid.NewString(), HostCredentialID: uuid.NewString(), BootID: uuid.NewString(), OwnershipScope: "personal", ProtocolFeatures: []string{textServiceBridgeProtocol}, RunnerEpoch: time.Now().UTC()}
	state := t.TempDir()
	if e := os.Chmod(state, 0700); e != nil {
		t.Fatal(e)
	}
	s := newTextServiceSupervisor(&Daemon{Config: Config{ServerURL: server.URL, HostID: p.HostID, Credential: "test-host", StateDir: state}})
	s.admit(p)
	s.runProfile = nil // phase-one claim tests deliberately stop before runtime startup
	t.Cleanup(s.disconnect)
	v := textServiceInstallation{ID: uuid.NewString(), ServiceID: uuid.NewString(), HostID: p.HostID, Role: "responder", ProfileVersion: 1, DesiredState: "enabled", Generation: 1}
	dir, e := textbridge.ProfileDirectory(state, v.ServiceID)
	if e != nil {
		t.Fatal(e)
	}
	profile := textbridge.Profile{Service: v.ServiceID, Server: server.URL, Credential: "pgn_act_v1_test", KeyFile: filepath.Join(state, "key"), Fingerprint: "fixed", Limits: ledger.Limits{CallsPerDay: 2, MaxConcurrent: 1}, Registration: &textbridge.ProfileRegistration{InstallationID: v.ID, HostID: v.HostID, Role: v.Role, ProfileVersion: 1, TenantID: p.TenantID, OwnerUserID: p.AccountID, Generation: 1, DesiredState: "enabled"}}
	if e = textbridge.SaveProfile(dir, profile); e != nil {
		t.Fatal(e)
	}
	st, e := ledger.Open(filepath.Join(dir, "ledger"), ledger.Binding{ServiceOrigin: profile.Server, PrincipalID: profile.Service}, profile.Limits)
	if e != nil {
		t.Fatal(e)
	}
	if e = st.Close(); e != nil {
		t.Fatal(e)
	}
	return s, s.client, dir, profile, v
}

func TestTextServiceGates(t *testing.T) {
	for _, gate := range []string{"owner", "server", "host", "pending", "disabled", "ledger", "remote-disabled"} {
		t.Run(gate, func(t *testing.T) {
			var calls atomic.Int32
			s, c, dir, p, v := textFixture(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) })
			switch gate {
			case "owner":
				p.Registration.OwnerUserID = uuid.NewString()
			case "server":
				p.Server = "https://other.example"
			case "host":
				p.Registration.HostID = uuid.NewString()
			case "pending":
				p.Registration.Pending = true
			case "disabled":
				p.Disabled = true
			case "remote-disabled":
				v.DesiredState = "disabled"
			case "ledger":
				st, e := textbridge.OpenProfileLedger(dir, p)
				if e != nil {
					t.Fatal(e)
				}
				if e = st.SetEnabled(context.Background(), false); e != nil {
					t.Fatal(e)
				}
				st.Close()
			}
			if e := textbridge.SaveProfile(dir, p); e != nil {
				t.Fatal(e)
			}
			e := s.installation(context.Background(), c, v)
			if gate == "pending" && e == nil {
				t.Fatal("pending must retain outstanding retry")
			}
			if calls.Load() != 0 {
				t.Fatal("gate sent claim")
			}
		})
	}
}

func TestTextServiceAmbiguousClaimRetriesDurableBody(t *testing.T) {
	var bodies [][]byte
	var dir string
	s, c, d, _, v := textFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Pagnet-Native-Admission-Id") == "" {
			t.Error("missing admission")
		}
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, raw)
		saved, e := textbridge.ReadPrivate(filepath.Join(dir, "claim-attempt.json"), 8192)
		var a textServiceAttempt
		if e != nil || json.Unmarshal(saved, &a) != nil || !bytes.Equal(a.Body, raw) {
			t.Error("POST preceded exact durable record")
		}
		if len(bodies) == 1 {
			w.WriteHeader(500)
			return
		}
		var body textServiceClaimBody
		json.Unmarshal(raw, &body)
		json.NewEncoder(w).Encode(sdk.TextServiceReadiness{InstallationID: a.InstallationID, ClaimID: &body.ClaimID, Generation: body.ExpectedGeneration + 1})
	})
	dir = d
	if e := s.installation(context.Background(), c, v); e == nil {
		t.Fatal("ambiguous request succeeded")
	}
	var attempted textServiceClaimBody
	json.Unmarshal(bodies[0], &attempted)
	v.ActiveClaimID = &attempted.ClaimID
	v.Generation++ // authoritative GET after a committed but lost response
	if e := s.installation(context.Background(), c, v); e != nil {
		t.Fatal(e)
	}
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("ambiguous retry changed claim")
	}
	if e := s.installation(context.Background(), c, v); e != nil {
		t.Fatal(e)
	}
	if len(bodies) != 2 {
		t.Fatal("confirmed claim repeated")
	}
	info, e := os.Stat(filepath.Join(dir, "claim-attempt.json"))
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("attempt not private")
	}
}

func TestTextServiceRejectsStaleResponse(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	s, c, _, _, _ := textFixture(t, func(w http.ResponseWriter, r *http.Request) { close(entered); <-release; w.Write([]byte("[]")) })
	done := make(chan error, 1)
	go func() {
		var out []textServiceInstallation
		done <- c.request(context.Background(), http.MethodGet, "", nil, &out)
	}()
	<-entered
	s.disconnect()
	close(release)
	if e := <-done; e == nil {
		t.Fatal("accepted disconnected response")
	}
}

func TestTextServiceRegistrationLockWakeRace(t *testing.T) {
	var posts atomic.Int32
	var v textServiceInstallation
	s, c, dir, p, item := textFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode([]textServiceInstallation{v})
			return
		}
		posts.Add(1)
		var b textServiceClaimBody
		json.NewDecoder(r.Body).Decode(&b)
		json.NewEncoder(w).Encode(sdk.TextServiceReadiness{InstallationID: v.ID, ClaimID: &b.ClaimID, Generation: 2})
	})
	v = item
	unlock, e := textbridge.LockProfile(dir)
	if e != nil {
		t.Fatal(e)
	}
	p.Registration.Pending = true
	if e = textbridge.SaveProfile(dir, p); e != nil {
		t.Fatal(e)
	}
	if e = s.installation(context.Background(), c, v); e == nil {
		t.Fatal("contention lost outstanding work")
	}
	s.retry = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.run(ctx) }()
	s.signal() // remote wake arrives while registration still holds the lock
	time.Sleep(20 * time.Millisecond)
	p.Registration.Pending = false
	if e = textbridge.SaveProfile(dir, p); e != nil {
		t.Fatal(e)
	}
	unlock()
	deadline := time.Now().Add(time.Second)
	for posts.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if posts.Load() != 1 {
		t.Fatal("registration completion was stranded")
	}
}

func TestTextServiceAdmissionWrongSession(t *testing.T) {
	s, c, _, _, _ := textFixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("invalid session made request") })
	for _, kind := range []string{"host", "scope", "admission"} {
		p := c.session
		switch kind {
		case "host":
			p.HostID = uuid.NewString()
		case "scope":
			p.OwnershipScope = "network"
		case "admission":
			p.NativeAdmissionID = "bad"
		}
		if got, e := newTextServiceClient(s.daemon, p); e == nil {
			got.cancel()
			t.Fatal("invalid session accepted")
		}
	}
}

func TestTextServiceCapabilityAndCoalescedWake(t *testing.T) {
	d := &Daemon{Config: Config{ServerURL: "https://control.example"}}
	u, e := url.Parse(d.wsURL(context.Background()))
	if e != nil {
		t.Fatal(e)
	}
	if u.Query().Get("text_service_bridge") != textServiceBridgeProtocol {
		t.Fatal("capability absent")
	}
	s := newTextServiceSupervisor(d)
	d.textServices = s
	for range 10 {
		d.handleCommand(nil, transport.Envelope{Type: textServicesChanged})
	}
	if len(s.wake) != 1 {
		t.Fatal("wakes did not coalesce")
	}
}

func TestTextServiceReconnectRetiresOldAttempt(t *testing.T) {
	var bodies [][]byte
	var item textServiceInstallation
	var admission string
	s, c, dir, _, v := textFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if r.Header.Get("X-Pagnet-Native-Admission-Id") != admission {
				t.Error("GET used old admission")
			}
			json.NewEncoder(w).Encode([]textServiceInstallation{item})
			return
		}
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, raw)
		if len(bodies) == 1 {
			w.WriteHeader(500)
			return
		}
		var b textServiceClaimBody
		json.Unmarshal(raw, &b)
		json.NewEncoder(w).Encode(sdk.TextServiceReadiness{InstallationID: item.ID, ClaimID: &b.ClaimID, Generation: b.ExpectedGeneration + 1})
	})
	if e := s.installation(context.Background(), c, v); e == nil {
		t.Fatal("expected ambiguous outcome")
	}
	before, e := textbridge.ReadPrivate(filepath.Join(dir, "claim-attempt.json"), 8192)
	if e != nil {
		t.Fatal(e)
	}
	var old textServiceClaimBody
	json.Unmarshal(bodies[0], &old)
	v.Generation++
	v.ActiveClaimID = &old.ClaimID
	item = v
	replacement := c.session
	replacement.NativeAdmissionID = uuid.NewString()
	replacement.RunnerEpoch = replacement.RunnerEpoch.Add(time.Second)
	admission = replacement.NativeAdmissionID
	s.admit(replacement)
	if e = s.reconcile(context.Background(), s.client); e != nil {
		t.Fatal(e)
	}
	retired, e := textbridge.ReadPrivate(filepath.Join(dir, "claim-attempt-retired.json"), 8192)
	if e != nil || !bytes.Equal(before, retired) {
		t.Fatal("old attempt not durably retired")
	}
	var fresh textServiceClaimBody
	json.Unmarshal(bodies[1], &fresh)
	if len(bodies) != 2 || fresh.ClaimID == old.ClaimID || fresh.Nonce == old.Nonce || fresh.ExpectedGeneration != v.Generation || !fresh.ConnectionEpoch.Equal(replacement.RunnerEpoch) {
		t.Fatal("replacement replayed old attempt")
	}
}

func TestTextServiceUnsupportedSessionStaysDormant(t *testing.T) {
	var calls atomic.Int32
	s, c, _, _, _ := textFixture(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(404) })
	p := c.session
	p.ProtocolFeatures = []string{"unrelated"}
	s.admit(p)
	if s.client != nil {
		t.Fatal("unsupported session admitted")
	}
	s.retry = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.run(ctx) }()
	s.signal()
	time.Sleep(20 * time.Millisecond)
	cancel()
	<-done
	if calls.Load() != 0 {
		t.Fatal("unsupported server received GET or retry")
	}
}

func TestTextServiceAttemptRepersistedAfterUncertainDirectorySync(t *testing.T) {
	var posts int
	var current textServiceInstallation
	s, c, dir, _, v := textFixture(t, func(w http.ResponseWriter, r *http.Request) {
		posts++
		var b textServiceClaimBody
		json.NewDecoder(r.Body).Decode(&b)
		json.NewEncoder(w).Encode(sdk.TextServiceReadiness{InstallationID: current.ID, ClaimID: &b.ClaimID, Generation: b.ExpectedGeneration + 1})
	})
	current = v
	writes := 0
	s.savePrivate = func(dir, name string, value any) error {
		if e := textbridge.SavePrivateJSON(dir, name, value); e != nil {
			return e
		}
		if name == "claim-attempt.json" {
			writes++
			if writes == 1 {
				return errors.New("injected directory sync failure after rename")
			}
		}
		return nil
	}
	if e := s.installation(context.Background(), c, v); e == nil {
		t.Fatal("durability failure ignored")
	}
	if posts != 0 {
		t.Fatal("POST sent before durability confirmed")
	}
	before, e := textbridge.ReadPrivate(filepath.Join(dir, "claim-attempt.json"), 8192)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.installation(context.Background(), c, v); e != nil {
		t.Fatal(e)
	}
	after, e := textbridge.ReadPrivate(filepath.Join(dir, "claim-attempt.json"), 8192)
	if e != nil {
		t.Fatal(e)
	}
	var a, b textServiceAttempt
	json.Unmarshal(before, &a)
	json.Unmarshal(after, &b)
	if posts != 1 || writes != 3 || !bytes.Equal(a.Body, b.Body) {
		t.Fatal("existing attempt was not re-persisted unchanged before POST")
	}
}

func TestTextServiceAmbiguousClaimSnapshotEvidence(t *testing.T) {
	for _, evidence := range []string{"superseded", "missing-active", "own-wrong-generation", "regressed"} {
		t.Run(evidence, func(t *testing.T) {
			var bodies [][]byte
			var snapshot textServiceInstallation
			s, c, dir, _, v := textFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					json.NewEncoder(w).Encode([]textServiceInstallation{snapshot})
					return
				}
				raw, _ := io.ReadAll(r.Body)
				bodies = append(bodies, raw)
				if len(bodies) == 1 {
					w.WriteHeader(500)
					return
				}
				var b textServiceClaimBody
				json.Unmarshal(raw, &b)
				json.NewEncoder(w).Encode(sdk.TextServiceReadiness{InstallationID: snapshot.ID, ClaimID: &b.ClaimID, Generation: b.ExpectedGeneration + 1})
			})
			if e := s.installation(context.Background(), c, v); e == nil {
				t.Fatal("expected ambiguous outcome")
			}
			before, e := textbridge.ReadPrivate(filepath.Join(dir, "claim-attempt.json"), 8192)
			if e != nil {
				t.Fatal(e)
			}
			var old textServiceClaimBody
			json.Unmarshal(bodies[0], &old)
			v.Generation += 2
			switch evidence {
			case "superseded":
				other := uuid.NewString()
				v.ActiveClaimID = &other
			case "own-wrong-generation":
				v.ActiveClaimID = &old.ClaimID
			case "regressed":
				v.Generation = old.ExpectedGeneration - 1
			}
			snapshot = v
			if evidence == "regressed" { // A valid snapshot may still precede a retained attempt.
				var a textServiceAttempt
				json.Unmarshal(before, &a)
				old.ExpectedGeneration = 3
				a.Body, _ = json.Marshal(old)
				if e = textbridge.SavePrivateJSON(dir, "claim-attempt.json", a); e != nil {
					t.Fatal(e)
				}
				snapshot.Generation = 2
			}
			if e = s.reconcile(context.Background(), c); e != nil {
				t.Fatal(e)
			}
			if evidence == "superseded" {
				if len(bodies) != 2 {
					t.Fatal("superseded attempt stranded")
				}
				var fresh textServiceClaimBody
				json.Unmarshal(bodies[1], &fresh)
				if fresh.ClaimID == old.ClaimID || fresh.Nonce == old.Nonce || fresh.ExpectedGeneration != snapshot.Generation {
					t.Fatal("superseded claim replayed")
				}
				retired, e := textbridge.ReadPrivate(filepath.Join(dir, "claim-attempt-retired.json"), 8192)
				if e != nil || !bytes.Equal(before, retired) {
					t.Fatal("superseded attempt not retired")
				}
			} else if len(bodies) != 1 {
				t.Fatal("uncertain snapshot authorized a claim")
			}
		})
	}
}

func TestTextServiceRemoteDisableRepairsPartialWrites(t *testing.T) {
	for _, failure := range []string{"ledger", "profile"} {
		t.Run(failure, func(t *testing.T) {
			s, c, dir, p, v := textFixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("disabled installation sent HTTP request") })
			v.DesiredState = "disabled"
			v.Generation++
			disable := s.disableLedger
			save := s.savePrivate
			ledgerWrites, profileWrites := 0, 0
			s.disableLedger = func(store *ledger.Store) error {
				ledgerWrites++
				if failure == "ledger" && ledgerWrites == 1 {
					return errors.New("injected ledger disable failure")
				}
				return disable(store)
			}
			s.savePrivate = func(dir, name string, value any) error {
				if name == "profile.json" {
					profileWrites++
					if failure == "profile" && profileWrites == 1 {
						return errors.New("injected profile save failure")
					}
				}
				return save(dir, name, value)
			}
			if err := s.installation(context.Background(), c, v); err == nil {
				t.Fatal("partial write failure ignored")
			}
			check := func(wantProfile, wantLedger bool) {
				t.Helper()
				saved, err := textbridge.LoadProfile(dir, p.Service)
				if err != nil {
					t.Fatal(err)
				}
				store, err := textbridge.OpenProfileLedger(dir, saved)
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				budget, err := store.BudgetSnapshot(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if saved.Disabled != wantProfile || (!budget.Enabled) != wantLedger {
					t.Fatal("durable disable state did not match writes")
				}
				if wantProfile && (saved.Registration.DesiredState != "disabled" || saved.Registration.Generation != v.Generation) {
					t.Fatal("disabled registration metadata lost")
				}
			}
			check(failure != "profile", failure != "ledger")
			if err := s.installation(context.Background(), c, v); err != nil {
				t.Fatal(err)
			}
			check(true, true)
			if ledgerWrites != 2 || profileWrites != 2 {
				t.Fatal("partial disable did not retry both durable flags")
			}
			if err := s.installation(context.Background(), c, v); err != nil {
				t.Fatal(err)
			}
			check(true, true)
		})
	}
}

func TestTextServiceRemoteDisablePreservesBindingGate(t *testing.T) {
	s, c, dir, p, v := textFixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("binding mismatch sent HTTP") })
	p.Disabled = true
	p.Registration.OwnerUserID = uuid.NewString()
	if err := textbridge.SaveProfile(dir, p); err != nil {
		t.Fatal(err)
	}
	v.DesiredState = "disabled"
	s.disableLedger = func(*ledger.Store) error { t.Fatal("wrong binding disabled ledger"); return nil }
	s.savePrivate = func(string, string, any) error { t.Fatal("wrong binding rewrote profile"); return nil }
	if err := s.installation(context.Background(), c, v); err != nil {
		t.Fatal(err)
	}
}

func textFixtureContract(t *testing.T, dir string, p textbridge.Profile, contract string) textbridge.Profile {
	t.Helper()
	p.ProjectContract = contract
	if err := textbridge.SaveProfile(dir, p); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(dir, "ledger")); err != nil {
		t.Fatal(err)
	}
	store, err := ledger.Open(filepath.Join(dir, "ledger"), p.LedgerBinding(), p.Limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTextServiceContractClaimRetry(t *testing.T) {
	for _, contract := range []string{"", textbridge.SharingProjectContract, textbridge.OwnerTextProjectContract} {
		t.Run(contract, func(t *testing.T) {
			var bodies [][]byte
			s, c, dir, p, v := textFixture(t, func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				bodies = append(bodies, raw)
				w.WriteHeader(500)
			})
			c.session.ProtocolFeatures = append(c.session.ProtocolFeatures, textServiceContractsProtocol)
			p = textFixtureContract(t, dir, p, contract)
			for i := 0; i < 2; i++ {
				if err := s.installation(context.Background(), c, v); err == nil {
					t.Fatal("ambiguous claim accepted")
				}
			}
			if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
				t.Fatal("retry changed body")
			}
			var body map[string]json.RawMessage
			json.Unmarshal(bodies[0], &body)
			var got string
			json.Unmarshal(body["projectContract"], &got)
			if got != contract || (contract == "" && body["projectContract"] != nil) {
				t.Fatal("wrong claim contract")
			}
			raw, err := textbridge.ReadPrivate(filepath.Join(dir, "claim-attempt.json"), 8192)
			if err != nil {
				t.Fatal(err)
			}
			next := textbridge.OwnerTextProjectContract
			if contract == next {
				next = textbridge.SharingProjectContract
			}
			textFixtureContract(t, dir, p, next)
			if err := s.installation(context.Background(), c, v); !errors.Is(err, errTextServiceSession) {
				t.Fatal("changed contract accepted")
			}
			after, err := textbridge.ReadPrivate(filepath.Join(dir, "claim-attempt.json"), 8192)
			if err != nil || !bytes.Equal(raw, after) || len(bodies) != 2 {
				t.Fatal("changed contract mutated or transported attempt")
			}
		})
	}
}

func TestTextServiceOwnerRequiresContractProtocol(t *testing.T) {
	var calls int
	s, c, dir, p, v := textFixture(t, func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(500) })
	textFixtureContract(t, dir, p, textbridge.OwnerTextProjectContract)
	if err := s.installation(context.Background(), c, v); !errors.Is(err, errTextServiceSession) || calls != 0 {
		t.Fatal("old server accepted owner claim")
	}
	if _, err := os.Stat(filepath.Join(dir, "claim-attempt.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("old server created owner attempt")
	}
}
