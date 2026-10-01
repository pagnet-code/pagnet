package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/internal/jev"
	"github.com/pagnet-code/pagnet/transport"
)

type fakeJevProvider struct{ checks atomic.Int32 }

func (p *fakeJevProvider) CheckKey(context.Context) error { p.checks.Add(1); return nil }
func (p *fakeJevProvider) EvaluateValue(context.Context, any) (jev.Result, error) {
	panic("setup must not run paid judgments")
}

func TestJevSetupUsesServiceCredentialWithoutAccountLogin(t *testing.T) {
	for _, otherAccount := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "another account"}[otherAccount], func(t *testing.T) {
			dir := t.TempDir()
			service := uuid.NewString()
			setup := "pgn_act_v1_fixture"
			durable := "pgn_epd_v1_fixture"
			if otherAccount {
				t.Setenv("PAGNET_TOKEN", "another-account-bearer")
			}
			t.Setenv("TYPESAFE_API_KEY", "local-provider-fixture")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var advertised atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				if auth != "Bearer "+setup && auth != "Bearer "+durable {
					t.Error("service command used another account credential")
					w.WriteHeader(401)
					return
				}
				switch r.URL.Path {
				case "/api/v1/services/" + service + "/jev/setup":
					_ = json.NewEncoder(w).Encode(map[string]string{"serviceId": service, "integration": "typesafe-jev"})
				case "/api/v1/auth/principal/me":
					_ = json.NewEncoder(w).Encode(map[string]any{"principal": map[string]any{"ID": service, "Kind": "service", "Name": "Jev", "OwningTenantID": uuid.NewString()}, "memberships": []any{}})
				case "/api/v1/networks":
					_ = json.NewEncoder(w).Encode([]any{})
				case "/wss/endpoints":
					conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
					if err != nil {
						return
					}
					defer conn.Close()
					var env transport.Envelope
					if conn.ReadJSON(&env) != nil {
						return
					}
					var reg transport.EndpointRegisterPayload
					if env.DecodePayload(&reg) != nil {
						t.Error("registration malformed")
						return
					}
					ack, _ := transport.NewEnvelope(transport.MsgEndpointAuthOK, transport.EndpointAuthOKPayload{PrincipalID: service, EndpointID: uuid.NewString(), Credential: durable, ProtocolVersion: transport.ProtocolVersion})
					if conn.WriteJSON(ack) != nil {
						return
					}
					for _, cap := range reg.Capabilities {
						if cap.ID == jev.CapabilityID {
							advertised.Store(true)
							cancel()
						}
					}
					for conn.ReadJSON(&env) == nil {
					}
				default:
					t.Errorf("unexpected account or daemon request %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			provider := new(fakeJevProvider)
			cmd := jevServiceCmdWithProvider(func(key, model string) (jevProvider, error) {
				if key != "local-provider-fixture" {
					t.Error("local provider key missing")
				}
				return provider, nil
			})
			var output bytes.Buffer
			cmd.SetErr(&output)
			cmd.SetOut(&output)
			cmd.SetContext(ctx)
			cmd.SetArgs([]string{"--service", service, "--setup", setup, "--server", server.URL, "--state-dir", dir})
			timer := time.AfterFunc(5*time.Second, cancel)
			defer timer.Stop()
			if err := cmd.Execute(); err != nil {
				t.Fatalf("setup failed: %v", err)
			}
			if !advertised.Load() || provider.checks.Load() != 1 {
				t.Fatal("setup did not advertise Jev capability independently of account")
			}
			text := output.String()
			if strings.Contains(text, setup) || strings.Contains(text, durable) || strings.Contains(text, "local-provider-fixture") {
				t.Fatal("secret exposed in setup progress")
			}
			if !strings.Contains(text, "CLI account login is not required") || !strings.Contains(text, "endpoint connected") {
				t.Fatal("startup phases absent")
			}
		})
	}
}

func TestServiceDetachedCommandKeepsSecretsOutOfArguments(t *testing.T) {
	t.Setenv("TYPESAFE_API_KEY", "obsolete-provider-key")
	profile := serviceRunnerProfile{Service: uuid.NewString(), Adapter: "jev", Credential: "pgn_act_v1_secret"}
	child := serviceDetachedCommand("pagnet", profile, t.TempDir(), []string{"TYPESAFE_API_KEY=local-provider-key"})
	for _, arg := range child.Args {
		if strings.Contains(arg, "secret") || strings.Contains(arg, "provider-key") || arg == "--setup" || arg == "--daemon" {
			t.Fatal("child args leaked secrets or recurse")
		}
	}
	count := 0
	for _, entry := range child.Env {
		if strings.HasPrefix(entry, "TYPESAFE_API_KEY=") {
			count++
			if entry != "TYPESAFE_API_KEY=local-provider-key" {
				t.Fatal("stale key inherited")
			}
		}
	}
	if count != 1 {
		t.Fatal("provider environment override ambiguous")
	}
}
