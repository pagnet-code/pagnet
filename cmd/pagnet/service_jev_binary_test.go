package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/internal/jev"
	"github.com/pagnet-code/pagnet/transport"
)

// Exercise the shipped binary with a trusted local HTTPS proxy for the fixed
// TypeSafe hostname. It makes model discovery only, never a paid evaluation.
func TestJevBinaryFreshAndOtherAccountSetup(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess build")
	}
	if runtime.GOOS == "windows" {
		t.Skip("native Unix subprocess signals; Windows compile covered separately")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "pagnet")
	build := exec.Command("go", "build", "-o", binary, ".")
	if raw, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, raw)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "api.typesafe.ai"}, DNSNames: []string{"api.typesafe.ai"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "test-ca.pem")
	if err := os.WriteFile(root, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	var checks atomic.Int32
	provider := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" || r.Method != "GET" || r.Header.Get("Authorization") != "Bearer fixture-provider-key" {
			t.Error("unexpected provider request (no paid requests allowed)")
			w.WriteHeader(400)
			return
		}
		checks.Add(1)
		io.WriteString(w, `{"models":[{"name":"jev-latest"}]}`)
	}))
	provider.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	provider.StartTLS()
	defer provider.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != "api.typesafe.ai:443" {
			t.Error("proxy refused non-provider destination")
			w.WriteHeader(403)
			return
		}
		upstream, err := net.Dial("tcp", provider.Listener.Addr().String())
		if err != nil {
			w.WriteHeader(502)
			return
		}
		client, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			upstream.Close()
			return
		}
		_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = rw.Flush()
		go func() { defer client.Close(); defer upstream.Close(); _, _ = io.Copy(upstream, client) }()
		go func() { defer client.Close(); defer upstream.Close(); _, _ = io.Copy(client, upstream) }()
	}))
	defer proxy.Close()
	for _, account := range []string{"fresh", "other-account", "daemon"} {
		t.Run(account, func(t *testing.T) {
			service := uuid.NewString()
			ready := make(chan struct{})
			var once sync.Once
			credential := "pgn_act_v1_fixture"
			durable := "pgn_epd_v1_fixture"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer "+credential && r.Header.Get("Authorization") != "Bearer "+durable {
					t.Error("binary used account credentials instead of setup")
					w.WriteHeader(401)
					return
				}
				switch r.URL.Path {
				case "/api/v1/services/" + service + "/jev/setup":
					_ = json.NewEncoder(w).Encode(map[string]string{"serviceId": service, "integration": "typesafe-jev"})
				case "/api/v1/auth/principal/me":
					_ = json.NewEncoder(w).Encode(map[string]any{"principal": map[string]any{"ID": service, "Kind": "service", "Name": "Jev", "OwningTenantID": uuid.NewString()}, "memberships": []any{}})
				case "/api/v1/networks":
					io.WriteString(w, "[]")
				case "/wss/endpoints":
					ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
					if err != nil {
						return
					}
					defer ws.Close()
					var env transport.Envelope
					if ws.ReadJSON(&env) != nil {
						return
					}
					var reg transport.EndpointRegisterPayload
					if env.DecodePayload(&reg) != nil {
						return
					}
					ack, _ := transport.NewEnvelope(transport.MsgEndpointAuthOK, transport.EndpointAuthOKPayload{PrincipalID: service, EndpointID: uuid.NewString(), Credential: durable, ProtocolVersion: transport.ProtocolVersion, ProtocolFeatures: []string{transport.EndpointDispatchProtocol}})
					if ws.WriteJSON(ack) != nil {
						return
					}
					for _, cap := range reg.Capabilities {
						if cap.ID == jev.CapabilityID {
							once.Do(func() { close(ready) })
						}
					}
					for ws.ReadJSON(&env) == nil {
					}
				default:
					t.Error("unexpected account/login request")
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			home := t.TempDir()
			if account == "other-account" {
				accountDir := filepath.Join(home, ".pagnet", "accounts", "other")
				if err := os.MkdirAll(accountDir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(home, ".pagnet", "config.yaml"), []byte("currentAccount: other\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(accountDir, "config.yaml"), []byte("serverUrl: https://unrelated-account.invalid\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "service", "jev", "--service", service, "--setup", credential, "--server", server.URL)
			if account == "daemon" {
				cmd.Args = append(cmd.Args, "--daemon")
			}

			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "HOME=") && !strings.HasPrefix(entry, "HTTPS_PROXY=") && !strings.HasPrefix(entry, "SSL_CERT_FILE=") && !strings.HasPrefix(entry, "TYPESAFE_API_KEY=") && !strings.HasPrefix(entry, "PAGNET_TOKEN=") {
					cmd.Env = append(cmd.Env, entry)
				}
			}
			cmd.Env = append(cmd.Env, "HOME="+home, "HTTPS_PROXY="+proxy.URL, "SSL_CERT_FILE="+root, "TYPESAFE_API_KEY=fixture-provider-key")
			if account == "other-account" {
				cmd.Env = append(cmd.Env, "PAGNET_TOKEN=unrelated-account-fixture")
			}
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			finished := make(chan error, 1)
			go func() { finished <- cmd.Wait() }()
			if account == "daemon" {
				if err := <-finished; err != nil {
					t.Fatalf("daemon launch: %v %s", err, output.String())
				}
				raw, err := os.ReadFile(filepath.Join(home, ".pagnet", "services", "jev", service+".pid"))
				if err != nil {
					t.Fatal(err)
				}
				pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
				if err != nil {
					t.Fatal(err)
				}
				child, err := os.FindProcess(pid)
				if err != nil {
					t.Fatal(err)
				}
				defer child.Kill()
				select {
				case <-ready:
				case <-ctx.Done():
					t.Fatal("daemon endpoint did not register")
				}
				_ = child.Kill()
				raw, err = os.ReadFile(filepath.Join(home, ".pagnet", "services", "jev", service+".log"))
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(raw, []byte("fixture-provider-key")) || bytes.Contains(raw, []byte(credential)) {
					t.Fatal("daemon log leaked secret")
				}
			} else {
				select {
				case <-ready:
					cancel()
					<-finished
				case err := <-finished:
					t.Fatalf("binary exited before registration: %v %s", err, output.String())
				case <-ctx.Done():
					cancel()
					<-finished
					t.Fatalf("binary did not register endpoint: %s", output.String())
				}
			}

			if strings.Contains(output.String(), credential) || strings.Contains(output.String(), "fixture-provider-key") {
				t.Fatal("binary logged a secret")
			}
		})
	}
	if checks.Load() != 4 {
		t.Fatalf("model checks %d want4", checks.Load())
	}
}
