package sdk

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/transport"
)

func managedStandbyConfig() ManagedBrowserStandbyConfig {
	const id = "10000000-0000-4000-8000-000000000001"
	return ManagedBrowserStandbyConfig{BindingCredential: "pgn_epd_private", ExpectedTuple: transport.ManagedBrowserStandbyTuple{ConnectionID: id, BindingID: id, NetworkID: id, PrincipalID: id, HostID: id, Provider: "chatgpt", DesiredRevision: 1, LeaseID: id, InstanceID: id, LeaseGeneration: 1, CredentialID: id, CredentialGeneration: 1, PolicyFingerprint: strings.Repeat("ab", 32)}, AuthorityDeadline: time.Now().Add(15 * time.Second)}
}
func managedStandbySession(kind string) transport.ManagedBrowserStandbySession {
	return transport.ManagedBrowserStandbySession{Version: 1, Type: kind, SessionID: "20000000-0000-4000-8000-000000000001", SessionGeneration: 1}
}
func managedStandbyChallenge(config ManagedBrowserStandbyConfig) transport.ManagedBrowserStandbyChallenge {
	return transport.ManagedBrowserStandbyChallenge{ManagedBrowserStandbySession: managedStandbySession("challenge"), Tuple: config.ExpectedTuple, Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), ValidForMs: 5000}
}
func managedStandbyFrame(validity int64) transport.ManagedBrowserStandby {
	expiry := time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)
	return transport.ManagedBrowserStandby{ManagedBrowserStandbySession: managedStandbySession("standby"), LeaseExpiresAt: expiry, CredentialExpiresAt: expiry, ValidForMs: validity}
}
func managedStandbyServer(t *testing.T, config *ManagedBrowserStandbyConfig, serve func(*websocket.Conn)) func() {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/wss/managed-browser-bindings/"+config.ExpectedTuple.BindingID+"/standby" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer pgn_epd_private" {
			t.Error("incorrect standby request")
			w.WriteHeader(400)
			return
		}
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		serve(conn)
	}))
	config.Server = server.URL
	return server.Close
}
func managedStandbyHandshake(t *testing.T, conn *websocket.Conn, config ManagedBrowserStandbyConfig, validity int64) bool {
	t.Helper()
	challenge := managedStandbyChallenge(config)
	if conn.WriteJSON(challenge) != nil {
		return false
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	var ack transport.ManagedBrowserStandbyAck
	if conn.ReadJSON(&ack) != nil {
		return false
	}
	if ack.ManagedBrowserStandbySession != managedStandbySession("ack") || ack.Nonce != challenge.Nonce {
		t.Error("incorrect challenge ack")
		return false
	}
	return conn.WriteJSON(managedStandbyFrame(validity)) == nil
}
func managedStandbyFailure(t *testing.T, config ManagedBrowserStandbyConfig) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	err := ServeManagedBrowserStandby(ctx, config)
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected bounded protocol failure, got %v", err)
	}
	for _, secret := range []string{config.Server, config.BindingCredential, managedStandbyChallenge(config).Nonce} {
		if strings.Contains(err.Error(), secret) {
			t.Fatal("error leaked private protocol material")
		}
	}
	return err
}
func TestManagedStandbyRejectsEveryTupleMutation(t *testing.T) {
	tupleType := reflect.TypeOf(transport.ManagedBrowserStandbyTuple{})
	for i := 0; i < tupleType.NumField(); i++ {
		t.Run(tupleType.Field(i).Name, func(t *testing.T) {
			config := managedStandbyConfig()
			challenge := managedStandbyChallenge(config)
			field := reflect.ValueOf(&challenge.Tuple).Elem().Field(i)
			if field.Kind() == reflect.Int64 {
				field.SetInt(2)
			} else if tupleType.Field(i).Name == "PolicyFingerprint" {
				field.SetString(strings.Repeat("cd", 32))
			} else if tupleType.Field(i).Name == "Provider" {
				field.SetString("other")
			} else {
				field.SetString("30000000-0000-4000-8000-000000000001")
			}
			closeServer := managedStandbyServer(t, &config, func(conn *websocket.Conn) {
				conn.WriteJSON(challenge)
				conn.SetReadDeadline(time.Now().Add(time.Second))
				if _, _, err := conn.ReadMessage(); err == nil {
					t.Error("acknowledged mismatched assignment")
				}
			})
			defer closeServer()
			if err := managedStandbyFailure(t, config); errors.Is(err, ErrManagedBrowserStandbyTransport) {
				t.Fatalf("terminal failure classified as transport: %v", err)
			}
		})
	}
}
func TestManagedStandbyRejectsMalformedOrExecutionFrames(t *testing.T) {
	cases := []string{"missing-ready", "ready", "binary", "oversize", "malformed", "execution", "standby-ready", "standby-session", "standby-generation"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			config := managedStandbyConfig()
			closeServer := managedStandbyServer(t, &config, func(conn *websocket.Conn) {
				challenge := managedStandbyChallenge(config)
				raw, _ := json.Marshal(challenge)
				kind := websocket.TextMessage
				switch name {
				case "missing-ready":
					var v map[string]any
					json.Unmarshal(raw, &v)
					delete(v, "executionReady")
					raw, _ = json.Marshal(v)
				case "ready":
					challenge.ExecutionReady = true
					raw, _ = json.Marshal(challenge)
				case "binary":
					kind = websocket.BinaryMessage
				case "oversize":
					raw = []byte(strings.Repeat("x", 8193))
				case "malformed":
					raw = []byte("{")
				case "execution":
					raw = []byte(`{"type":"request","body":{"method":"tools/call"}}`)
				}
				conn.WriteMessage(kind, raw)
				conn.SetReadDeadline(time.Now().Add(time.Second))
				_, _, err := conn.ReadMessage()
				if strings.HasPrefix(name, "standby-") {
					if err != nil {
						t.Error("missing challenge ack")
						return
					}
					standby := managedStandbyFrame(10000)
					switch name {
					case "standby-ready":
						standby.ExecutionReady = true
					case "standby-session":
						standby.SessionID = "30000000-0000-4000-8000-000000000001"
					case "standby-generation":
						standby.SessionGeneration++
					}
					conn.WriteJSON(standby)
					_, _, err = conn.ReadMessage()
				}
				if err == nil {
					t.Error("sent a frame after rejected input")
				}
			})
			defer closeServer()
			if err := managedStandbyFailure(t, config); errors.Is(err, ErrManagedBrowserStandbyTransport) {
				t.Fatalf("terminal failure classified as transport: %v", err)
			}
		})
	}
}
func TestManagedStandbyHTTPFailuresAreSanitizedAndDoNotFallback(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 302, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			config := managedStandbyConfig()
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Location", "https://private.invalid/nonce")
				w.WriteHeader(status)
				w.Write([]byte("pgn_epd_private secret body"))
			}))
			defer server.Close()
			config.Server = server.URL
			err := managedStandbyFailure(t, config)
			if errors.Is(err, ErrManagedBrowserStandbyTransport) {
				t.Fatal("HTTP failure classified as transport")
			}
			if status == 401 && !errors.Is(err, ErrManagedBrowserStandbyUnauthorized) {
				t.Fatal("missing unauthorized classification")
			}
			if status == 404 && !errors.Is(err, ErrManagedBrowserStandbyUnsupported) {
				t.Fatal("missing unsupported classification")
			}
			if requests.Load() != 1 {
				t.Fatal("retried or used fallback")
			}
		})
	}
}
func TestManagedStandbyCancellationClosesConnection(t *testing.T) {
	for _, phase := range []string{"challenge", "standby"} {
		t.Run(phase, func(t *testing.T) {
			config := managedStandbyConfig()
			ready := make(chan struct{})
			closed := make(chan struct{})
			closeServer := managedStandbyServer(t, &config, func(conn *websocket.Conn) {
				defer close(closed)
				if phase == "standby" && !managedStandbyHandshake(t, conn, config, 10000) {
					return
				}
				close(ready)
				conn.SetReadDeadline(time.Now().Add(time.Second))
				conn.ReadMessage()
			})
			defer closeServer()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- ServeManagedBrowserStandby(ctx, config) }()
			<-ready
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("got %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation blocked")
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("connection remained open")
			}
		})
	}
}
func TestManagedStandbyValidityStartsBeforeResponse(t *testing.T) {
	for _, phase := range []string{"challenge", "standby"} {
		t.Run(phase, func(t *testing.T) {
			config := managedStandbyConfig()
			closeServer := managedStandbyServer(t, &config, func(conn *websocket.Conn) {
				challenge := managedStandbyChallenge(config)
				if phase == "challenge" {
					challenge.ValidForMs = 20
					time.Sleep(60 * time.Millisecond)
					conn.WriteJSON(challenge)
				} else {
					conn.WriteJSON(challenge)
					conn.ReadMessage()
					time.Sleep(60 * time.Millisecond)
					conn.WriteJSON(managedStandbyFrame(20))
				}
				conn.SetReadDeadline(time.Now().Add(time.Second))
				conn.ReadMessage()
			})
			defer closeServer()
			if err := managedStandbyFailure(t, config); errors.Is(err, ErrManagedBrowserStandbyTransport) {
				t.Fatalf("terminal failure classified as transport: %v", err)
			}
		})
	}
}
func TestManagedStandbyAuthorityCannotBeExtended(t *testing.T) {
	for _, source := range []string{"local", "lease", "credential"} {
		t.Run(source, func(t *testing.T) {
			config := managedStandbyConfig()
			if source == "local" {
				config.AuthorityDeadline = time.Now().Add(150 * time.Millisecond)
			}
			closeServer := managedStandbyServer(t, &config, func(conn *websocket.Conn) {
				conn.WriteJSON(managedStandbyChallenge(config))
				conn.ReadMessage()
				standby := managedStandbyFrame(10000)
				short := time.Now().Add(150 * time.Millisecond).UTC().Format(time.RFC3339Nano)
				if source == "lease" {
					standby.LeaseExpiresAt = short
				}
				if source == "credential" {
					standby.CredentialExpiresAt = short
				}
				conn.WriteJSON(standby)
				conn.ReadMessage()
			})
			defer closeServer()
			start := time.Now()
			if err := managedStandbyFailure(t, config); errors.Is(err, ErrManagedBrowserStandbyTransport) {
				t.Fatal("expired authority classified as transport")
			}
			if time.Since(start) > time.Second {
				t.Fatal("server extended authority")
			}
		})
	}
}
func TestManagedStandbyHeartbeatOrderingAndDelayedAck(t *testing.T) {
	for _, mutation := range []string{"valid", "sequence", "session", "generation", "delayed", "execution"} {
		t.Run(mutation, func(t *testing.T) {
			t.Parallel()
			config := managedStandbyConfig()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			closeServer := managedStandbyServer(t, &config, func(conn *websocket.Conn) {
				if !managedStandbyHandshake(t, conn, config, 10000) {
					return
				}
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				var heartbeat transport.ManagedBrowserStandbyHeartbeat
				if conn.ReadJSON(&heartbeat) != nil {
					t.Error("missing heartbeat")
					return
				}
				if heartbeat.ManagedBrowserStandbySession != managedStandbySession("heartbeat") || heartbeat.Sequence != 1 {
					t.Error("invalid heartbeat")
				}
				base := managedStandbyFrame(10000)
				ack := transport.ManagedBrowserStandbyHeartbeatAck{ManagedBrowserStandbySession: managedStandbySession("heartbeat_ack"), Sequence: 1, LeaseExpiresAt: base.LeaseExpiresAt, CredentialExpiresAt: base.CredentialExpiresAt, ValidForMs: 10000}
				switch mutation {
				case "sequence":
					ack.Sequence++
				case "session":
					ack.SessionID = "30000000-0000-4000-8000-000000000001"
				case "generation":
					ack.SessionGeneration++
				case "delayed":
					time.Sleep(60 * time.Millisecond)
					ack.ValidForMs = 20
				case "execution":
					conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"request","method":"execute"}`))
					conn.ReadMessage()
					return
				}
				conn.WriteJSON(ack)
				if mutation == "valid" {
					time.Sleep(30 * time.Millisecond)
					cancel()
				}
				conn.ReadMessage()
			})
			defer closeServer()
			err := ServeManagedBrowserStandby(ctx, config)
			if mutation == "valid" {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("got %v", err)
				}
			} else if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, ErrManagedBrowserStandbyTransport) {
				t.Fatalf("accepted invalid heartbeat ack: %v", err)
			}
		})
	}
}

func TestManagedStandbyRejectsInvalidLocalAuthority(t *testing.T) {
	for _, name := range []string{"zero", "expired", "credential", "tuple", "remote-http", "query"} {
		t.Run(name, func(t *testing.T) {
			config := managedStandbyConfig()
			config.Server = "http://127.0.0.1:1"
			switch name {
			case "zero":
				config.AuthorityDeadline = time.Time{}
			case "expired":
				config.AuthorityDeadline = time.Now().Add(-time.Second)
			case "credential":
				config.BindingCredential = "other-private"
			case "tuple":
				config.ExpectedTuple.LeaseGeneration = 0
			case "remote-http":
				t.Setenv("PAGNET_INSECURE_REMOTE_HTTP", "")
				config.Server = "http://private.invalid"
			case "query":
				config.Server += "?private=secret"
			}
			if err := managedStandbyFailure(t, config); errors.Is(err, ErrManagedBrowserStandbyTransport) {
				t.Fatalf("terminal failure classified as transport: %v", err)
			}
		})
	}
}

func TestManagedStandbyRejectsUnsolicitedHeartbeatAck(t *testing.T) {
	config := managedStandbyConfig()
	closeServer := managedStandbyServer(t, &config, func(conn *websocket.Conn) {
		if !managedStandbyHandshake(t, conn, config, 10000) {
			return
		}
		base := managedStandbyFrame(10000)
		conn.WriteJSON(transport.ManagedBrowserStandbyHeartbeatAck{ManagedBrowserStandbySession: managedStandbySession("heartbeat_ack"), Sequence: 1, LeaseExpiresAt: base.LeaseExpiresAt, CredentialExpiresAt: base.CredentialExpiresAt, ValidForMs: 10000})
		conn.SetReadDeadline(time.Now().Add(time.Second))
		if _, _, err := conn.ReadMessage(); err == nil {
			t.Error("sent a frame after unsolicited ack")
		}
	})
	defer closeServer()
	managedStandbyFailure(t, config)
}

func TestManagedStandbyCancellationInterruptsHTTPUpgrade(t *testing.T) {
	config := managedStandbyConfig()
	requested := make(chan struct{})
	closed := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requested)
		<-r.Context().Done()
		close(closed)
	}))
	defer server.Close()
	config.Server = server.URL
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- ServeManagedBrowserStandby(ctx, config) }()
	<-requested
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation blocked during HTTP upgrade")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("upgrade socket remained open")
	}
}

func TestManagedStandbyRedirectDoesNotForwardCredential(t *testing.T) {
	var forwarded atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded.Add(1); w.WriteHeader(http.StatusUnauthorized) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	config := managedStandbyConfig()
	config.Server = source.URL
	managedStandbyFailure(t, config)
	if forwarded.Load() != 0 {
		t.Fatal("followed credential-bearing redirect")
	}
}

func TestManagedStandbyHeartbeatSecondSequence(t *testing.T) {
	t.Parallel()
	config := managedStandbyConfig()
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
	defer cancel()
	closeServer := managedStandbyServer(t, &config, func(conn *websocket.Conn) {
		if !managedStandbyHandshake(t, conn, config, 10000) {
			return
		}
		conn.SetReadDeadline(time.Now().Add(8 * time.Second))
		for sequence := int64(1); sequence <= 2; sequence++ {
			var heartbeat transport.ManagedBrowserStandbyHeartbeat
			if err := conn.ReadJSON(&heartbeat); err != nil {
				t.Error("missing heartbeat")
				return
			}
			if heartbeat.ManagedBrowserStandbySession != managedStandbySession("heartbeat") || heartbeat.Sequence != sequence {
				t.Error("incorrect heartbeat sequence or session")
				return
			}
			base := managedStandbyFrame(10000)
			if err := conn.WriteJSON(transport.ManagedBrowserStandbyHeartbeatAck{ManagedBrowserStandbySession: managedStandbySession("heartbeat_ack"), Sequence: sequence, LeaseExpiresAt: base.LeaseExpiresAt, CredentialExpiresAt: base.CredentialExpiresAt, ValidForMs: 10000}); err != nil {
				t.Error("heartbeat ack failed")
				return
			}
		}
		cancel()
		conn.ReadMessage()
	})
	defer closeServer()
	if err := ServeManagedBrowserStandby(ctx, config); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestManagedStandbyMissingAckExpires(t *testing.T) {
	t.Parallel()
	config := managedStandbyConfig()
	closeServer := managedStandbyServer(t, &config, func(conn *websocket.Conn) {
		if !managedStandbyHandshake(t, conn, config, 3300) {
			return
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		var heartbeat transport.ManagedBrowserStandbyHeartbeat
		if conn.ReadJSON(&heartbeat) != nil || heartbeat.Sequence != 1 {
			t.Error("missing first heartbeat")
			return
		}
		if _, _, err := conn.ReadMessage(); err == nil {
			t.Error("sent another frame without an ack")
		}
	})
	defer closeServer()
	start := time.Now()
	if err := managedStandbyFailure(t, config); !errors.Is(err, ErrManagedBrowserStandbyTransport) {
		t.Fatalf("missing transport classification: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 3*time.Second || elapsed > 5*time.Second {
		t.Fatalf("incorrect freshness expiry: %v", elapsed)
	}
}

func TestManagedStandbyTransportWhitelist(t *testing.T) {
	for _, err := range []error{io.EOF, io.ErrUnexpectedEOF, net.ErrClosed, &net.OpError{Op: "read", Err: os.NewSyscallError("read", syscall.ECONNRESET)}, &net.DNSError{IsTimeout: true}, &websocket.CloseError{Code: 1006}} {
		if !managedStandbyTransportError(fmt.Errorf("private detail: %w", err)) {
			t.Errorf("not recognized: %T", err)
		}
	}
	for _, err := range []error{errors.New("private unknown"), context.Canceled, &net.DNSError{IsNotFound: true}, &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, tls.RecordHeaderError{}, websocket.ErrReadLimit, &websocket.CloseError{Code: 1008}, &websocket.CloseError{Code: 1002}, &websocket.CloseError{Code: 1000}} {
		if managedStandbyTransportError(err) {
			t.Errorf("terminal error recognized as transport: %T", err)
		}
	}
}

func TestManagedStandbyReadFailures(t *testing.T) {
	for _, phase := range []string{"challenge", "standby", "heartbeat"} {
		for _, failure := range []string{"disconnect", "reset", "policy", "protocol", "malformed", "invalid-websocket"} {
			t.Run(phase+"/"+failure, func(t *testing.T) {
				config := managedStandbyConfig()
				var attempts atomic.Int32
				closeServer := managedStandbyServer(t, &config, func(conn *websocket.Conn) {
					attempts.Add(1)
					if phase == "heartbeat" {
						if !managedStandbyHandshake(t, conn, config, 10000) {
							return
						}
					} else if phase == "standby" {
						if conn.WriteJSON(managedStandbyChallenge(config)) != nil {
							return
						}
						if _, _, err := conn.ReadMessage(); err != nil {
							return
						}
					}
					switch failure {
					case "disconnect":
						return
					case "reset":
						socket := conn.UnderlyingConn().(*net.TCPConn)
						socket.SetLinger(0)
						socket.Close()
					case "policy":
						conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(1008, "pgn_epd_private"))
					case "protocol":
						conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(1002, "pgn_epd_private"))
					case "malformed":
						conn.WriteMessage(websocket.TextMessage, []byte("{"))
					case "invalid-websocket":
						conn.UnderlyingConn().Write([]byte{0xc1, 0}) // unexpected RSV1 bit
					}
					conn.SetReadDeadline(time.Now().Add(time.Second))
					conn.ReadMessage()
				})
				defer closeServer()
				err := managedStandbyFailure(t, config)
				wantTransport := failure == "disconnect" || failure == "reset"
				if errors.Is(err, ErrManagedBrowserStandbyTransport) != wantTransport {
					t.Fatalf("incorrect classification: %v", err)
				}
				if attempts.Load() != 1 {
					t.Fatal("retried interrupted attempt")
				}
			})
		}
	}
}

func TestManagedStandbyInvalidTLSIsTerminal(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("accepted untrusted TLS") }))
	defer server.Close()
	config := managedStandbyConfig()
	config.Server = server.URL
	if err := managedStandbyFailure(t, config); errors.Is(err, ErrManagedBrowserStandbyTransport) {
		t.Fatal("certificate error classified as transport")
	}
}

func TestManagedStandbyDialInterruption(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	config := managedStandbyConfig()
	config.Server = "http://" + address
	if err := managedStandbyFailure(t, config); !errors.Is(err, ErrManagedBrowserStandbyTransport) {
		t.Fatalf("missing transport classification: %v", err)
	}
}

func TestManagedStandbyHandshakeTimeout(t *testing.T) {
	t.Parallel()
	config := managedStandbyConfig()
	closeServer := managedStandbyServer(t, &config, func(conn *websocket.Conn) {
		conn.SetReadDeadline(time.Now().Add(6 * time.Second))
		conn.ReadMessage()
	})
	defer closeServer()
	if err := managedStandbyFailure(t, config); !errors.Is(err, ErrManagedBrowserStandbyTransport) {
		t.Fatalf("missing transport classification: %v", err)
	}
}

func TestManagedStandbyMissingAckCannotOutliveAuthority(t *testing.T) {
	for _, source := range []string{"local", "lease", "credential"} {
		t.Run(source, func(t *testing.T) {
			t.Parallel()
			config := managedStandbyConfig()
			authority := time.Now().Add(3300 * time.Millisecond)
			if source == "local" {
				config.AuthorityDeadline = authority
			}
			closeServer := managedStandbyServer(t, &config, func(conn *websocket.Conn) {
				if conn.WriteJSON(managedStandbyChallenge(config)) != nil {
					return
				}
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
				standby := managedStandbyFrame(10000)
				if source == "lease" {
					standby.LeaseExpiresAt = authority.UTC().Format(time.RFC3339Nano)
				}
				if source == "credential" {
					standby.CredentialExpiresAt = authority.UTC().Format(time.RFC3339Nano)
				}
				if conn.WriteJSON(standby) != nil {
					return
				}
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				var heartbeat transport.ManagedBrowserStandbyHeartbeat
				if conn.ReadJSON(&heartbeat) != nil || heartbeat.Sequence != 1 {
					t.Error("missing heartbeat")
					return
				}
				conn.ReadMessage()
			})
			defer closeServer()
			if err := managedStandbyFailure(t, config); errors.Is(err, ErrManagedBrowserStandbyTransport) {
				t.Fatal("expired authority classified as transport")
			}
		})
	}
}
