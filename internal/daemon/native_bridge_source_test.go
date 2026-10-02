package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func TestNativeBridgeSourcePinsOriginalWorkerTurn(t *testing.T) {
	scope := sessionworker.Scope{TenantID: domain.NewID().String(), HostID: domain.NewID().String(), InstanceID: domain.NewID().String()}
	origin := transport.NativeObservationOrigin{ID: domain.NewID().String(), TenantID: scope.TenantID, HostID: scope.HostID, InstanceID: scope.InstanceID, NativeGeneration: "original-A", NativeSessionID: "vendor-session-A"}
	encoded, _ := json.Marshal(origin)
	original := sessionworker.NativeTurnSource{Sequence: 9, LogicalTurnID: "pagnet-worker-turn-9", NativeGeneration: "original-A", NativeSessionID: "vendor-session-A", SourceCommandID: domain.NewID().String(), SourceAdmissionID: domain.NewID().String(), InputKind: "user_input"}
	for _, mode := range []string{"original", "generation", "session", "command", "admission", "sequence", "origin"} {
		t.Run(mode, func(t *testing.T) {
			source := original
			call := &sessionworker.BridgeCall{Scope: scope, NativeGeneration: "original-A", Origin: encoded, TurnSource: &source}
			switch mode {
			case "generation":
				source.NativeGeneration = "B"
			case "session":
				source.NativeSessionID = "B"
			case "command":
				source.SourceCommandID = ""
			case "admission":
				source.SourceAdmissionID = ""
			case "sequence":
				source.Sequence = 0
			case "origin":
				call.Origin = json.RawMessage(`{}`)
			}
			got, err := nativeBridgeSource(call)
			if mode == "original" {
				if err != nil || got.SourceCommandID != original.SourceCommandID || got.SourceAdmissionID != original.SourceAdmissionID || got.SessionID != original.NativeSessionID || got.NativeTurnSequence != 9 {
					t.Fatal(got, err)
				}
			} else if err == nil {
				t.Fatal("accepted foreign or incomplete source", got)
			}
		})
	}
}

func TestNativeBridgeRepeatsOnlyExplicitPreEffectRefusal(t *testing.T) {
	for _, mode := range []string{"ready", "generic_retryable", "not_retryable"} {
		t.Run(mode, func(t *testing.T) {
			d := newTestDaemon(t)
			source := &transport.NativeAgentSource{OriginID: domain.NewID().String(), NativeGeneration: "original-A", SessionID: "vendor-A", LogicalTurnID: "turn-A", NativeTurnSequence: 7, InputKind: "user_input", SourceCommandID: domain.NewID().String(), SourceAdmissionID: domain.NewID().String()}
			request := transport.AgentRequestPayload{InstanceID: domain.NewID().String(), PrincipalID: domain.NewID().String(), Tool: "control_channel_send", Args: json.RawMessage(`{"body":"original conversation"}`), NativeSource: source}
			var calls atomic.Int32
			failures := make(chan string, 4)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				peer, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer peer.Close()
				for {
					var env transport.Envelope
					if peer.ReadJSON(&env) != nil {
						return
					}
					var actual transport.AgentRequestPayload
					if env.DecodePayload(&actual) != nil {
						failures <- "malformed request"
						return
					}
					if !reflect.DeepEqual(actual, request) {
						failures <- "original source or arguments changed"
						return
					}
					n := calls.Add(1)
					response := transport.AgentResponsePayload{RequestID: env.ID, Error: "original source not ready", ErrorCode: "source_not_ready", Retryable: true}
					if mode == "generic_retryable" {
						response.ErrorCode = "other"
					}
					if mode == "not_retryable" {
						response.Retryable = false
					}
					if mode == "ready" && n == 2 {
						response.OK = true
						response.Result = json.RawMessage(`{"delivered":true}`)
						response.Error = ""
						response.ErrorCode = ""
						response.Retryable = false
					}
					frame, _ := transport.NewEnvelope(transport.MsgAgentResponse, response)
					if peer.WriteJSON(frame) != nil {
						return
					}
				}
			}))
			defer server.Close()
			conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			readDone := make(chan struct{})
			go func() {
				defer close(readDone)
				for {
					var env transport.Envelope
					if conn.ReadJSON(&env) != nil {
						return
					}
					d.deliverAgentResponse(env)
				}
			}()
			connection := NewNativeObservationConnection(server.URL, "host", "boot", nil)
			defer connection.Close()
			link := &nativeWorkerLink{conn: conn, proxy: &NativeWorkerProxy{connection: connection}}
			got, message := d.relayNativeSourceRequest(t.Context(), link, request)
			want := int32(1)
			if mode == "ready" {
				want = 2
				if message != "" || string(got) != `{"delivered":true}` {
					t.Fatal(string(got), message)
				}
			} else if message == "" {
				t.Fatal("unexpected success")
			}
			if calls.Load() != want {
				t.Fatal("unsafe retry count", calls.Load(), want)
			}
			select {
			case failure := <-failures:
				t.Fatal(failure)
			default:
			}
			conn.Close()
			select {
			case <-readDone:
			case <-time.After(time.Second):
				t.Fatal("read loop leaked")
			}
		})
	}
}

func TestNativeTerminalOutcomeUsesOriginalLocalOperationMapping(t *testing.T) {
	proof := transport.NativeDispatchProof{OwnershipID: domain.NewID().String(), OwnershipGeneration: "original-A", DispatchSequence: 9, SourceCommandID: domain.NewID().String(), SourceAdmissionID: domain.NewID().String()}
	records := []sessionworker.NativeDispatchRecord{{Proof: proof, OperationSequence: 42, State: "admitted"}}
	got, err := nativeDispatchOperationSequence(proof, records)
	if err != nil || got != 42 {
		t.Fatal("terminal outcome adopted server ordinal", got, err)
	}
	foreign := proof
	foreign.SourceAdmissionID = domain.NewID().String()
	if _, err = nativeDispatchOperationSequence(foreign, records); err == nil {
		t.Fatal("terminal outcome adopted foreign original source")
	}
}
