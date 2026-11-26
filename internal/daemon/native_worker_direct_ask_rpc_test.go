//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/nativedirect"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func proxyDirectASKSource(t *testing.T) (nativedirect.NativeDirectASKSource, json.RawMessage) {
	t.Helper()
	now := time.Now().UTC()
	binary := func(n int) string { return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, n)) }
	id := uuid.NewString()
	epoch, _ := uuid.NewV7()
	w := transport.DirectChannelMessageV2{Header: transport.DirectChannelMessageHeaderV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/message", Kind: "ASK", ChannelID: binary(32), DescriptorHash: binary(32), EpochID: epoch.String(), MessageID: id, RootID: id, SenderRole: "S"}, Nonce: binary(12), Ciphertext: binary(16)}
	wire, err := w.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := transport.DirectChannelMessageHashV2(w)
	party := func(role string) transport.DirectDeliveryPartyV2 {
		return transport.DirectDeliveryPartyV2{Role: role, PrincipalID: uuid.NewString(), EndpointID: uuid.NewString(), CredentialID: uuid.NewString()}
	}
	scope := sessionworker.Scope{ServerURL: "https://example.test", TenantID: "tenant", AccountID: "account", HostID: "host", InstanceID: "instance", Generation: "generation"}
	ownership := transport.NativeWorkerOwnership{ID: "ownership", InstanceID: scope.InstanceID, OwnershipGeneration: scope.Generation, State: "active", Runtime: "codex", OriginalAdmissionID: "admission", ProfileFingerprint: strings.Repeat("a", 64)}
	receipt := transport.DirectMessageAdmissionReceiptV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/admission", AdmissionState: "admitted", AdmittedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano), Binding: transport.DirectMessageBindingV2{Context: transport.DirectDeliveryContextV2{ChannelID: w.Header.ChannelID, DescriptorHash: w.Header.DescriptorHash, PublicationHash: binary(32), ParentGrantID: uuid.NewString(), GrantGeneration: "1"}, MessageID: id, WireHash: hash, WireBytes: len(wire), Sender: party("S"), Recipient: party("P")}}
	source := nativedirect.NativeDirectASKSource{Protocol: nativedirect.Protocol, AdmissionID: uuid.NewString(), ServerOrigin: scope.ServerURL, Scope: scope, Ownership: ownership, NativeSessionID: "session", NativeGeneration: "native-generation", NativeStartIdentity: "start", NativePID: 42, EndpointIssueID: "issue", EndpointLeaseID: "lease", EndpointGeneration: "1", ConsentRevision: 1, Receipt: receipt, InputDigest: strings.Repeat("b", 64), Deadline: now.Add(time.Hour)}
	if err := source.ValidateWire(wire); err != nil {
		t.Fatal(err)
	}
	return source, wire
}

func proxyDirectASKOwnership(t *testing.T, server net.Conn, source nativedirect.NativeDirectASKSource) bool {
	t.Helper()
	if !endpointRPCRequest(t, server) {
		return false
	}
	return swWriteFrame(server, sessionworker.Response{OwnershipVerify: &sessionworker.NativeOwnershipVerifyResult{Snapshot: sessionworker.NativeSnapshot{NativeSessionID: source.NativeSessionID, NativeGeneration: source.NativeGeneration, NativeStartIdentity: source.NativeStartIdentity, PID: source.NativePID}}}) == nil
}

func TestNativeWorkerDirectASKRPCResults(t *testing.T) {
	for _, name := range []string{"reserved", "unknown-state", "absent", "missing", "omitted-found", "null-found", "found-without-reservation", "reservation-without-found", "reserve-absent", "wrong-source", "wrong-wire", "wrong-state"} {
		t.Run(name, func(t *testing.T) {
			source, wire := proxyDirectASKSource(t)
			reserve := name == "reserved" || name == "reserve-absent"
			valid := name == "reserved" || name == "unknown-state" || name == "absent"
			p, _ := endpointRPCFixture(t, func(server net.Conn, _ *NativeObservationConnection) {
				if !proxyDirectASKOwnership(t, server, source) {
					return
				}
				var req sessionworker.Request
				if swReadFrame(server, &req) != nil {
					return
				}
				wantType := "direct_ask_lookup_v1"
				if reserve {
					wantType = "direct_ask_reserve_v1"
				}
				if req.Type != wantType || req.DirectASK == nil || req.DirectASK.Source.AdmissionID != source.AdmissionID || !bytes.Equal(req.DirectASK.Wire, wire) {
					t.Error("wrong direct ASK request")
					return
				}
				if name == "omitted-found" || name == "null-found" {
					raw := json.RawMessage(`{"directASK":{}}`)
					if name == "null-found" {
						raw = json.RawMessage(`{"directASK":{"found":null}}`)
					}
					_ = swWriteFrame(server, raw)
					var b [1]byte
					_, _ = server.Read(b[:])
					return
				}
				result := &sessionworker.DirectASKResult{Found: true, Reservation: &sessionworker.DirectASKReservation{Source: source, Wire: wire, State: "reserved"}}
				switch name {
				case "unknown-state":
					result.Reservation.State = "unknown"
				case "absent", "reserve-absent":
					result = &sessionworker.DirectASKResult{}
				case "missing":
					result = nil
				case "found-without-reservation":
					result.Reservation = nil
				case "reservation-without-found":
					result.Found = false
				case "wrong-source":
					result.Reservation.Source.AdmissionID = uuid.NewString()
				case "wrong-wire":
					result.Reservation.Wire = json.RawMessage(`{}`)
				case "wrong-state":
					result.Reservation.State = "accepted"
				}
				if swWriteFrame(server, sessionworker.Response{DirectASK: result}) != nil {
					return
				}
				if valid {
					proxyDirectASKOwnership(t, server, source)
				}
				var b [1]byte
				_, _ = server.Read(b[:])
			})
			result, err := p.directASK(t.Context(), source, wire, reserve)
			if valid {
				if err != nil || (result == nil) != (name == "absent") || p.aborted() {
					t.Fatalf("result=%v err=%v aborted=%v", result, err, p.aborted())
				}
			} else if err != errDirectEndpointRPCUnknown || result != nil || !p.aborted() {
				t.Fatalf("malformed response result=%v err=%v aborted=%v", result, err, p.aborted())
			}
		})
	}
}

func TestNativeWorkerDirectASKRPCNoDispatch(t *testing.T) {
	source, wire := proxyDirectASKSource(t)
	p, _ := endpointRPCFixture(t, func(server net.Conn, _ *NativeObservationConnection) {
		var b [1]byte
		_, _ = server.Read(b[:])
	})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := p.reserveDirectASK(ctx, source, wire); !errors.Is(err, sessionworker.ErrControllerCallNotStarted) || !errors.Is(err, context.Canceled) || p.aborted() {
		t.Fatalf("canceled preflight err=%v aborted=%v", err, p.aborted())
	}
	if _, err := p.lookupDirectASK(t.Context(), source, json.RawMessage(`{}`)); !errors.Is(err, sessionworker.ErrControllerCallNotStarted) || p.aborted() {
		t.Fatalf("invalid wire err=%v aborted=%v", err, p.aborted())
	}
}

func TestNativeWorkerDirectASKRPCUnknown(t *testing.T) {
	for _, failure := range []string{"EOF", "timeout", "revocation"} {
		t.Run(failure, func(t *testing.T) {
			source, wire := proxyDirectASKSource(t)
			p, _ := endpointRPCFixture(t, func(server net.Conn, native *NativeObservationConnection) {
				if !proxyDirectASKOwnership(t, server, source) {
					return
				}
				var req sessionworker.Request
				if swReadFrame(server, &req) != nil || req.Type != "direct_ask_reserve_v1" {
					return
				}
				switch failure {
				case "timeout":
					var b [1]byte
					_, _ = server.Read(b[:])
				case "revocation":
					close(native.closed)
					_ = swWriteFrame(server, sessionworker.Response{DirectASK: &sessionworker.DirectASKResult{Found: true, Reservation: &sessionworker.DirectASKReservation{Source: source, Wire: wire, State: "reserved"}}})
				}
			})
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			result, err := p.reserveDirectASK(ctx, source, wire)
			if result != nil || err != errDirectEndpointRPCUnknown || errors.Is(err, sessionworker.ErrControllerCallNotStarted) {
				t.Fatalf("result=%v err=%v", result, err)
			}
		})
	}
}
