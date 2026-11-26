//go:build linux || darwin

package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func TestNativeHostSessionFeatureReplay(t *testing.T) {
	for _, scenario := range []string{"identical", "reordered", "upgrade", "downgrade", "duplicate count", "receipt removed"} {
		t.Run(scenario, func(t *testing.T) {
			host, boot := domain.NewID().String(), domain.NewID().String()
			conn := NewNativeObservationConnection("https://example.test", host, boot, nil)
			session := transport.HostSessionPayload{TenantID: host, AccountID: host, OwnershipScope: "personal", NativeAdmissionID: domain.NewID().String(), HostID: host, BootID: boot, RunnerID: domain.NewID().String(), RunnerEpoch: time.Now().UTC(), ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol, "extension-a", "extension-a", "extension-b"}}
			if handled, err := conn.HandleEnvelope(nativeBindingEnvelope(t, transport.MsgHostSession, session)); !handled || err != nil {
				t.Fatal("initial admission failed", handled, err)
			}
			replay := session
			replay.ProtocolFeatures = append([]string(nil), session.ProtocolFeatures...)
			switch scenario {
			case "reordered":
				replay.ProtocolFeatures = []string{"extension-b", "extension-a", transport.NativeObservationReceiptProtocol, "extension-a"}
			case "upgrade":
				replay.ProtocolFeatures = append(replay.ProtocolFeatures, "extension-c")
			case "downgrade":
				replay.ProtocolFeatures = replay.ProtocolFeatures[:3]
			case "duplicate count":
				replay.ProtocolFeatures[2] = "extension-b"
			case "receipt removed":
				replay.ProtocolFeatures = replay.ProtocolFeatures[1:]
			}
			handled, err := conn.HandleEnvelope(nativeBindingEnvelope(t, transport.MsgHostSession, replay))
			if !handled {
				t.Fatal("session replay escaped native handling")
			}
			if scenario == "identical" || scenario == "reordered" {
				if err != nil {
					t.Fatal("equivalent feature replay rejected", err)
				}
				retained, err := conn.AuthenticatedNativeHostSession()
				if err != nil || len(retained.ProtocolFeatures) != len(session.ProtocolFeatures) {
					t.Fatal("equivalent replay lost admission", err)
				}
				for i, feature := range session.ProtocolFeatures {
					if retained.ProtocolFeatures[i] != feature {
						t.Fatal("replay replaced admitted feature order")
					}
				}
				return
			}
			if !errors.Is(err, ErrNativeObservationConflict) {
				t.Fatal("changed features did not conflict", err)
			}
			if _, err := conn.AuthenticatedNativeHostSession(); !errors.Is(err, ErrNativeOriginAdmissionDeferred) {
				t.Fatal("conflicting replay retained authority", err)
			}
			if err := conn.Admit(session); !errors.Is(err, ErrNativeOriginAdmissionDeferred) {
				t.Fatal("revoked connection was readmitted", err)
			}
		})
	}
}

func TestNativeHostSessionFeatureReplayBlocksCredentialDispatchV2(t *testing.T) {
	for _, scenario := range []string{"upgrade", "downgrade"} {
		t.Run(scenario, func(t *testing.T) {
			_, lane, peer, executor, issue := directSourceCredentialLaneFixtureV2(t)
			replay, err := lane.native.AuthenticatedNativeHostSession()
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "upgrade" {
				replay.ProtocolFeatures = append(replay.ProtocolFeatures, transport.NativeShareSourceEnrollmentProtocol)
			} else {
				replay.ProtocolFeatures = replay.ProtocolFeatures[:1]
			}
			if _, err := lane.native.HandleEnvelope(nativeBindingEnvelope(t, transport.MsgHostSession, replay)); !errors.Is(err, ErrNativeObservationConflict) {
				t.Fatal("changed feature replay did not conflict", err)
			}
			if !lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourceCredentialV2, issue)) {
				t.Fatal("credential command escaped dedicated lane")
			}
			select {
			case <-executor.started:
				t.Fatal("revoked connection dispatched credential command")
			default:
			}
			_ = peer.SetReadDeadline(time.Now().Add(time.Second))
			if _, _, err := peer.ReadMessage(); err == nil {
				t.Fatal("revoked connection published an ACK")
			}
		})
	}
}

func TestNativeHostSessionFeatureReplayBlocksCredentialPublicationV2(t *testing.T) {
	for _, scenario := range []string{"upgrade", "downgrade"} {
		t.Run(scenario, func(t *testing.T) {
			keys, issue, d, token, captured := sourceCredentialAuthorityFixtureV2(t)
			lane := newDirectManagedSourceCredentialPublicationLane()
			ack, err := keys.InstallCredential(issue, "https://example.test", captured.Session, directSourceCredentialScopeOKV2, d.directManagedSourceCredentialPublicationFenceV2(token, captured, lane))
			if err != nil {
				t.Fatal(err)
			}
			replay := captured.Session
			replay.ProtocolFeatures = append([]string(nil), replay.ProtocolFeatures...)
			if scenario == "upgrade" {
				replay.ProtocolFeatures = append(replay.ProtocolFeatures, transport.NativeShareSourceEnrollmentProtocol)
			} else {
				replay.ProtocolFeatures = replay.ProtocolFeatures[:1]
			}
			if _, err := captured.Connection.HandleEnvelope(nativeBindingEnvelope(t, transport.MsgHostSession, replay)); !errors.Is(err, ErrNativeObservationConflict) {
				t.Fatal("changed feature replay did not conflict", err)
			}
			e := &localDirectManagedSourceCredentialV2{&localDirectManagedSourcePoPV2{&localDirectManagedSourcePrepareV2{d: d, keys: keys}}}
			wrote := false
			err = e.publishCredentialACKWithToken(context.Background(), token, captured.Socket, captured.Connection, captured.Session, "https://example.test", issue, lane, ack, func() error { wrote = true; return nil })
			if err == nil || wrote {
				t.Fatal("revoked connection published installed credential ACK", err, wrote)
			}
		})
	}
}
