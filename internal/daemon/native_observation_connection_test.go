package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func TestNativeObservationConnectionKeepsAdmissionExactAndDisconnectUnblocks(t *testing.T) {
	host, boot, runner := domain.NewID().String(), domain.NewID().String(), domain.NewID().String()
	requests := make(chan transport.NativeOriginRegisterPayload, 1)
	conn := NewNativeObservationConnection("https://example.test", host, boot, func(_ context.Context, typ string, p any) error {
		if typ != transport.MsgNativeOriginRegister {
			t.Fatal(typ)
		}
		requests <- p.(transport.NativeOriginRegisterPayload)
		return nil
	})
	admission := transport.HostSessionPayload{TenantID: host, AccountID: host, OwnershipScope: "personal", NativeAdmissionID: runner, HostID: host, BootID: boot, RunnerID: runner, RunnerEpoch: time.Now().UTC(), ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol}}
	wrong := admission
	wrong.BootID = domain.NewID().String()
	if err := conn.Admit(wrong); !errors.Is(err, ErrNativeObservationConflict) {
		t.Fatal(err)
	}
	if err := conn.Admit(admission); err != nil {
		t.Fatal(err)
	}
	command, instance := domain.NewID().String(), domain.NewID().String()
	errs := make(chan error, 1)
	go func() {
		_, err := conn.RegisterOrigin(t.Context(), command, instance, "qwen-code", "test-native-generation")
		errs <- err
	}()
	request := <-requests
	// An opaque ID is not sufficient: reject a descriptor from another host.
	conn.OriginRegistered(transport.NativeOriginRegisteredPayload{RequestID: request.RequestID, Origin: &transport.NativeObservationOrigin{NativeAdmissionID: runner, NativeGeneration: "test-native-generation", ID: domain.NewID().String(), HostID: domain.NewID().String(), RunnerID: runner, BootID: boot, RunnerEpoch: admission.RunnerEpoch, CreatedAt: time.Now(), CommandID: command, InstanceID: instance, Runtime: "qwen-code"}})
	if err := <-errs; !errors.Is(err, ErrNativeObservationConflict) {
		t.Fatal("foreign origin admitted", err)
	}
	go func() {
		_, err := conn.RegisterOrigin(t.Context(), command, instance, "qwen-code", "test-native-generation")
		errs <- err
	}()
	<-requests
	conn.Close()
	conn.Close()
	select {
	case err := <-errs:
		if err == nil {
			t.Fatal("disconnect admitted origin")
		}
	case <-time.After(time.Second):
		t.Fatal("disconnect left activation waiting")
	}
	if err := conn.Admit(admission); err == nil {
		t.Fatal("old connection re-admitted")
	}
}

func TestNativeObservationConnectionRetainsOriginalOriginAcrossReconnect(t *testing.T) {
	host, boot, runner := domain.NewID().String(), domain.NewID().String(), domain.NewID().String()
	requests := make(chan transport.NativeOriginRegisterPayload, 1)
	conn := NewNativeObservationConnection("https://example.test", host, boot, func(_ context.Context, _ string, p any) error {
		requests <- p.(transport.NativeOriginRegisterPayload)
		return nil
	})
	epoch := time.Now().UTC()
	if err := conn.Admit(transport.HostSessionPayload{TenantID: host, AccountID: host, OwnershipScope: "personal", NativeAdmissionID: runner, HostID: host, BootID: boot, RunnerID: runner, RunnerEpoch: epoch, ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol}}); err != nil {
		t.Fatal(err)
	}
	command, instance := domain.NewID().String(), domain.NewID().String()
	done := make(chan error, 1)
	go func() {
		source := transport.HostSessionPayload{TenantID: host, AccountID: host, OwnershipScope: "personal", NativeAdmissionID: runner, HostID: host, RunnerID: runner, BootID: boot, RunnerEpoch: epoch.Add(-time.Minute)}
		origin, err := conn.RegisterOriginForSource(t.Context(), source, command, instance, "qwen-code", "test-native-generation")
		if err == nil && !origin.RunnerEpoch.Equal(epoch.Add(-time.Minute)) {
			err = errors.New("original native epoch replaced")
		}
		done <- err
	}()
	request := <-requests
	conn.OriginRegistered(transport.NativeOriginRegisteredPayload{RequestID: request.RequestID, Origin: &transport.NativeObservationOrigin{NativeAdmissionID: runner, NativeGeneration: "test-native-generation", ID: domain.NewID().String(), HostID: host, RunnerID: runner, BootID: boot, RunnerEpoch: epoch.Add(-time.Minute), CreatedAt: time.Now().Add(-time.Minute), CommandID: command, InstanceID: instance, Runtime: "qwen-code"}})
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestNativeObservationConnectionAdmissionFailuresHaveDistinctDisposition(t *testing.T) {
	for _, retryable := range []bool{false, true} {
		host, boot, runner := domain.NewID().String(), domain.NewID().String(), domain.NewID().String()
		requests := make(chan transport.NativeOriginRegisterPayload, 1)
		conn := NewNativeObservationConnection("https://example.test", host, boot, func(_ context.Context, _ string, p any) error {
			requests <- p.(transport.NativeOriginRegisterPayload)
			return nil
		})
		if err := conn.Admit(transport.HostSessionPayload{TenantID: host, AccountID: host, OwnershipScope: "personal", NativeAdmissionID: runner, HostID: host, BootID: boot, RunnerID: runner, RunnerEpoch: time.Now(), ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol}}); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := conn.RegisterOrigin(t.Context(), domain.NewID().String(), domain.NewID().String(), "qwen-code", "test-native-generation")
			done <- err
		}()
		request := <-requests
		conn.OriginRegistered(transport.NativeOriginRegisteredPayload{RequestID: request.RequestID, PublicError: "native_origin_unavailable", Retryable: retryable})
		expected := ErrNativeOriginAdmissionRejected
		if retryable {
			expected = ErrNativeOriginAdmissionDeferred
		}
		if err := <-done; !errors.Is(err, expected) {
			t.Fatal("temporary admission failure could end the command", retryable, err)
		}
	}
}

func TestNativeObservationSessionConfirmationRequiresLiveProofAndExactReceipt(t *testing.T) {
	for _, scenario := range []string{"exact", "journal_only", "stale_before_send", "wrong_generation", "replacement_after_commit", "retryable"} {
		t.Run(scenario, func(t *testing.T) {
			host, boot, runner := domain.NewID().String(), domain.NewID().String(), domain.NewID().String()
			epoch := time.Now().UTC()
			sent, verified := 0, 0
			var conn *NativeObservationConnection
			conn = NewNativeObservationConnection("https://example.test", host, boot, func(_ context.Context, typ string, p any) error {
				sent++
				request := p.(transport.NativeOriginSessionPayload)
				if typ != transport.MsgNativeOriginSession || request.RunnerID != runner || !request.RunnerEpoch.Equal(epoch) {
					t.Fatal("incorrect session confirmation")
				}
				reply := transport.NativeOriginSessionConfirmedPayload{RequestID: request.RequestID, OriginID: request.OriginID, NativeGeneration: request.NativeGeneration, SessionID: request.SessionID, RunnerID: runner, RunnerEpoch: epoch}
				if scenario == "wrong_generation" {
					reply.NativeGeneration = "replacement"
				}
				if scenario == "retryable" {
					reply.PublicError = "unavailable"
					reply.Retryable = true
				}
				conn.SessionConfirmed(reply)
				return nil
			})
			if err := conn.Admit(transport.HostSessionPayload{TenantID: host, AccountID: host, OwnershipScope: "personal", NativeAdmissionID: domain.NewID().String(), HostID: host, RunnerID: runner, RunnerEpoch: epoch, BootID: boot, ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol}}); err != nil {
				t.Fatal(err)
			}
			origin := transport.NativeObservationOrigin{ID: domain.NewID().String(), HostID: host, InstanceID: domain.NewID().String(), Runtime: "qwen-code", NativeGeneration: "actual-generation"}
			verify := func(context.Context) error {
				verified++
				if scenario == "stale_before_send" || (scenario == "replacement_after_commit" && verified == 2) {
					return ErrNativeOriginAdmissionRejected
				}
				return nil
			}
			if scenario == "journal_only" {
				verify = nil
			}
			err := conn.ConfirmSession(t.Context(), origin, "actual-session", verify)
			if scenario == "exact" {
				if err != nil || verified != 2 || sent != 1 {
					t.Fatal("live receipt not validated", err, verified, sent)
				}
				return
			}
			if err == nil {
				t.Fatal("nonlive or incorrect receipt renewed native authority")
			}
			if (scenario == "journal_only" || scenario == "stale_before_send") && sent != 0 {
				t.Fatal("journal-only liveness reached server")
			}
			if scenario == "retryable" && !errors.Is(err, ErrNativeOriginAdmissionDeferred) {
				t.Fatal("transient failure became permanent", err)
			}
		})
	}
}

func TestNativeObservationConnectionPinsAuthenticatedHostCredential(t *testing.T) {
	host, boot, runner := domain.NewID().String(), domain.NewID().String(), domain.NewID().String()
	credential := "00000000-0000-4000-8000-00000000abcd"
	admission := transport.HostSessionPayload{TenantID: host, AccountID: host, OwnershipScope: "personal", NativeAdmissionID: runner, HostID: host, HostCredentialID: credential, BootID: boot, RunnerID: runner, RunnerEpoch: time.Now().UTC(), ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol}}
	newConnection := func() *NativeObservationConnection {
		return NewNativeObservationConnection("https://example.test", host, boot, nil)
	}
	for _, invalid := range []string{"invalid", "0000000000004000800000000000abcd", "00000000-0000-4000-8000-00000000ABCD", "urn:uuid:" + credential} {
		wrong := admission
		wrong.HostCredentialID = invalid
		if err := newConnection().Admit(wrong); !errors.Is(err, ErrNativeObservationConflict) {
			t.Fatal("noncanonical credential admitted", invalid, err)
		}
	}
	conn := newConnection()
	if err := conn.Admit(admission); err != nil {
		t.Fatal(err)
	}
	if err := conn.Admit(admission); err != nil {
		t.Fatal("exact repeat rejected", err)
	}
	for _, mismatch := range []string{"", domain.NewID().String()} {
		wrong := admission
		wrong.HostCredentialID = mismatch
		if err := conn.Admit(wrong); !errors.Is(err, ErrNativeObservationConflict) {
			t.Fatal("credential pin changed on same connection", err)
		}
	}
	retained, err := conn.AuthenticatedNativeHostSession()
	if err != nil || retained.HostCredentialID != credential {
		t.Fatal("authenticated credential not retained", err)
	}
	retained.HostCredentialID = domain.NewID().String()
	retained.ProtocolFeatures[0] = "modified"
	retained, err = conn.AuthenticatedNativeHostSession()
	if err != nil || retained.HostCredentialID != credential || retained.ProtocolFeatures[0] != transport.NativeObservationReceiptProtocol {
		t.Fatal("accessor mutated authenticated authority", err)
	}
	conn.Close()
	if _, err := conn.AuthenticatedNativeHostSession(); !errors.Is(err, ErrNativeOriginAdmissionDeferred) {
		t.Fatal("closed connection retained credential authority", err)
	}
	admission.HostCredentialID = domain.NewID().String()
	reconnected := newConnection()
	if err := reconnected.Admit(admission); err != nil {
		t.Fatal("replacement credential rejected on new connection", err)
	}
	retained, err = reconnected.AuthenticatedNativeHostSession()
	if err != nil || retained.HostCredentialID != admission.HostCredentialID {
		t.Fatal("reconnect inherited previous credential", err)
	}
	admission.HostCredentialID = ""
	legacy := newConnection()
	if err := legacy.Admit(admission); err != nil {
		t.Fatal("older server lost native admission", err)
	}
	retained, err = legacy.AuthenticatedNativeHostSession()
	if err != nil || retained.HostCredentialID != "" {
		t.Fatal("older server manufactured credential pin", err)
	}
	admission.HostCredentialID = credential
	if err := legacy.Admit(admission); !errors.Is(err, ErrNativeObservationConflict) {
		t.Fatal("legacy connection upgraded credential pin", err)
	}
}
