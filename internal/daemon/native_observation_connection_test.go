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
	conn := NewNativeObservationConnection(host, boot, func(_ context.Context, typ string, p any) error {
		if typ != transport.MsgNativeOriginRegister {
			t.Fatal(typ)
		}
		requests <- p.(transport.NativeOriginRegisterPayload)
		return nil
	})
	admission := transport.HostSessionPayload{NativeAdmissionID: runner, HostID: host, BootID: boot, RunnerID: runner, RunnerEpoch: time.Now().UTC(), ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol}}
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
	conn := NewNativeObservationConnection(host, boot, func(_ context.Context, _ string, p any) error {
		requests <- p.(transport.NativeOriginRegisterPayload)
		return nil
	})
	epoch := time.Now().UTC()
	if err := conn.Admit(transport.HostSessionPayload{NativeAdmissionID: runner, HostID: host, BootID: boot, RunnerID: runner, RunnerEpoch: epoch, ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol}}); err != nil {
		t.Fatal(err)
	}
	command, instance := domain.NewID().String(), domain.NewID().String()
	done := make(chan error, 1)
	go func() {
		source := transport.HostSessionPayload{NativeAdmissionID: runner, HostID: host, RunnerID: runner, BootID: boot, RunnerEpoch: epoch.Add(-time.Minute)}
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
		conn := NewNativeObservationConnection(host, boot, func(_ context.Context, _ string, p any) error {
			requests <- p.(transport.NativeOriginRegisterPayload)
			return nil
		})
		if err := conn.Admit(transport.HostSessionPayload{NativeAdmissionID: runner, HostID: host, BootID: boot, RunnerID: runner, RunnerEpoch: time.Now(), ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol}}); err != nil {
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
			conn = NewNativeObservationConnection(host, boot, func(_ context.Context, typ string, p any) error {
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
			if err := conn.Admit(transport.HostSessionPayload{NativeAdmissionID: domain.NewID().String(), HostID: host, RunnerID: runner, RunnerEpoch: epoch, BootID: boot, ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol}}); err != nil {
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
