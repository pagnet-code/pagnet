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
	admission := transport.HostSessionPayload{HostID: host, BootID: boot, RunnerID: runner, RunnerEpoch: time.Now().UTC(), ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol}}
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
	go func() { _, err := conn.RegisterOrigin(t.Context(), command, instance, "qwen-code"); errs <- err }()
	request := <-requests
	// An opaque ID is not sufficient: reject a descriptor from another host.
	conn.OriginRegistered(transport.NativeOriginRegisteredPayload{RequestID: request.RequestID, Origin: &transport.NativeObservationOrigin{ID: domain.NewID().String(), HostID: domain.NewID().String(), RunnerID: runner, BootID: boot, RunnerEpoch: admission.RunnerEpoch, CreatedAt: time.Now(), CommandID: command, InstanceID: instance, Runtime: "qwen-code"}})
	if err := <-errs; !errors.Is(err, ErrNativeObservationConflict) {
		t.Fatal("foreign origin admitted", err)
	}
	go func() { _, err := conn.RegisterOrigin(t.Context(), command, instance, "qwen-code"); errs <- err }()
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
	if err := conn.Admit(transport.HostSessionPayload{HostID: host, BootID: boot, RunnerID: runner, RunnerEpoch: epoch, ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol}}); err != nil {
		t.Fatal(err)
	}
	command, instance := domain.NewID().String(), domain.NewID().String()
	done := make(chan error, 1)
	go func() {
		origin, err := conn.RegisterOrigin(t.Context(), command, instance, "qwen-code")
		if err == nil && !origin.RunnerEpoch.Equal(epoch.Add(-time.Minute)) {
			err = errors.New("original native epoch replaced")
		}
		done <- err
	}()
	request := <-requests
	conn.OriginRegistered(transport.NativeOriginRegisteredPayload{RequestID: request.RequestID, Origin: &transport.NativeObservationOrigin{ID: domain.NewID().String(), HostID: host, RunnerID: runner, BootID: boot, RunnerEpoch: epoch.Add(-time.Minute), CreatedAt: time.Now().Add(-time.Minute), CommandID: command, InstanceID: instance, Runtime: "qwen-code"}})
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
		if err := conn.Admit(transport.HostSessionPayload{HostID: host, BootID: boot, RunnerID: runner, RunnerEpoch: time.Now(), ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol}}); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := conn.RegisterOrigin(t.Context(), domain.NewID().String(), domain.NewID().String(), "qwen-code")
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
