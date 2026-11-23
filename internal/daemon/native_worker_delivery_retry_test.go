package daemon

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func TestNativeWorkerObservationRetryPinsOriginPayloadAndDeadline(t *testing.T) {
	type sentObservation struct {
		payload  transport.NativeObservationPayload
		deadline time.Time
	}
	sent := make(chan sentObservation, 4)
	c, observation := deliveryFixture(t, func(ctx context.Context, typ string, value any) error {
		deadline, _ := ctx.Deadline()
		sent <- sentObservation{payload: value.(transport.NativeObservationPayload), deadline: deadline}
		return nil
	})
	defer c.Close()
	first, err := NativeWorkerWireObservation(observation)
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.ObservationID = domain.NewID().String()
	second.OriginID = domain.NewID().String()
	firstDone, secondDone := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := c.deliverWorkerObservation(t.Context(), first)
		firstDone <- err
	}()
	go func() {
		_, err := c.deliverWorkerObservation(t.Context(), second)
		secondDone <- err
	}()
	initial := map[string]sentObservation{}
	for range 2 {
		select {
		case p := <-sent:
			initial[p.payload.ObservationID] = p
		case <-time.After(time.Second):
			t.Fatal("initial observation did not reach server")
		}
	}
	c.retryNativeWorkerObservations(first.OriginID)
	select {
	case replay := <-sent:
		if !reflect.DeepEqual(replay, initial[first.ObservationID]) {
			t.Fatal("retry changed origin, payload or original deadline")
		}
	case <-time.After(time.Second):
		t.Fatal("fresh confirmation did not wake pending source")
	}
	select {
	case <-sent:
		t.Fatal("confirmation retried an unrelated origin")
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case <-firstDone:
		t.Fatal("retry wake acted as a receipt")
	default:
	}
	c.NativeWorkerObservationDisposition(transport.MsgNativeObservationReceipt, transport.NativeObservationReceiptPayload{ObservationID: first.ObservationID, OriginID: first.OriginID, Digest: first.Digest, Disposition: "committed"})
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("matching receipt did not finish delivery")
	}
	c.Close()
	select {
	case err := <-secondDone:
		if !errors.Is(err, ErrNativeOriginAdmissionDeferred) {
			t.Fatal("disconnect did not cancel pending source", err)
		}
	case <-time.After(time.Second):
		t.Fatal("disconnect did not finish delivery")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pendingObservations) != 0 || len(c.pendingObservationRetries) != 0 {
		t.Fatal("completion or disconnect leaked a pending retry")
	}
}

func TestNativeWorkerObservationRetryTimeoutRemovesWaiter(t *testing.T) {
	sent := make(chan struct{}, 2)
	c, observation := deliveryFixture(t, func(context.Context, string, any) error {
		sent <- struct{}{}
		return nil
	})
	defer c.Close()
	payload, err := NativeWorkerWireObservation(observation)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := c.deliverWorkerObservation(ctx, payload)
		done <- err
	}()
	waitForSend := func() {
		t.Helper()
		select {
		case <-sent:
		case err := <-done:
			t.Fatal("delivery finished before expected send", err)
		case <-time.After(2 * time.Second):
			t.Fatal("delivery did not send observation")
		}
	}
	waitForSend()
	c.retryNativeWorkerObservations(payload.OriginID)
	waitForSend()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("retry extended the original receipt wait", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retry extended the original receipt wait")
	}
	c.retryNativeWorkerObservations(payload.OriginID)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pendingObservations) != 0 || len(c.pendingObservationRetries) != 0 {
		t.Fatal("timeout leaked a pending retry")
	}
}
