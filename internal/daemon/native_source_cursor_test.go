package daemon

import (
	"context"
	"errors"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"testing"
)

func TestNativeDrainCursorBoundsScanAndRetainsFailedPage(t *testing.T) {
	c, o := deliveryFixture(t, func(context.Context, string, any) error { return errors.New("native transport down") })
	unsupported := o
	unsupported.Event.Type = session.EventPlanUpdated
	unsupported.SourceSequence = 0
	requests := 0
	call := func(_ context.Context, r sessionworker.Request) (sessionworker.Response, error) {
		if r.Type != "observations" {
			t.Fatal("unsupported source ACKed")
		}
		requests++
		if r.Cursor != int64((requests-1)*32) {
			t.Fatal("cursor skipped or restarted original rows")
		}
		rows := make([]sessionworker.NativeObservation, 32)
		for i := range rows {
			rows[i] = unsupported
		}
		if requests == 5 {
			rows[0] = o
		}
		return sessionworker.Response{Observations: rows, ObservationPage: &sessionworker.NativeObservationPage{After: r.Cursor, NextCursor: r.Cursor + 32, More: true}}, nil
	}
	next, err := c.DrainNativeWorkerSourcesPage(context.Background(), call, 0)
	if err != nil || requests != 4 || next != 128 {
		t.Fatal("bounded128-row cursor scan failed", requests, next, err)
	}
	next, err = c.DrainNativeWorkerSourcesPage(context.Background(), call, next)
	if err == nil || requests != 5 || next != 128 {
		t.Fatal("failed supported page advanced original cursor", requests, next, err)
	}
}
func TestNativeDrainRejectsInvalidCursorMetadata(t *testing.T) {
	c, o := deliveryFixture(t, nil)
	o.Event.Type = session.EventPlanUpdated
	for _, page := range []sessionworker.NativeObservationPage{{After: 99, NextCursor: 100, More: true}, {After: 0, NextCursor: 0, More: true}, {After: 0, NextCursor: -1}} {
		call := func(context.Context, sessionworker.Request) (sessionworker.Response, error) {
			return sessionworker.Response{Observations: []sessionworker.NativeObservation{o}, ObservationPage: &page}, nil
		}
		next, err := c.DrainNativeWorkerSourcesPage(context.Background(), call, 0)
		if !errors.Is(err, ErrNativeObservationConflict) || next != 0 {
			t.Fatal("untrusted cursor metadata accepted", next, err)
		}
	}
}
