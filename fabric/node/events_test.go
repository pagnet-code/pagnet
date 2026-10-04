package node

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/pagnet-code/pagnet/fabric"
)

type observerFixture struct {
	mu     sync.Mutex
	events []event.Event
	err    error
}

func (b *observerFixture) TryPublish(_ context.Context, e event.Event) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, e.Clone())
	return b.err
}

func TestNodeEventsAreMetadataOnlyAndObserverLossDoesNotFailOperation(t *testing.T) {
	s, envelope, _, _, dispatcher := setup(t)
	bus := &observerFixture{err: errors.New("observer's private credential failure")}
	s.config.Events, s.config.EventSource = bus, "pagnet://local/node/test"
	envelope.Operation = fabric.OperationDiscover
	envelope.Payload = json.RawMessage(`{"query":"secret-query-not-in-events","scope":{},"limit":10}`)
	result, err := execute(t, s, envelope)
	if err != nil || result.Discover == nil || s.EventLoss() != 2 || len(dispatcher.requests) != 0 {
		t.Fatal(result, err, s.EventLoss())
	}
	if len(bus.events) != 2 || bus.events[0].Type() != "dev.pagnet.discover.started" || bus.events[1].Type() != "dev.pagnet.discover.completed" {
		t.Fatal(bus.events)
	}
	for _, e := range bus.events {
		var data map[string]any
		if e.DataAs(&data) != nil || len(data) != 3 || data["invocationId"] != envelope.ID {
			t.Fatal("event carried application content", data)
		}
	}
}

func TestNodeStreamingObservationDoesNotDrainAndTerminatesOnce(t *testing.T) {
	s, envelope, _, store, _ := setup(t)
	bus := &observerFixture{}
	s.config.Events, s.config.EventSource = bus, "pagnet://local/node/test"
	envelope.Operation, envelope.Target = fabric.OperationInvoke, &store.endpoint.Ref
	envelope.Payload = json.RawMessage(`{"message":"secret-input"}`)
	result, err := execute(t, s, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if len(bus.events) != 1 {
		t.Fatal("invocation response was drained eagerly")
	}
	if _, err = result.Stream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(bus.events) != 1 {
		t.Fatal("start frame invented completion")
	}
	if _, err = result.Stream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = result.Stream.Close(); err != nil {
		t.Fatal(err)
	}
	if len(bus.events) != 2 || bus.events[1].Type() != "dev.pagnet.invoke.completed" || bus.events[1].Subject() != store.endpoint.Ref.String() {
		t.Fatal(bus.events)
	}
}

func TestUnauthenticatedRequestNeverPublishesCallerAssertedEvents(t *testing.T) {
	s, envelope, _, _, _ := setup(t)
	bus := &observerFixture{}
	s.config.Events, s.config.EventSource = bus, "pagnet://local/node/test"
	envelope.Operation = fabric.OperationDiscover
	envelope.Payload = json.RawMessage(`{"query":"x","scope":{},"limit":1}`)
	raw, _ := json.Marshal(envelope)
	if _, err := s.Execute(context.Background(), raw, "forged-peer"); err == nil {
		t.Fatal("forged authentication accepted")
	}
	if len(bus.events) != 0 {
		t.Fatal("forged caller published lifecycle event")
	}
}
