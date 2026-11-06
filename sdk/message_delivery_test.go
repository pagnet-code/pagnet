package sdk

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

func messageDeliveryFixture(t *testing.T, fs *fakeServer, network, recipient string) (string, transport.Envelope) {
	t.Helper()
	id := domain.NewID().String()
	aad := fs.buildAAD(network, e2ee.ObjectTypeMessage, id, "sender", recipient)
	encrypted, err := e2ee.Encrypt([]byte("durable message"), fs.epochKey, aad)
	if err != nil {
		t.Fatal(err)
	}
	env, err := transport.NewEnvelope(transport.MsgEndpointMessageDeliver, transport.EndpointMessageDeliverPayload{
		MessageID: id, NetworkID: network, Kind: "ASK", Envelope: &encrypted, AAD: &aad,
	})
	if err != nil {
		t.Fatal(err)
	}
	fs.mu.Lock()
	fs.messages[id] = &fakeMessage{id: id}
	fs.mu.Unlock()
	return id, env
}

func TestMessageDeliveryWithoutHandlerRemainsRetryable(t *testing.T) {
	for _, reconnect := range []bool{false, true} {
		name := "registration"
		if reconnect {
			name = "reconnect"
		}
		t.Run(name, func(t *testing.T) {
			fs := newFakeServer(t)
			network := fs.createNetwork("messages", true)
			recipient, credential := fs.createPrincipal("agent", "recipient", network)
			stateDir := t.TempDir()
			c := mustConnect(t, fs, credential, stateDir)
			waitForCryptoReady(t, fs, recipient)
			id, env := messageDeliveryFixture(t, fs, network, recipient)

			c.handleMessageDeliver(env)
			// The server processes frames in order. A heartbeat after dispatch
			// proves any ACK sent by that dispatch has also been processed.
			before := fs.heartbeatCount()
			if err := c.send(transport.MsgEndpointHeartbeat, transport.EndpointHeartbeatPayload{}); err != nil {
				t.Fatal(err)
			}
			waitFor(t, 5*time.Second, "heartbeat after unhandled message", func() bool { return fs.heartbeatCount() > before })
			if fs.messageAcked(id) || c.seenDeliveries.Contains(id) {
				t.Fatal("message without a handler was acknowledged or marked seen")
			}
			c.delivMu.Lock()
			_, inflight := c.inflightDeliveries[id]
			c.delivMu.Unlock()
			if inflight {
				t.Fatal("message without a handler blocks retry")
			}

			if reconnect {
				if err := c.Close(); err != nil {
					t.Fatal(err)
				}
				c = mustConnect(t, fs, credential, stateDir)
				waitForCryptoReady(t, fs, recipient)
			}
			var calls atomic.Int32
			c.Agent("recipient").OnMessage(func(_ context.Context, m *Message) error {
				calls.Add(1)
				if m.TextBody() != "durable message" {
					t.Errorf("retry received %q", m.TextBody())
				}
				return nil
			})
			c.handleMessageDeliver(env)
			waitFor(t, 5*time.Second, "retried message ACK", func() bool { return fs.messageAcked(id) })
			c.handleMessageDeliver(env)
			if calls.Load() != 1 {
				t.Fatalf("handler calls = %d, want 1", calls.Load())
			}
		})
	}
}

func TestMessageDeliveryHandlerFailureStillAcknowledges(t *testing.T) {
	for _, failure := range []string{"error", "panic"} {
		t.Run(failure, func(t *testing.T) {
			fs := newFakeServer(t)
			network := fs.createNetwork("messages", true)
			recipient, credential := fs.createPrincipal("agent", "recipient", network)
			c := mustConnect(t, fs, credential, t.TempDir())
			waitForCryptoReady(t, fs, recipient)
			id, env := messageDeliveryFixture(t, fs, network, recipient)
			calls := 0
			c.Agent("recipient").OnMessage(func(context.Context, *Message) error {
				calls++
				if failure == "panic" {
					panic("handler failure")
				}
				return errors.New("handler failure")
			})
			c.handleMessageDeliver(env)
			waitFor(t, 5*time.Second, "failed handler message ACK", func() bool { return fs.messageAcked(id) })
			c.handleMessageDeliver(env)
			if calls != 1 || !c.seenDeliveries.Contains(id) {
				t.Fatalf("failed handler retry: calls=%d seen=%v", calls, c.seenDeliveries.Contains(id))
			}
		})
	}
}

func TestDurableMessageHandlerFailureRemainsRetryable(t *testing.T) {
	fs := newFakeServer(t)
	network := fs.createNetwork("messages", true)
	recipient, credential := fs.createPrincipal("agent", "recipient", network)
	stateDir := t.TempDir()
	calls := 0
	var handlerErr error = errors.New("storage unavailable")
	c, err := Connect(context.Background(), Config{
		Server: fs.URL(), Credential: credential, StateDir: stateDir,
		RetryMessageHandlerErrors: true,
		MessageHandler:            func(context.Context, *Message) error { calls++; return handlerErr },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	waitForCryptoReady(t, fs, recipient)
	id, env := messageDeliveryFixture(t, fs, network, recipient)
	c.handleMessageDeliver(env)
	if calls != 1 || fs.messageAcked(id) || c.seenDeliveries.Contains(id) {
		t.Fatalf("failed durable admission: calls=%d acked=%v seen=%v", calls, fs.messageAcked(id), c.seenDeliveries.Contains(id))
	}
	handlerErr = nil
	c.handleMessageDeliver(env)
	waitFor(t, 5*time.Second, "durable message ACK", func() bool { return fs.messageAcked(id) })
	if calls != 2 {
		t.Fatalf("retry calls = %d, want 2", calls)
	}
}
