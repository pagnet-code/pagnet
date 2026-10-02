package daemon

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func TestNativeConnectionWriterDoesNotMoveOriginalSourceToReplacement(t *testing.T) {
	peers := make(chan *websocket.Conn, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err == nil {
			peers <- conn
		}
	}))
	defer server.Close()
	dial := func() (*websocket.Conn, *websocket.Conn) {
		client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
		if err != nil {
			t.Fatal(err)
		}
		peer := <-peers
		t.Cleanup(func() { client.Close(); peer.Close() })
		return client, peer
	}
	a, peerA := dial()
	b, peerB := dial()
	d := &Daemon{Config: Config{ServerURL: "https://example.test", HostID: domain.NewID().String()}, writeTimeout: time.Second}
	c := d.nativeConnection(a)
	defer c.Close()
	d.curConn = b // B already replaced A; provenance must still use A.
	if err := c.send(t.Context(), "original-source", struct{}{}); err != nil {
		t.Fatal(err)
	}
	peerA.SetReadDeadline(time.Now().Add(time.Second))
	var got transport.Envelope
	if err := peerA.ReadJSON(&got); err != nil || got.Type != "original-source" {
		t.Fatal("original source moved to B", got.Type, err)
	}
	a.Close()
	if err := c.send(t.Context(), "lost-original-source", struct{}{}); err == nil {
		t.Fatal("closed A silently selected B")
	}
	if d.curConn != b {
		t.Fatal("A write failure invalidated B")
	}
	if err := d.send(b, "replacement-marker", struct{}{}); err != nil {
		t.Fatal(err)
	}
	peerB.SetReadDeadline(time.Now().Add(time.Second))
	if err := peerB.ReadJSON(&got); err != nil || got.Type != "replacement-marker" {
		t.Fatal("B received an A source", got.Type, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := c.send(ctx, "cancelled", struct{}{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestNativeConnectionReadLoopRejectsForeignAndMalformedAdmission(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		c := NewNativeObservationConnection("https://example.test", domain.NewID().String(), "boot", nil)
		var payload any = transport.HostSessionPayload{HostID: domain.NewID().String(), BootID: "boot"}
		if malformed {
			payload = "invalid-admission"
		}
		env, err := transport.NewEnvelope(transport.MsgHostSession, payload)
		if err != nil {
			t.Fatal(err)
		}
		if handled, err := c.HandleEnvelope(env); !handled || err == nil {
			t.Fatal("invalid authenticated scope accepted")
		}
		select {
		case <-c.closed:
		default:
			t.Fatal("invalid lane stayed open")
		}
		if _, err := c.AuthenticatedNativeHostSession(); err == nil {
			t.Fatal("closed admission exposed")
		}
	}
	c := NewNativeObservationConnection("https://example.test", domain.NewID().String(), "boot", nil)
	defer c.Close()
	env, _ := transport.NewEnvelope(transport.MsgNativeContentRejected, transport.NativeContentStagedPayload{})
	if _, err := c.HandleEnvelope(env); err == nil {
		t.Fatal("rejection treated as staged success")
	}
}
