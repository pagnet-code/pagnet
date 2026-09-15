package daemon

// F8: a re-send of an already-processed command must re-ack the STORED result
// verbatim. Before the fix, the re-ack path sent an empty result, so a lost
// ack + server re-send of a crypto command yielded a zero-value result (an
// empty activate result looks like a failed self-test and reverts a
// successful activation; enrollment legs get a zero key-package/challenge).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/pagnet-code/pagnet/transport"
)

// newMemWS creates an in-memory websocket pair: the daemon writes to `client`,
// the test reads from `server`. A tiny httptest server performs the upgrade so
// both ends are real *websocket.Conn (no raw frame parsing in the test).
func newMemWS(t *testing.T) (*websocket.Conn, *websocket.Conn) {
	t.Helper()
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	serverCh := make(chan *websocket.Conn, 1)
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serverCh <- c
		<-done // keep the connection open until the test ends
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	u.Scheme = "ws"
	client, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("dial in-memory ws: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	select {
	case server := <-serverCh:
		return client, server
	case <-time.After(5 * time.Second):
		t.Fatal("in-memory ws server did not accept the connection")
		return nil, nil
	}
}

// readAck reads one command_ack envelope from the server side and returns its
// payload.
func readAck(t *testing.T, server *websocket.Conn) map[string]any {
	t.Helper()
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, raw, err := server.ReadMessage()
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	var env transport.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode ack envelope: %v", err)
	}
	if env.Type != transport.MsgCommandAck {
		t.Fatalf("ack type = %s, want %s", env.Type, transport.MsgCommandAck)
	}
	var payload map[string]any
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		t.Fatalf("decode ack payload: %v", err)
	}
	return payload
}

// TestReAck_EchoesStoredResult: a re-send of a processed crypto command
// re-acks the stored result verbatim (and does not re-run the handler).
func TestReAck_EchoesStoredResult(t *testing.T) {
	d := newTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	const commandID = "cmd-activate-1"
	result := &transport.CryptoActivateResult{
		HostPub:    transport.CryptoHostPublic{X25519: "x25519-pub", Ed25519: "ed25519-pub"},
		EpochID:    "epoch-1",
		SelfTestOK: true,
	}
	// First run: process the crypto command (persists the result + acks it).
	d.guardedResult(nil, commandID, func() (any, error) { return result, nil })
	ack1 := readAck(t, server)
	if ack1["commandId"] != commandID {
		t.Fatalf("first ack commandId = %v, want %s", ack1["commandId"], commandID)
	}
	res1, _ := ack1["result"].(map[string]any)
	if res1 == nil || res1["epochId"] != "epoch-1" || res1["selfTestOk"] != true {
		t.Fatalf("first ack result = %v, want the activate result", ack1["result"])
	}

	// Re-send the same command (the server re-sends after a lost ack). It must
	// NOT re-run the handler and must re-ack the SAME result.
	ran := 0
	d.enqueueCommand(nil, "inst-1", commandID, func() { ran++ })
	if ran != 0 {
		t.Fatalf("re-sent command re-ran the handler %d times, want 0", ran)
	}
	ack2 := readAck(t, server)
	if ack2["commandId"] != commandID {
		t.Fatalf("re-ack commandId = %v, want %s", ack2["commandId"], commandID)
	}
	res2, _ := ack2["result"].(map[string]any)
	if res2 == nil || res2["epochId"] != "epoch-1" || res2["selfTestOk"] != true {
		t.Fatalf("re-ack result = %v, want the stored result echoed verbatim", ack2["result"])
	}
}

// TestReAck_EmptyResultForNonCrypto: a re-send of a processed command that
// carried no result (non-crypto) re-acks with no result field (the plain
// empty ack), which is the correct behavior for a result-less command.
func TestReAck_EmptyResultForNonCrypto(t *testing.T) {
	d := newTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	const commandID = "cmd-plain-1"
	// First run: a non-crypto command (no result).
	d.guarded(nil, commandID, func() error { return nil })
	ack1 := readAck(t, server)
	if _, hasResult := ack1["result"]; hasResult {
		t.Fatalf("non-crypto first ack carried a result: %v", ack1["result"])
	}

	// Re-send: must re-ack with no result (not a zero-value crypto result).
	ran := 0
	d.enqueueCommand(nil, "inst-1", commandID, func() { ran++ })
	if ran != 0 {
		t.Fatalf("re-sent command re-ran the handler %d times, want 0", ran)
	}
	ack2 := readAck(t, server)
	if ack2["commandId"] != commandID {
		t.Fatalf("re-ack commandId = %v, want %s", ack2["commandId"], commandID)
	}
	if _, hasResult := ack2["result"]; hasResult {
		t.Fatalf("non-crypto re-ack carried a result: %v", ack2["result"])
	}
}
