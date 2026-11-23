package daemon

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/transport"
)

func TestHostFrameReadLimit(t *testing.T) {
	for _, oversize := range []bool{false, true} {
		t.Run(map[bool]string{false: "at limit", true: "over limit"}[oversize], func(t *testing.T) {
			size := transport.NativeContentMaxPageWireBytes
			if oversize {
				size++
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer conn.Close()
				if conn.WriteMessage(websocket.TextMessage, bytes.Repeat([]byte("x"), size)) != nil {
					return
				}
				_, _, _ = conn.ReadMessage()
			}))
			defer server.Close()
			conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			raw, err := readHostFrame(conn)
			if oversize {
				if err == nil {
					t.Fatal("oversized host frame accepted")
				}
			} else if err != nil || len(raw) != size {
				t.Fatal("bounded host frame rejected")
			}
		})
	}
}
