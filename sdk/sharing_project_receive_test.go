package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func projectReceiveServer(t *testing.T, f *projectTransportFixture, inbox http.HandlerFunc) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/messages") {
			if r.URL.Query().Get("limit") != "50" {
				t.Error("receive did not request bounded inbox page")
			}
			inbox(w, r)
			return
		}
		f.serve(w, r)
	}))
	t.Cleanup(server.Close)
	for _, c := range f.clients {
		c.rest = newRestClient(server.URL, "test", func() string { return "pgn_epd_v1_test" })
	}
}

func projectReceiveWire(t *testing.T, f *projectTransportFixture) []byte {
	t.Helper()
	prepared, err := f.clients[0].PrepareSharingProjectMessage(f.project, f.clients[1].PrincipalID(), "ASK", []byte("receive payload"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return prepared.Wire
}

func TestReceiveSharingProjectMessagesPaginationAndReplyWire(t *testing.T) {
	f := newProjectTransportFixture(t)
	wire := projectReceiveWire(t, f)
	var cursors []string
	projectReceiveServer(t, f, func(w http.ResponseWriter, r *http.Request) {
		cursor := r.URL.Query().Get("cursor")
		cursors = append(cursors, cursor)
		if cursor == "" {
			w.Header().Set("X-Next-Cursor", "9")
			_ = json.NewEncoder(w).Encode([]json.RawMessage{wire})
		} else if cursor == "9" {
			w.Header().Set("X-Next-Cursor", "10")
			_ = json.NewEncoder(w).Encode([]json.RawMessage{wire})
		} else {
			_ = json.NewEncoder(w).Encode([]json.RawMessage{})
		}
	})
	calls := 0
	err := f.clients[1].ReceiveSharingProjectMessages(context.Background(), f.project, func(_ context.Context, message SharingProjectMessage) error {
		calls++
		if string(message.Plaintext) != "receive payload" || !bytes.Equal(message.Wire, wire) {
			t.Fatal("handler did not receive plaintext and exact authenticated wire")
		}
		if _, err := f.clients[1].PrepareSharingProjectMessage(f.project, f.clients[0].PrincipalID(), "REPLY", []byte("reply"), message.Wire); err != nil {
			t.Fatal(err)
		}
		return nil
	})
	if err != nil || calls != 2 || f.acks != 2 || strings.Join(cursors, ",") != ",9,10" {
		t.Fatalf("receive: %v, callbacks %d, acks %d, cursors %v", err, calls, f.acks, cursors)
	}
}

func TestReceiveSharingProjectMessagesFailuresLeavePending(t *testing.T) {
	for _, mode := range []string{"handler", "panic", "cancel", "session", "ack", "tampered"} {
		t.Run(mode, func(t *testing.T) {
			f := newProjectTransportFixture(t)
			wire := projectReceiveWire(t, f)
			if mode == "tampered" {
				var raw map[string]any
				_ = json.Unmarshal(wire, &raw)
				raw["ciphertext"] = "AAAA"
				wire, _ = json.Marshal(raw)
			}
			projectReceiveServer(t, f, func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode([]json.RawMessage{wire})
			})
			f.failACK = mode == "ack"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			err := f.clients[1].ReceiveSharingProjectMessages(ctx, f.project, func(context.Context, SharingProjectMessage) error {
				calls++
				switch mode {
				case "handler":
					return errors.New("handler failed")
				case "panic":
					panic("handler panic")
				case "cancel":
					cancel()
				case "session":
					f.clients[1].connGeneration.Add(1)
				}
				return nil
			})
			wantCalls, wantACKs := 1, 0
			if mode == "tampered" {
				wantCalls = 0
			}
			if mode == "ack" {
				wantACKs = 1
			}
			if err == nil || calls != wantCalls || f.acks != wantACKs {
				t.Fatalf("receive: %v, callbacks %d, acks %d", err, calls, f.acks)
			}
		})
	}
}

func TestReceiveSharingProjectMessagesRejectsInvalidPages(t *testing.T) {
	for _, mode := range []string{"oversized", "zero", "repeated", "backward", "empty"} {
		t.Run(mode, func(t *testing.T) {
			f := newProjectTransportFixture(t)
			wire := projectReceiveWire(t, f)
			projectReceiveServer(t, f, func(w http.ResponseWriter, r *http.Request) {
				page := []json.RawMessage{wire}
				next := "10"
				switch mode {
				case "oversized":
					page = make([]json.RawMessage, 51)
					for i := range page {
						page[i] = wire
					}
				case "zero":
					next = "0"
				case "backward":
					if r.URL.Query().Get("cursor") != "" {
						next = "9"
					}
				case "empty":
					page = nil
				}
				w.Header().Set("X-Next-Cursor", next)
				_ = json.NewEncoder(w).Encode(page)
			})
			calls := 0
			err := f.clients[1].ReceiveSharingProjectMessages(context.Background(), f.project, func(context.Context, SharingProjectMessage) error { calls++; return nil })
			want := 0
			if mode == "repeated" || mode == "backward" {
				want = 1
			}
			if err == nil || calls != want || f.acks != want {
				t.Fatalf("receive: %v, callbacks %d, acks %d", err, calls, f.acks)
			}
		})
	}
}

func TestReceiveSharingProjectMessagesReplyUsesLocalPredecessor(t *testing.T) {
	f := newProjectTransportFixture(t)
	ask := projectReceiveWire(t, f)
	reply, err := f.clients[1].PrepareSharingProjectMessage(f.project, f.clients[0].PrincipalID(), "REPLY", []byte("reply payload"), ask)
	if err != nil {
		t.Fatal(err)
	}
	projectReceiveServer(t, f, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]json.RawMessage{reply.Wire})
	})
	calls := 0
	err = f.clients[0].ReceiveSharingProjectMessages(context.Background(), f.project, func(_ context.Context, message SharingProjectMessage) error {
		calls++
		if string(message.Plaintext) != "reply payload" {
			t.Fatal("wrong reply payload")
		}
		return nil
	})
	if err != nil || calls != 1 || f.acks != 1 {
		t.Fatalf("receive reply: %v, callbacks %d, acks %d", err, calls, f.acks)
	}
}

func TestReceiveSharingProjectMessagesRequiresHandler(t *testing.T) {
	if err := new(Client).ReceiveSharingProjectMessages(context.Background(), "", nil); err == nil {
		t.Fatal("nil handler accepted")
	}
}

func TestReceiveSharingProjectMessagesRedeliversAfterHandlerFailure(t *testing.T) {
	f := newProjectTransportFixture(t)
	wire := projectReceiveWire(t, f)
	projectReceiveServer(t, f, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]json.RawMessage{wire})
	})
	calls := 0
	handler := func(context.Context, SharingProjectMessage) error {
		calls++
		if calls == 1 {
			return errors.New("retry processing")
		}
		return nil
	}
	if err := f.clients[1].ReceiveSharingProjectMessages(context.Background(), f.project, handler); err == nil || f.acks != 0 {
		t.Fatalf("failed handler acknowledged: %v, acks %d", err, f.acks)
	}
	if err := f.clients[1].ReceiveSharingProjectMessages(context.Background(), f.project, handler); err != nil || calls != 2 || f.acks != 1 {
		t.Fatalf("redelivery: %v, callbacks %d, acks %d", err, calls, f.acks)
	}
}

func TestReceiveSharingProjectMessagesSessionChangesBeforeHandler(t *testing.T) {
	f := newProjectTransportFixture(t)
	wire := projectReceiveWire(t, f)
	projectReceiveServer(t, f, func(w http.ResponseWriter, r *http.Request) {
		f.clients[1].connGeneration.Add(1)
		_ = json.NewEncoder(w).Encode([]json.RawMessage{wire})
	})
	err := f.clients[1].ReceiveSharingProjectMessages(context.Background(), f.project, func(context.Context, SharingProjectMessage) error {
		t.Fatal("stale session reached handler")
		return nil
	})
	if err == nil || f.acks != 0 {
		t.Fatalf("stale session accepted: %v, acks %d", err, f.acks)
	}
}
