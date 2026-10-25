package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/sdk"
	"github.com/pagnet-code/pagnet/transport"
)

type ownerOperationFixture struct {
	*ownerMailboxFixture
	keys    e2ee.OwnerMailboxKeys
	results chan transport.OwnerMailboxResultPayload
	worker  *sharingOutboundWorker
}

func newOwnerOperationFixture(t *testing.T) *ownerOperationFixture {
	t.Helper()
	f := &ownerOperationFixture{ownerMailboxFixture: newOwnerMailboxFixture(t), results: make(chan transport.OwnerMailboxResultPayload, 10)}
	m, err := openSharingMailbox(t.TempDir()+"/mailbox", f.d.sharingBridges.active[f.descriptor.InstallationID].binding)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.db.Close() })
	f.worker = newSharingOutboundWorker(m)
	f.d.sharingBridges.outbound = map[string]*sharingOutboundWorker{f.descriptor.InstallationID: f.worker}
	send := f.c.send
	f.c.send = func(typ string, payload any) error {
		if typ == transport.MsgOwnerMailboxResult {
			f.results <- payload.(transport.OwnerMailboxResultPayload)
			return nil
		}
		return send(typ, payload)
	}
	f.open(t, f.descriptor)
	f.keys, err = e2ee.VerifyOwnerMailboxBootstrap(f.ready[0].Descriptor, f.ready[0].Bootstrap, f.browser)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *ownerOperationFixture) frame(t *testing.T, seq uint64, r ownerMailboxRequest) transport.OwnerMailboxOperationPayload {
	t.Helper()
	plain, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := e2ee.SealOwnerMailboxFrame(f.descriptor, f.keys.ClientToHost[:], e2ee.OwnerMailboxClientToHost, seq, plain)
	if err != nil {
		t.Fatal(err)
	}
	return transport.OwnerMailboxOperationPayload{Protocol: transport.OwnerMailboxProtocolV1, SessionID: f.descriptor.SessionID, RequestID: r.RequestID, Sequence: seq, Ciphertext: ct}
}
func (f *ownerOperationFixture) deliver(t *testing.T, p transport.OwnerMailboxOperationPayload) {
	t.Helper()
	env, err := transport.NewEnvelope(transport.MsgOwnerMailboxOperation, p)
	if err != nil {
		t.Fatal(err)
	}
	f.c.handle(env, 1024)
}
func (f *ownerOperationFixture) response(t *testing.T, seq uint64) ownerMailboxResponse {
	t.Helper()
	select {
	case p := <-f.results:
		if p.Sequence != seq {
			t.Fatal("wrong host sequence")
		}
		raw, err := e2ee.OpenOwnerMailboxFrame(f.descriptor, f.keys.HostToClient[:], e2ee.OwnerMailboxHostToClient, p.Sequence, p.Ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) > e2ee.OwnerMailboxMaxPlaintext {
			t.Fatal("oversize response")
		}
		var response ownerMailboxResponse
		if err = json.Unmarshal(raw, &response); err != nil {
			t.Fatal(err)
		}
		if response.RequestID != p.RequestID || response.Version != 1 {
			t.Fatal("response correlation mismatch")
		}
		// Synchronize with the send completion under the socket lock.
		f.c.mu.Lock()
		f.c.mu.Unlock()
		return response
	case <-time.After(5 * time.Second):
		t.Fatal("no result")
		return ownerMailboxResponse{}
	}
}
func (f *ownerOperationFixture) assertErased(t *testing.T, s *ownerMailboxSession) {
	t.Helper()
	f.c.mu.Lock()
	defer f.c.mu.Unlock()
	if len(f.c.sessions) != 0 || s.keys != (e2ee.OwnerMailboxKeys{}) {
		t.Fatal("invalid operation retained keys")
	}
}
func TestOwnerMailboxOperationRejectsInvalidFrames(t *testing.T) {
	for _, name := range []string{"sequence", "request", "ciphertext", "oversize", "revoked", "authority", "version", "wire"} {
		t.Run(name, func(t *testing.T) {
			f := newOwnerOperationFixture(t)
			s := f.c.sessions[f.descriptor.SessionID]
			r := ownerMailboxRequest{Version: 1, RequestID: "request", Action: "inbox"}
			if name == "version" {
				r.Version = 2
			}
			p := f.frame(t, 0, r)
			switch name {
			case "sequence":
				p.Sequence = 1
			case "request":
				p.RequestID = "other"
			case "ciphertext":
				p.Ciphertext[0] ^= 1
			case "oversize":
				p.Ciphertext = make([]byte, e2ee.OwnerMailboxMaxPlaintext+17)
			case "revoked":
				f.d.sharingBridges.disconnect()
			case "authority":
				f.p.NativeAdmissionID = "other"
				f.c.native.mu.Lock()
				f.c.native.session = &f.p
				f.c.native.mu.Unlock()
			}
			if name == "wire" {
				env, _ := transport.NewEnvelope(transport.MsgOwnerMailboxOperation, p)
				f.c.handle(env, transport.OwnerMailboxMaxWireBytes+1)
			} else {
				f.deliver(t, p)
			}
			f.assertErased(t, s)
		})
	}
}
func TestOwnerMailboxDuplicateSequenceAndSendIdempotence(t *testing.T) {
	f := newOwnerOperationFixture(t)
	in := outboundInput()
	r := ownerMailboxRequest{Version: 1, RequestID: "send", Action: "send", OperationID: in.OperationID, GrantID: in.GrantID, ExpectedGeneration: 1, Text: in.Text}
	p := f.frame(t, 0, r)
	f.deliver(t, p)
	first := f.response(t, 0)
	if first.Code != "ok" {
		t.Fatal(first.Code)
	}
	r.RequestID = "repeat"
	f.deliver(t, f.frame(t, 1, r))
	second := f.response(t, 1)
	a, _ := json.Marshal(first.Data)
	b, _ := json.Marshal(second.Data)
	if !bytes.Equal(a, b) {
		t.Fatal("duplicate intent changed durable record")
	}
	for i, action := range []string{"status", "retry"} {
		r.Action = action
		r.RequestID = action
		f.deliver(t, f.frame(t, uint64(i+2), r))
		response := f.response(t, uint64(i+2))
		data, _ := json.Marshal(response.Data)
		if response.Code != "ok" || !bytes.Equal(a, data) {
			t.Fatalf("%s changed journal status", action)
		}
	}
	var count int
	if err := f.worker.mailbox.db.QueryRow("SELECT count(*) FROM outbound").Scan(&count); err != nil || count != 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	s := f.c.sessions[f.descriptor.SessionID]
	f.deliver(t, p)
	f.assertErased(t, s)
}
func TestOwnerMailboxPaginatedReadAndInbox(t *testing.T) {
	f := newOwnerOperationFixture(t)
	_, _, _, record := mailboxFixture(t)
	record.Message.RecipientPrincipalID = f.descriptor.ServiceID
	record.Text = strings.Repeat("\x00\"界", 25000)
	if err := f.worker.mailbox.put(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		next := record
		next.Message.ID = record.Message.ID + string(rune('a'+i))
		if err := f.worker.mailbox.put(context.Background(), next); err != nil {
			t.Fatal(err)
		}
	}
	var all strings.Builder
	seq := uint64(0)
	for offset := 0; offset < len(record.Text); seq++ {
		r := ownerMailboxRequest{Version: 1, RequestID: "read", Action: "read", GrantID: record.Message.GrantID, ExpectedGeneration: 1, MessageID: record.Message.ID, Offset: offset}
		f.deliver(t, f.frame(t, seq, r))
		response := f.response(t, seq)
		if response.Code != "ok" {
			t.Fatal(response.Code)
		}
		data := response.Data.(map[string]any)
		chunk := data["text"].(string)
		if !utf8.ValidString(chunk) || chunk == "" {
			t.Fatal("invalid chunk")
		}
		all.WriteString(chunk)
		offset = int(data["nextOffset"].(float64))
	}
	if all.String() != record.Text {
		t.Fatal("chunked read hid message content")
	}
	cursor := ""
	seen := map[string]bool{}
	for page := 0; page < 4; page++ {
		r := ownerMailboxRequest{Version: 1, RequestID: "inbox", Action: "inbox", Cursor: cursor, Limit: 1}
		f.deliver(t, f.frame(t, seq, r))
		response := f.response(t, seq)
		seq++
		data := response.Data.(map[string]any)
		items := data["items"].([]any)
		if len(items) != 1 {
			t.Fatal("incorrect page size")
		}
		id := items[0].(map[string]any)["messageId"].(string)
		if seen[id] {
			t.Fatal("cursor duplicated existing entry")
		}
		seen[id] = true
		if page == 0 {
			next := record
			next.Message.ID = "arrival-before-existing-sort-order"
			if err := f.worker.mailbox.put(context.Background(), next); err != nil {
				t.Fatal(err)
			}
		}
		if page == 3 {
			if data["nextCursor"] != nil {
				t.Fatal("missing end cursor")
			}
		} else {
			cursor = data["nextCursor"].(string)
		}
	}
	if len(seen) != 4 || !seen[record.Message.ID] || !seen[record.Message.ID+"a"] || !seen[record.Message.ID+"b"] {
		t.Fatal("arrival skipped existing entries")
	}

}
func TestOwnerMailboxResultSendFailureAndClosedSocket(t *testing.T) {
	for _, closed := range []bool{false, true} {
		t.Run(map[bool]string{false: "send", true: "socket"}[closed], func(t *testing.T) {
			f := newOwnerOperationFixture(t)
			s := f.c.sessions[f.descriptor.SessionID]
			if closed {
				f.c.native.Close()
			} else {
				f.c.send = func(string, any) error { return errors.New("private error") }
				f.deliver(t, f.frame(t, 0, ownerMailboxRequest{Version: 1, RequestID: "request", Action: "inbox"}))
			}
			select {
			case <-s.ctx.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("session not canceled")
			}
			f.assertErased(t, s)
		})
	}
}

type ownerPairsEndpoint struct {
	*bridgeTestEndpoint
	list func(context.Context, string) ([]sdk.SharingPairStatus, string, error)
}

func (e *ownerPairsEndpoint) ListSharingPairs(ctx context.Context, cursor string) ([]sdk.SharingPairStatus, string, error) {
	return e.list(ctx, cursor)
}
func (f *ownerOperationFixture) setPairsEndpoint(fn func(context.Context, string) ([]sdk.SharingPairStatus, string, error)) *ownerPairsEndpoint {
	ep := &ownerPairsEndpoint{&bridgeTestEndpoint{done: make(chan struct{})}, fn}
	f.d.sharingBridges.mu.Lock()
	a := f.d.sharingBridges.active[f.descriptor.InstallationID]
	a.endpoint = ep
	f.d.sharingBridges.active[f.descriptor.InstallationID] = a
	f.d.sharingBridges.mu.Unlock()
	return ep
}
func TestOwnerMailboxOneOutstandingAndRetirement(t *testing.T) {
	for _, retired := range []bool{false, true} {
		t.Run(map[bool]string{false: "outstanding", true: "retired"}[retired], func(t *testing.T) {
			f := newOwnerOperationFixture(t)
			started := make(chan time.Duration, 1)
			ep := f.setPairsEndpoint(func(ctx context.Context, _ string) ([]sdk.SharingPairStatus, string, error) {
				deadline, _ := ctx.Deadline()
				started <- time.Until(deadline)
				<-ctx.Done()
				return nil, "", ctx.Err()
			})
			r := ownerMailboxRequest{Version: 1, RequestID: "pairs", Action: "pairs"}
			s := f.c.sessions[f.descriptor.SessionID]
			f.deliver(t, f.frame(t, 0, r))
			select {
			case timeout := <-started:
				if timeout <= 0 || timeout > 30*time.Second {
					t.Fatal("unbounded operation")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("operation not started")
			}
			if retired {
				close(ep.done)
			} else {
				r.RequestID = "second"
				f.deliver(t, f.frame(t, 1, r))
			}
			select {
			case <-s.ctx.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("operation not canceled")
			}
			f.assertErased(t, s)
			select {
			case <-f.results:
				t.Fatal("closed session sent result")
			default:
			}
		})
	}
}
func TestOwnerMailboxSanitizedResultsAndSizeCap(t *testing.T) {
	f := newOwnerOperationFixture(t)
	f.setPairsEndpoint(func(context.Context, string) ([]sdk.SharingPairStatus, string, error) {
		return []sdk.SharingPairStatus{{GrantID: "grant", Generation: 1, State: "active", InvitationID: "private-invitation", Limits: sdk.SharingPairLimits{}}}, "next", nil
	})
	r := ownerMailboxRequest{Version: 1, RequestID: "pairs", Action: "pairs"}
	f.deliver(t, f.frame(t, 0, r))
	response := f.response(t, 0)
	raw, _ := json.Marshal(response)
	if response.Code != "ok" || bytes.Contains(raw, []byte("private-invitation")) {
		t.Fatal("pairs response exposed unrelated SDK fields")
	}
	f.setPairsEndpoint(func(context.Context, string) ([]sdk.SharingPairStatus, string, error) {
		return []sdk.SharingPairStatus{{GrantID: strings.Repeat("x", e2ee.OwnerMailboxMaxPlaintext)}}, "", nil
	})
	f.deliver(t, f.frame(t, 1, r))
	if response = f.response(t, 1); response.Code != "response_too_large" {
		t.Fatal("oversize result not bounded")
	}
	r.Action = "unsupported"
	r.Text = strings.Repeat("x", e2ee.OwnerMailboxMaxPlaintext-1000)
	f.deliver(t, f.frame(t, 2, r))
	if response = f.response(t, 2); response.Code != "operation_failed" {
		t.Fatal("large valid frame was not processed")
	}
}
