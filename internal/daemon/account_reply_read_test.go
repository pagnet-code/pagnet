package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/accountmessage"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/nativecontent"
	"github.com/pagnet-code/pagnet/transport"
)

func accountReplyReadFixture(t *testing.T, plain []byte) (readinessFixture, transport.BrowserAccountReplyReadBeginPayload, nativecontent.Transfer) {
	t.Helper()
	f, _, r := accountSealFixture(t)
	f.c.d.AccountReplyReadEnabled = true
	f.c.native.mu.Lock()
	f.c.native.session.ProtocolFeatures = append(f.c.native.session.ProtocolFeatures, transport.BrowserAccountReplyReadProtocol)
	f.c.native.mu.Unlock()
	d := accountmessage.Descriptor(r.Descriptor)
	s := transport.NativeAccountMessageSource{V: 1, MessageID: d.MessageID, BindingDigest: d.BindingDigest(), SealedDigest: strings.Repeat("a", 64), Descriptor: d, InputAAD: r.Descriptor.AAD(d.BindingDigest())}
	p := transport.NativeDispatchProof{AccountMessageSource: &s, SourceBootID: domain.NewID().String(), OwnershipID: domain.NewID().String(), OwnershipGeneration: "1", DispatchSequence: 1, SourceCommandID: domain.NewID().String(), SourceAdmissionID: domain.NewID().String(), SourceRunnerID: d.RunnerID, SourceRunnerEpoch: f.session.RunnerEpoch}
	reply := domain.NewID().String()
	a := e2ee.AAD{ProtocolVersion: 2, TenantID: d.TenantID, NetworkID: d.NetworkID, ObjectType: e2ee.ObjectTypeBrowserAccountReply, ObjectID: reply, Sender: d.TargetInstanceID, Recipient: d.Sender.ID, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), KeyEpochID: d.EpochID, BrowserAccountReply: &e2ee.BrowserAccountReplyBinding{Format: e2ee.BrowserAccountReplyBindingFormat, ReplyID: reply, MessageID: d.MessageID, BindingDigest: s.BindingDigest, SealedDigest: s.SealedDigest, OwnerUserID: d.OwnerUserID, ConnectionID: d.ConnectionID, Delegate: e2ee.BrowserAccountDelegate{Kind: d.Sender.Kind, ID: d.Sender.ID}, SourceCommandID: p.SourceCommandID, SourceAdmissionID: p.SourceAdmissionID, OwnershipID: p.OwnershipID, OwnershipGeneration: p.OwnershipGeneration, DispatchSequence: 1, LogicalTurnID: "pagnet-worker-turn-1", OriginalEpochID: d.EpochID}}
	b := e2ee.NativeContentBinding{ContentID: domain.NewID().String(), ObservationID: domain.NewID().String(), OriginID: domain.NewID().String(), InstanceID: d.TargetInstanceID, NativeGeneration: "generation", NativeSessionID: "session", SubjectType: e2ee.ObjectTypeBrowserAccountReply, SubjectID: d.MessageID, Purpose: e2ee.ObjectTypeBrowserAccountReply, SourceCommandID: p.SourceCommandID, SourceAdmissionID: p.SourceAdmissionID, LogicalTurnID: "pagnet-worker-turn-1"}
	kr, err := crypto.LoadKeyring(f.c.d.StateDir, d.NetworkID)
	if err != nil {
		t.Fatal(err)
	}
	epoch, _ := kr.EpochByID(d.EpochID)
	key, err := epoch.KeyArray()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key[:])
	transfer, err := nativecontent.Build(plain, key, a, b, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	return f, transport.BrowserAccountReplyReadBeginPayload{V: 1, MessageID: d.MessageID, Deadline: time.Now().UTC().Add(30 * time.Second).Format(time.RFC3339Nano), Reference: transfer.Reference, Proof: p}, transfer
}

func accountReplyReadFrame(t *testing.T, f readinessFixture, kind, id string, payload any) transport.Envelope {
	t.Helper()
	e, err := transport.NewEnvelope(kind, nil)
	if err != nil {
		t.Fatal(err)
	}
	if id != "" {
		e.CorrelationID = &id
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err = encoder.Encode(payload); err != nil {
		t.Fatal(err)
	}
	e.Payload = bytes.TrimSpace(encoded.Bytes())
	var frame bytes.Buffer
	encoder = json.NewEncoder(&frame)
	encoder.SetEscapeHTML(false)
	if err = encoder.Encode(e); err != nil {
		t.Fatal(err)
	}
	raw := bytes.TrimSpace(frame.Bytes())
	if !f.c.interceptAccountReplyRead(raw) {
		t.Fatal("read frame not reserved")
	}
	return e
}

func accountReplyReadTransfer(t *testing.T, f readinessFixture, p transport.BrowserAccountReplyReadBeginPayload, transfer nativecontent.Transfer) string {
	t.Helper()
	e := accountReplyReadFrame(t, f, transport.MsgAccountReplyRead, "", p)
	for _, fragment := range transfer.Fragments {
		accountReplyReadFrame(t, f, transport.MsgAccountReplyReadFragment, e.ID, transport.BrowserAccountReplyReadFragmentPayload{V: 1, Fragment: fragment})
	}
	accountReplyReadFrame(t, f, transport.MsgAccountReplyReadCommit, e.ID, transport.BrowserAccountReplyReadVersionPayload{V: 1})
	return e.ID
}

func TestAccountReplyReadOriginalAndRotatedEpoch(t *testing.T) {
	for _, rotated := range []bool{false, true} {
		t.Run(map[bool]string{false: "active", true: "rotated"}[rotated], func(t *testing.T) {
			plain := []byte(`{"version":1,"textBlocks":["  private <&> answer\n","","€\tend  "]}`)
			f, p, transfer := accountReplyReadFixture(t, plain)
			if rotated {
				kr, err := crypto.LoadKeyring(f.c.d.StateDir, p.Proof.AccountMessageSource.Descriptor.NetworkID)
				if err != nil {
					t.Fatal(err)
				}
				active, err := kr.Rotate(time.Now())
				if err != nil {
					t.Fatal(err)
				}
				if err = crypto.SaveKeyring(f.c.d.StateDir, kr); err != nil {
					t.Fatal(err)
				}
				f.c.mu.Lock()
				n := f.c.networks[kr.NetworkID]
				n.EpochID = active.ID
				f.c.networks[kr.NetworkID] = n
				f.c.mu.Unlock()
			}
			id := accountReplyReadTransfer(t, f, p, transfer)
			e := f.expect(t, transport.MsgAccountReplyReadChunk)
			var chunk transport.BrowserAccountReplyReadChunkPayload
			if json.Unmarshal(e.Payload, &chunk) != nil || e.CorrelationID == nil || *e.CorrelationID != id || chunk.Sequence != 0 {
				t.Fatal("unbound result chunk")
			}
			got, err := base64.StdEncoding.DecodeString(chunk.Data)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatal("answer bytes changed")
			}
			e = f.expect(t, transport.MsgAccountReplyReadDone)
			var done transport.BrowserAccountReplyReadDonePayload
			sum := sha256.Sum256(plain)
			if json.Unmarshal(e.Payload, &done) != nil || done.MessageID != p.MessageID || done.ContentID != transfer.Reference.ContentID || done.CiphertextDigest != transfer.Reference.CiphertextDigest || done.PlaintextDigest != hex.EncodeToString(sum[:]) || done.PlaintextBytes != int64(len(plain)) || done.ChunkCount != 1 {
				t.Fatal("unbound completion")
			}
		})
	}
}

func TestAccountReplyReadRejectsForgedMixedAndTruncated(t *testing.T) {
	for _, kind := range []string{"owner", "host", "network", "mixed", "message", "runner", "epoch", "proof", "truncated", "fragment", "plaintext", "revoked", "missing", "disabled", "offline", "disconnect"} {
		t.Run(kind, func(t *testing.T) {
			plain := []byte(`{"version":1,"textBlocks":["private"]}`)
			if kind == "plaintext" {
				plain = []byte(`{"version":1,"textBlocks":null}`)
			}
			f, p, transfer := accountReplyReadFixture(t, plain)
			switch kind {
			case "mixed":
				p.Proof.TaskSource = &transport.NativeTaskSource{}
			case "message":
				p.MessageID = domain.NewID().String()
			case "runner":
				p.Proof.SourceRunnerID = domain.NewID().String()
			case "epoch":
				p.Reference.ManifestAAD.KeyEpochID = domain.NewID().String()
			case "proof":
				p.Proof.SourceCommandID = domain.NewID().String()
			case "owner":
				f.c.native.mu.Lock()
				f.c.native.session.AccountID = domain.NewID().String()
				f.c.native.mu.Unlock()
			case "host":
				f.c.native.mu.Lock()
				f.c.native.session.HostID = domain.NewID().String()
				f.c.native.mu.Unlock()
			case "network":
				f.c.mu.Lock()
				n := f.c.networks[p.Proof.AccountMessageSource.Descriptor.NetworkID]
				n.TenantID = domain.NewID().String()
				f.c.networks[n.NetworkID] = n
				f.c.mu.Unlock()
			case "disabled":
				f.c.d.AccountReplyReadEnabled = false
			case "offline":
				f.c.mu.Lock()
				n := f.c.networks[p.Proof.AccountMessageSource.Descriptor.NetworkID]
				n.Status = "inactive"
				f.c.networks[n.NetworkID] = n
				f.c.mu.Unlock()
			case "disconnect":
				f.c.close()
			case "revoked", "missing":
				kr, err := crypto.LoadKeyring(f.c.d.StateDir, p.Proof.AccountMessageSource.Descriptor.NetworkID)
				if err != nil {
					t.Fatal(err)
				}
				if kind == "revoked" {
					if err = kr.Revoke(p.Reference.ManifestAAD.KeyEpochID); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "missing" {
					path, err := crypto.KeyringPath(f.c.d.StateDir, kr.NetworkID)
					if err != nil {
						t.Fatal(err)
					}
					if err = os.Remove(path); err != nil {
						t.Fatal(err)
					}
				} else if err = crypto.SaveKeyring(f.c.d.StateDir, kr); err != nil {
					t.Fatal(err)
				}
			}
			e := accountReplyReadFrame(t, f, transport.MsgAccountReplyRead, "", p)
			if kind != "truncated" {
				for _, fragment := range transfer.Fragments {
					if kind == "fragment" {
						fragment.Envelope.Ciphertext = strings.Repeat("A", len(fragment.Envelope.Ciphertext))
					}
					accountReplyReadFrame(t, f, transport.MsgAccountReplyReadFragment, e.ID, transport.BrowserAccountReplyReadFragmentPayload{V: 1, Fragment: fragment})
				}
			}
			accountReplyReadFrame(t, f, transport.MsgAccountReplyReadCommit, e.ID, transport.BrowserAccountReplyReadVersionPayload{V: 1})
			if kind == "disconnect" || kind == "host" {
				f.quiet(t)
				return
			}
			for {
				select {
				case frame := <-f.frames:
					if frame.Type != transport.MsgAccountReplyReadError {
						t.Fatalf("published %s", frame.Type)
					}
					return
				case <-time.After(time.Second):
					t.Fatal("missing sanitized error")
				}
			}
		})
	}
}

func TestAccountReplyReadChunkBoundaries(t *testing.T) {
	plain := []byte(`{"version":1,"textBlocks":["` + strings.Repeat("€", 30000) + `",""]}`)
	f, p, transfer := accountReplyReadFixture(t, plain)
	id := accountReplyReadTransfer(t, f, p, transfer)
	var joined []byte
	count := (len(plain) + transport.BrowserAccountReplyReadChunkBytes - 1) / transport.BrowserAccountReplyReadChunkBytes
	for i := 0; i < count; i++ {
		e := f.expect(t, transport.MsgAccountReplyReadChunk)
		var chunk transport.BrowserAccountReplyReadChunkPayload
		if json.Unmarshal(e.Payload, &chunk) != nil || chunk.Sequence != i || e.CorrelationID == nil || *e.CorrelationID != id {
			t.Fatal("mixed or unordered chunk")
		}
		part, err := base64.StdEncoding.DecodeString(chunk.Data)
		if err != nil || len(part) == 0 || len(part) > transport.BrowserAccountReplyReadChunkBytes || (i < count-1 && len(part) != transport.BrowserAccountReplyReadChunkBytes) {
			t.Fatal("unbounded result chunk")
		}
		joined = append(joined, part...)
	}
	if !bytes.Equal(joined, plain) {
		t.Fatal("chunk assembly changed original UTF-8 output")
	}
	f.expect(t, transport.MsgAccountReplyReadDone)
}

func TestAccountReplyReadWriterCancellationAndInvalidation(t *testing.T) {
	for _, kind := range []string{"cancel", "disconnect", "network", "route", "mutation"} {
		t.Run(kind, func(t *testing.T) {
			f, p, transfer := accountReplyReadFixture(t, []byte(`{"version":1,"textBlocks":["private"]}`))
			entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			f.c.write = func(raw []byte, guard func() bool) error {
				var env transport.Envelope
				if err := json.Unmarshal(raw, &env); err != nil {
					return err
				}
				if env.Type == transport.MsgAccountReplyReadChunk {
					once.Do(func() { close(entered) })
					<-release
					defer close(finished)
				}
				if guard() {
					f.frames <- env
				}
				return nil
			}
			id := accountReplyReadTransfer(t, f, p, transfer)
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("writer not reached")
			}
			switch kind {
			case "cancel":
				accountReplyReadFrame(t, f, transport.MsgAccountReplyReadCancel, id, transport.BrowserAccountReplyReadVersionPayload{V: 1})
			case "disconnect":
				f.c.close()
			case "network":
				f.c.mu.Lock()
				n := f.c.networks[p.Reference.ManifestAAD.NetworkID]
				n.Status = "inactive"
				f.c.networks[n.NetworkID] = n
				f.c.mu.Unlock()
			case "route":
				f.c.subscription.clear()
			case "mutation":
				finish := f.c.d.beginAccountMessagingMutation()
				defer finish()
			}
			close(release)
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("writer did not exit")
			}
			select {
			case e := <-f.frames:
				if e.Type != transport.MsgAccountReplyReadError {
					t.Fatalf("published %s after invalidation", e.Type)
				}
			case <-time.After(30 * time.Millisecond):
			}
		})
	}
}

func TestAccountReplyReadCapacityDeadlineAndReservation(t *testing.T) {
	f, p, _ := accountReplyReadFixture(t, []byte(`{"version":1,"textBlocks":[]}`))
	first := accountReplyReadFrame(t, f, transport.MsgAccountReplyRead, "", p)
	second := accountReplyReadFrame(t, f, transport.MsgAccountReplyRead, "", p)
	accountReplyReadFrame(t, f, transport.MsgAccountReplyRead, "", p)
	f.expect(t, transport.MsgAccountReplyReadError)
	f.c.readMu.Lock()
	if len(f.c.reads) != 2 || f.c.readCipherBytes != 2*p.Reference.CiphertextBytes {
		t.Fatal("operation capacity was not reserved")
	}
	f.c.readMu.Unlock()
	accountReplyReadFrame(t, f, transport.MsgAccountReplyReadCancel, first.ID, transport.BrowserAccountReplyReadVersionPayload{V: 1})
	accountReplyReadFrame(t, f, transport.MsgAccountReplyReadCancel, second.ID, transport.BrowserAccountReplyReadVersionPayload{V: 1})
	for _, deadline := range []time.Time{time.Now().Add(-time.Second), time.Now().Add(2 * time.Minute)} {
		p.Deadline = deadline.UTC().Format(time.RFC3339Nano)
		accountReplyReadFrame(t, f, transport.MsgAccountReplyRead, "", p)
		f.expect(t, transport.MsgAccountReplyReadError)
	}
	f.c.readMu.Lock()
	defer f.c.readMu.Unlock()
	if len(f.c.reads) != 0 || f.c.readWireBytes != 0 || f.c.readCipherBytes != 0 {
		t.Fatal("canceled read retained operation capacity")
	}
}

func TestAccountReplyReadCancellationWhileFinalGuardWaits(t *testing.T) {
	f, _, _ := accountReplyReadFixture(t, []byte(`{"version":1,"textBlocks":[]}`))
	ctx, cancel := context.WithCancel(f.c.ctx)
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	calls := 0
	op := &accountReplyRead{id: domain.NewID().String(), ctx: ctx, cancel: cancel, guard: func() bool {
		calls++
		if calls == 2 {
			close(entered)
			<-release
		}
		return true
	}}
	result := make(chan bool, 1)
	go func() {
		result <- f.c.readPublish(op, transport.MsgAccountReplyReadChunk, transport.BrowserAccountReplyReadChunkPayload{V: 1, Sequence: 0, Data: "e30="})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("final guard not reached")
	}
	cancel()
	close(release)
	select {
	case published := <-result:
		if published {
			t.Fatal("plaintext published after cancellation during guard wait")
		}
	case <-time.After(time.Second):
		t.Fatal("guard did not exit")
	}
	f.quiet(t)
}

func TestAccountReplyReadScopeChecksAfterEvidenceLock(t *testing.T) {
	f, p, transfer := accountReplyReadFixture(t, []byte(`{"version":1,"textBlocks":[]}`))
	var atWriter atomic.Bool
	entered, resume, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	guard := f.c.accountReplyReadGuard(p.Proof.AccountMessageSource.Descriptor, func() {
		if atWriter.Load() {
			close(entered)
			<-resume
		}
	})
	begin := accountReplyReadFrame(t, f, transport.MsgAccountReplyRead, "", p)
	f.c.readMu.Lock()
	f.c.reads[begin.ID].guard = guard
	f.c.readMu.Unlock()
	f.c.write = func(raw []byte, check func() bool) error {
		var env transport.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return err
		}
		if env.Type == transport.MsgAccountReplyReadChunk {
			atWriter.Store(true)
			defer close(finished)
		}
		if check() {
			f.frames <- env
		}
		return nil
	}
	for _, fragment := range transfer.Fragments {
		accountReplyReadFrame(t, f, transport.MsgAccountReplyReadFragment, begin.ID, transport.BrowserAccountReplyReadFragmentPayload{V: 1, Fragment: fragment})
	}
	accountReplyReadFrame(t, f, transport.MsgAccountReplyReadCommit, begin.ID, transport.BrowserAccountReplyReadVersionPayload{V: 1})
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("writer did not enter final scope guard")
	}
	f.c.subscription.mu.Lock()
	finish := f.c.d.beginAccountMessagingMutation()
	defer finish()
	close(resume)
	f.c.subscription.mu.Unlock()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("writer guard did not exit")
	}
	e := f.expect(t, transport.MsgAccountReplyReadError)
	if e.Type != transport.MsgAccountReplyReadError {
		t.Fatal("plaintext published after mutation during scope guard wait")
	}
}

func TestAccountReplyReadReplayExhaustionReconnects(t *testing.T) {
	f, p, _ := accountReplyReadFixture(t, []byte(`{"version":1,"textBlocks":[]}`))
	f.c.readMu.Lock()
	f.c.readSeen = make(map[string]bool, accountReplyReadMaxSeenFrames)
	for i := 0; i < accountReplyReadMaxSeenFrames; i++ {
		f.c.readSeen[domain.NewID().String()] = true
	}
	f.c.readMu.Unlock()
	accountReplyReadFrame(t, f, transport.MsgAccountReplyRead, "", p)
	f.expect(t, transport.MsgAccountReplyReadError)
	if f.c.ctx.Err() == nil {
		t.Fatal("exhausted lane did not cancel its socket scope")
	}
	if err := f.c.socket.WriteMessage(1, []byte("{}")); err == nil {
		t.Fatal("exhausted replay evidence did not close socket for reconnect")
	}
}

func TestAccountReplyReadFeatureOfferDefaultOff(t *testing.T) {
	d := newTestDaemon(t)
	d.ServerURL = "https://example.test?browser_account_reply_read=untrusted&native_account_reply=untrusted"
	d.nativeRegistry, _, _ = nativeRegistryFixture(t)
	for _, enabled := range []bool{false, true} {
		d.AccountReplyReadEnabled = enabled
		u, err := url.Parse(d.wsURL(t.Context()))
		if err != nil {
			t.Fatal(err)
		}
		want := ""
		if enabled {
			want = transport.BrowserAccountReplyReadProtocol
		}
		if got := u.Query().Get("browser_account_reply_read"); got != want {
			t.Fatalf("read feature = %q, want %q", got, want)
		}
		if u.Query().Get("native_account_reply") != "" {
			t.Fatal("read offer enabled reply delivery")
		}
	}
	d.nativeRegistry = nil
	u, err := url.Parse(d.wsURL(t.Context()))
	if err != nil || u.Query().Get("browser_account_reply_read") != "" {
		t.Fatal("offered reply read without local worker composition")
	}
}

func TestAccountReplyReadReplayEvidenceReleasedWithOperation(t *testing.T) {
	f, p, transfer := accountReplyReadFixture(t, []byte(`{"version":1,"textBlocks":[]}`))
	id := accountReplyReadTransfer(t, f, p, transfer)
	f.expect(t, transport.MsgAccountReplyReadChunk)
	f.expect(t, transport.MsgAccountReplyReadDone)
	// Completion is sent before the worker's deferred capacity release.
	deadline := time.After(time.Second)
	for {
		f.c.readMu.Lock()
		active := len(f.c.reads)
		seen := len(f.c.readSeen)
		tombstone := f.c.readSeen[id]
		f.c.readMu.Unlock()
		if active == 0 {
			if seen != 1 || !tombstone {
				t.Fatal("followup replay evidence leaked after completion")
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("operation not released")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	accountReplyReadFrame(t, f, transport.MsgAccountReplyReadCommit, id, transport.BrowserAccountReplyReadVersionPayload{V: 1})
	f.quiet(t)
	// Unrecognized old correlations do not allocate new replay entries.
	f.c.readMu.Lock()
	defer f.c.readMu.Unlock()
	if len(f.c.readSeen) != 1 {
		t.Fatal("late correlation retained replay state")
	}
}
