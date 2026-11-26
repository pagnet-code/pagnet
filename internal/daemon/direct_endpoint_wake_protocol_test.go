package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/gorilla/websocket"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func wakeProtocolEntry(t *testing.T, lane *directEndpointWakeConnection, handle *DirectEndpointSubscription) *directEndpointWakeAttachment {
	t.Helper()
	lane.mu.Lock()
	defer lane.mu.Unlock()
	entry := lane.byHandle[handle]
	if entry == nil {
		t.Fatal("attachment missing")
	}
	return entry
}

func wakeProtocolEnvelope(typ string, payload any) transport.Envelope {
	raw, _ := json.Marshal(payload)
	return transport.Envelope{ProtocolVersion: transport.ProtocolVersion, Type: typ, Payload: raw}
}

func wakeProtocolOffer(entry *directEndpointWakeAttachment) transport.DirectEndpointWakeOfferV1 {
	return transport.DirectEndpointWakeOfferV1{Protocol: transport.DirectEndpointWakeProtocolV1, SubscriptionID: entry.subscription.SubscriptionID, StreamID: domain.NewID().String(), ContinuityID: domain.NewID().String(), Generation: "1", OfferID: domain.NewID().String(), Revision: "1"}
}

func wakeProtocolReceive(t *testing.T, writes <-chan transport.Envelope, typ string) transport.Envelope {
	t.Helper()
	select {
	case env := <-writes:
		if env.Type != typ || env.ProtocolVersion != transport.ProtocolVersion {
			t.Fatalf("unexpected write: %+v", env)
		}
		return env
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", typ)
		return transport.Envelope{}
	}
}

func wakeProtocolRecorder(writes chan<- transport.Envelope) func(time.Time, []byte) error {
	return func(_ time.Time, raw []byte) error {
		var env transport.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return err
		}
		writes <- env
		return nil
	}
}

func wakeProtocolAccept(t *testing.T, lane *directEndpointWakeConnection, offer transport.DirectEndpointWakeOfferV1) {
	t.Helper()
	if handled, err := lane.handle(wakeProtocolEnvelope(transport.MsgDirectEndpointWakeOffer, offer)); !handled || err != nil {
		t.Fatalf("offer rejected: handled=%v err=%v", handled, err)
	}
}

func TestDirectEndpointWakeImmediateOfferDuringSubscribe(t *testing.T) {
	_, lane, handle := wakeAttachmentFixture(t, true)
	writes := make(chan transport.Envelope, 4)
	handled := make(chan error, 1)
	callback := make(chan struct{}, 1)
	lane.write = func(deadline time.Time, raw []byte) error {
		var env transport.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return err
		}
		writes <- env
		if env.Type == transport.MsgDirectEndpointWakeSubscribe {
			subscribe, err := transport.DecodeDirectEndpointWakeSubscribeV1(env.Payload)
			if err != nil {
				handled <- err
				return err
			}
			offer := transport.DirectEndpointWakeOfferV1{Protocol: transport.DirectEndpointWakeProtocolV1, SubscriptionID: subscribe.SubscriptionID, StreamID: domain.NewID().String(), ContinuityID: domain.NewID().String(), Generation: "1", OfferID: domain.NewID().String(), Revision: "1"}
			_, err = lane.handle(wakeProtocolEnvelope(transport.MsgDirectEndpointWakeOffer, offer))
			handled <- err
		}
		return nil
	}
	if err := lane.attach(handle, func(context.Context) error { callback <- struct{}{}; return nil }); err != nil {
		t.Fatal(err)
	}
	wakeProtocolReceive(t, writes, transport.MsgDirectEndpointWakeSubscribe)
	select {
	case err := <-handled:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("subscribe write deadlocked with immediate offer")
	}
	wakeProtocolReceive(t, writes, transport.MsgDirectEndpointWakeACK)
	select {
	case <-callback:
	case <-time.After(time.Second):
		t.Fatal("immediate offer lost callback")
	}
}

func TestDirectEndpointWakeACKIndependentAndCallbacksCoalesce(t *testing.T) {
	_, lane, handle := wakeAttachmentFixture(t, true)
	writes := make(chan transport.Envelope, 32)
	lane.write = wakeProtocolRecorder(writes)
	started := make(chan int32, 4)
	release := make(chan struct{})
	defer close(release)
	var calls, active, maximum atomic.Int32
	if err := lane.attach(handle, func(ctx context.Context) error {
		n := active.Add(1)
		defer active.Add(-1)
		if n > maximum.Load() {
			maximum.Store(n)
		}
		started <- calls.Add(1)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	wakeProtocolReceive(t, writes, transport.MsgDirectEndpointWakeSubscribe)
	first := wakeProtocolOffer(wakeProtocolEntry(t, lane, handle))
	wakeProtocolAccept(t, lane, first)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("callback did not start")
	}
	offers := []transport.DirectEndpointWakeOfferV1{first, first}
	second := first
	second.OfferID = domain.NewID().String()
	second.Revision = "2"
	third := first
	third.OfferID = domain.NewID().String()
	third.Revision = "3"
	offers = append(offers, second, third, second, third)
	for _, offer := range offers {
		wakeProtocolAccept(t, lane, offer)
	}
	for _, offer := range append([]transport.DirectEndpointWakeOfferV1{first}, offers...) {
		env := wakeProtocolReceive(t, writes, transport.MsgDirectEndpointWakeACK)
		ack, err := transport.DecodeDirectEndpointWakeACKV1(env.Payload)
		if err != nil || transport.ValidateDirectEndpointWakeACKV1(ack, offer) != nil {
			t.Fatalf("ACK did not echo offer: %s (%v)", env.Payload, err)
		}
	}
	if calls.Load() != 1 || maximum.Load() != 1 {
		t.Fatal("callback overlapped while blocked")
	}
	release <- struct{}{}
	select {
	case n := <-started:
		if n != 2 {
			t.Fatalf("callback count %d", n)
		}
	case <-time.After(time.Second):
		t.Fatal("newer offers lost coalesced obligation")
	}
	lane.mu.Lock()
	pending := lane.byHandle[handle].pending
	lane.mu.Unlock()
	if pending || calls.Load() != 2 || maximum.Load() != 1 {
		t.Fatal("duplicates created extra callback obligation")
	}
}

func TestDirectEndpointWakeCallbackFailureRemovesExactEntry(t *testing.T) {
	for _, panics := range []bool{false, true} {
		t.Run(map[bool]string{false: "error", true: "panic"}[panics], func(t *testing.T) {
			d, lane, handle := wakeAttachmentFixture(t, true)
			writes := make(chan transport.Envelope, 16)
			lane.write = wakeProtocolRecorder(writes)
			other := d.directSubscriptions.add(handle.binding)
			if err := lane.attach(other, func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
			if err := lane.attach(handle, func(context.Context) error {
				if panics {
					panic("test callback")
				}
				return errors.New("callback failed")
			}); err != nil {
				t.Fatal(err)
			}
			wakeProtocolReceive(t, writes, transport.MsgDirectEndpointWakeSubscribe)
			wakeProtocolReceive(t, writes, transport.MsgDirectEndpointWakeSubscribe)
			entry := wakeProtocolEntry(t, lane, handle)
			wakeProtocolAccept(t, lane, wakeProtocolOffer(entry))
			waitWakeAttachmentRemoved(t, lane, entry)
			if !handle.Valid() {
				t.Fatal("callback failure revoked admitted handle")
			}
			wakeProtocolEntry(t, lane, other)
		})
	}
}

func TestDirectEndpointWakeRejectsInvalidOfferAndClosed(t *testing.T) {
	_, lane, handle := wakeAttachmentFixture(t, true)
	lane.write = func(time.Time, []byte) error { return nil }
	if err := lane.attach(handle, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	entry := wakeProtocolEntry(t, lane, handle)
	first := wakeProtocolOffer(entry)
	wakeProtocolAccept(t, lane, first)
	second := first
	second.OfferID = domain.NewID().String()
	second.Revision = "2"
	wakeProtocolAccept(t, lane, second)
	third := second
	third.OfferID = domain.NewID().String()
	third.Revision = "3"
	wakeProtocolAccept(t, lane, third)
	for _, mutation := range []string{"unknown", "stream", "continuity", "generation", "same-revision", "old-revision", "old-duplicate", "reuse-offer"} {
		t.Run(mutation, func(t *testing.T) {
			offer := third
			offer.Revision = "4"
			offer.OfferID = domain.NewID().String()
			switch mutation {
			case "unknown":
				offer.SubscriptionID = domain.NewID().String()
			case "stream":
				offer.StreamID = domain.NewID().String()
			case "continuity":
				offer.ContinuityID = domain.NewID().String()
			case "generation":
				offer.Generation = "2"
			case "same-revision":
				offer.Revision = "3"
			case "old-revision":
				offer.Revision = "1"
			case "old-duplicate":
				offer = first
			case "reuse-offer":
				offer.OfferID = third.OfferID
			}
			if handled, err := lane.handle(wakeProtocolEnvelope(transport.MsgDirectEndpointWakeOffer, offer)); !handled || err != ErrNativeObservationConflict {
				t.Fatalf("invalid offer accepted: %v %v", handled, err)
			}
		})
	}
	valid := wakeProtocolEnvelope(transport.MsgDirectEndpointWakeOffer, third)
	for _, payload := range [][]byte{[]byte(`{}`), []byte(`null`), append(append([]byte(nil), valid.Payload[:len(valid.Payload)-1]...), []byte(`,"unknown":true}`)...), append(append([]byte(nil), valid.Payload...), []byte(` {}`)...)} {
		env := valid
		env.Payload = payload
		if handled, err := lane.handle(env); !handled || err != ErrNativeObservationConflict {
			t.Fatalf("malformed offer accepted: %s", payload)
		}
	}
	invalidVersion := valid
	invalidVersion.ProtocolVersion = 1
	if _, err := lane.handle(invalidVersion); err != ErrNativeObservationConflict {
		t.Fatal("wrong envelope version accepted")
	}
	closed := transport.DirectEndpointWakeClosedV1{Protocol: transport.DirectEndpointWakeProtocolV1, SubscriptionID: entry.subscription.SubscriptionID, Reason: transport.DirectEndpointWakeClosedUnavailable}
	if _, err := lane.handle(wakeProtocolEnvelope(transport.MsgDirectEndpointWakeClosed, closed)); err != nil {
		t.Fatal(err)
	}
	waitWakeAttachmentRemoved(t, lane, entry)
	if _, err := lane.handle(valid); err != ErrNativeObservationConflict {
		t.Fatal("stale subscription ID accepted")
	}
	if _, err := lane.handle(wakeProtocolEnvelope(transport.MsgDirectEndpointWakeClosed, closed)); err != ErrNativeObservationConflict {
		t.Fatal("stale closed accepted")
	}
}

func TestDirectEndpointWakeWriterContentionCutoff(t *testing.T) {
	d, lane, handle := wakeAttachmentFixture(t, true)
	d.writeTimeout = 40 * time.Millisecond
	var writes atomic.Int32
	lane.write = func(time.Time, []byte) error { writes.Add(1); return nil }
	d.writeMu.Lock()
	locked := true
	defer func() {
		if locked {
			d.writeMu.Unlock()
		}
	}()
	if err := lane.attach(handle, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	entry := wakeProtocolEntry(t, lane, handle)
	waitWakeAttachmentRemoved(t, lane, entry)
	if writes.Load() != 0 {
		t.Fatal("write bypassed daemon writer mutex")
	}
	d.writeMu.Unlock()
	locked = false
	select {
	case <-lane.writerDone:
		t.Fatal("single attachment timeout terminated lane writer")
	case <-time.After(20 * time.Millisecond):
	}
	if writes.Load() != 0 {
		t.Fatal("expired queued subscribe reached socket")
	}
}

func TestDirectEndpointWakeQueueBackpressure(t *testing.T) {
	d, lane, handle := wakeAttachmentFixture(t, true)
	d.writeTimeout = time.Second
	lane.write = func(time.Time, []byte) error { return nil }
	d.writeMu.Lock()
	locked := true
	defer func() {
		if locked {
			d.writeMu.Unlock()
		}
	}()
	if err := lane.attach(handle, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	entry := wakeProtocolEntry(t, lane, handle)
	offer := wakeProtocolOffer(entry)
	for i := 0; i < 66; i++ {
		handled, err := lane.handle(wakeProtocolEnvelope(transport.MsgDirectEndpointWakeOffer, offer))
		if !handled {
			t.Fatal("wake offer escaped reserved lane")
		}
		if err != nil && err != ErrNativeObservationConflict {
			t.Fatal(err)
		}
	}
	waitWakeAttachmentRemoved(t, lane, entry)
	lane.mu.Lock()
	err := entry.err
	lane.mu.Unlock()
	if err != ErrNativeObservationCapacity {
		t.Fatalf("backpressure removal: %v", err)
	}
	d.writeMu.Unlock()
	locked = false
}

func TestDirectEndpointWakeCloseUnsubscribeRaces(t *testing.T) {
	for _, remote := range []bool{false, true} {
		t.Run(map[bool]string{false: "local", true: "remote"}[remote], func(t *testing.T) {
			_, lane, handle := wakeAttachmentFixture(t, true)
			writes := make(chan transport.Envelope, 16)
			lane.write = wakeProtocolRecorder(writes)
			if err := lane.attach(handle, func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
			entry := wakeProtocolEntry(t, lane, handle)
			wakeProtocolReceive(t, writes, transport.MsgDirectEndpointWakeSubscribe)
			if remote {
				closed := transport.DirectEndpointWakeClosedV1{Protocol: transport.DirectEndpointWakeProtocolV1, SubscriptionID: entry.subscription.SubscriptionID, Reason: transport.DirectEndpointWakeClosedUnavailable}
				if _, err := lane.handle(wakeProtocolEnvelope(transport.MsgDirectEndpointWakeClosed, closed)); err != nil {
					t.Fatal(err)
				}
			}
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() { defer wg.Done(); handle.Remove(); lane.close() }()
			}
			wg.Wait()
			waitWakeAttachmentRemoved(t, lane, entry)
			select {
			case <-lane.writerDone:
			case <-time.After(time.Second):
				t.Fatal("writer did not stop")
			}
			count := 0
			for len(writes) > 0 {
				env := <-writes
				if env.Type != transport.MsgDirectEndpointWakeUnsubscribe {
					t.Fatalf("unexpected close write: %s", env.Type)
				}
				unsub, err := transport.DecodeDirectEndpointWakeUnsubscribeV1(env.Payload)
				if err != nil || unsub.SubscriptionID != entry.subscription.SubscriptionID {
					t.Fatal("unsubscribe lost exact identity")
				}
				count++
			}
			if count > 1 || (remote && count != 0) {
				t.Fatalf("unsubscribe count=%d remote=%v", count, remote)
			}
		})
	}
}

func TestDirectEndpointWakeWriteDeadlineBound(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second, 10 * time.Second, 100 * time.Millisecond} {
		t.Run(timeout.String(), func(t *testing.T) {
			d, lane, handle := wakeAttachmentFixture(t, true)
			d.writeTimeout = timeout
			deadlines := make(chan time.Time, 2)
			lane.write = func(deadline time.Time, _ []byte) error { deadlines <- deadline; return nil }
			before := time.Now()
			if err := lane.attach(handle, func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
			var deadline time.Time
			select {
			case deadline = <-deadlines:
			case <-time.After(time.Second):
				t.Fatal("subscribe did not write")
			}
			bound := 2 * time.Second
			if timeout > 0 && timeout < bound {
				bound = timeout
			}
			if deadline.Before(before.Add(bound)) || deadline.After(time.Now().Add(bound)) {
				t.Fatalf("deadline %v outside absolute %v bound", deadline, bound)
			}
		})
	}
}

func wakeProtocolSocketPair(t *testing.T) (*websocket.Conn, *websocket.Conn) {
	t.Helper()
	accepted := make(chan *websocket.Conn, 1)
	upgrade := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		socket, err := upgrade.Upgrade(w, r, nil)
		if err == nil {
			accepted <- socket
		}
	}))
	t.Cleanup(server.Close)
	socket, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var peer *websocket.Conn
	select {
	case peer = <-accepted:
	case <-time.After(time.Second):
		socket.Close()
		t.Fatal("websocket upgrade blocked")
	}
	t.Cleanup(func() { socket.Close(); peer.Close() })
	return socket, peer
}

func wakeProtocolRealFixture(t *testing.T) (*Daemon, *directEndpointWakeConnection, *DirectEndpointSubscription, *websocket.Conn) {
	t.Helper()
	socket, peer := wakeProtocolSocketPair(t)
	native, session := wakeNative(t, wakeOffer(true))
	if err := native.Admit(session); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{Config: Config{ServerURL: "https://example.test"}, Log: slog.Default(), writeTimeout: time.Second}
	d.curConn, d.nativeConn = socket, native
	lane := newDirectEndpointWakeConnection(d, socket, native)
	raw, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	handle := d.directSubscriptions.add(directEndpointBinding{socket: socket, native: native, sessionIdentity: string(raw), metadata: DirectEndpointSubscriptionMetadata{
		InstallationID: domain.NewID(), IntentID: domain.NewID(), CredentialID: domain.NewID(), Role: "S", ServerOrigin: "https://example.test", Deadline: time.Now().Add(time.Hour),
	}})
	t.Cleanup(func() { lane.close(); native.Close(); d.directSubscriptions.close() })
	return d, lane, handle, peer
}

func wakeProtocolReadSocket(t *testing.T, socket *websocket.Conn, typ string) transport.Envelope {
	t.Helper()
	if err := socket.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var env transport.Envelope
	if err := socket.ReadJSON(&env); err != nil {
		t.Fatal(err)
	}
	if env.Type != typ || env.ProtocolVersion != transport.ProtocolVersion {
		t.Fatalf("unexpected socket message: %+v", env)
	}
	return env
}

func TestDirectEndpointWakeCapturedSocketProtocol(t *testing.T) {
	t.Run("unattached-silence", func(t *testing.T) {
		_, _, _, peer := wakeProtocolRealFixture(t)
		if err := peer.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if _, raw, err := peer.ReadMessage(); err == nil {
			t.Fatalf("traffic before explicit attach: %s", raw)
		} else {
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				t.Fatalf("silence check failed before timeout: %v", err)
			}
		}
	})
	t.Run("subscribe-offer-ack", func(t *testing.T) {
		_, lane, handle, peer := wakeProtocolRealFixture(t)
		callback := make(chan struct{}, 1)
		if err := lane.attach(handle, func(context.Context) error { callback <- struct{}{}; return nil }); err != nil {
			t.Fatal(err)
		}
		entry := wakeProtocolEntry(t, lane, handle)
		env := wakeProtocolReadSocket(t, peer, transport.MsgDirectEndpointWakeSubscribe)
		subscribe, err := transport.DecodeDirectEndpointWakeSubscribeV1(env.Payload)
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := entry.subscription.CanonicalBytes()
		if err != nil || subscribe != entry.subscription || !bytes.Equal(env.Payload, canonical) {
			t.Fatalf("subscribe differs from exact canonical attachment: %s", env.Payload)
		}
		offer := wakeProtocolOffer(entry)
		if err := peer.WriteJSON(wakeProtocolEnvelope(transport.MsgDirectEndpointWakeOffer, offer)); err != nil {
			t.Fatal(err)
		}
		received := wakeProtocolReadSocket(t, lane.socket, transport.MsgDirectEndpointWakeOffer)
		if handled, err := lane.handle(received); !handled || err != nil {
			t.Fatalf("received offer rejected: %v", err)
		}
		env = wakeProtocolReadSocket(t, peer, transport.MsgDirectEndpointWakeACK)
		ack, err := transport.DecodeDirectEndpointWakeACKV1(env.Payload)
		canonical, canonicalErr := transport.DirectEndpointWakeACKV1(offer).CanonicalBytes()
		if err != nil || canonicalErr != nil || transport.ValidateDirectEndpointWakeACKV1(ack, offer) != nil || !bytes.Equal(env.Payload, canonical) {
			t.Fatalf("ACK differs from exact canonical offer: %s", env.Payload)
		}
		select {
		case <-callback:
		case <-time.After(time.Second):
			t.Fatal("received offer lost callback")
		}
	})
}

func TestDirectEndpointWakeCapturedSocketReplacement(t *testing.T) {
	d, lane, handle, peer := wakeProtocolRealFixture(t)
	if err := lane.attach(handle, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	entry := wakeProtocolEntry(t, lane, handle)
	wakeProtocolReadSocket(t, peer, transport.MsgDirectEndpointWakeSubscribe)
	replacementSocket, replacementPeer := wakeProtocolSocketPair(t)
	replacementNative, session := wakeNative(t, wakeOffer(true))
	if err := replacementNative.Admit(session); err != nil {
		t.Fatal(err)
	}
	replacement := newDirectEndpointWakeConnection(d, replacementSocket, replacementNative)
	t.Cleanup(func() { replacement.close(); replacementNative.Close() })
	d.connMu.Lock()
	d.curConn, d.nativeConn = replacementSocket, replacementNative
	d.connMu.Unlock()
	handle.Remove()
	waitWakeAttachmentRemoved(t, lane, entry)
	env := wakeProtocolReadSocket(t, peer, transport.MsgDirectEndpointWakeUnsubscribe)
	unsub, err := transport.DecodeDirectEndpointWakeUnsubscribeV1(env.Payload)
	if err != nil || unsub.SubscriptionID != entry.subscription.SubscriptionID {
		t.Fatal("unsubscribe did not retire original subscription")
	}
	lane.close()
	select {
	case <-lane.writerDone:
	case <-time.After(time.Second):
		t.Fatal("original writer did not drain")
	}
	marker := wakeProtocolEnvelope("test.marker", struct{}{})
	d.writeMu.Lock()
	err = lane.socket.WriteJSON(marker)
	if err == nil {
		err = replacementSocket.WriteJSON(marker)
	}
	d.writeMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	wakeProtocolReadSocket(t, peer, "test.marker")
	wakeProtocolReadSocket(t, replacementPeer, "test.marker")
	replacement.mu.Lock()
	count := len(replacement.byHandle) + len(replacement.byID) + len(replacement.usedIDs)
	replacement.mu.Unlock()
	if count != 0 {
		t.Fatal("replacement socket restored attachment")
	}
}

func TestDirectEndpointWakeWriteFailureAndIODeadline(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(map[bool]string{false: "write-error", true: "io-deadline"}[blocked], func(t *testing.T) {
			d, lane, handle := wakeAttachmentFixture(t, true)
			d.writeTimeout = 40 * time.Millisecond
			lane.writeFailed = func() {}
			entered := make(chan time.Time, 2)
			returned := make(chan struct{}, 2)
			release := make(chan struct{})
			var attempts atomic.Int32
			lane.write = func(deadline time.Time, raw []byte) error {
				var env transport.Envelope
				if err := json.Unmarshal(raw, &env); err != nil {
					return err
				}
				if env.Type == transport.MsgDirectEndpointWakeUnsubscribe || attempts.Add(1) > 1 {
					return nil
				}
				entered <- deadline
				<-release
				if blocked {
					timer := time.NewTimer(time.Until(deadline))
					defer timer.Stop()
					<-timer.C
				}
				returned <- struct{}{}
				return errors.New("socket write failed")
			}
			if err := lane.attach(handle, func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
			entry := wakeProtocolEntry(t, lane, handle)
			var deadline time.Time
			select {
			case deadline = <-entered:
				close(release)
			case <-time.After(time.Second):
				t.Fatal("write did not enter socket hook")
			}
			waitWakeAttachmentRemoved(t, lane, entry)
			if blocked && time.Now().Before(deadline) {
				t.Fatal("in-flight write removed before absolute deadline")
			}
			select {
			case <-returned:
			case <-time.After(time.Second):
				t.Fatal("write did not finish within I/O budget")
			}
			if !handle.Valid() {
				t.Fatal("socket write failure revoked admitted handle")
			}
			if err := lane.attach(handle, func(context.Context) error { return nil }); err != nil {
				t.Fatal("failed attachment prevented fresh explicit attachment", err)
			}
			replacement := wakeProtocolEntry(t, lane, handle)
			if replacement == entry || replacement.subscription.SubscriptionID == entry.subscription.SubscriptionID {
				t.Fatal("fresh attachment reused failed exact identity")
			}
			lane.mu.Lock()
			lane.removeLocked(entry, true, errors.New("late failure"))
			current := lane.byHandle[handle]
			lane.mu.Unlock()
			if current != replacement {
				t.Fatal("late failure removed replacement attachment")
			}
		})
	}
}

func TestDirectEndpointWakeLifecycleContentionReleasesWriter(t *testing.T) {
	for _, fence := range []string{"connection", "native"} {
		t.Run(fence, func(t *testing.T) {
			d, lane, handle := wakeAttachmentFixture(t, true)
			d.writeTimeout = 40 * time.Millisecond
			writes := make(chan transport.Envelope, 8)
			lane.write = wakeProtocolRecorder(writes)
			if err := lane.attach(handle, func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
			wakeProtocolReceive(t, writes, transport.MsgDirectEndpointWakeSubscribe)
			entry := wakeProtocolEntry(t, lane, handle)
			d.writeMu.Lock()
			wakeProtocolAccept(t, lane, wakeProtocolOffer(entry))
			var unlock func()
			if fence == "connection" {
				d.connMu.Lock()
				unlock = d.connMu.Unlock
			} else {
				lane.native.mu.Lock()
				unlock = lane.native.mu.Unlock
			}
			defer unlock()
			d.writeMu.Unlock()
			waitWakeAttachmentRemoved(t, lane, entry)
			cutoff := time.Now().Add(100 * time.Millisecond)
			for !d.writeMu.TryLock() {
				if !time.Now().Before(cutoff) {
					t.Fatal("lifecycle contention retained shared writer mutex")
				}
				time.Sleep(time.Millisecond)
			}
			d.writeMu.Unlock()
			lane.mu.Lock()
			err := entry.err
			lane.mu.Unlock()
			if err != context.DeadlineExceeded {
				t.Fatalf("contended ACK removal: %v", err)
			}
			for len(writes) > 0 {
				if env := <-writes; env.Type == transport.MsgDirectEndpointWakeACK {
					t.Fatal("ACK bypassed contended lifecycle fence")
				}
			}
		})
	}
}

func TestDirectEndpointWakeLocalRemovalToleratesRacedHints(t *testing.T) {
	for _, previous := range []bool{false, true} {
		t.Run(map[bool]string{false: "late-first-offer", true: "pinned-stream"}[previous], func(t *testing.T) {
			_, lane, handle := wakeAttachmentFixture(t, true)
			writes := make(chan transport.Envelope, 16)
			lane.write = wakeProtocolRecorder(writes)
			callbacks := make(chan struct{}, 4)
			if err := lane.attach(handle, func(context.Context) error { callbacks <- struct{}{}; return nil }); err != nil {
				t.Fatal(err)
			}
			wakeProtocolReceive(t, writes, transport.MsgDirectEndpointWakeSubscribe)
			entry := wakeProtocolEntry(t, lane, handle)
			offer := wakeProtocolOffer(entry)
			if previous {
				wakeProtocolAccept(t, lane, offer)
				wakeProtocolReceive(t, writes, transport.MsgDirectEndpointWakeACK)
				select {
				case <-callbacks:
				case <-time.After(time.Second):
					t.Fatal("initial callback missing")
				}
			}
			handle.Remove()
			waitWakeAttachmentRemoved(t, lane, entry)
			wakeProtocolReceive(t, writes, transport.MsgDirectEndpointWakeUnsubscribe)
			if previous {
				wakeProtocolAccept(t, lane, offer)
				offer.OfferID = domain.NewID().String()
				offer.Revision = "2"
			}
			wakeProtocolAccept(t, lane, offer)
			if previous {
				changed := offer
				changed.StreamID = domain.NewID().String()
				changed.OfferID = domain.NewID().String()
				changed.Revision = "3"
				if _, err := lane.handle(wakeProtocolEnvelope(transport.MsgDirectEndpointWakeOffer, changed)); err != ErrNativeObservationConflict {
					t.Fatal("raced offer changed pinned stream", err)
				}
			}
			unknown := offer
			unknown.SubscriptionID = domain.NewID().String()
			if _, err := lane.handle(wakeProtocolEnvelope(transport.MsgDirectEndpointWakeOffer, unknown)); err != ErrNativeObservationConflict {
				t.Fatal("unknown raced offer accepted", err)
			}
			closed := transport.DirectEndpointWakeClosedV1{Protocol: transport.DirectEndpointWakeProtocolV1, SubscriptionID: entry.subscription.SubscriptionID, Reason: transport.DirectEndpointWakeClosedRetryExhausted}
			if _, err := lane.handle(wakeProtocolEnvelope(transport.MsgDirectEndpointWakeClosed, closed)); err != nil {
				t.Fatal("raced retry exhaustion rejected", err)
			}
			for _, reason := range []string{transport.DirectEndpointWakeClosedUnsubscribed, transport.DirectEndpointWakeClosedUnavailable} {
				closed.Reason = reason
				if _, err := lane.handle(wakeProtocolEnvelope(transport.MsgDirectEndpointWakeClosed, closed)); err != ErrNativeObservationConflict {
					t.Fatalf("canceled tombstone accepted closed(%s): %v", reason, err)
				}
			}
			lane.close()
			select {
			case <-lane.writerDone:
			case <-time.After(time.Second):
				t.Fatal("writer did not drain")
			}
			if len(writes) != 0 {
				t.Fatal("raced hint produced traffic after unsubscribe")
			}
			select {
			case <-callbacks:
				t.Fatal("raced hint invoked callback after removal")
			default:
			}
		})
	}
}

func TestDirectEndpointWakeRevocationBeforeDoneWatcher(t *testing.T) {
	_, lane, handle := wakeAttachmentFixture(t, true)
	writes := make(chan transport.Envelope, 8)
	lane.write = wakeProtocolRecorder(writes)
	var callbacks atomic.Int32
	if err := lane.attach(handle, func(context.Context) error { callbacks.Add(1); return nil }); err != nil {
		t.Fatal(err)
	}
	wakeProtocolReceive(t, writes, transport.MsgDirectEndpointWakeSubscribe)
	entry := wakeProtocolEntry(t, lane, handle)
	handle.owner.mu.Lock()
	delete(handle.owner.entries, handle)
	if handle.timer != nil {
		handle.timer.Stop()
	}
	handle.owner.mu.Unlock()
	defer close(handle.done)
	// Revocation has linearized, while the Done notification and its watcher
	// remain delayed. The inbound hint must retire this exact registration.
	wakeProtocolAccept(t, lane, wakeProtocolOffer(entry))
	waitWakeAttachmentRemoved(t, lane, entry)
	env := wakeProtocolReceive(t, writes, transport.MsgDirectEndpointWakeUnsubscribe)
	unsub, err := transport.DecodeDirectEndpointWakeUnsubscribeV1(env.Payload)
	if err != nil || unsub.SubscriptionID != entry.subscription.SubscriptionID {
		t.Fatal("revocation lost exact unsubscribe identity")
	}
	lane.close()
	select {
	case <-lane.writerDone:
	case <-time.After(time.Second):
		t.Fatal("revoked writer did not drain")
	}
	if len(writes) != 0 || callbacks.Load() != 0 {
		t.Fatal("revoked hint produced ACK or callback")
	}
}

func TestDirectEndpointWakeDefaultWriteFailureAvoidsLifecycleLock(t *testing.T) {
	d, lane, handle, peer := wakeProtocolRealFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	lane.write = func(_ time.Time, raw []byte) error {
		var env transport.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return err
		}
		if env.Type == transport.MsgDirectEndpointWakeUnsubscribe {
			return nil
		}
		close(entered)
		<-release
		return errors.New("captured socket write failed")
	}
	if err := lane.attach(handle, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	entry := wakeProtocolEntry(t, lane, handle)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("write did not pass final guard")
	}
	d.connMu.Lock()
	defer d.connMu.Unlock()
	releaseOnce.Do(func() { close(release) })
	waitWakeAttachmentRemoved(t, lane, entry)
	lane.close()
	select {
	case <-lane.writerDone:
	case <-time.After(time.Second):
		t.Fatal("write failure blocked on lifecycle mutex")
	}
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := peer.ReadMessage(); err == nil {
		t.Fatal("default failure handler left captured socket open")
	} else {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatal("default failure handler did not close captured socket")
		}
	}
}
