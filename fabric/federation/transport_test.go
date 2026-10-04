package federation

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type relaySpy struct {
	PacketStream
	mu      sync.Mutex
	records [][]byte
}

func (s *relaySpy) Write(ctx context.Context, p Packet) error {
	raw, e := EncodePacket(p)
	if e != nil {
		return e
	}
	s.mu.Lock()
	s.records = append(s.records, raw)
	s.mu.Unlock()
	return s.PacketStream.Write(ctx, p)
}
func boundedStream(t *testing.T, c net.Conn) *ConnStream {
	t.Helper()
	s, e := NewConnStream(c, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestBlindRelayDuplexExactRecordsBackpressureAndClose(t *testing.T) {
	a, b, _ := cryptoFixture(t)
	left, relayLeft := net.Pipe()
	relayRight, right := net.Pipe()
	source, e := NewDuplex(context.Background(), a, boundedStream(t, left), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	destination, e := NewDuplex(context.Background(), b, boundedStream(t, right), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	forward := &relaySpy{PacketStream: boundedStream(t, relayRight)}
	reverse := &relaySpy{PacketStream: boundedStream(t, relayLeft)}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	relayed := make(chan error, 1)
	go func() {
		relayed <- RelayOpaque(ctx, reverse, forward, a.Channel, RelayLimits{MaxPackets: 8, MaxBytes: 1 << 20, Lifetime: 2 * time.Second})
	}()
	secret := []byte(`{"query":"private semantic query","input":{"n":9007199254740993123456789}}`)
	sent := make(chan error, 1)
	go func() { sent <- source.Send(ctx, secret) }()
	// Exactly one bounded frame may be in flight inside the relay. Its next
	// upstream read remains blocked until the downstream write is consumed.
	if e = <-sent; e != nil {
		t.Fatal(e)
	}
	second := bytes.Repeat([]byte("private output "), 2048)
	go func() { sent <- source.Send(ctx, second) }()
	select {
	case e := <-sent:
		t.Fatal("relay read ahead without downstream credit", e)
	case <-time.After(20 * time.Millisecond):
	}
	for _, payload := range [][]byte{secret, second} {
		got, e := destination.Receive(ctx)
		if e != nil || !bytes.Equal(got, payload) {
			t.Fatal("encrypted exact pull", e)
		}
	}
	if e = <-sent; e != nil {
		t.Fatal(e)
	}
	response := []byte(`{"state":"native.stopped","effect":"unknown"}`)
	go func() { sent <- destination.Send(ctx, response) }()
	got, e := source.Receive(ctx)
	if e != nil || !bytes.Equal(got, response) {
		t.Fatal("reverse ciphertext", e)
	}
	if e = <-sent; e != nil {
		t.Fatal(e)
	}
	for _, spy := range []*relaySpy{forward, reverse} {
		spy.mu.Lock()
		for _, raw := range spy.records {
			for _, private := range [][]byte{[]byte("private"), []byte("native.stopped"), []byte(a.Local.Authority.Namespace), []byte(b.Local.Authority.StoreID)} {
				if bytes.Contains(raw, private) {
					t.Fatal("blind relay saw private data")
				}
			}
		}
		spy.mu.Unlock()
	}
	source.Close()
	select {
	case <-relayed:
	case <-time.After(time.Second):
		t.Fatal("relay did not join owned directions")
	}
	if e = source.Send(ctx, []byte("after close")); e == nil {
		t.Fatal("closed encrypted stream sent again")
	}
}

func TestOwnedConnStreamCancellationUnblocksReadWrite(t *testing.T) {
	for _, reading := range []bool{true, false} {
		t.Run(map[bool]string{true: "read", false: "write"}[reading], func(t *testing.T) {
			a, _, _ := cryptoFixture(t)
			sender, e := NewSender(context.Background(), a)
			if e != nil {
				t.Fatal(e)
			}
			p, e := sender.Seal(context.Background(), []byte("bounded private record"))
			if e != nil {
				t.Fatal(e)
			}
			left, right := net.Pipe()
			defer right.Close()
			s := boundedStream(t, left)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				if reading {
					_, e := s.Read(ctx)
					done <- e
				} else {
					done <- s.Write(ctx, p)
				}
			}()
			cancel()
			select {
			case e := <-done:
				if !errors.Is(e, context.Canceled) {
					t.Fatal("caller cancellation lost", e)
				}
			case <-time.After(time.Second):
				t.Fatal("owned blocked IO not canceled")
			}
		})
	}
}

func TestOwnedConnStreamRejectsOversizeBeforeBodyAndUnknownOuterFields(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	s := boundedStream(t, left)
	done := make(chan error, 1)
	go func() { _, e := s.Read(context.Background()); done <- e }()
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], MaxRecordWire+1)
	if _, e := right.Write(prefix[:]); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("oversize body accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("waited for oversize body")
	}
	a, _, _ := cryptoFixture(t)
	sender, _ := NewSender(context.Background(), a)
	p, _ := sender.Seal(context.Background(), []byte("secret"))
	raw, _ := EncodePacket(p)
	raw = append(bytes.TrimSuffix(raw, []byte("}")), []byte(`,"trace":"private-name"}`)...)
	if _, e := DecodePacket(raw); e == nil {
		t.Fatal("arbitrary semantic relay field accepted")
	}
}

func TestBlindRelayRejectsWrongOpaqueRouteAndBudget(t *testing.T) {
	for _, wrongRoute := range []bool{true, false} {
		t.Run(map[bool]string{true: "route", false: "budget"}[wrongRoute], func(t *testing.T) {
			a, b, _ := cryptoFixture(t)
			sender, e := NewSender(context.Background(), a)
			if e != nil {
				t.Fatal(e)
			}
			left, rl := net.Pipe()
			rr, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			l, r := boundedStream(t, rl), boundedStream(t, rr)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- RelayOpaque(ctx, l, r, a.Channel, RelayLimits{MaxPackets: 1, MaxBytes: 1 << 20, Lifetime: time.Second})
			}()
			source, dest := boundedStream(t, left), boundedStream(t, right)
			p, _ := sender.Seal(ctx, []byte("one"))
			if wrongRoute {
				p.Route = b.Channel.SourceRoute
			}
			if e = source.Write(ctx, p); e != nil {
				t.Fatal(e)
			}
			if !wrongRoute {
				if _, e = dest.Read(ctx); e != nil {
					t.Fatal(e)
				}
				p, _ = sender.Seal(ctx, []byte("two"))
				if e = source.Write(ctx, p); e != nil {
					t.Fatal(e)
				}
			}
			select {
			case e := <-done:
				if e == nil {
					t.Fatal("relay accepted invalid route/budget")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("relay invalid packet did not stop")
			}
		})
	}
}
