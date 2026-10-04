package federation

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

func unitForwardChannels(t *testing.T, c Config, g *forwardUnitGate) (*ForwardChannel, *ForwardChannel) {
	t.Helper()
	left, right := net.Pipe()
	a, e := NewDuplex(context.Background(), g.source, boundedStream(t, left), 8<<20)
	if e != nil {
		t.Fatal(e)
	}
	b, e := NewDuplex(context.Background(), c, boundedStream(t, right), 8<<20)
	if e != nil {
		t.Fatal(e)
	}
	source, _ := NewForwardChannel(a)
	destination, _ := NewForwardChannel(b)
	t.Cleanup(func() { source.Close(); destination.Close() })
	return source, destination
}
func TestEncryptedForwardBundleFragmentationRetainsExactUnitProofAndNumbers(t *testing.T) {
	c, b, key, g := forwardUnitFixture(t)
	for _, original := range []bool{true, false} {
		editUnitEnvelope(t, &b, original, func(e *fabric.Envelope) {
			e.Payload = json.RawMessage(`{"private":"` + strings.Repeat("x", 350000) + `","n":9007199254740993123456789}`)
		})
	}
	signUnitBundle(t, &b, key)
	source, dest := unitForwardChannels(t, c, g)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sent := make(chan error, 1)
	go func() { sent <- source.SendBundle(ctx, b) }()
	got, e := dest.ReceiveBundle(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = <-sent; e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(got.Original, b.Original) || !bytes.Equal(got.Forwarded, b.Forwarded) || !reflect.DeepEqual(got.Proof, b.Proof) {
		t.Fatal("fragmentation rewrote signed data")
	}
	called := false
	if e = VerifyForwardBundle(ctx, c, got, VerifyLimits{MaxLifetime: time.Minute}, func(context.Context, fabric.ExecutionContext) error { called = true; return nil }); e != nil || !called {
		t.Fatal("unit proof after real encrypted transport", e)
	}
}
func TestEncryptedForwardBundleRejectsOversizeAndIncompleteDigest(t *testing.T) {
	for _, oversize := range []bool{true, false} {
		t.Run(map[bool]string{true: "oversize", false: "digest"}[oversize], func(t *testing.T) {
			c, b, _, g := forwardUnitFixture(t)
			source, dest := unitForwardChannels(t, c, g)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			raw, e := EncodeForwardBundle(b)
			if e != nil {
				t.Fatal(e)
			}
			sent := make(chan error, 1)
			go func() {
				head := make([]byte, 37)
				head[0] = bundleStart
				size := uint32(len(raw))
				if oversize {
					size = MaxForwardBundleBytes + 1
				}
				binary.BigEndian.PutUint32(head[1:], size)
				if e := source.transport.Send(ctx, head); e != nil {
					sent <- e
					return
				}
				if oversize {
					sent <- nil
					return
				}
				if e := source.transport.Send(ctx, append([]byte{bundleChunk}, raw...)); e != nil {
					sent <- e
					return
				}
				end := make([]byte, 33)
				end[0] = bundleEnd
				sent <- source.transport.Send(ctx, end)
			}()
			if b, e := dest.ReceiveBundle(ctx); e == nil || len(b.Original) != 0 || len(b.Forwarded) != 0 {
				t.Fatal("invalid document became visible")
			}
			select {
			case <-sent:
			case <-time.After(time.Second):
				t.Fatal("failed receiver did not unblock producer")
			}
		})
	}
}
