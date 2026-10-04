package federation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

type testKeys struct {
	public  [32]byte
	private []byte
}

func (k testKeys) ExchangePrivateKey(_ context.Context, p PeerBinding) ([]byte, error) {
	if p.ExchangePublicKey != k.public {
		return nil, authError()
	}
	return bytes.Clone(k.private), nil
}

type testRootGate struct {
	mu        sync.Mutex
	stores    []*registry.Store
	peers     []PeerBinding
	revoked   bool
	duplicate bool
}

func (g *testRootGate) WithCurrent(ctx context.Context, local, remote PeerBinding, f func(context.Context) error) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.revoked {
		return authError()
	}
	for _, p := range []PeerBinding{local, remote} {
		found := false
		for i, expected := range g.peers {
			current, e := g.stores[i].CurrentAuthorityIdentity(ctx)
			if e == nil && reflect.DeepEqual(current, p.Authority) && reflect.DeepEqual(expected, p) {
				found = true
			}
		}
		if !found {
			return authError()
		}
	}
	e := f(ctx)
	if g.duplicate {
		_ = f(ctx)
	}
	return e
}
func cryptoFixture(t *testing.T) (Config, Config, *testRootGate) {
	t.Helper()
	g := &testRootGate{}
	var configs [2]Config
	for i := range 2 {
		owner := fabric.Principal{Ref: "operator", Kind: "local.owner", Issuer: "actual.local"}
		store, e := registry.Bootstrap(context.Background(), filepath.Join(t.TempDir(), "domain"), owner)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { store.Close() })
		public, private, e := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
		if e != nil {
			t.Fatal(e)
		}
		p, e := public.MarshalBinary()
		if e != nil {
			t.Fatal(e)
		}
		s, e := private.MarshalBinary()
		if e != nil {
			t.Fatal(e)
		}
		var pk [32]byte
		copy(pk[:], p)
		peer := PeerBinding{Authority: store.AuthorityIdentity(), ExchangePublicKey: pk, ExchangeKeyRevision: 1, BindingDigest: sha256.Sum256(p), ExpiresAt: time.Now().UTC().Add(time.Hour)}
		g.peers = append(g.peers, peer)
		g.stores = append(g.stores, store)
		configs[i] = Config{Local: peer, Keys: testKeys{pk, s}, Trust: g, MaxRecords: 128}
	}
	var channel ChannelBinding
	rand.Read(channel.ID[:])
	rand.Read(channel.SourceRoute[:])
	rand.Read(channel.DestinationRoute[:])
	configs[0].Channel = channel
	configs[1].Channel = channel
	configs[0].SourceRole = true
	configs[1].SourceRole = false
	configs[0].Remote = configs[1].Local
	configs[1].Remote = configs[0].Local
	return configs[0], configs[1], g
}
func TestAuthenticatedHPKEBothDirectionsOpaqueExactRecord(t *testing.T) {
	a, b, _ := cryptoFixture(t)
	ctx := context.Background()
	sender, e := NewSender(ctx, a)
	if e != nil {
		t.Fatal(e)
	}
	receiver, e := NewReceiver(b)
	if e != nil {
		t.Fatal(e)
	}
	secret := []byte(`{"principal":"private owner","query":"private query","name":"private service","ref":"pagnet://private/ref","schema":"private schema","input":{"n":9007199254740993123456789}}`)
	for i := range 3 {
		packet, e := sender.Seal(ctx, secret)
		if e != nil {
			t.Fatal(e)
		}
		raw, e := EncodePacket(packet)
		if e != nil {
			t.Fatal(e)
		}
		for _, marker := range [][]byte{[]byte("private"), []byte(a.Local.Authority.Namespace), []byte(a.Local.Authority.StoreID)} {
			if bytes.Contains(raw, marker) {
				t.Fatal("relay saw private semantics")
			}
		}
		if i == 0 && len(packet.Encapsulation) != 32 || i > 0 && len(packet.Encapsulation) != 0 {
			t.Fatal("HPKE encapsulation profile changed")
		}
		decoded, e := DecodePacket(raw)
		if e != nil {
			t.Fatal(e)
		}
		plain, e := receiver.Open(ctx, decoded)
		if e != nil || !bytes.Equal(plain, secret) {
			t.Fatal("authenticated exact-byte record changed", e)
		}
	}
	reverse, e := NewSender(ctx, b)
	if e != nil {
		t.Fatal(e)
	}
	source, e := NewReceiver(a)
	if e != nil {
		t.Fatal(e)
	}
	packet, e := reverse.Seal(ctx, []byte("actual response"))
	if e != nil {
		t.Fatal(e)
	}
	if packet.Direction != 2 || packet.Route != a.Channel.SourceRoute {
		t.Fatal("reverse direction mismatch")
	}
	plain, e := source.Open(ctx, packet)
	if e != nil || string(plain) != "actual response" {
		t.Fatal("reverse auth", e)
	}
}
func TestAuthenticatedHPKEReplayTamperAndCrossBindingDenied(t *testing.T) {
	for _, name := range []string{"cipher", "ordinal", "channel", "route", "direction", "encapsulation", "binding", "sender-key", "receiver-key", "expired", "revoked"} {
		t.Run(name, func(t *testing.T) {
			a, b, g := cryptoFixture(t)
			ctx := context.Background()
			sender, e := NewSender(ctx, a)
			if e != nil {
				t.Fatal(e)
			}
			packet, e := sender.Seal(ctx, []byte("secret"))
			if e != nil {
				t.Fatal(e)
			}
			switch name {
			case "cipher":
				packet.Ciphertext = bytes.Clone(packet.Ciphertext)
				packet.Ciphertext[len(packet.Ciphertext)-1] ^= 1
			case "ordinal":
				packet.Ordinal++
			case "channel":
				packet.Channel[0] ^= 1
			case "route":
				packet.Route[0] ^= 1
			case "direction":
				packet.Direction = 2
			case "encapsulation":
				packet.Encapsulation = bytes.Clone(packet.Encapsulation)
				packet.Encapsulation[0] ^= 1
			case "binding":
				b.Remote.BindingDigest[0] ^= 1
			case "sender-key":
				b.Remote.ExchangePublicKey[0] ^= 1
			case "receiver-key":
				b.Local.ExchangePublicKey[0] ^= 1
			case "expired":
				b.Local.ExpiresAt = time.Now().UTC().Add(-time.Second)
			case "revoked":
				g.revoked = true
			}
			receiver, e := NewReceiver(b)
			if e != nil {
				return
			}
			if plain, e := receiver.Open(ctx, packet); e == nil || len(plain) != 0 {
				t.Fatal("forged record accepted")
			}
		})
	}
	a, b, _ := cryptoFixture(t)
	sender, _ := NewSender(context.Background(), a)
	receiver, _ := NewReceiver(b)
	packet, _ := sender.Seal(context.Background(), []byte("once"))
	if _, e := receiver.Open(context.Background(), packet); e != nil {
		t.Fatal(e)
	}
	if _, e := receiver.Open(context.Background(), packet); e == nil {
		t.Fatal("same-channel replay accepted")
	}
	next, _ := sender.Seal(context.Background(), []byte("next"))
	if _, e := receiver.Open(context.Background(), next); e == nil {
		t.Fatal("failed receiver silently recovered")
	}
}
func TestAuthenticatedHPKECurrentGateAndFiniteBudgets(t *testing.T) {
	a, b, g := cryptoFixture(t)
	ctx := context.Background()
	missing := a
	missing.Trust = nil
	if _, e := NewSender(ctx, missing); e == nil {
		t.Fatal("missing current trust gate")
	}
	g.duplicate = true
	if _, e := NewSender(ctx, a); e == nil {
		t.Fatal("duplicate ignored-gate callback accepted")
	}
	g.duplicate = false
	a.MaxRecords = 1
	b.MaxRecords = 1
	sender, e := NewSender(ctx, a)
	if e != nil {
		t.Fatal(e)
	}
	receiver, _ := NewReceiver(b)
	packet, e := sender.Seal(ctx, bytes.Repeat([]byte{'x'}, MaxRecordPlaintext))
	if e != nil {
		t.Fatal(e)
	}
	raw, e := EncodePacket(packet)
	if e != nil || len(raw) > MaxRecordWire {
		t.Fatal("wire budget", e)
	}
	if plain, e := receiver.Open(ctx, packet); e != nil || len(plain) != MaxRecordPlaintext {
		t.Fatal("bounded maximum", e)
	}
	if _, e = sender.Seal(ctx, []byte("overflow")); e == nil {
		t.Fatal("record budget ignored")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	newSender, _ := NewSender(ctx, a)
	if _, e = newSender.Seal(cancelled, []byte("cancelled")); !errors.Is(e, context.Canceled) && e == nil {
		t.Fatal("cancelled encryption")
	}
	if _, e = newSender.Seal(ctx, []byte("retry")); e == nil {
		t.Fatal("denied HPKE context reused")
	}
	if _, e = DecodePacket(append(raw, []byte(" {}")...)); e == nil {
		t.Fatal("trailing wire document accepted")
	}
	g.stores[0].Close()
	if _, e = NewSender(ctx, a); e == nil {
		t.Fatal("closed retained source root accepted")
	}
}
