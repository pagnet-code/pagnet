package federation

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"sync"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/pagnet-code/pagnet/fabric"
)

var suite = hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)

// Sender/Receiver are single-direction RFC9180 contexts. They are never
// reconstructed/reused after restart or error. Original invocation admission
// and explicit recovery are separate durable node responsibilities.
type Sender struct {
	mu            sync.Mutex
	config        Config
	sealer        hpke.Sealer
	encapsulation []byte
	next          uint64
	failed        bool
}
type Receiver struct {
	mu     sync.Mutex
	config Config
	opener hpke.Opener
	next   uint64
	failed bool
}

func direction(source bool) uint8 {
	if source {
		return 1
	}
	return 2
}
func receiverRoute(c Config, sending bool) [32]byte {
	if c.SourceRole == sending {
		return c.Channel.DestinationRoute
	}
	return c.Channel.SourceRoute
}
func checkPeer(p PeerBinding) bool {
	namespace, e := fabric.DomainNamespace(p.Authority.PublicKey[:])
	return e == nil && namespace == p.Authority.Namespace && p.Authority.StoreID != "" && p.Authority.KeyRevision > 0 && p.ExchangeKeyRevision > 0 && p.ExchangePublicKey != ([32]byte{}) && p.BindingDigest != ([32]byte{}) && time.Now().Before(p.ExpiresAt)
}
func checkConfig(c Config) error {
	if !checkPeer(c.Local) || !checkPeer(c.Remote) || c.Local.Authority.Namespace == c.Remote.Authority.Namespace || c.Keys == nil || c.Trust == nil || c.Channel.ID == ([32]byte{}) || c.Channel.SourceRoute == ([32]byte{}) || c.Channel.DestinationRoute == ([32]byte{}) || c.Channel.SourceRoute == c.Channel.DestinationRoute || c.MaxRecords == 0 || c.MaxRecords > MaxChannelRecords {
		return authError()
	}
	return nil
}
func info(c Config, sending bool) ([]byte, error) {
	source, destination := c.Local, c.Remote
	if !c.SourceRole {
		source, destination = destination, source
	}
	// This context is never emitted to the relay. Exact typed owners/keys/roots
	// and binding revisions are covered without string-concatenation ambiguity.
	return json.Marshal(struct {
		Profile             string
		Source, Destination PeerBinding
		Channel             ChannelBinding
		Direction           uint8
	}{Profile, source, destination, c.Channel, direction(c.SourceRole == sending)})
}
func aad(p Packet) []byte {
	raw := make([]byte, 0, 128)
	raw = append(raw, Profile...)
	raw = append(raw, 0)
	raw = append(raw, p.Channel[:]...)
	raw = append(raw, p.Route[:]...)
	raw = append(raw, p.Direction)
	raw = binary.BigEndian.AppendUint64(raw, p.Ordinal)
	// Encapsulation is fixed-size on the first record and absent thereafter.
	raw = append(raw, byte(len(p.Encapsulation)))
	raw = append(raw, p.Encapsulation...)
	return raw
}
func private(c Config, ctx context.Context) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, authError()
	}
	raw, e := c.Keys.ExchangePrivateKey(ctx, c.Local)
	if e != nil {
		return nil, e
	}
	if len(raw) != 32 {
		clear(raw)
		return nil, authError()
	}
	sk, e := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPrivateKey(raw)
	if e != nil {
		clear(raw)
		return nil, authError()
	}
	pub, e := sk.Public().MarshalBinary()
	if e != nil || !bytes.Equal(pub, c.Local.ExchangePublicKey[:]) {
		clear(raw)
		return nil, authError()
	}
	return raw, nil
}

// guarded rejects missing/duplicate/late callback results. A refused gate never
// leaves a potentially advanced HPKE context reusable.
func guarded(ctx context.Context, c Config, step func(context.Context) error) error {
	if ctx == nil || ctx.Err() != nil || checkConfig(c) != nil {
		return authError()
	}
	var gate sync.Mutex
	active, called := true, false
	rejected := false
	var stepError error
	e := c.Trust.WithCurrent(ctx, c.Local, c.Remote, func(current context.Context) error {
		gate.Lock()
		defer gate.Unlock()
		if !active || called || current == nil || current.Err() != nil || ctx.Err() != nil {
			rejected = true
			return authError()
		}
		called = true
		stepError = step(current)
		return stepError
	})
	gate.Lock()
	active = false
	ran := called
	failure := stepError
	invalid := rejected
	gate.Unlock()
	if e != nil {
		return e
	}
	if !ran || invalid {
		return authError()
	}
	if failure != nil {
		return failure
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}
func NewSender(ctx context.Context, c Config) (*Sender, error) {
	c = cloneConfig(c)
	if checkConfig(c) != nil {
		return nil, authError()
	}
	// Resolve the explicitly selected operator key before entering a current
	// peer SQL fence. Providers may perform bounded IO; crypto inside the fence
	// must not reenter the registry or invoke an external credential service.
	raw, e := private(c, ctx)
	if e != nil {
		return nil, e
	}
	defer clear(raw)
	s := &Sender{config: c}
	e = guarded(ctx, c, func(current context.Context) error {
		sk, e := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPrivateKey(raw)
		if e != nil {
			return authError()
		}
		pk, e := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPublicKey(c.Remote.ExchangePublicKey[:])
		if e != nil {
			return authError()
		}
		contextInfo, e := info(c, true)
		if e != nil {
			return e
		}
		sender, e := suite.NewSender(pk, contextInfo)
		if e != nil {
			return e
		}
		s.encapsulation, s.sealer, e = sender.SetupAuth(rand.Reader, sk)
		return e
	})
	if e != nil {
		return nil, e
	}
	return s, nil
}
func NewReceiver(c Config) (*Receiver, error) {
	c = cloneConfig(c)
	if checkConfig(c) != nil {
		return nil, authError()
	}
	return &Receiver{config: c}, nil
}
func (s *Sender) Seal(ctx context.Context, plaintext []byte) (Packet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed || s.next >= s.config.MaxRecords || len(plaintext) == 0 || len(plaintext) > MaxRecordPlaintext {
		return Packet{}, protocolError()
	}
	p := Packet{Profile: Profile, Channel: s.config.Channel.ID, Route: receiverRoute(s.config, true), Direction: direction(s.config.SourceRole), Ordinal: s.next}
	if s.next == 0 {
		p.Encapsulation = bytes.Clone(s.encapsulation)
	}
	e := guarded(ctx, s.config, func(current context.Context) error {
		var e error
		p.Ciphertext, e = s.sealer.Seal(plaintext, aad(p))
		return e
	})
	if e != nil {
		s.failed = true
		return Packet{}, e
	}
	s.next++
	return p, nil
}
func (r *Receiver) Open(ctx context.Context, p Packet) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed || r.next >= r.config.MaxRecords || p.Profile != Profile || p.Channel != r.config.Channel.ID || p.Route != receiverRoute(r.config, false) || p.Direction != direction(!r.config.SourceRole) || p.Ordinal != r.next || len(p.Ciphertext) < 16 || len(p.Ciphertext) > MaxRecordPlaintext+16 || (r.next == 0 && len(p.Encapsulation) != 32) || (r.next > 0 && len(p.Encapsulation) != 0) {
		r.failed = true
		return nil, protocolError()
	}
	var raw []byte
	if r.opener == nil {
		var e error
		raw, e = private(r.config, ctx)
		if e != nil {
			r.failed = true
			return nil, e
		}
		defer clear(raw)
	}
	var out []byte
	e := guarded(ctx, r.config, func(current context.Context) error {
		if r.opener == nil {
			sk, e := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPrivateKey(raw)
			if e != nil {
				return authError()
			}
			senderPub, e := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPublicKey(r.config.Remote.ExchangePublicKey[:])
			if e != nil {
				return authError()
			}
			contextInfo, e := info(r.config, false)
			if e != nil {
				return e
			}
			receiver, e := suite.NewReceiver(sk, contextInfo)
			if e != nil {
				return e
			}
			r.opener, e = receiver.SetupAuth(p.Encapsulation, senderPub)
			if e != nil {
				return authError()
			}
		}
		var e error
		out, e = r.opener.Open(p.Ciphertext, aad(p))
		if e != nil {
			return authError()
		}
		return nil
	})
	if e != nil {
		clear(out)
		r.failed = true
		return nil, e
	}
	r.next++
	return out, nil
}
func EncodePacket(p Packet) ([]byte, error) {
	if !validPacket(p) {
		return nil, protocolError()
	}
	raw, e := json.Marshal(p)
	if e != nil || len(raw) > MaxRecordWire {
		return nil, protocolError()
	}
	return raw, nil
}
func DecodePacket(raw []byte) (Packet, error) {
	var p Packet
	if e := fabric.DecodeJSONWithLimits(raw, &p, fabric.WireLimits{MaxBytes: MaxRecordWire, MaxDepth: 4, MaxMembers: 128}); e != nil {
		return p, e
	}
	// Relay-visible fields are a closed profile: extra semantic/tracing fields
	// must not be accidentally accepted and forwarded in an outer envelope.
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&p) != nil || !validPacket(p) {
		return Packet{}, protocolError()
	}
	return p, nil
}

func cloneConfig(c Config) Config {
	c.Local.Authority.PublicKey = bytes.Clone(c.Local.Authority.PublicKey)
	c.Remote.Authority.PublicKey = bytes.Clone(c.Remote.Authority.PublicKey)
	return c
}

func validPacket(p Packet) bool {
	return p.Profile == Profile && p.Channel != ([32]byte{}) && p.Route != ([32]byte{}) && (p.Direction == 1 || p.Direction == 2) && p.Ordinal < MaxChannelRecords && len(p.Ciphertext) >= 16 && len(p.Ciphertext) <= MaxRecordPlaintext+16 && ((p.Ordinal == 0 && len(p.Encapsulation) == 32) || (p.Ordinal > 0 && len(p.Encapsulation) == 0))
}
