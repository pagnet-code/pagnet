package e2ee

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	OwnerTextConsoleProtocol             = "pagnet/owner-text-console/v1"
	OwnerTextConsoleHPKEInfo             = "pagnet/owner-text-console/keys/v1"
	OwnerTextConsoleMaxPlaintext         = 64 * 1024
	OwnerTextConsoleSequenceLimit uint64 = 1 << 20
	OwnerTextConsoleClientToHost  byte   = 0
	OwnerTextConsoleHostToClient  byte   = 1
)

// OwnerTextConsoleDescriptor is immutable project and sender context. Decimal
// versions stay strings so JSON never rounds them through browser numbers.
type OwnerTextConsoleDescriptor struct {
	OwnershipScope             string `json:"ownershipScope"`
	Role                       string `json:"role"`
	ProjectContract            string `json:"projectContract"`
	TenantID                   string `json:"tenantId"`
	OwnerUserID                string `json:"ownerUserId"`
	ProjectID                  string `json:"projectId"`
	NetworkID                  string `json:"networkId"`
	SessionID                  string `json:"sessionId"`
	ProjectVersion             string `json:"projectVersion"`
	PolicyHash                 string `json:"policyHash"`
	ProjectDescriptorHash      []byte `json:"projectDescriptorHash"`
	SenderPrincipalID          string `json:"senderPrincipalId"`
	SenderInstallationID       string `json:"senderInstallationId"`
	ResponderPrincipalID       string `json:"responderPrincipalId"`
	ResponderInstallationID    string `json:"responderInstallationId"`
	HostID                     string `json:"hostId"`
	RunnerID                   string `json:"runnerId"`
	RunnerEpoch                string `json:"runnerEpoch"`
	HostCredentialID           string `json:"hostCredentialId"`
	SenderGeneration           string `json:"senderGeneration"`
	SenderClaimID              string `json:"senderClaimId"`
	SenderEndpointID           string `json:"senderEndpointId"`
	SenderEndpointCredentialID string `json:"senderEndpointCredentialId"`
	SenderEndpointStartedAt    string `json:"senderEndpointStartedAt"`
	SenderProofID              string `json:"senderProofId"`
	BrowserX25519Pub           []byte `json:"browserX25519Pub"`
	HostX25519Pub              []byte `json:"hostX25519Pub"`
	HostEd25519Pub             []byte `json:"hostEd25519Pub"`
	IssuedAtUnixSeconds        uint64 `json:"issuedAtUnixSeconds"`
	ExpiresAtUnixSeconds       uint64 `json:"expiresAtUnixSeconds"`
}

// strictConsoleJSON rejects duplicate names at every depth as well as trailing
// values. Decoding into a struct separately rejects unknown fields.
func strictConsoleJSON(data []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var scan func() error
	scan = func() error {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("e2ee: duplicate console JSON field")
				}
				seen[name] = true
				if err := scan(); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := scan(); err != nil {
					return err
				}
			}
		default:
			return errors.New("e2ee: invalid console JSON")
		}
		_, err = d.Token()
		return err
	}
	if err := scan(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("e2ee: trailing console JSON")
	}
	// encoding/json otherwise accepts case-insensitive aliases for struct fields.
	var names map[string]json.RawMessage
	if err := json.Unmarshal(data, &names); err != nil {
		return err
	}
	targetType := reflect.TypeOf(target).Elem()
	allowed := make(map[string]bool, targetType.NumField())
	for i := 0; i < targetType.NumField(); i++ {
		allowed[targetType.Field(i).Tag.Get("json")] = true
	}
	if len(names) != len(allowed) {
		return errors.New("e2ee: missing or unknown console JSON field")
	}
	for name := range names {
		if !allowed[name] {
			return errors.New("e2ee: unknown console JSON field")
		}
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(target)
}

func (d *OwnerTextConsoleDescriptor) UnmarshalJSON(data []byte) error {
	type descriptor OwnerTextConsoleDescriptor
	var decoded descriptor
	if err := strictConsoleJSON(data, &decoded); err != nil {
		return err
	}
	// Go's base64 decoder accepts newlines; require canonical padded base64.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if len(fields) != 30 {
		return errors.New("e2ee: missing console descriptor field")
	}
	for name, value := range map[string]uint64{"issuedAtUnixSeconds": decoded.IssuedAtUnixSeconds, "expiresAtUnixSeconds": decoded.ExpiresAtUnixSeconds} {
		if string(fields[name]) != strconv.FormatUint(value, 10) {
			return errors.New("e2ee: noncanonical console timestamp integer")
		}
	}
	for name, value := range map[string][]byte{"projectDescriptorHash": decoded.ProjectDescriptorHash, "browserX25519Pub": decoded.BrowserX25519Pub, "hostX25519Pub": decoded.HostX25519Pub, "hostEd25519Pub": decoded.HostEd25519Pub} {
		var text string
		if err := json.Unmarshal(fields[name], &text); err != nil || text != base64.StdEncoding.EncodeToString(value) {
			return errors.New("e2ee: noncanonical console base64")
		}
	}
	result := OwnerTextConsoleDescriptor(decoded)
	if _, err := EncodeOwnerTextConsoleDescriptor(result); err != nil {
		return err
	}
	*d = result
	return nil
}

func consoleEpoch(s string) bool {
	const layout = "2006-01-02T15:04:05.000000000Z"
	t, err := time.Parse(layout, s)
	return err == nil && !t.IsZero() && t.Format(layout) == s
}

func consoleDecimal(s string) bool {
	n, err := strconv.ParseUint(s, 10, 63)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == s
}

// EncodeOwnerTextConsoleDescriptor returns canonical B, with fixed scope, role,
// contract and field order. It never changes mailbox v1's encoding.
func EncodeOwnerTextConsoleDescriptor(d OwnerTextConsoleDescriptor) ([]byte, error) {
	if d.OwnershipScope != "personal" || d.Role != "sender" || d.ProjectContract != "owner_text_project_v1" {
		return nil, errors.New("e2ee: invalid console scope, role or contract")
	}
	ids := []string{d.TenantID, d.OwnerUserID, d.ProjectID, d.NetworkID, d.SessionID, d.SenderPrincipalID, d.SenderInstallationID, d.ResponderPrincipalID, d.ResponderInstallationID, d.HostID, d.RunnerID, d.HostCredentialID, d.SenderClaimID, d.SenderEndpointID, d.SenderEndpointCredentialID, d.SenderProofID}
	for _, id := range ids {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed.String() != id {
			return nil, errors.New("e2ee: invalid console UUID")
		}
	}
	if !consoleDecimal(d.ProjectVersion) || !consoleDecimal(d.SenderGeneration) {
		return nil, errors.New("e2ee: invalid console decimal")
	}
	if !consoleEpoch(d.RunnerEpoch) || !consoleEpoch(d.SenderEndpointStartedAt) {
		return nil, errors.New("e2ee: noncanonical console epoch")
	}
	policy, err := hex.DecodeString(d.PolicyHash)
	if err != nil || len(policy) != 32 || hex.EncodeToString(policy) != d.PolicyHash {
		return nil, errors.New("e2ee: invalid console policy hash")
	}
	for _, value := range [][]byte{d.ProjectDescriptorHash, d.BrowserX25519Pub, d.HostX25519Pub, d.HostEd25519Pub} {
		if len(value) != 32 {
			return nil, errors.New("e2ee: invalid console hash or key length")
		}
	}
	const safe = 1<<53 - 1
	if d.IssuedAtUnixSeconds > safe || d.ExpiresAtUnixSeconds > safe || d.ExpiresAtUnixSeconds <= d.IssuedAtUnixSeconds || d.ExpiresAtUnixSeconds-d.IssuedAtUnixSeconds > 900 {
		return nil, errors.New("e2ee: invalid console lifetime")
	}
	b := []byte("pagnet/owner-text-console/session/v1\x00")
	fields := [][]byte{}
	add := func(values ...string) {
		for _, v := range values {
			fields = append(fields, []byte(v))
		}
	}
	add(d.OwnershipScope, d.Role, d.ProjectContract, d.TenantID, d.OwnerUserID, d.ProjectID, d.NetworkID, d.SessionID, d.ProjectVersion)
	fields = append(fields, policy, d.ProjectDescriptorHash)
	add(d.SenderPrincipalID, d.SenderInstallationID, d.ResponderPrincipalID, d.ResponderInstallationID, d.HostID, d.RunnerID, d.RunnerEpoch, d.HostCredentialID, d.SenderGeneration, d.SenderClaimID, d.SenderEndpointID, d.SenderEndpointCredentialID, d.SenderEndpointStartedAt, d.SenderProofID)
	fields = append(fields, d.BrowserX25519Pub, d.HostX25519Pub, d.HostEd25519Pub)
	for _, v := range fields {
		b = ownerMailboxField(b, v)
	}
	b = binary.BigEndian.AppendUint64(b, d.IssuedAtUnixSeconds)
	return binary.BigEndian.AppendUint64(b, d.ExpiresAtUnixSeconds), nil
}

type OwnerTextConsoleKeys struct {
	ClientToHost [32]byte
	HostToClient [32]byte
}
type OwnerTextConsoleBootstrap struct {
	Enc        []byte `json:"enc"`
	Ciphertext []byte `json:"ct"`
	Signature  []byte `json:"signature"`
}

func (b *OwnerTextConsoleBootstrap) UnmarshalJSON(data []byte) error {
	type bootstrap OwnerTextConsoleBootstrap
	var decoded bootstrap
	if err := strictConsoleJSON(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for name, value := range map[string][]byte{"enc": decoded.Enc, "ct": decoded.Ciphertext, "signature": decoded.Signature} {
		var text string
		if err := json.Unmarshal(fields[name], &text); err != nil || text != base64.StdEncoding.EncodeToString(value) {
			return errors.New("e2ee: noncanonical console bootstrap base64")
		}
	}
	if len(decoded.Enc) != 32 || len(decoded.Ciphertext) != 80 || len(decoded.Signature) != 64 {
		return errors.New("e2ee: invalid console bootstrap lengths")
	}
	*b = OwnerTextConsoleBootstrap(decoded)
	return nil
}

func OwnerTextConsoleBootstrapTranscript(d OwnerTextConsoleDescriptor, enc, ct []byte) ([]byte, error) {
	b, err := EncodeOwnerTextConsoleDescriptor(d)
	if err != nil {
		return nil, err
	}
	if len(enc) != 32 || len(ct) != 80 {
		return nil, errors.New("e2ee: invalid console HPKE lengths")
	}
	t := ownerMailboxField([]byte("pagnet/owner-text-console/bootstrap-signature/v1\x00"), b)
	return ownerMailboxField(ownerMailboxField(t, enc), ct), nil
}

func CreateOwnerTextConsoleBootstrap(d OwnerTextConsoleDescriptor, signer ed25519.PrivateKey) (OwnerTextConsoleBootstrap, OwnerTextConsoleKeys, error) {
	var bootstrap OwnerTextConsoleBootstrap
	var keys OwnerTextConsoleKeys
	b, err := EncodeOwnerTextConsoleDescriptor(d)
	if err != nil {
		return bootstrap, keys, err
	}
	if len(signer) != 64 || !bytes.Equal(signer.Public().(ed25519.PublicKey), d.HostEd25519Pub) {
		return bootstrap, keys, errors.New("e2ee: console signer mismatch")
	}
	material := make([]byte, 64)
	defer clear(material)
	if _, err = rand.Read(material); err != nil {
		return bootstrap, keys, err
	}
	enc, ct, err := HPKEWrap(d.BrowserX25519Pub, []byte(OwnerTextConsoleHPKEInfo), b, material)
	if err != nil {
		return bootstrap, keys, err
	}
	t, err := OwnerTextConsoleBootstrapTranscript(d, enc, ct)
	if err != nil {
		return bootstrap, keys, err
	}
	copy(keys.ClientToHost[:], material[:32])
	copy(keys.HostToClient[:], material[32:])
	return OwnerTextConsoleBootstrap{enc, ct, ed25519.Sign(signer, t)}, keys, nil
}

// VerifyOwnerTextConsoleBootstrap requires exact caller-pinned expected context.
// The authenticated server pins host keys; Ed25519 proves host key possession.
// A malicious control plane substituting those keys is outside this trust model.
func VerifyOwnerTextConsoleBootstrap(expected, d OwnerTextConsoleDescriptor, bootstrap OwnerTextConsoleBootstrap, browserPrivate []byte) (OwnerTextConsoleKeys, error) {
	var keys OwnerTextConsoleKeys
	pinned, err := EncodeOwnerTextConsoleDescriptor(expected)
	if err != nil {
		return keys, err
	}
	b, err := EncodeOwnerTextConsoleDescriptor(d)
	if err != nil {
		return keys, err
	}
	if !bytes.Equal(pinned, b) {
		return keys, errors.New("e2ee: console descriptor mismatch")
	}
	t, err := OwnerTextConsoleBootstrapTranscript(d, bootstrap.Enc, bootstrap.Ciphertext)
	if err != nil {
		return keys, err
	}
	if !ed25519.Verify(d.HostEd25519Pub, t, bootstrap.Signature) {
		return keys, errors.New("e2ee: invalid console signature")
	}
	material, err := HPKEUnwrap(browserPrivate, bootstrap.Enc, []byte(OwnerTextConsoleHPKEInfo), b, bootstrap.Ciphertext)
	if err != nil {
		return keys, fmt.Errorf("e2ee: console unwrap: %w", err)
	}
	defer clear(material)
	if len(material) != 64 {
		return keys, errors.New("e2ee: invalid console key material")
	}
	copy(keys.ClientToHost[:], material[:32])
	copy(keys.HostToClient[:], material[32:])
	return keys, nil
}

func OwnerTextConsoleFrameAAD(d OwnerTextConsoleDescriptor, direction byte, seq uint64) ([]byte, error) {
	b, err := EncodeOwnerTextConsoleDescriptor(d)
	if err != nil {
		return nil, err
	}
	if direction > 1 || seq >= OwnerTextConsoleSequenceLimit {
		return nil, errors.New("e2ee: invalid console frame direction or sequence")
	}
	hash := sha256.Sum256(b)
	aad := append([]byte("pagnet/owner-text-console/frame/v1\x00"), hash[:]...)
	aad = append(aad, direction)
	return binary.BigEndian.AppendUint64(aad, seq), nil
}
func SealOwnerTextConsoleFrame(d OwnerTextConsoleDescriptor, key []byte, direction byte, seq uint64, plaintext []byte) ([]byte, error) {
	aad, err := OwnerTextConsoleFrameAAD(d, direction, seq)
	if err != nil {
		return nil, err
	}
	if len(plaintext) > OwnerTextConsoleMaxPlaintext {
		return nil, errors.New("e2ee: console frame too large")
	}
	aead, nonce, err := ownerMailboxFrameCipher(key, seq)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}
func OpenOwnerTextConsoleFrame(d OwnerTextConsoleDescriptor, key []byte, direction byte, seq uint64, ct []byte) ([]byte, error) {
	aad, err := OwnerTextConsoleFrameAAD(d, direction, seq)
	if err != nil {
		return nil, err
	}
	if len(ct) < 16 || len(ct) > OwnerTextConsoleMaxPlaintext+16 {
		return nil, errors.New("e2ee: invalid console ciphertext size")
	}
	aead, nonce, err := ownerMailboxFrameCipher(key, seq)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ct, aad)
}

// OwnerTextConsoleSession serializes counters and owns copies of its context and
// keys. A failed receive permanently closes the session. Construct one instance
// per fresh bootstrap; never reuse its keys for a reconnect.
type OwnerTextConsoleSession struct {
	mu                                   sync.Mutex
	descriptor                           OwnerTextConsoleDescriptor
	keys                                 OwnerTextConsoleKeys
	transcriptHash                       string
	host                                 bool
	sentConfirm, receivedConfirm, closed bool
	sendSeq, receiveSeq                  uint64
	clock                                func() time.Time
}

func NewOwnerTextConsoleSession(d OwnerTextConsoleDescriptor, bootstrap OwnerTextConsoleBootstrap, keys OwnerTextConsoleKeys, host bool, clock func() time.Time) (*OwnerTextConsoleSession, error) {
	t, err := OwnerTextConsoleBootstrapTranscript(d, bootstrap.Enc, bootstrap.Ciphertext)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(d.HostEd25519Pub, t, bootstrap.Signature) {
		return nil, errors.New("e2ee: invalid console signature")
	}
	// JSON round-trip makes a deep copy and validates all wire fields.
	data, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	var cloned OwnerTextConsoleDescriptor
	if err = json.Unmarshal(data, &cloned); err != nil {
		return nil, err
	}
	if clock == nil {
		clock = time.Now
	}
	hash := sha256.Sum256(t)
	s := &OwnerTextConsoleSession{descriptor: cloned, keys: keys, host: host, transcriptHash: base64.StdEncoding.EncodeToString(hash[:]), clock: clock}
	if err = s.check(); err != nil {
		return nil, err
	}
	return s, nil
}
func (s *OwnerTextConsoleSession) check() error {
	if s.closed {
		return errors.New("e2ee: console session closed")
	}
	now := s.clock().Unix()
	if now < 0 || uint64(now) < s.descriptor.IssuedAtUnixSeconds || uint64(now) >= s.descriptor.ExpiresAtUnixSeconds {
		s.close()
		return errors.New("e2ee: console session expired or not yet valid")
	}
	return nil
}
func (s *OwnerTextConsoleSession) close() {
	s.closed = true
	clear(s.keys.ClientToHost[:])
	clear(s.keys.HostToClient[:])
}
func (s *OwnerTextConsoleSession) Close() { s.mu.Lock(); defer s.mu.Unlock(); s.close() }
func (s *OwnerTextConsoleSession) confirmation(host bool) []byte {
	kind := "client_confirm"
	if host {
		kind = "host_confirm"
	}
	return []byte(`{"version":1,"type":"` + kind + `","transcriptHash":"` + s.transcriptHash + `"}`)
}
func (s *OwnerTextConsoleSession) direction(send bool) (byte, []byte) {
	if s.host == send {
		return 1, s.keys.HostToClient[:]
	}
	return 0, s.keys.ClientToHost[:]
}
func (s *OwnerTextConsoleSession) SealConfirmation() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(); err != nil {
		return nil, err
	}
	if s.sentConfirm || (s.host && !s.receivedConfirm) {
		return nil, errors.New("e2ee: console confirmation order")
	}
	direction, key := s.direction(true)
	ct, err := SealOwnerTextConsoleFrame(s.descriptor, key, direction, 0, s.confirmation(s.host))
	if err != nil {
		return nil, err
	}
	s.sentConfirm = true
	s.sendSeq = 1
	return ct, nil
}
func (s *OwnerTextConsoleSession) OpenConfirmation(seq uint64, ct []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(); err != nil {
		return err
	}
	fail := func(err error) error { s.close(); return err }
	if seq != 0 || s.receivedConfirm || (!s.host && !s.sentConfirm) {
		return fail(errors.New("e2ee: console confirmation order"))
	}
	direction, key := s.direction(false)
	plain, err := OpenOwnerTextConsoleFrame(s.descriptor, key, direction, seq, ct)
	if err != nil {
		return fail(err)
	}
	defer clear(plain)
	if !bytes.Equal(plain, s.confirmation(!s.host)) {
		return fail(errors.New("e2ee: invalid console confirmation"))
	}
	s.receivedConfirm = true
	s.receiveSeq = 1
	return nil
}
func (s *OwnerTextConsoleSession) Seal(plain []byte) (uint64, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(); err != nil {
		return 0, nil, err
	}
	if !s.sentConfirm || !s.receivedConfirm {
		return 0, nil, errors.New("e2ee: console confirmation required")
	}
	direction, key := s.direction(true)
	seq := s.sendSeq
	ct, err := SealOwnerTextConsoleFrame(s.descriptor, key, direction, seq, plain)
	if err != nil {
		return 0, nil, err
	}
	s.sendSeq++
	return seq, ct, nil
}
func (s *OwnerTextConsoleSession) Open(seq uint64, ct []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(); err != nil {
		return nil, err
	}
	fail := func(err error) ([]byte, error) { s.close(); return nil, err }
	if !s.sentConfirm || !s.receivedConfirm || seq != s.receiveSeq {
		return fail(errors.New("e2ee: console sequence or confirmation mismatch"))
	}
	direction, key := s.direction(false)
	plain, err := OpenOwnerTextConsoleFrame(s.descriptor, key, direction, seq, ct)
	if err != nil {
		return fail(err)
	}
	s.receiveSeq++
	return plain, nil
}
