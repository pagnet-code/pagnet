// The local hosted-invocation admission chain (step 6b): the daemon prepares
// the deterministic sealed invocation input and admits it to the server over
// the exact authenticated host connection. Prepare mirrors
// PrepareHostedCatalog; Admit mirrors PublishHostedCatalog structurally.

package daemon

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/fabricagent"
	"github.com/pagnet-code/pagnet/transport"
)

// HostedInvocationCommandID derives the stable command identity for one hosted
// invocation. The server idempotency contract requires the client-supplied
// CommandID to be byte-stable across exact retries, and the journal's
// compareRetained treats a changed command as a conflict — so the command is a
// pure function of (the hosted actor principal, the invocation ID): sha256 of
// the canonical JSON [purpose, principal ref, invocation id], rendered as a
// canonical UUIDv4 string (ParseID-valid).
func HostedInvocationCommandID(principal fabric.Principal, invocationID string) string {
	raw, err := json.Marshal([3]string{"pagnet.hosted.invocation-command.v1", principal.Ref, invocationID})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(raw)
	// Canonicalize the version/variant nibbles so the derived ID is a valid
	// UUID for every input (the digest is otherwise arbitrary).
	id := append([]byte(nil), digest[:16]...)
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16])
}

// deterministicInvocationCreatedAt is the single deterministic clock source
// for the invocation AAD's CreatedAt: the timestamp embedded in a UUIDv7
// invocation ID. A non-v7 ID (the engine's random envelope IDs) carries no
// timestamp, and the AAD then carries none — no wall clock is ever consulted,
// so exact retries re-derive byte-identical AAD bytes.
func deterministicInvocationCreatedAt(invocationID string) string {
	id, err := uuid.Parse(invocationID)
	if err != nil {
		return ""
	}
	t, ok := uuidV7Time(id)
	if !ok {
		return ""
	}
	return t.Format(time.RFC3339)
}

// hostedInvocationSealPurpose is the HKDF purpose separating the hosted
// invocation seal from any other derivation under a key epoch.
const hostedInvocationSealPurpose = "pagnet.hosted.invocation.seal.v1"

// deterministicHostedSeal seals the invocation input under the network key
// epoch with DETERMINISTIC per-object keys: the CEK, payload nonce and wrap
// nonce are HKDF-derived from (epoch key, canonical AAD, sha256(plaintext)).
// e2ee.Encrypt uses fresh random values, which would defeat the retry contract
// (the journal's compareRetained and the server's body digest both require an
// exact retry to re-present byte-identical ciphertext/AAD). Determinism makes
// re-encryption idempotent: same (CEK, nonce) implies same plaintext, so GCM
// nonce reuse across distinct plaintexts is impossible by construction. The
// output is an ordinary v1 envelope: e2ee.Decrypt (and the daemon's
// decryptProtected) open it with the unchanged layout.
func deterministicHostedSeal(epochKey [32]byte, aad e2ee.AAD, plaintext []byte) (e2ee.EncryptedPayloadV1, e2ee.AAD, error) {
	sum := sha256.Sum256(plaintext)
	salt := make([]byte, 0, len(hostedInvocationSealPurpose)+1+len(aad.CanonicalBytes())+sha256.Size)
	salt = append(salt, hostedInvocationSealPurpose...)
	salt = append(salt, 0)
	salt = append(salt, aad.CanonicalBytes()...)
	salt = append(salt, sum[:]...)
	material, err := hkdf.Key[hash.Hash](sha256.New, epochKey[:], salt, hostedInvocationSealPurpose, 56)
	if err != nil {
		return e2ee.EncryptedPayloadV1{}, e2ee.AAD{}, fmt.Errorf("hosted invocation seal: %w", err)
	}
	defer clear(material)
	cek := [32]byte(material[:32])
	nonce := [12]byte(material[32:44])
	nonceWrap := [12]byte(material[44:56])
	epochAead, err := hostedSealGCM(epochKey)
	if err != nil {
		return e2ee.EncryptedPayloadV1{}, e2ee.AAD{}, err
	}
	// CEK wrap layout mirrors e2ee.wrapCEK: nonce(12) || GCM(CEK), no AAD.
	wrapped := make([]byte, 0, 12+32+16)
	wrapped = append(wrapped, nonceWrap[:]...)
	wrapped = append(wrapped, epochAead.Seal(nil, nonceWrap[:], cek[:], nil)...)
	// The payload is sealed under the CEK, bound to the canonical AAD.
	ceKead, err := hostedSealGCM(cek)
	if err != nil {
		return e2ee.EncryptedPayloadV1{}, e2ee.AAD{}, err
	}
	ciphertext := ceKead.Seal(nil, nonce[:], plaintext, aad.CanonicalBytes())
	return e2ee.EncryptedPayloadV1{
		Version:           e2ee.EnvelopeVersion,
		CipherSuite:       e2ee.CipherSuiteAES256GCM,
		KeyEpochID:        aad.KeyEpochID,
		Nonce:             base64.StdEncoding.EncodeToString(nonce[:]),
		Ciphertext:        base64.StdEncoding.EncodeToString(ciphertext),
		WrappedContentKey: base64.StdEncoding.EncodeToString(wrapped),
		AADVersion:        e2ee.AADVersion,
	}, aad, nil
}

func hostedSealGCM(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// PrepareHostedInvocation seals one hosted invocation input with the genuine
// original worker's cloud network key epoch. The invocationID is the engine's
// envelope ID (bounded printable text, never parsed as a UUID); the prompt is
// the RAW invoke payload bytes (byte-exact, never re-marshaled). The result is
// deterministic in (profile, epoch, invocationID, prompt): an exact retry
// re-derives the identical envelope and AAD. It refuses before sealing when
// the prompt is not the exact retained-prompt binding, an undeliverable prompt
// must never be sealed.
func (d *Daemon) PrepareHostedInvocation(ctx context.Context, profile fabricagent.HostedProfile, invocationID string, prompt []byte) (e2ee.EncryptedPayloadV1, e2ee.AAD, error) {
	if invocationID == "" || len(invocationID) > 256 || !utf8.ValidString(invocationID) {
		return e2ee.EncryptedPayloadV1{}, e2ee.AAD{}, fabric.NewError(fabric.CodeInvalidInput, "Hosted invocation identity is missing or invalid")
	}
	for _, r := range invocationID {
		if r < 32 || r == 127 {
			return e2ee.EncryptedPayloadV1{}, e2ee.AAD{}, fabric.NewError(fabric.CodeInvalidInput, "Hosted invocation identity is missing or invalid")
		}
	}
	if _, e := hostedInvocationPromptInput(prompt); e != nil {
		return e2ee.EncryptedPayloadV1{}, e2ee.AAD{}, fabric.NewError(fabric.CodeInvalidInput, "Hosted invocation prompt is not the exact retained-prompt binding")
	}
	if err := d.ProbeHostedProfile(ctx, profile); err != nil {
		return e2ee.EncryptedPayloadV1{}, e2ee.AAD{}, err
	}
	st, err := d.contentCryptoReady(profile.NetworkID)
	if err != nil {
		return e2ee.EncryptedPayloadV1{}, e2ee.AAD{}, err
	}
	kr, err := crypto.LoadKeyring(d.StateDir, st.NetworkID)
	if err != nil {
		return e2ee.EncryptedPayloadV1{}, e2ee.AAD{}, err
	}
	epoch, ok := kr.EpochByID(st.EpochID)
	if !ok {
		return e2ee.EncryptedPayloadV1{}, e2ee.AAD{}, fmt.Errorf("%s: epoch %s not in local keyring", errKeyEpochUnavailable, st.EpochID)
	}
	key, err := epoch.KeyArray()
	if err != nil {
		return e2ee.EncryptedPayloadV1{}, e2ee.AAD{}, err
	}
	defer clear(key[:])
	// The AAD binds the sealed input to the routing metadata: the network,
	// the exact invocation object, the host as sender and the worker instance
	// as recipient (the server contract). CreatedAt is deterministic (the ID's
	// embedded timestamp, if any) — never the wall clock.
	aad := e2ee.AAD{
		ProtocolVersion: transport.ProtocolVersion,
		TenantID:        st.TenantID,
		NetworkID:       profile.NetworkID,
		ObjectType:      e2ee.ObjectTypeInvocationInput,
		ObjectID:        invocationID,
		Sender:          profile.Scope.HostID,
		Recipient:       profile.Scope.InstanceID,
		CreatedAt:       deterministicInvocationCreatedAt(invocationID),
		KeyEpochID:      st.EpochID,
	}
	return deterministicHostedSeal(key, aad, prompt)
}

// AdmitHostedFabric admits one prepared hosted invocation to the server over
// the exact authenticated host connection. It is the structural mirror of
// PublishHostedCatalog: it never chooses another authenticated connection.
// Losing the original account/socket returns an error to the caller (deferred
// or conflict), never a replacement connection. The sealed record the caller
// reserved REMAINS on failure: an exact retry re-presents the retained bytes
// and retries the admission (the server idempotency is the effect authority).
func (d *Daemon) AdmitHostedFabric(ctx context.Context, profile fabricagent.HostedProfile, p transport.FabricHostedInvocation) (*transport.NativeDispatchProof, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.NetworkID != profile.NetworkID || p.InstanceID != profile.Scope.InstanceID || p.OwnershipID != profile.OwnershipID || p.OwnershipGeneration != profile.Scope.Generation {
		return nil, ErrNativeObservationConflict
	}
	if err := d.ProbeHostedProfile(ctx, profile); err != nil {
		return nil, err
	}
	d.nativeWorkersMu.Lock()
	link := d.nativeWorkers[profile.Scope.InstanceID]
	d.nativeWorkersMu.Unlock()
	if link == nil {
		return nil, ErrNativeOriginAdmissionDeferred
	}
	proxy, err := d.nativeWorkerFor(link.conn, profile.Scope.InstanceID)
	if err != nil || proxy != link.proxy || proxy.scope != profile.Scope {
		return nil, ErrNativeObservationConflict
	}
	d.connMu.Lock()
	connection := d.nativeConn
	current := d.curConn == link.conn
	d.connMu.Unlock()
	if connection == nil || !current {
		return nil, ErrNativeOriginAdmissionDeferred
	}
	session, err := connection.AuthenticatedNativeHostSession()
	if err != nil || session.TenantID != profile.Scope.TenantID || session.AccountID != profile.Scope.AccountID {
		return nil, ErrNativeObservationConflict
	}
	return connection.AdmitHostedFabric(ctx, p)
}
