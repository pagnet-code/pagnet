// Package nativecontent implements bounded complete encrypted native content.
// Staged fragments are not complete evidence; only a verified whole reference
// may be attached by the server's observation commit transaction.
package nativecontent

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

var ErrInvalid = errors.New("invalid or incomplete native content")

type Transfer struct {
	Reference transport.NativeContentReference
	Fragments []transport.NativeContentFragment
}

func digest(plain []byte) string { s := sha256.Sum256(plain); return hex.EncodeToString(s[:]) }

// Build must finish and its exact output must COMMIT to the local outbox before
// any network send. Retries retrieve persisted ciphertext; they never Build again.
func Build(plain []byte, key [32]byte, aad e2ee.AAD, binding e2ee.NativeContentBinding, mimeType string) (Transfer, error) {
	if len(plain) == 0 || len(plain) > transport.NativeContentMaxPlaintextBytes || len(mimeType) == 0 || len(mimeType) > 128 {
		return Transfer{}, ErrInvalid
	}
	if requiresUTF8(mimeType) && !utf8.Valid(plain) {
		return Transfer{}, ErrInvalid
	}
	count := (len(plain) + transport.NativeContentFragmentPlaintextBytes - 1) / transport.NativeContentFragmentPlaintextBytes
	binding.Format = e2ee.NativeContentBindingFormat
	binding.FragmentCount = count
	binding.Ordinal = nil
	aad.NativeContent = &binding
	if aad.ValidateScope() != nil {
		return Transfer{}, ErrInvalid
	}
	manifest := transport.NativeContentManifest{Format: transport.NativeContentManifestFormat, ContentID: binding.ContentID, Purpose: binding.Purpose, MimeType: mimeType, PlaintextBytes: int64(len(plain)), PlaintextDigest: digest(plain)}
	ref := transport.NativeContentReference{Format: transport.NativeContentFormat, ContentID: binding.ContentID, ObservationID: binding.ObservationID, OriginID: binding.OriginID, InstanceID: binding.InstanceID, NativeGeneration: binding.NativeGeneration, NativeSessionID: binding.NativeSessionID, SubjectType: binding.SubjectType, SubjectID: binding.SubjectID, Purpose: binding.Purpose, FragmentCount: count, ManifestAAD: aad, CiphertextDigest: strings.Repeat("0", 64)}
	transfer := Transfer{Reference: ref}
	for index, offset := 0, 0; offset < len(plain); index++ {
		size := min(transport.NativeContentFragmentPlaintextBytes, len(plain)-offset)
		part := plain[offset : offset+size]
		fragmentAAD := fragmentAAD(aad, index)
		encrypted, err := e2ee.Encrypt(part, key, fragmentAAD)
		if err != nil {
			return Transfer{}, err
		}
		transfer.Fragments = append(transfer.Fragments, transport.NativeContentFragment{ContentID: binding.ContentID, Ordinal: index, Envelope: encrypted, AAD: fragmentAAD})
		manifest.Chunks = append(manifest.Chunks, transport.NativeContentChunkDescription{Ordinal: index, Offset: int64(offset), Length: size, PlaintextDigest: digest(part)})
		offset += size
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil || len(manifestRaw) > transport.NativeContentMaxManifestPlaintextBytes {
		return Transfer{}, ErrInvalid
	}
	defer clear(manifestRaw)
	transfer.Reference.ManifestEnvelope, err = e2ee.Encrypt(manifestRaw, key, aad)
	if err != nil {
		return Transfer{}, err
	}
	total, err := ciphertextLength(transfer.Reference.ManifestEnvelope, transport.NativeContentMaxManifestPlaintextBytes+16)
	if err != nil {
		return Transfer{}, err
	}
	for _, fragment := range transfer.Fragments {
		n, err := ciphertextLength(fragment.Envelope, transport.NativeContentFragmentPlaintextBytes+16)
		if err != nil {
			return Transfer{}, err
		}
		total += n
	}
	transfer.Reference.CiphertextBytes = total
	transfer.Reference.CiphertextDigest, err = CiphertextCommitment(transfer.Reference, transfer.Fragments)
	if err != nil {
		return Transfer{}, err
	}
	return transfer, nil
}

func fragmentAAD(manifest e2ee.AAD, index int) e2ee.AAD {
	result := manifest
	binding := *manifest.NativeContent
	binding.Ordinal = &index
	result.NativeContent = &binding
	result.ObjectType = e2ee.ObjectTypeNativeContentFragment
	result.ObjectID, _ = e2ee.NativeContentFragmentID(binding.ContentID, index)
	return result
}

func ciphertextLength(envelope e2ee.EncryptedPayloadV1, maxBytes int) (int64, error) {
	if len(envelope.Ciphertext) > base64.StdEncoding.EncodedLen(maxBytes) || envelope.Validate() != nil {
		return 0, ErrInvalid
	}
	raw, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil || len(raw) < 16 || len(raw) > maxBytes {
		return 0, ErrInvalid
	}
	return int64(len(raw)), nil
}

func ValidateReference(ref transport.NativeContentReference) error {
	if ref.Format != transport.NativeContentFormat || ref.FragmentCount < 1 || ref.FragmentCount > e2ee.NativeContentMaxFragments || ref.CiphertextBytes < 1 || ref.CiphertextBytes > transport.NativeContentMaxCiphertextBytes || len(ref.CiphertextDigest) != 64 {
		return ErrInvalid
	}
	if _, err := hex.DecodeString(ref.CiphertextDigest); err != nil {
		return ErrInvalid
	}
	a := ref.ManifestAAD
	b := a.NativeContent
	created, err := time.Parse(time.RFC3339Nano, a.CreatedAt)
	if err != nil || created.UTC().Format(time.RFC3339Nano) != a.CreatedAt || a.ProtocolVersion != transport.ProtocolVersion || len(a.KeyEpochID) == 0 || len(a.KeyEpochID) > 256 || len(a.Recipient) > 256 {
		return ErrInvalid
	}
	if a.ValidateScope() != nil || b == nil || b.Ordinal != nil || b.ContentID != ref.ContentID || b.ObservationID != ref.ObservationID || b.OriginID != ref.OriginID || b.InstanceID != ref.InstanceID || b.NativeGeneration != ref.NativeGeneration || b.NativeSessionID != ref.NativeSessionID || b.SubjectType != ref.SubjectType || b.SubjectID != ref.SubjectID || b.Purpose != ref.Purpose || b.FragmentCount != ref.FragmentCount || ref.ManifestEnvelope.KeyEpochID != a.KeyEpochID {
		return ErrInvalid
	}
	_, err = ciphertextLength(ref.ManifestEnvelope, transport.NativeContentMaxManifestPlaintextBytes+16)
	return err
}

func ValidateFragment(ref transport.NativeContentReference, fragment transport.NativeContentFragment) error {
	if ValidateReference(ref) != nil {
		return ErrInvalid
	}
	return validateFragment(ref, fragment)
}

func validateFragment(ref transport.NativeContentReference, fragment transport.NativeContentFragment) error {
	if fragment.ContentID != ref.ContentID || fragment.Ordinal < 0 || fragment.Ordinal >= ref.FragmentCount || fragment.Envelope.KeyEpochID != ref.ManifestAAD.KeyEpochID {
		return ErrInvalid
	}
	expected := fragmentAAD(ref.ManifestAAD, fragment.Ordinal)
	if !bytes.Equal(expected.CanonicalBytes(), fragment.AAD.CanonicalBytes()) || fragment.AAD.ValidateScope() != nil {
		return ErrInvalid
	}
	_, err := ciphertextLength(fragment.Envelope, transport.NativeContentFragmentPlaintextBytes+16)
	return err
}

func field(hash hash.Hash, value []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	hash.Write(size[:])
	hash.Write(value)
}
func ordinal(hash hash.Hash, index int) {
	var value [4]byte
	binary.BigEndian.PutUint32(value[:], uint32(index))
	hash.Write(value[:])
}

// CiphertextCommitment hashes only randomized ciphertext and public AAD. The
// canonical ordered, length-prefixed encoding is shared with browser consumers.
func CiphertextCommitment(ref transport.NativeContentReference, fragments []transport.NativeContentFragment) (string, error) {
	if ValidateReference(ref) != nil || len(fragments) != ref.FragmentCount {
		return "", ErrInvalid
	}
	hash := sha256.New()
	hash.Write([]byte("pagnet/native-content/ciphertext/v1\x00"))
	raw, err := ref.ManifestEnvelope.CanonicalJSON()
	if err != nil {
		return "", err
	}
	field(hash, raw)
	field(hash, ref.ManifestAAD.CanonicalBytes())
	ordinal(hash, ref.FragmentCount)
	total, err := ciphertextLength(ref.ManifestEnvelope, transport.NativeContentMaxManifestPlaintextBytes+16)
	if err != nil {
		return "", err
	}
	for index, fragment := range fragments {
		if fragment.Ordinal != index || validateFragment(ref, fragment) != nil {
			return "", ErrInvalid
		}
		ordinal(hash, index)
		field(hash, fragment.AAD.CanonicalBytes())
		raw, err := fragment.Envelope.CanonicalJSON()
		if err != nil {
			return "", err
		}
		field(hash, raw)
		n, err := ciphertextLength(fragment.Envelope, transport.NativeContentFragmentPlaintextBytes+16)
		if err != nil {
			return "", err
		}
		total += n
	}
	if total != ref.CiphertextBytes {
		return "", ErrInvalid
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Open returns content only after whole ciphertext, manifest and every ordered
// plaintext fragment authenticate. Callers clear the returned private buffer.
func Open(ref transport.NativeContentReference, fragments []transport.NativeContentFragment, key [32]byte) ([]byte, string, error) {
	commitment, err := CiphertextCommitment(ref, fragments)
	if err != nil || commitment != ref.CiphertextDigest {
		return nil, "", ErrInvalid
	}
	raw, err := e2ee.Decrypt(ref.ManifestEnvelope, key, ref.ManifestAAD)
	if err != nil {
		return nil, "", err
	}
	defer clear(raw)
	var manifest transport.NativeContentManifest
	if json.Unmarshal(raw, &manifest) != nil || manifest.Format != transport.NativeContentManifestFormat || manifest.ContentID != ref.ContentID || manifest.Purpose != ref.Purpose || manifest.PlaintextBytes < 1 || manifest.PlaintextBytes > transport.NativeContentMaxPlaintextBytes || len(manifest.MimeType) == 0 || len(manifest.MimeType) > 128 || len(manifest.Chunks) != ref.FragmentCount {
		return nil, "", ErrInvalid
	}
	result := make([]byte, 0, int(manifest.PlaintextBytes))
	success := false
	defer func() {
		if !success {
			clear(result)
		}
	}()
	for index, fragment := range fragments {
		description := manifest.Chunks[index]
		if description.Ordinal != index || description.Offset != int64(len(result)) || description.Length < 1 || description.Length > transport.NativeContentFragmentPlaintextBytes || int64(len(result)+description.Length) > manifest.PlaintextBytes {
			return nil, "", ErrInvalid
		}
		part, err := e2ee.Decrypt(fragment.Envelope, key, fragment.AAD)
		if err != nil {
			return nil, "", err
		}
		if len(part) != description.Length || digest(part) != description.PlaintextDigest {
			clear(part)
			return nil, "", ErrInvalid
		}
		result = append(result, part...)
		clear(part)
	}
	if int64(len(result)) != manifest.PlaintextBytes || digest(result) != manifest.PlaintextDigest {
		return nil, "", ErrInvalid
	}
	if requiresUTF8(manifest.MimeType) && !utf8.Valid(result) {
		return nil, "", ErrInvalid
	}
	success = true
	return result, manifest.MimeType, nil
}

func requiresUTF8(mimeType string) bool {
	return strings.HasPrefix(mimeType, "text/") || mimeType == "application/json"
}
