package sessionworker

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
)

const captureChunkBytes = 64 << 10

// Local pending capture is not a transcript or a control-plane receipt.
const maxPrivateSourceBytes = 20 << 20

type NativeCaptureRef struct {
	Version          int    `json:"version"`
	CiphertextBytes  int    `json:"ciphertextBytes"`
	CiphertextDigest string `json:"ciphertextDigest"`
}
type NativeCaptureChunk struct {
	Offset int    `json:"offset"`
	Data   []byte `json:"data"`
}

func canonicalNativeJSON(value any) ([]byte, error) {
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte{'\n'}), nil
}

func captureAEAD(key []byte, scope Scope, directory string) (cipher.AEAD, error) {
	if len(key) != 32 || !filepath.IsAbs(directory) {
		return nil, errors.New("private source capture authority is missing")
	}
	info, err := canonicalNativeJSON(struct {
		Domain    string
		Scope     Scope
		Directory string
	}{"pagnet-worker-private-source-key-v1", scope, filepath.Clean(directory)})
	if err != nil {
		return nil, err
	}
	derived, err := hkdf.Key(sha256.New, key, nil, string(info), 32)
	if err != nil {
		return nil, err
	}
	defer clear(derived)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func captureAAD(scope Scope, directory string, observation NativeObservation) ([]byte, error) {
	// Origin bytes are retained exactly, rather than reconstructed on retry.
	return canonicalNativeJSON(struct {
		Domain                            string
		Version                           int
		Scope                             Scope
		Directory                         string
		ID                                string
		Origin                            []byte
		NativeGeneration, NativeSessionID string
		ObservedAt                        string
	}{"pagnet-worker-private-source-aad-v1", 1, scope, filepath.Clean(directory), observation.ID, []byte(observation.Origin), observation.NativeGeneration, observation.NativeSessionID, observation.ObservedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")})
}

func sealNativeCapture(key []byte, scope Scope, directory string, observation NativeObservation, source any) (*NativeCaptureRef, []byte, error) {
	raw, err := canonicalNativeJSON(source)
	if err != nil {
		return nil, nil, err
	}
	defer clear(raw)
	if len(raw) > maxPrivateSourceBytes {
		return nil, nil, errors.New("private native source exceeds pending capture bound")
	}
	aead, err := captureAEAD(key, scope, directory)
	if err != nil {
		return nil, nil, err
	}
	aad, err := captureAAD(scope, directory, observation)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	encrypted := aead.Seal(nonce, nonce, raw, aad)
	digest := sha256.Sum256(encrypted)
	return &NativeCaptureRef{Version: 1, CiphertextBytes: len(encrypted), CiphertextDigest: hex.EncodeToString(digest[:])}, encrypted, nil
}

// OpenNativeCapture is controller-local. Nothing here authorizes publication or
// native actuation; the exact original source is authenticated before use.
func OpenNativeCapture(key []byte, scope Scope, directory string, observation NativeObservation, encrypted []byte) (json.RawMessage, error) {
	ref := observation.Capture
	if ref == nil || ref.Version != 1 || ref.CiphertextBytes != len(encrypted) || len(encrypted) > maxPrivateSourceBytes+64 {
		return nil, errors.New("invalid private capture reference")
	}
	digest := sha256.Sum256(encrypted)
	if hex.EncodeToString(digest[:]) != ref.CiphertextDigest {
		return nil, errors.New("private capture ciphertext differs")
	}
	aead, err := captureAEAD(key, scope, directory)
	if err != nil {
		return nil, err
	}
	aad, err := captureAAD(scope, directory, observation)
	if err != nil {
		return nil, err
	}
	if len(encrypted) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("private capture is truncated")
	}
	raw, err := aead.Open(nil, encrypted[:aead.NonceSize()], encrypted[aead.NonceSize():], aad)
	if err != nil {
		return nil, err
	}
	if !json.Valid(raw) {
		clear(raw)
		return nil, errors.New("private capture source is invalid")
	}
	return raw, nil
}

// ReadCaptureChunk checks the current controller lease inside the same read
// transaction as the observation and ciphertext binding. Superseded controllers
// cannot read an old private source after a replacement obtains ownership.
func (j *Journal) ReadCaptureChunk(ctx context.Context, lease int64, id, digest string, offset int) (*NativeCaptureChunk, error) {
	if id == "" || len(id) > 256 || len(digest) != 64 || offset < 0 || offset%captureChunkBytes != 0 {
		return nil, errors.New("invalid private source cursor")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, _, err = checkLease(ctx, tx, lease); err != nil {
		return nil, err
	}
	var stored string
	var size int
	err = tx.QueryRowContext(ctx, `SELECT o.digest,c.size FROM worker_observations o JOIN worker_source_captures c ON c.id=o.id WHERE o.id=?`, id).Scan(&stored, &size)
	if err != nil {
		return nil, err
	}
	if stored != digest {
		return nil, ErrConflict
	}
	if offset >= size {
		return nil, errors.New("private source cursor outside capture")
	}
	var data []byte
	if err = tx.QueryRowContext(ctx, `SELECT substr(ciphertext,?,?) FROM worker_source_captures WHERE id=?`, offset+1, captureChunkBytes, id).Scan(&data); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &NativeCaptureChunk{Offset: offset, Data: data}, nil
}

func verifyCapture(ref *NativeCaptureRef, encrypted []byte) error {
	if ref == nil {
		if len(encrypted) != 0 {
			return ErrConflict
		}
		return nil
	}
	if ref.Version != 1 || ref.CiphertextBytes != len(encrypted) || len(encrypted) > maxPrivateSourceBytes+64 || len(encrypted) < 28 {
		return errors.New("invalid private source capture")
	}
	digest := sha256.Sum256(encrypted)
	if hex.EncodeToString(digest[:]) != ref.CiphertextDigest {
		return ErrConflict
	}
	return nil
}

func (j *Journal) initializeCaptures() error {
	_, err := j.db.Exec(`CREATE TABLE IF NOT EXISTS worker_source_captures(id TEXT PRIMARY KEY REFERENCES worker_observations(id) ON DELETE CASCADE,ciphertext BLOB NOT NULL,size INTEGER NOT NULL)`)
	if err != nil {
		return err
	}
	var orphan int
	if err = j.db.QueryRow(`SELECT COUNT(*) FROM worker_source_captures c LEFT JOIN worker_observations o ON o.id=c.id WHERE o.id IS NULL`).Scan(&orphan); err != nil {
		return err
	}
	if orphan != 0 {
		return errors.New("orphaned private source capture")
	}
	var count, size int
	if err = j.db.QueryRow(`SELECT COUNT(*),COALESCE(SUM(size),0)+(SELECT COALESCE(SUM(size),0) FROM worker_observations) FROM worker_source_captures`).Scan(&count, &size); err != nil {
		return err
	}
	if count > maxPendingObservations || size > maxPendingObservationBytes {
		return ErrFull
	}
	rows, err := j.db.Query(`SELECT o.payload,c.ciphertext,c.size FROM worker_observations o LEFT JOIN worker_source_captures c ON c.id=o.id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var payload, encrypted []byte
		var size *int
		if err = rows.Scan(&payload, &encrypted, &size); err != nil {
			return err
		}
		var observation NativeObservation
		if err = json.Unmarshal(payload, &observation); err != nil {
			return err
		}
		if size != nil && *size != len(encrypted) {
			return errors.New("private source capture size differs")
		}
		if err = verifyCapture(observation.Capture, encrypted); err != nil {
			return err
		}
	}
	return rows.Err()
}
