package sessionworker

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"

	fabricidentity "github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
)

type localActivationEvidence struct {
	Origin    fabricidentity.Origin    `json:"origin"`
	Admission fabricidentity.Admission `json:"admission"`
}

func (j *Journal) initializeLocalActivations() error {
	if !j.isLocal() {
		return nil
	}
	_, e := j.db.Exec(`CREATE TABLE IF NOT EXISTS worker_local_activations(native_generation TEXT PRIMARY KEY,ciphertext BLOB NOT NULL CHECK(length(ciphertext)<=131072))`)
	return e
}
func localActivationAAD(scope AuthorityScope, dir, generation string) []byte {
	raw, _ := canonicalNativeJSON(struct {
		Purpose                     string
		Authority                   AuthorityScope
		Directory, NativeGeneration string
	}{"pagnet.worker.local-activation-evidence.v1", scope, dir, generation})
	return raw
}
func (j *Journal) retainLocalActivation(ctx context.Context, key []byte, r LocalActivationRequest, origin fabricidentity.Origin) error {
	if !j.isLocal() || r.Authority != j.authority || validateLocalReservation(j.authority, r.OriginalSource) != nil || nativeauthority.ValidateOriginalOrigin(j.authority, r.OriginalSource.Admission, origin, r.NativeGeneration) != nil {
		return ErrFenced
	}
	evidence := localActivationEvidence{Origin: origin, Admission: r.OriginalSource.Admission}
	plain, e := canonicalNativeJSON(evidence)
	if e != nil || len(plain) > 128<<10 {
		return ErrFull
	}
	defer clear(plain)
	aead, e := captureAEADBound(key, j.authority, j.dir)
	if e != nil {
		return e
	}
	nonce := make([]byte, aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	ciphertext := aead.Seal(nonce, nonce, plain, localActivationAAD(j.authority, j.dir, r.NativeGeneration))
	if len(ciphertext) > 128<<10 {
		return ErrFull
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, e := j.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	existing, e := j.localActivationEvidenceTx(ctx, tx, key, r.NativeGeneration)
	if e == nil {
		if !sameLocalJSON(existing.Origin, evidence.Origin) || !sameLocalJSON(existing.Admission, evidence.Admission) {
			return ErrConflict
		}
		return tx.Commit()
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	// A finite, explicit backpressure limit; no history is silently discarded.
	var count int
	if e = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM worker_local_activations`).Scan(&count); e != nil {
		return e
	}
	if count >= 128 {
		return ErrFull
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO worker_local_activations(native_generation,ciphertext) VALUES(?,?)`, r.NativeGeneration, ciphertext); e != nil {
		return e
	}
	return tx.Commit()
}
func (j *Journal) localActivationEvidenceTx(ctx context.Context, tx *sql.Tx, key []byte, generation string) (localActivationEvidence, error) {
	var result localActivationEvidence
	var ciphertext []byte
	if !j.isLocal() || generation == "" {
		return result, ErrFenced
	}
	if e := tx.QueryRowContext(ctx, `SELECT ciphertext FROM worker_local_activations WHERE native_generation=?`, generation).Scan(&ciphertext); e != nil {
		return result, e
	}
	aead, e := captureAEADBound(key, j.authority, j.dir)
	if e != nil || len(ciphertext) < aead.NonceSize()+aead.Overhead() || len(ciphertext) > 128<<10 {
		return result, ErrConflict
	}
	plain, e := aead.Open(nil, ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():], localActivationAAD(j.authority, j.dir, generation))
	if e != nil {
		return result, ErrConflict
	}
	defer clear(plain)
	if e = json.Unmarshal(plain, &result); e != nil || nativeauthority.ValidateOriginalOrigin(j.authority, result.Admission, result.Origin, generation) != nil {
		return localActivationEvidence{}, ErrConflict
	}
	return result, nil
}
