//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"

	"github.com/pagnet-code/pagnet/transport"
)

var errNativeShareSourcePrepare = errors.New("native share source prepare unavailable, unsafe or conflicting")

// NativeShareSourcePrepareStore is a dormant local transcript journal. Its
// reservations and public replies convey no enrollment or source authority.
// Reservations are permanent: an uncertain operation cannot free an identity
// for another transcript. Only dedicated holder keys sign the public reply.
type NativeShareSourcePrepareStore struct {
	holder *NativeShareSourceHolderStore
}

func NewNativeShareSourcePrepareStore(holder *NativeShareSourceHolderStore) (*NativeShareSourcePrepareStore, error) {
	if holder == nil || holder.registry == nil || holder.sync == nil {
		return nil, errNativeShareSourcePrepare
	}
	return &NativeShareSourcePrepareStore{holder: holder}, nil
}

// Prepare binds both command and enrollment identities before touching holder
// storage. Each SQLite connection and registry lock is released before Ensure
// or WithKeys, which acquire the same registry lock themselves.
func (s *NativeShareSourcePrepareStore) Prepare(request transport.NativeShareSourcePreparePayload) (transport.NativeShareSourcePreparedPayload, error) {
	var empty transport.NativeShareSourcePreparedPayload
	if s == nil || s.holder == nil {
		return empty, errNativeShareSourcePrepare
	}
	raw, err := request.CanonicalBytes()
	if err != nil {
		return empty, err
	}
	subject := request.Enrollment.Subject
	// Holder scope normalization must never change the signed transcript.
	if textServiceServer(subject.ServerURL) != subject.ServerURL {
		return empty, errNativeShareSourcePrepare
	}
	scope, name, err := nativeShareSourceHolderScope(NativeShareSourceHolderScope{ServerURL: subject.ServerURL, TenantID: subject.TenantID, AccountID: subject.AccountID, HostID: subject.HostID})
	if err != nil {
		return empty, err
	}
	digest := sha256.Sum256(append([]byte("pagnet/native-share-source/prepare-request/v1/"), raw...))
	cached, err := s.journal(request, name, digest[:], nil)
	if err != nil {
		return empty, err
	}
	// Reject corrupt journal bytes before accessing holder storage.
	if cached != nil {
		if _, err := nativeShareSourcePreparedCached(cached, request, nil); err != nil {
			return empty, err
		}
	}
	descriptor, err := s.holder.Ensure(scope)
	if err != nil {
		return empty, err
	}
	public := transport.NativeShareSourceHolderDescriptor{
		Version:        descriptor.Version,
		Scope:          transport.NativeShareSourceHolderScope{ServerURL: descriptor.Scope.ServerURL, TenantID: descriptor.Scope.TenantID, AccountID: descriptor.Scope.AccountID, HostID: descriptor.Scope.HostID},
		InstallationID: descriptor.InstallationID, HolderID: descriptor.HolderID, Generation: descriptor.Generation,
		X25519: descriptor.X25519, Ed25519: descriptor.Ed25519, Fingerprint: descriptor.Fingerprint,
	}
	if cached != nil {
		return nativeShareSourcePreparedCached(cached, request, &public)
	}
	prepared := transport.NativeShareSourcePreparedPayload{Prepare: request, Descriptor: public}
	prepared.EnrollmentDigest, err = prepared.Digest()
	if err != nil {
		return empty, err
	}
	message, err := prepared.SignatureBytes()
	if err != nil {
		return empty, err
	}
	// The callback only signs; it cannot reenter registry or holder storage.
	if err = s.holder.WithKeys(scope, descriptor, func(keys NativeShareSourceHolderKeyUse) error {
		var signErr error
		prepared.Signature, signErr = keys.Sign(message)
		return signErr
	}); err != nil {
		return empty, err
	}
	raw, err = prepared.CanonicalBytes()
	if err != nil {
		return empty, err
	}
	persisted, err := s.journal(request, name, digest[:], raw)
	if err != nil {
		return empty, err
	}
	return nativeShareSourcePreparedCached(persisted, request, &public)
}

func nativeShareSourcePreparedCached(raw []byte, request transport.NativeShareSourcePreparePayload, expected *transport.NativeShareSourceHolderDescriptor) (transport.NativeShareSourcePreparedPayload, error) {
	var empty transport.NativeShareSourcePreparedPayload
	prepared, err := transport.DecodeNativeShareSourcePreparedPayload(raw)
	if err != nil {
		return empty, errNativeShareSourcePrepare
	}
	canonical, err := prepared.CanonicalBytes()
	if err != nil || !bytes.Equal(raw, canonical) || expected != nil && prepared.Descriptor != *expected {
		return empty, errNativeShareSourcePrepare
	}
	key, err := hex.DecodeString(prepared.Descriptor.Ed25519)
	if err != nil || prepared.Verify(request, prepared.Descriptor, ed25519.PublicKey(key)) != nil {
		return empty, errNativeShareSourcePrepare
	}
	return prepared, nil
}

// journal reserves on the first call and completes on the second. It checks the
// entire identity on every transaction, including retries after a restart.
func (s *NativeShareSourcePrepareStore) journal(request transport.NativeShareSourcePreparePayload, scope string, digest, prepared []byte) ([]byte, error) {
	r := s.holder.registry
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx := context.Background()
	conn, err := r.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return nil, err
	}
	defer func() { _, _ = conn.ExecContext(ctx, "ROLLBACK") }()
	var installation string
	if err = conn.QueryRowContext(ctx, `SELECT value FROM native_registry_metadata WHERE name='installation_id'`).Scan(&installation); err != nil || installation != string(s.holder.installation) {
		return nil, errNativeShareSourcePrepare
	}
	var collisions int
	if err = conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM native_source_prove_journal WHERE command_id=?`, request.CommandID).Scan(&collisions); err != nil || collisions != 0 {
		return nil, errNativeShareSourcePrepare
	}
	var commandID, enrollmentID, enrolledInstallation, enrolledScope string
	var enrolledDigest, cached []byte
	err = conn.QueryRowContext(ctx, `SELECT command_id,enrollment_id,installation_id,scope,request_digest,prepared FROM native_source_prepare_journal WHERE command_id=? OR enrollment_id=?`, request.CommandID, request.Enrollment.EnrollmentID).Scan(&commandID, &enrollmentID, &enrolledInstallation, &enrolledScope, &enrolledDigest, &cached)
	if errors.Is(err, sql.ErrNoRows) {
		if prepared != nil {
			return nil, errNativeShareSourcePrepare
		}
		_, err = conn.ExecContext(ctx, `INSERT INTO native_source_prepare_journal(command_id,enrollment_id,installation_id,scope,request_digest) VALUES(?,?,?,?,?)`, request.CommandID, request.Enrollment.EnrollmentID, installation, scope, digest)
	} else if err == nil {
		if commandID != string(request.CommandID) || enrollmentID != string(request.Enrollment.EnrollmentID) || enrolledInstallation != installation || enrolledScope != scope || !bytes.Equal(enrolledDigest, digest) {
			return nil, errNativeShareSourcePrepare
		}
		if prepared != nil {
			if cached != nil && !bytes.Equal(cached, prepared) {
				return nil, errNativeShareSourcePrepare
			}
			if cached == nil {
				_, err = conn.ExecContext(ctx, `UPDATE native_source_prepare_journal SET prepared=? WHERE command_id=? AND prepared IS NULL`, prepared, request.CommandID)
				cached = prepared
			}
		}
	}
	if err != nil {
		return nil, err
	}
	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		return nil, err
	}
	return cached, nil
}
