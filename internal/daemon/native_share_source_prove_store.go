//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

var errNativeShareSourceProve = errors.New("native share source prove unavailable, unsafe or conflicting")

// NativeShareSourceProveStore retains encrypted requests and receipt digests,
// never plaintext challenges or raw acknowledgements. Reservations survive
// uncertain operations and cannot be reused for a different proof transcript.
type NativeShareSourceProveStore struct{ holder *NativeShareSourceHolderStore }

func NewNativeShareSourceProveStore(holder *NativeShareSourceHolderStore) (*NativeShareSourceProveStore, error) {
	if holder == nil || holder.registry == nil || holder.sync == nil {
		return nil, errNativeShareSourceProve
	}
	return &NativeShareSourceProveStore{holder: holder}, nil
}

func nativeShareSourceProveBefore(now func() time.Time, expiry string) bool {
	deadline, err := time.Parse(time.RFC3339Nano, expiry)
	current := now()
	return err == nil && !current.IsZero() && current.Before(deadline)
}

func (s *NativeShareSourceProveStore) prove(request transport.NativeShareSourceProvePayload, subject transport.NativeShareSourceHostSubject, credential, ownership string, now func() time.Time) (transport.NativeShareSourceProvedPayload, error) {
	var empty transport.NativeShareSourceProvedPayload
	if s == nil || s.holder == nil || now == nil {
		return empty, errNativeShareSourceProve
	}
	raw, err := request.CanonicalBytes()
	if err != nil || !nativeShareSourceProveBefore(now, request.ExpiresAt) {
		return empty, errNativeShareSourceProve
	}
	scope, name, err := nativeShareSourceHolderScope(NativeShareSourceHolderScope{ServerURL: subject.ServerURL, TenantID: subject.TenantID, AccountID: subject.AccountID, HostID: subject.HostID})
	if err != nil {
		return empty, err
	}
	digest := sha256.Sum256(append([]byte("pagnet/native-share-source/prove-request/v1/"), raw...))
	prepared, err := s.journal(request, subject, credential, ownership, name, raw, digest[:], "", now)
	if err != nil {
		return empty, err
	}
	d := prepared.Descriptor
	descriptor := NativeShareSourceHolderDescriptor{Version: d.Version, Scope: scope, InstallationID: d.InstallationID, HolderID: d.HolderID, Generation: d.Generation, X25519: d.X25519, Ed25519: d.Ed25519, Fingerprint: d.Fingerprint}
	proved := transport.NativeShareSourceProvedPayload{NativeShareSourceChallengeContext: request.NativeShareSourceChallengeContext}
	// All registry transactions are released before WithKeys acquires its locks.
	err = s.holder.WithKeys(scope, descriptor, func(keys NativeShareSourceHolderKeyUse) error {
		if !nativeShareSourceProveBefore(now, request.ExpiresAt) || !nativeShareSourceProveBefore(now, prepared.Prepare.Enrollment.ExpiresAt) {
			return errNativeShareSourceProve
		}
		challenge, err := keys.OpenEnrollmentChallenge(request)
		if err != nil {
			return err
		}
		defer clear(challenge)
		proved.Challenge = challenge
		transcript, err := proved.SignatureBytes()
		if err != nil {
			return err
		}
		defer clear(transcript)
		proved.Signature, err = keys.Sign(transcript)
		if err == nil {
			proved.Challenge = bytes.Clone(challenge)
		}
		return err
	})
	if err != nil {
		return empty, err
	}
	receipt, err := proved.ReceiptDigest()
	if err == nil {
		_, err = s.journal(request, subject, credential, ownership, name, raw, digest[:], receipt, now)
	}
	if err != nil || !nativeShareSourceProveBefore(now, request.ExpiresAt) || !nativeShareSourceProveBefore(now, prepared.Prepare.Enrollment.ExpiresAt) {
		clear(proved.Challenge)
		return empty, errNativeShareSourceProve
	}
	return proved, nil
}

// journal checks the exact completed Prepare and authenticated incarnation on
// both reservation and completion. Only ciphertext and its canonical digest are
// durable; deterministic Ed25519 regeneration must match any retained receipt.
func (s *NativeShareSourceProveStore) journal(request transport.NativeShareSourceProvePayload, subject transport.NativeShareSourceHostSubject, credential, ownership, scope string, raw, digest []byte, receipt string, now func() time.Time) (transport.NativeShareSourcePreparedPayload, error) {
	var empty transport.NativeShareSourcePreparedPayload
	r := s.holder.registry
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx := context.Background()
	conn, err := r.db.Conn(ctx)
	if err != nil {
		return empty, err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return empty, err
	}
	defer func() { _, _ = conn.ExecContext(ctx, "ROLLBACK") }()
	var installation, enrolledInstallation, enrolledScope, prepareCommand string
	var preparedRaw, prepareDigest []byte
	if err = conn.QueryRowContext(ctx, `SELECT value FROM native_registry_metadata WHERE name='installation_id'`).Scan(&installation); err != nil || installation != string(s.holder.installation) {
		return empty, errNativeShareSourceProve
	}
	if err = conn.QueryRowContext(ctx, `SELECT command_id,installation_id,scope,request_digest,prepared FROM native_source_prepare_journal WHERE enrollment_id=?`, request.EnrollmentID).Scan(&prepareCommand, &enrolledInstallation, &enrolledScope, &prepareDigest, &preparedRaw); err != nil || enrolledInstallation != installation || enrolledScope != scope || preparedRaw == nil {
		return empty, errNativeShareSourceProve
	}
	prepared, err := transport.DecodeNativeShareSourcePreparedPayload(preparedRaw)
	if err != nil {
		return empty, errNativeShareSourceProve
	}
	prepared, err = nativeShareSourcePreparedCached(preparedRaw, prepared.Prepare, nil)
	if err != nil {
		return empty, errNativeShareSourceProve
	}
	prepareRaw, err := prepared.Prepare.CanonicalBytes()
	if err != nil {
		return empty, errNativeShareSourceProve
	}
	expectedDigest := sha256.Sum256(append([]byte("pagnet/native-share-source/prepare-request/v1/"), prepareRaw...))
	enrollment := prepared.Prepare.Enrollment
	if prepareCommand != string(prepared.Prepare.CommandID) || !bytes.Equal(prepareDigest, expectedDigest[:]) || prepared.Descriptor.InstallationID != s.holder.installation || prepared.Descriptor.Scope != (transport.NativeShareSourceHolderScope{ServerURL: subject.ServerURL, TenantID: subject.TenantID, AccountID: subject.AccountID, HostID: subject.HostID}) || enrollment.EnrollmentID != request.EnrollmentID || enrollment.Subject != subject || enrollment.HostCredentialID != credential || enrollment.OwnershipScope != ownership || prepared.EnrollmentDigest != request.EnrollmentDigest || prepared.Descriptor.Fingerprint != request.DescriptorFingerprint || !nativeShareSourceProveBefore(now, request.ExpiresAt) || !nativeShareSourceProveBefore(now, enrollment.ExpiresAt) {
		return empty, errNativeShareSourceProve
	}
	var collisions int
	if err = conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM native_source_prepare_journal WHERE command_id=?`, request.CommandID).Scan(&collisions); err != nil || collisions != 0 {
		return empty, errNativeShareSourceProve
	}
	var commandID, enrollmentID, cachedInstallation, cachedScope string
	var cachedDigest, cachedRaw []byte
	var cachedReceipt sql.NullString
	err = conn.QueryRowContext(ctx, `SELECT command_id,enrollment_id,installation_id,scope,request_digest,request,receipt_digest FROM native_source_prove_journal WHERE command_id=? OR enrollment_id=?`, request.CommandID, request.EnrollmentID).Scan(&commandID, &enrollmentID, &cachedInstallation, &cachedScope, &cachedDigest, &cachedRaw, &cachedReceipt)
	if errors.Is(err, sql.ErrNoRows) {
		if receipt != "" {
			return empty, errNativeShareSourceProve
		}
		_, err = conn.ExecContext(ctx, `INSERT INTO native_source_prove_journal(command_id,enrollment_id,installation_id,scope,request_digest,request) VALUES(?,?,?,?,?,?)`, request.CommandID, request.EnrollmentID, installation, scope, digest, raw)
	} else if err == nil {
		if commandID != string(request.CommandID) || enrollmentID != string(request.EnrollmentID) || cachedInstallation != installation || cachedScope != scope || !bytes.Equal(cachedDigest, digest) || !bytes.Equal(cachedRaw, raw) || cachedReceipt.Valid && len(cachedReceipt.String) != 64 {
			return empty, errNativeShareSourceProve
		}
		if receipt != "" {
			if cachedReceipt.Valid && cachedReceipt.String != receipt {
				return empty, errNativeShareSourceProve
			}
			if !cachedReceipt.Valid {
				_, err = conn.ExecContext(ctx, `UPDATE native_source_prove_journal SET receipt_digest=? WHERE command_id=? AND receipt_digest IS NULL`, receipt, request.CommandID)
			}
		}
	}
	if err != nil {
		return empty, err
	}
	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		return empty, err
	}
	return prepared, nil
}
