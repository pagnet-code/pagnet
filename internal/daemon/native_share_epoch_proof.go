//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
	"golang.org/x/sys/unix"
)

// Prove returns dormant stage-possession evidence against an independently
// retained challenge and full stage authority. Reauthorize must check current
// owner/proposal/grant/source/committed previous epoch and both live connection
// IDs. It must not call this store, holder store, registry or its database: the
// registry mutex, existing holder and stage flocks and SQLite write reservation
// are held during callbacks. No file, directory, keyring or epoch is created.
// Exact retries are permitted; one-time challenge acceptance belongs to callers.
func (s *NativeShareEpochStore) Prove(request, expected transport.NativeShareEpochProofChallenge, a NativeShareEpochStageAuthorization) (transport.NativeShareEpochProof, error) {
	var empty transport.NativeShareEpochProof
	if s == nil || s.registry == nil || s.holders == nil || s.now == nil || len(s.signer) != ed25519.PrivateKeySize || a.Reauthorize == nil {
		return empty, errNativeShareEpochStage
	}
	request.Nonce = append([]byte(nil), request.Nonce...)
	expected.Nonce = append([]byte(nil), expected.Nonce...)
	a.TrustedSource = append(ed25519.PublicKey(nil), a.TrustedSource...)
	a.Prepared.Signature = append([]byte(nil), a.Prepared.Signature...)
	a.Session.ProtocolFeatures = append([]string(nil), a.Session.ProtocolFeatures...)
	got, err := request.CanonicalBytes()
	want, expectedErr := expected.CanonicalBytes()
	if err != nil || expectedErr != nil || !bytes.Equal(got, want) || request.Metadata != a.Expected || request.BindingID != a.Prepared.Prepare.Binding.BindingID || request.CommandID == a.Prepared.Prepare.CommandID {
		return empty, errNativeShareEpochStage
	}
	valid := func() error {
		if err := request.Validate(s.now()); err != nil {
			return errNativeShareEpochStage
		}
		expiry, err := time.Parse(time.RFC3339Nano, a.Prepared.Prepare.Binding.ExpiresAt)
		challengeExpiry, parseErr := time.Parse(time.RFC3339Nano, request.ExpiresAt)
		if err != nil || parseErr != nil || challengeExpiry.After(expiry) {
			return errNativeShareEpochStage
		}
		return s.deadline(a)
	}
	if err := valid(); err != nil {
		return empty, err
	}
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()
	root, err := nativeShareHolderDirectory(s.registry.root)
	if err != nil {
		return empty, err
	}
	defer root.Close()
	holders, err := nativeShareHolderExistingChild(root, "closed-share-bindings")
	if err != nil {
		return empty, err
	}
	defer holders.Close()
	holder, err := nativeShareHolderExistingChild(holders, string(request.BindingID))
	if err != nil {
		return empty, err
	}
	defer holder.Close()
	holderLock, err := nativeShareHolderLockMode(holder, false)
	if err != nil {
		return empty, err
	}
	defer holderLock.Close()
	if err := nativeShareHolderEntries(holder, "holder.lock", "holder.json"); err != nil {
		return empty, err
	}
	holderFile, err := nativeShareHolderOpen(holder, "holder.json", false)
	if err != nil {
		return empty, err
	}
	defer holderFile.Close()
	h, err := s.holders.loadRecord(holderFile)
	if err != nil {
		return empty, err
	}
	defer clear(h.PrivateKey)
	prepared, _ := json.Marshal(a.Prepared)
	savedPrepared, _ := json.Marshal(h.Prepared)
	if !bytes.Equal(prepared, savedPrepared) {
		return empty, errNativeShareEpochStage
	}
	namespace, err := nativeShareHolderExistingChild(root, "staged-share-epochs")
	if err != nil {
		return empty, err
	}
	defer namespace.Close()
	if err := nativeShareEpochStageChildren(namespace); err != nil {
		return empty, err
	}
	binding, err := nativeShareHolderExistingChild(namespace, string(request.BindingID))
	if err != nil {
		return empty, err
	}
	defer binding.Close()
	if err := nativeShareEpochStageChildren(binding); err != nil {
		return empty, err
	}
	directory, err := nativeShareHolderExistingChild(binding, string(a.Expected.OperationID))
	if err != nil {
		return empty, err
	}
	defer directory.Close()
	lock, err := nativeShareEpochProofLock(directory)
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	conn, err := s.registry.db.Conn(context.Background())
	if err != nil {
		return empty, errNativeShareEpochStage
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		return empty, errNativeShareEpochStage
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), "ROLLBACK") }()
	if err := nativeShareHolderEntries(directory, "stage.lock", "stage.json"); err != nil {
		return empty, err
	}
	file, err := nativeShareHolderOpen(directory, "stage.json", false)
	if err != nil {
		return empty, err
	}
	saved, readErr := io.ReadAll(io.LimitReader(file, nativeShareEpochStageMaxBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(saved) > nativeShareEpochStageMaxBytes {
		return empty, errNativeShareEpochStage
	}
	var record nativeShareEpochStageRecord
	if err := json.Unmarshal(saved, &record); err != nil {
		return empty, errNativeShareEpochStage
	}
	// Reconstruct every persisted public field from caller authority and the exact
	// original ciphertext. Canonical byte equality rejects ambiguous JSON.
	canonical := nativeShareEpochStageRecord{Version: 1, Session: nativeShareEpochStageSessionSnapshot(a.Session), Package: record.Package, Expected: a.Expected, TrustedSource: a.TrustedSource, Prepared: a.Prepared}
	canonical.Digest, err = nativeShareEpochStageDigest(canonical)
	if err != nil || canonical.Digest != request.StageDigest {
		return empty, errNativeShareEpochStage
	}
	canonical.Receipt = NativeShareEpochStageReceipt{Version: 1, BindingID: request.BindingID, OperationID: a.Expected.OperationID, Digest: canonical.Digest}
	canonical.Receipt.Signature = record.Receipt.Signature
	if err := canonical.Receipt.Verify(request.BindingID, a.Expected.OperationID, s.signer.Public().(ed25519.PublicKey)); err != nil {
		return empty, errNativeShareEpochStage
	}
	raw, err := json.Marshal(canonical)
	if err != nil || !bytes.Equal(saved, raw) {
		return empty, errNativeShareEpochStage
	}
	p, err := transport.DecodeNativeShareEpochPackage(record.Package, a.Expected, a.TrustedSource, s.now())
	if err != nil {
		return empty, errNativeShareEpochStage
	}
	if err := s.authorize(conn, a); err != nil {
		return empty, err
	}
	if err := valid(); err != nil {
		return empty, err
	}
	signature, err := crypto.ProveNativeShareEpoch(p, a.Expected, a.TrustedSource, h.PrivateKey, request, s.now())
	if err != nil {
		return empty, errNativeShareEpochStage
	}
	reply := transport.NativeShareEpochProof{Challenge: request, EpochSignature: signature}
	signed, err := reply.SignatureBytes()
	if err != nil {
		return empty, err
	}
	reply.HostSignature = ed25519.Sign(s.signer, signed)
	if err := s.authorize(conn, a); err != nil {
		return empty, err
	}
	if err := valid(); err != nil {
		return empty, err
	}
	if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		return empty, errNativeShareEpochStage
	}
	if err := valid(); err != nil {
		return empty, err
	}
	return reply, nil
}

func nativeShareEpochProofLock(directory *os.File) (*os.File, error) {
	file, err := nativeShareHolderOpen(directory, "stage.lock", false)
	if err != nil {
		return nil, err
	}
	for {
		err = unix.Flock(int(file.Fd()), unix.LOCK_EX)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}
