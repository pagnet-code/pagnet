//go:build linux || darwin

package daemon

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

// Prove opens an existing closed holder by the authenticated binding ID. The
// persisted, host-signed prepare supplies all routing/selection authority; no
// retained in-memory command, directory scan, caller path or new holder is used.
// The only decrypted value is the fresh random 32-byte challenge. Exact command
// retries are permitted; challenge freshness and one-time acceptance remain the
// server's responsibility. This operation changes no holder or worker state.
func (s *NativeShareHolderStore) Prove(request transport.NativeShareBindingProvePayload, capturedServerURL string, session transport.HostSessionPayload) (transport.NativeShareBindingProvedPayload, error) {
	var empty transport.NativeShareBindingProvedPayload
	if s == nil || s.registry == nil || len(s.signer) != ed25519.PrivateKeySize || s.now == nil {
		return empty, errNativeShareHolder
	}
	if _, err := request.CanonicalBytes(); err != nil {
		return empty, err
	}
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()
	root, err := nativeShareHolderDirectory(s.registry.root)
	if err != nil {
		return empty, err
	}
	defer root.Close()
	namespace, err := nativeShareHolderExistingChild(root, "closed-share-bindings")
	if err != nil {
		return empty, err
	}
	defer namespace.Close()
	binding, err := nativeShareHolderExistingChild(namespace, string(request.BindingID))
	if err != nil {
		return empty, err
	}
	defer binding.Close()
	lock, err := nativeShareHolderLockMode(binding, false)
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	if err := nativeShareHolderEntries(binding, "holder.lock", "holder.json"); err != nil {
		return empty, err
	}
	file, err := nativeShareHolderOpen(binding, "holder.json", false)
	if err != nil {
		return empty, err
	}
	defer file.Close()
	record, err := s.loadRecord(file)
	if err != nil {
		return empty, err
	}
	defer clear(record.PrivateKey)
	prepared := record.Prepared
	if request.BindingID != prepared.Prepare.Binding.BindingID || request.BindingDigest != prepared.BindingDigest || request.CommandID == prepared.Prepare.CommandID {
		return empty, errNativeShareHolder
	}
	expiry, _ := time.Parse(time.RFC3339Nano, prepared.Prepare.Binding.ExpiresAt)
	if !s.now().Before(expiry) {
		return empty, errNativeShareHolder
	}
	conn, err := s.registry.db.Conn(context.Background())
	if err != nil {
		return empty, errNativeShareHolder
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		return empty, errNativeShareHolder
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), "ROLLBACK") }()
	subject, err := s.subject(conn, prepared.Prepare, capturedServerURL, session)
	if err != nil || subject != prepared.Subject {
		return empty, errNativeShareHolder
	}
	aad, err := request.ChallengeAAD()
	if err != nil {
		return empty, err
	}
	challenge, err := e2ee.HPKEUnwrap(record.PrivateKey, request.Challenge.Enc, []byte(transport.NativeShareBindingChallengeInfo), aad, request.Challenge.Ciphertext)
	if err != nil || len(challenge) != 32 {
		clear(challenge)
		return empty, errNativeShareHolder
	}
	defer clear(challenge)
	reply := transport.NativeShareBindingProvedPayload{BindingID: request.BindingID, Version: request.Version, CommandID: request.CommandID, BindingDigest: request.BindingDigest, ChallengeID: request.ChallengeID, Challenge: challenge}
	transcript, err := reply.SignatureBytes()
	if err != nil {
		return empty, err
	}
	reply.Signature = ed25519.Sign(s.signer, transcript)
	if !s.now().Before(expiry) {
		return empty, errNativeShareHolder
	}
	if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		return empty, errNativeShareHolder
	}
	if !s.now().Before(expiry) {
		return empty, errNativeShareHolder
	}
	// Retain only the intentional wire reply; wipe the local decrypted buffer.
	reply.Challenge = append([]byte(nil), challenge...)
	return reply, nil
}
