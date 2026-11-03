//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
	"golang.org/x/sys/unix"
)

const nativeShareEpochStageMaxBytes = 64 << 10

var errNativeShareEpochStage = errors.New("native share epoch stage unavailable, unsafe, expired or conflicting")

// NativeShareEpochStageAuthorization is independently retained local authority,
// never populated from an untrusted package. Reauthorize is a mandatory trusted
// integration boundary: it checks current owner/proposal/grant, binding/principal/
// context, exact live connection IDs, source identity, and that PreviousEpochID is
// the current committed target epoch. It must not reenter this store, the holder
// store, or ANY method/query on this registry or its database (including read-only
// Lookup/List): Stage holds its mutex and sole database connection while calling
// Reauthorize. Authorization reads must use independently owned authority state.
// The store itself grants no installation authority.
type NativeShareEpochStageAuthorization struct {
	Prepared      transport.NativeShareBindingPreparedPayload
	Expected      transport.NativeShareEpochMetadata
	TrustedSource ed25519.PublicKey
	ServerURL     string
	Session       transport.HostSessionPayload
	Reauthorize   func(NativeShareEpochStageAuthorization) error
}

type NativeShareEpochStageReceipt struct {
	Version     int       `json:"version"`
	BindingID   domain.ID `json:"bindingId"`
	OperationID domain.ID `json:"operationId"`
	Digest      string    `json:"digest"`
	Signature   []byte    `json:"signature"`
}

// This snapshot binds session fields outside Prepared.Subject. It is public
// retry context, never persisted authority. Features are a sorted distinct set.
type nativeShareEpochStageSession struct {
	HostCredentialID string   `json:"hostCredentialId"`
	OwnershipScope   string   `json:"ownershipScope"`
	ProtocolFeatures []string `json:"protocolFeatures"`
}

func nativeShareEpochStageSessionSnapshot(session transport.HostSessionPayload) nativeShareEpochStageSession {
	features := append([]string{}, session.ProtocolFeatures...)
	sort.Strings(features)
	distinct := features[:0]
	for _, feature := range features {
		if len(distinct) == 0 || distinct[len(distinct)-1] != feature {
			distinct = append(distinct, feature)
		}
	}
	return nativeShareEpochStageSession{HostCredentialID: session.HostCredentialID, OwnershipScope: session.OwnershipScope, ProtocolFeatures: distinct}
}

type nativeShareEpochStageRecord struct {
	Version       int                                         `json:"version"`
	Session       nativeShareEpochStageSession                `json:"session"`
	Package       []byte                                      `json:"package"`
	Expected      transport.NativeShareEpochMetadata          `json:"expected"`
	TrustedSource []byte                                      `json:"trustedSource"`
	Prepared      transport.NativeShareBindingPreparedPayload `json:"prepared"`
	Digest        string                                      `json:"digest"`
	Receipt       NativeShareEpochStageReceipt                `json:"receipt"`
}

// NativeShareEpochStore is a dormant immutable ciphertext store. No production
// command calls it. It never installs keys or changes workers, profiles or grants.
type NativeShareEpochStore struct {
	registry *NativeWorkerRegistry
	holders  *NativeShareHolderStore
	signer   ed25519.PrivateKey
	now      func() time.Time
}

func NewNativeShareEpochStore(registry *NativeWorkerRegistry, holders *NativeShareHolderStore, signer ed25519.PrivateKey, now func() time.Time) (*NativeShareEpochStore, error) {
	if registry == nil || holders == nil || holders.registry != registry || !holders.nativeShareBindingReady() || now == nil || len(signer) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(signer.Seed()), signer) || !bytes.Equal(signer, holders.signer) {
		return nil, errNativeShareEpochStage
	}
	return &NativeShareEpochStore{registry: registry, holders: holders, signer: append(ed25519.PrivateKey(nil), signer...), now: now}, nil
}

func (s *NativeShareEpochStore) String() string { return "NativeShareEpochStore{closed}" }

func nativeShareEpochStageID(id domain.ID) bool {
	u, err := uuid.Parse(string(id))
	return err == nil && u != uuid.Nil && u.String() == string(id)
}

func (s *NativeShareEpochStore) deadline(a NativeShareEpochStageAuthorization) error {
	deadline, err := time.Parse(time.RFC3339Nano, a.Expected.Deadline)
	expiry, expiryErr := time.Parse(time.RFC3339Nano, a.Prepared.Prepare.Binding.ExpiresAt)
	now := s.now()
	if err != nil || expiryErr != nil || now.IsZero() || deadline.After(expiry) || !now.Before(deadline) || !now.Before(expiry) {
		return errNativeShareEpochStage
	}
	return nil
}

func (s *NativeShareEpochStore) authorize(conn *sql.Conn, a NativeShareEpochStageAuthorization) error {
	subject, err := s.holders.subject(conn, a.Prepared.Prepare, a.ServerURL, a.Session)
	if err != nil || subject != a.Prepared.Subject {
		return errNativeShareEpochStage
	}
	if err := a.Prepared.Verify(a.Prepared.Prepare, subject, s.signer.Public().(ed25519.PublicKey)); err != nil {
		return errNativeShareEpochStage
	}
	b, m := a.Prepared.Prepare.Binding, a.Expected
	if m.BindingDigest != a.Prepared.BindingDigest || m.HolderID != a.Prepared.HolderID || m.HolderX25519 != a.Prepared.HolderX25519 || m.TenantID != subject.TenantID || m.NetworkID != b.NetworkID || m.ProposalRevision != b.ProposalRevision || m.GrantGeneration != b.GrantGeneration {
		return errNativeShareEpochStage
	}
	if err := s.deadline(a); err != nil {
		return err
	}
	// Keep callback-local slice mutations from changing the retained snapshot.
	checked := a
	checked.Prepared.Signature = append([]byte(nil), a.Prepared.Signature...)
	checked.TrustedSource = append(ed25519.PublicKey(nil), a.TrustedSource...)
	checked.Session.ProtocolFeatures = append([]string(nil), a.Session.ProtocolFeatures...)
	if err := a.Reauthorize(checked); err != nil {
		return errNativeShareEpochStage
	}
	return s.deadline(a)
}

func nativeShareEpochStageDigest(record nativeShareEpochStageRecord) (string, error) {
	record.Digest = ""
	record.Receipt = NativeShareEpochStageReceipt{}
	raw, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("pagnet/native-share-epoch/stage/v1/"), raw...))
	return hex.EncodeToString(digest[:]), nil
}

func nativeShareEpochStageReceiptBytes(r NativeShareEpochStageReceipt) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("pagnet/native-share-epoch/staged/v1/"), raw...)
}

// Stage opens only an existing dedicated holder. It decrypts briefly to verify
// possession, then destroys the key; only the original ciphertext and public
// signed evidence reach disk. Exact retries validate everything again.
func (s *NativeShareEpochStore) Stage(bindingID domain.ID, rawPackage []byte, a NativeShareEpochStageAuthorization) (NativeShareEpochStageReceipt, error) {
	var empty NativeShareEpochStageReceipt
	if s == nil || s.registry == nil || s.holders == nil || s.now == nil || len(s.signer) != ed25519.PrivateKeySize || a.Reauthorize == nil || len(rawPackage) == 0 || len(rawPackage) > 16<<10 || !nativeShareEpochStageID(bindingID) || bindingID != a.Prepared.Prepare.Binding.BindingID {
		return empty, errNativeShareEpochStage
	}
	// Own all byte slices used across authorization callbacks and publication.
	rawPackage = append([]byte(nil), rawPackage...)
	a.TrustedSource = append(ed25519.PublicKey(nil), a.TrustedSource...)
	a.Prepared.Signature = append([]byte(nil), a.Prepared.Signature...)
	a.Session.ProtocolFeatures = append([]string(nil), a.Session.ProtocolFeatures...)
	p, err := transport.DecodeNativeShareEpochPackage(rawPackage, a.Expected, a.TrustedSource, s.now())
	if err != nil {
		return empty, errNativeShareEpochStage
	}
	if err := s.deadline(a); err != nil {
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
	holder, err := nativeShareHolderExistingChild(holders, string(bindingID))
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
	expectedPrepared, _ := json.Marshal(a.Prepared)
	storedPrepared, _ := json.Marshal(h.Prepared)
	if !bytes.Equal(expectedPrepared, storedPrepared) {
		return empty, errNativeShareEpochStage
	}
	// Check current authority before even creating inert stage infrastructure.
	initial, err := s.registry.db.Conn(context.Background())
	if err != nil {
		return empty, errNativeShareEpochStage
	}
	authorityErr := s.authorize(initial, a)
	closeErr := initial.Close()
	if authorityErr != nil {
		return empty, authorityErr
	}
	if closeErr != nil {
		return empty, errNativeShareEpochStage
	}
	// Obtain the stage lock before SQLite's write reservation. Directory creation
	// does not publish stage evidence; authorization is checked before stage writes.
	namespace, err := nativeShareHolderChild(root, "staged-share-epochs")
	if err != nil {
		return empty, err
	}
	defer namespace.Close()
	if err := nativeShareEpochStageChildren(namespace); err != nil {
		return empty, err
	}
	binding, err := nativeShareHolderChild(namespace, string(bindingID))
	if err != nil {
		return empty, err
	}
	defer binding.Close()
	if err := nativeShareEpochStageChildren(binding); err != nil {
		return empty, err
	}
	directory, err := nativeShareHolderChild(binding, string(a.Expected.OperationID))
	if err != nil {
		return empty, err
	}
	defer directory.Close()
	lock, err := nativeShareEpochStageLock(directory)
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
	if err := s.authorize(conn, a); err != nil {
		return empty, err
	}
	if err := nativeShareHolderEntries(directory, "stage.lock", "stage.json"); err != nil {
		return empty, err
	}
	key, err := hostcrypto.OpenNativeShareEpoch(p, a.Expected, a.TrustedSource, h.PrivateKey, s.now())
	if err != nil {
		return empty, errNativeShareEpochStage
	}
	key.Destroy()
	record := nativeShareEpochStageRecord{Session: nativeShareEpochStageSessionSnapshot(a.Session), Version: 1, Package: rawPackage, Expected: a.Expected, TrustedSource: a.TrustedSource, Prepared: a.Prepared}
	record.Digest, err = nativeShareEpochStageDigest(record)
	if err != nil {
		return empty, err
	}
	record.Receipt = NativeShareEpochStageReceipt{Version: 1, BindingID: bindingID, OperationID: a.Expected.OperationID, Digest: record.Digest}
	record.Receipt.Signature = ed25519.Sign(s.signer, nativeShareEpochStageReceiptBytes(record.Receipt))
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > nativeShareEpochStageMaxBytes {
		return empty, errNativeShareEpochStage
	}
	file, err := nativeShareHolderOpen(directory, "stage.json", false)
	if err == nil {
		saved, readErr := io.ReadAll(io.LimitReader(file, nativeShareEpochStageMaxBytes+1))
		closeErr := file.Close()
		// Byte-exact comparison with the freshly reconstructed canonical record also
		// rejects unknown/duplicate fields, nulls, missing fields and trailing JSON.
		if readErr != nil || closeErr != nil || !bytes.Equal(saved, raw) {
			return empty, errNativeShareEpochStage
		}
	} else if errors.Is(err, unix.ENOENT) {
		if err := s.authorize(conn, a); err != nil {
			return empty, err
		}
		if err := nativeShareEpochStagePublish(directory, raw); err != nil {
			return empty, err
		}
	} else {
		return empty, err
	}
	for _, dir := range []*os.File{directory, binding, namespace, root} {
		if err := dir.Sync(); err != nil {
			return empty, err
		}
	}
	if err := s.authorize(conn, a); err != nil {
		return empty, err
	}
	if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		return empty, errNativeShareEpochStage
	}
	if err := s.deadline(a); err != nil {
		return empty, err
	}
	return record.Receipt, nil
}

func nativeShareEpochStageLock(directory *os.File) (*os.File, error) {
	fd, err := unix.Openat(int(directory.Fd()), "stage.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "stage.lock")
	if err = nativeShareHolderPrivate(file, false); err == nil {
		for {
			err = unix.Flock(fd, unix.LOCK_EX)
			if err != unix.EINTR {
				break
			}
		}
	}
	if err == nil {
		err = file.Sync()
	}
	if err == nil {
		err = directory.Sync()
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func nativeShareEpochStagePublish(directory *os.File, raw []byte) error {
	pending, err := nativeShareHolderOpen(directory, "stage.pending", true)
	if err != nil {
		return err
	}
	n, err := pending.Write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = pending.Sync()
	}
	closeErr := pending.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	// Leave uncertain pending state untouched on every failure.
	if err := unix.Linkat(int(directory.Fd()), "stage.pending", int(directory.Fd()), "stage.json", 0); err != nil {
		return err
	}
	if err := unix.Unlinkat(int(directory.Fd()), "stage.pending", 0); err != nil {
		return err
	}
	return directory.Sync()
}

// Namespace directories contain only canonical identifiers and private real
// directories. Empty operation directories/locks from an interrupted first
// attempt are recoverable. Any pending entry, including a complete pending save,
// is uncertain and fails closed; it is never promoted or silently removed.
func nativeShareEpochStageChildren(directory *os.File) error {
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !nativeShareEpochStageID(domain.ID(entry.Name())) {
			return errNativeShareEpochStage
		}
		child, err := nativeShareHolderExistingChild(directory, entry.Name())
		if err != nil {
			return err
		}
		if err := child.Close(); err != nil {
			return err
		}
	}
	return nil
}
