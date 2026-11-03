//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
	"golang.org/x/sys/unix"
)

const nativeShareHolderMaxBytes = 32 << 10

var errNativeShareHolder = errors.New("native share holder state is unavailable, unsafe, expired or conflicting")

// NativeShareHolderStore holds only closed dedicated holders. It cannot install
// epochs, admit membership, launch workers or modify their original profiles.
// Its root comes exclusively from an already-open authoritative worker registry.
// Whole-directory rollback requires external authority; this store cannot prove
// freshness independently of the captured session and immutable worker registry.
type NativeShareHolderStore struct {
	registry *NativeWorkerRegistry
	signer   ed25519.PrivateKey
	now      func() time.Time
}

func (s *NativeShareHolderStore) String() string { return "NativeShareHolderStore{closed}" }

func NewNativeShareHolderStore(registry *NativeWorkerRegistry, identity *hostcrypto.HostIdentity) (*NativeShareHolderStore, error) {
	if registry == nil || identity == nil || len(identity.Ed25519Priv) != ed25519.PrivateKeySize || len(identity.Ed25519Pub) != ed25519.PublicKeySize {
		return nil, errNativeShareHolder
	}
	signer := identity.Ed25519Signer()
	if !bytes.Equal(ed25519.NewKeyFromSeed(signer.Seed()), signer) || !bytes.Equal(signer.Public().(ed25519.PublicKey), identity.Ed25519Verifier()) {
		return nil, errNativeShareHolder
	}
	return &NativeShareHolderStore{registry: registry, signer: append(ed25519.PrivateKey(nil), signer...), now: time.Now}, nil
}

type nativeShareHolderRecord struct {
	Version    int                                         `json:"version"`
	Prepared   transport.NativeShareBindingPreparedPayload `json:"prepared"`
	PrivateKey []byte                                      `json:"privateKey"`
}

// Prepare revalidates the captured authenticated connection and registry before
// any holder access. Expiry is enforced on creation and exact retries. The server
// remains responsible for current grant/proposal authorization and replay policy.
// Successful return occurs only after the key and immutable signed evidence have
// been committed together and the containing directory has been synced.
func (s *NativeShareHolderStore) Prepare(request transport.NativeShareBindingPreparePayload, capturedServerURL string, session transport.HostSessionPayload) (transport.NativeShareBindingPreparedPayload, error) {
	var empty transport.NativeShareBindingPreparedPayload
	if s == nil || s.registry == nil || len(s.signer) != ed25519.PrivateKeySize || s.now == nil {
		return empty, errNativeShareHolder
	}
	if _, err := request.CanonicalBytes(); err != nil {
		return empty, err
	}
	expiry, _ := time.Parse(time.RFC3339Nano, request.Binding.ExpiresAt)
	if !s.now().Before(expiry) {
		return empty, errNativeShareHolder
	}
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()
	worker, err := s.registry.Lookup(string(request.Binding.InstanceID))
	if err != nil {
		return empty, errNativeShareHolder
	}
	if err := s.registry.checkRecoveryFence(worker.Scope.InstanceID, worker.Scope.Generation); err != nil {
		return empty, errNativeShareHolder
	}
	subject, err := ValidateNativeShareBinding(request, capturedServerURL, session, worker)
	if err != nil {
		return empty, err
	}
	root, err := nativeShareHolderDirectory(s.registry.root)
	if err != nil {
		return empty, err
	}
	defer root.Close()
	namespace, err := nativeShareHolderChild(root, "closed-share-bindings")
	if err != nil {
		return empty, err
	}
	defer namespace.Close()
	binding, err := nativeShareHolderChild(namespace, string(request.Binding.BindingID))
	if err != nil {
		return empty, err
	}
	defer binding.Close()
	if !s.now().Before(expiry) {
		return empty, errNativeShareHolder
	}
	lock, err := nativeShareHolderLock(binding)
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	// Serialize authority with every registry handle, including recovery writers.
	// A Go mutex alone cannot fence SQLite mutations from another manager/process
	// after this operation waits for the binding lock and while it publishes a file.
	conn, err := s.registry.db.Conn(context.Background())
	if err != nil {
		return empty, errNativeShareHolder
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		return empty, errNativeShareHolder
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), "ROLLBACK") }()
	subject, err = s.subject(conn, request, capturedServerURL, session)
	if err != nil {
		return empty, err
	}
	directory := binding
	if err := nativeShareHolderEntries(directory, "holder.lock", "holder.json"); err != nil {
		return empty, err
	}
	file, err := nativeShareHolderOpen(directory, "holder.json", false)
	if err == nil {
		defer file.Close()
		prepared, err := s.load(file, request, subject)
		if err != nil || !s.now().Before(expiry) {
			return empty, errNativeShareHolder
		}
		// Also persist directory creation/entry metadata observed after a prior crash.
		if err := directory.Sync(); err != nil {
			return empty, err
		}
		if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
			return empty, errNativeShareHolder
		}
		if !s.now().Before(expiry) {
			return empty, errNativeShareHolder
		}
		return prepared, nil
	}
	if !errors.Is(err, unix.ENOENT) {
		return empty, err
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return empty, err
	}
	private := key.Bytes()
	defer clear(private)
	prepared := transport.NativeShareBindingPreparedPayload{Prepare: request, Subject: subject, HolderID: domain.NewID(), HolderX25519: hex.EncodeToString(key.PublicKey().Bytes())}
	prepared.BindingDigest, err = prepared.Digest()
	if err != nil {
		return empty, err
	}
	transcript, err := prepared.SignatureBytes()
	if err != nil {
		return empty, err
	}
	prepared.Signature = ed25519.Sign(s.signer, transcript)
	raw, err := json.Marshal(nativeShareHolderRecord{Version: 1, Prepared: prepared, PrivateKey: private})
	if err != nil {
		return empty, err
	}
	defer clear(raw)
	if len(raw) > nativeShareHolderMaxBytes {
		return empty, errNativeShareHolder
	}
	pending, err := nativeShareHolderOpen(directory, "holder.pending", true)
	if err != nil {
		return empty, err
	}
	// Never remove an uncertain pending save. Restart must reject partial state,
	// rather than regenerate a key or expose evidence whose durability is unknown.
	if _, err = pending.Write(raw); err == nil {
		err = pending.Sync()
	}
	closeErr := pending.Close()
	if err != nil {
		return empty, err
	}
	if closeErr != nil {
		return empty, closeErr
	}
	if err = unix.Linkat(int(directory.Fd()), "holder.pending", int(directory.Fd()), "holder.json", 0); err != nil {
		return empty, err
	}
	if err = unix.Unlinkat(int(directory.Fd()), "holder.pending", 0); err != nil {
		return empty, err
	}
	if err = directory.Sync(); err != nil {
		return empty, err
	}
	if !s.now().Before(expiry) {
		return empty, errNativeShareHolder
	}
	if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		return empty, errNativeShareHolder
	}
	if !s.now().Before(expiry) {
		return empty, errNativeShareHolder
	}
	return prepared, nil
}

func (s *NativeShareHolderStore) load(file *os.File, request transport.NativeShareBindingPreparePayload, subject transport.NativeShareBindingSubject) (transport.NativeShareBindingPreparedPayload, error) {
	record, err := s.loadRecord(file)
	if err != nil {
		return transport.NativeShareBindingPreparedPayload{}, err
	}
	defer clear(record.PrivateKey)
	if err := record.Prepared.Verify(request, subject, s.signer.Public().(ed25519.PublicKey)); err != nil {
		return transport.NativeShareBindingPreparedPayload{}, errNativeShareHolder
	}
	return record.Prepared, nil
}

func (s *NativeShareHolderStore) loadRecord(file *os.File) (nativeShareHolderRecord, error) {
	var empty nativeShareHolderRecord
	raw, err := io.ReadAll(io.LimitReader(file, nativeShareHolderMaxBytes+1))
	defer clear(raw)
	if err != nil || len(raw) > nativeShareHolderMaxBytes {
		return empty, errNativeShareHolder
	}
	var record nativeShareHolderRecord
	valid := false
	defer func() {
		if !valid {
			clear(record.PrivateKey)
		}
	}()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return empty, errNativeShareHolder
	}
	if decoder.Decode(new(any)) != io.EOF || record.Version != 1 || len(record.PrivateKey) != 32 {
		return empty, errNativeShareHolder
	}
	key, err := ecdh.X25519().NewPrivateKey(record.PrivateKey)
	if err != nil || record.Prepared.HolderX25519 != hex.EncodeToString(key.PublicKey().Bytes()) {
		return empty, errNativeShareHolder
	}
	if err := record.Prepared.Verify(record.Prepared.Prepare, record.Prepared.Subject, s.signer.Public().(ed25519.PublicKey)); err != nil {
		return empty, errNativeShareHolder
	}
	valid = true
	return record, nil
}

// subject reads only through the active authority transaction. The reservation
// must remain held through signing and a successful COMMIT before evidence leaves.
func (s *NativeShareHolderStore) subject(conn *sql.Conn, request transport.NativeShareBindingPreparePayload, endpoint string, session transport.HostSessionPayload) (transport.NativeShareBindingSubject, error) {
	var empty transport.NativeShareBindingSubject
	var payload []byte
	var state string
	if err := conn.QueryRowContext(context.Background(), `SELECT payload,launch_state FROM native_workers WHERE instance_id=?`, string(request.Binding.InstanceID)).Scan(&payload, &state); err != nil {
		return empty, errNativeShareHolder
	}
	worker, err := s.registry.decodeRecord(string(request.Binding.InstanceID), payload, state)
	if err != nil {
		return empty, errNativeShareHolder
	}
	var fenced int
	if err := conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM native_worker_recoveries WHERE instance_id=? AND (original_generation=? OR original_generation='')`, worker.Scope.InstanceID, worker.Scope.Generation).Scan(&fenced); err != nil || fenced != 0 {
		return empty, errNativeShareHolder
	}
	return ValidateNativeShareBinding(request, endpoint, session, worker)
}

// Descriptor-relative walks mirror the native admission ledger: ancestors may
// include shared /tmp, but the registry root and every descendant are owned 0700
// directories. Every file is owned, single-linked, regular and exactly 0600.
func nativeShareHolderPrivate(file *os.File, directory bool) error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return err
	}
	typ, mode := uint32(unix.S_IFREG), uint32(0600)
	if directory {
		typ, mode = unix.S_IFDIR, 0700
	}
	if uint32(stat.Mode)&unix.S_IFMT != typ || uint32(stat.Mode)&07777 != mode || stat.Uid != uint32(os.Geteuid()) || (!directory && stat.Nlink != 1) {
		return errNativeShareHolder
	}
	return nil
}

func nativeShareHolderDirectory(root string) (*os.File, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return nil, errNativeShareHolder
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(fd), "/")
	for _, part := range strings.Split(strings.TrimPrefix(root, "/"), "/") {
		next, err := nativeShareHolderOpenDir(current, part)
		current.Close()
		if err != nil {
			return nil, err
		}
		current = next
	}
	if err := nativeShareHolderPrivate(current, true); err != nil {
		current.Close()
		return nil, err
	}
	return current, nil
}

func nativeShareHolderOpenDir(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func nativeShareHolderChild(parent *os.File, name string) (*os.File, error) {
	if err := unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	child, err := nativeShareHolderOpenDir(parent, name)
	if err != nil {
		return nil, err
	}
	if err = nativeShareHolderPrivate(child, true); err == nil {
		err = child.Sync()
	}
	if err == nil {
		err = parent.Sync()
	}
	if err != nil {
		child.Close()
		return nil, err
	}
	return child, nil
}

func nativeShareHolderOpen(directory *os.File, name string, create bool) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	if create {
		flags = unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	}
	fd, err := unix.Openat(int(directory.Fd()), name, flags, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if err := nativeShareHolderPrivate(file, false); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func nativeShareHolderLock(directory *os.File) (*os.File, error) {
	return nativeShareHolderLockMode(directory, true)
}

func nativeShareHolderLockMode(directory *os.File, create bool) (*os.File, error) {
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	if create {
		flags |= unix.O_CREAT
	}
	fd, err := unix.Openat(int(directory.Fd()), "holder.lock", flags, 0600)
	if err != nil {
		return nil, err
	}
	lock := os.NewFile(uintptr(fd), "holder.lock")
	if err = nativeShareHolderPrivate(lock, false); err == nil {
		for {
			err = unix.Flock(fd, unix.LOCK_EX)
			if err != unix.EINTR {
				break
			}
		}
	}
	if err == nil && create {
		err = lock.Sync()
		if err == nil {
			err = directory.Sync()
		}
	}
	if err != nil {
		lock.Close()
		return nil, err
	}
	return lock, nil
}

func nativeShareHolderEntries(directory *os.File, allowed ...string) error {
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		found := false
		for _, name := range allowed {
			if entry.Name() == name {
				found = true
				break
			}
		}
		if !found {
			return errNativeShareHolder
		}
	}
	return nil
}

func nativeShareHolderExistingChild(parent *os.File, name string) (*os.File, error) {
	child, err := nativeShareHolderOpenDir(parent, name)
	if err != nil {
		return nil, err
	}
	if err := nativeShareHolderPrivate(child, true); err != nil {
		child.Close()
		return nil, err
	}
	return child, nil
}
