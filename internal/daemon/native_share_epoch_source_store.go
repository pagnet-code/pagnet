//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/domain"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
	"golang.org/x/sys/unix"
)

var errNativeShareEpochSourceStore = errors.New("native share epoch source unavailable, unsafe, expired or conflicting")

const nativeShareEpochSourceMaxBytes = 64 << 10

// NativeShareEpochSourceIntent is independently retained public authority. Expected
// excludes EpochID and EpochPossessionVerifier: Prepare generates them once.
// Recipient and source sessions, keys, connections and the committed verifier
// must come from authenticated authority, never an incoming envelope.
// Expected.TenantID identifies the recipient; source authority may belong to a
// different account/tenant and is validated against its own registry and session.
// Expected's connection IDs identify the recipient command incarnation. Source
// connection IDs independently identify the source incarnation.
type NativeShareEpochSourceIntent struct {
	Prepared                       transport.NativeShareBindingPreparedPayload `json:"prepared"`
	RecipientHostKey               ed25519.PublicKey                           `json:"recipientHostKey"`
	RecipientServerURL             string                                      `json:"recipientServerUrl"`
	RecipientSession               transport.HostSessionPayload                `json:"recipientSession"`
	RecipientConnectionID          string                                      `json:"recipientConnectionId"`
	RecipientAuthorityConnectionID string                                      `json:"recipientAuthorityConnectionId"`
	Expected                       transport.NativeShareEpochMetadata          `json:"expected"`
	Source                         transport.NativeShareEpochSourceContext     `json:"source"`
	SourceSession                  transport.HostSessionPayload                `json:"sourceSession"`
	SourceInstanceID               domain.ID                                   `json:"sourceInstanceId"`
	SourceNativeGeneration         string                                      `json:"sourceNativeGeneration"`
	CommittedVerifier              ed25519.PublicKey                           `json:"committedVerifier"`
}

// Reauthorize must check current owner, consent, selection, binding, both live
// connection incarnations, source identity and committed epoch. It receives a
// deep public copy and MUST NOT reenter this store, the registry/database, holder
// store or network keyring locks. Prepare holds registry, operation and network
// locks, and may hold a SQLite write reservation while invoking it.
type NativeShareEpochSourceAuthorization struct {
	NativeShareEpochSourceIntent
	Reauthorize func(NativeShareEpochSourceIntent) error
}

type nativeShareEpochSourceRecord struct {
	Version        int                                      `json:"version"`
	Intent         NativeShareEpochSourceIntent             `json:"intent"`
	Package        transport.NativeShareEpochPackage        `json:"package"`
	SourceEnvelope transport.NativeShareEpochSourceEnvelope `json:"sourceEnvelope"`
}

// NativeShareEpochSourceStore is dormant: no production command invokes it. It
// writes only immutable public intent and ciphertext beneath the registry root;
// it never activates epochs or mutates a keyring, worker, grant or manifest.
// The caller MUST supply a dedicated source holder from trusted external storage.
// There is deliberately no host-identity or recipient-holder fallback. Production
// use requires a separate source-holder provisioning and provenance boundary.
type NativeShareEpochSourceStore struct {
	registry *NativeWorkerRegistry
	signer   ed25519.PrivateKey
	now      func() time.Time
	// Local seams allow testing every uncertain durability boundary.
	sync  func(*os.File) error
	fresh func() (*hostcrypto.FreshNativeShareEpoch, error)
}

func NewNativeShareEpochSourceStore(registry *NativeWorkerRegistry, signer ed25519.PrivateKey, now func() time.Time) (*NativeShareEpochSourceStore, error) {
	if registry == nil || now == nil || len(signer) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(signer.Seed()), signer) {
		return nil, errNativeShareEpochSourceStore
	}
	return &NativeShareEpochSourceStore{registry: registry, signer: bytes.Clone(signer), now: now, sync: (*os.File).Sync, fresh: hostcrypto.NewFreshNativeShareEpoch}, nil
}
func (s *NativeShareEpochSourceStore) String() string { return "NativeShareEpochSourceStore{closed}" }

// Format protects both pointer and value formatting, including %#v, from
// traversing the retained private signer.
func (s NativeShareEpochSourceStore) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, "NativeShareEpochSourceStore{closed}")
}

func nativeShareEpochSourceCopy(a NativeShareEpochSourceIntent) NativeShareEpochSourceIntent {
	a.Prepared.Signature = bytes.Clone(a.Prepared.Signature)
	a.RecipientHostKey = bytes.Clone(a.RecipientHostKey)
	a.CommittedVerifier = bytes.Clone(a.CommittedVerifier)
	a.RecipientSession.ProtocolFeatures = append([]string(nil), a.RecipientSession.ProtocolFeatures...)
	a.SourceSession.ProtocolFeatures = append([]string(nil), a.SourceSession.ProtocolFeatures...)
	return a
}
func nativeShareEpochSourceOpaque(s string) bool {
	return s != "" && len(s) <= 256 && utf8.ValidString(s) && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}
func nativeShareEpochSourceSession(subject transport.NativeShareBindingSubject, session transport.HostSessionPayload) bool {
	return string(subject.TenantID) == session.TenantID && string(subject.AccountID) == session.AccountID && string(subject.HostID) == session.HostID && string(subject.NativeAdmissionID) == session.NativeAdmissionID && string(subject.RunnerID) == session.RunnerID && subject.RunnerEpoch == session.RunnerEpoch.UTC().Format(time.RFC3339Nano) && subject.BootID == session.BootID && !session.RunnerEpoch.IsZero() && nativeShareEpochSourceOpaque(session.HostCredentialID) && (session.OwnershipScope == "personal" || session.OwnershipScope == "organization" && session.AccountID == session.TenantID)
}
func (s *NativeShareEpochSourceStore) deadline(a NativeShareEpochSourceIntent) error {
	deadline, e1 := time.Parse(time.RFC3339Nano, a.Expected.Deadline)
	expiry, e2 := time.Parse(time.RFC3339Nano, a.Prepared.Prepare.Binding.ExpiresAt)
	now := s.now()
	if e1 != nil || e2 != nil || now.IsZero() || deadline.After(expiry) || !now.Before(deadline) || !now.Before(expiry) {
		return errNativeShareEpochSourceStore
	}
	return nil
}
func (s *NativeShareEpochSourceStore) validate(a NativeShareEpochSourceIntent, private []byte) error {
	m, source, b := a.Expected, a.Source, a.Prepared.Prepare.Binding
	if m.EpochID != "" || m.EpochPossessionVerifier != "" || len(a.CommittedVerifier) != ed25519.PublicKeySize || len(a.RecipientHostKey) != ed25519.PublicKeySize || !nativeShareEpochStageID(a.SourceInstanceID) || !nativeShareEpochSourceOpaque(a.SourceNativeGeneration) {
		return errNativeShareEpochSourceStore
	}
	// Validate the entire metadata schema without assigning a generated epoch.
	check := m
	check.EpochID = "ffffffff-ffff-4fff-8fff-ffffffffffff"
	if check.EpochID == check.PreviousEpochID {
		check.EpochID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	}
	check.EpochPossessionVerifier = hex.EncodeToString(a.CommittedVerifier)
	if _, err := check.AAD(); err != nil {
		return errNativeShareEpochSourceStore
	}
	if _, err := source.CanonicalBytes(); err != nil {
		return errNativeShareEpochSourceStore
	}
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil || hex.EncodeToString(key.PublicKey().Bytes()) != source.HolderX25519 || source.HolderID == a.Prepared.HolderID || source.HolderX25519 == a.Prepared.HolderX25519 || source.SigningKey != hex.EncodeToString(s.signer.Public().(ed25519.PublicKey)) {
		return errNativeShareEpochSourceStore
	}
	if err := a.Prepared.Verify(a.Prepared.Prepare, a.Prepared.Subject, a.RecipientHostKey); err != nil {
		return errNativeShareEpochSourceStore
	}
	if a.RecipientServerURL != a.Prepared.Subject.ServerURL || !nativeShareEpochSourceSession(a.Prepared.Subject, a.RecipientSession) || !nativeShareEpochSourceSession(source.Subject, a.SourceSession) || !nativeShareEpochSourceOpaque(a.RecipientConnectionID) || !nativeShareEpochSourceOpaque(a.RecipientAuthorityConnectionID) {
		return errNativeShareEpochSourceStore
	}
	if source.Subject.ServerURL != a.RecipientServerURL || source.HostCredentialID != a.SourceSession.HostCredentialID || source.OwnershipScope != a.SourceSession.OwnershipScope || m.CommandConnectionID != a.RecipientConnectionID || m.AuthorityConnectionID != a.RecipientAuthorityConnectionID || source.ProposalID != b.ProposalID || source.GrantID != b.GrantID || source.BindingID != b.BindingID || m.BindingDigest != a.Prepared.BindingDigest || m.HolderID != a.Prepared.HolderID || m.HolderX25519 != a.Prepared.HolderX25519 || m.TenantID != a.Prepared.Subject.TenantID || m.NetworkID != b.NetworkID || m.ProposalRevision != b.ProposalRevision || m.GrantGeneration != b.GrantGeneration {
		return errNativeShareEpochSourceStore
	}
	return s.deadline(a)
}
func (s *NativeShareEpochSourceStore) authorize(conn *sql.Conn, a NativeShareEpochSourceAuthorization) error {
	request := a.Prepared.Prepare
	request.Binding.InstanceID = a.SourceInstanceID
	request.Binding.NativeGeneration = a.SourceNativeGeneration
	holder := NativeShareHolderStore{registry: s.registry}
	subject, err := holder.subject(conn, request, a.Source.Subject.ServerURL, a.SourceSession)
	if err != nil || subject != a.Source.Subject || s.deadline(a.NativeShareEpochSourceIntent) != nil {
		return errNativeShareEpochSourceStore
	}
	if err := a.Reauthorize(nativeShareEpochSourceCopy(a.NativeShareEpochSourceIntent)); err != nil {
		return errNativeShareEpochSourceStore
	}
	return s.deadline(a.NativeShareEpochSourceIntent)
}
func nativeShareEpochSourceAuthority(ring *hostcrypto.Keyring, a NativeShareEpochSourceIntent) error {
	active := 0
	seen := make(map[string]bool, len(ring.Epochs))
	for _, epoch := range ring.Epochs {
		if epoch.ID == "" || seen[epoch.ID] {
			return errNativeShareEpochSourceStore
		}
		seen[epoch.ID] = true
		if epoch.State == hostcrypto.EpochActive {
			active++
			if epoch.ID != string(a.Expected.PreviousEpochID) {
				return errNativeShareEpochSourceStore
			}
		}
	}
	if active != 1 {
		return errNativeShareEpochSourceStore
	}
	signer, err := hostcrypto.EpochPossessionSigner(ring, string(a.Expected.PreviousEpochID))
	if err != nil {
		return errNativeShareEpochSourceStore
	}
	defer clear(signer)
	if !bytes.Equal(signer.Public().(ed25519.PublicKey), a.CommittedVerifier) {
		return errNativeShareEpochSourceStore
	}
	return nil
}
func (s *NativeShareEpochSourceStore) verify(record nativeShareEpochSourceRecord, a NativeShareEpochSourceIntent, private []byte) error {
	expected := a.Expected
	expected.EpochID = record.Package.Metadata.EpochID
	expected.EpochPossessionVerifier = record.Package.Metadata.EpochPossessionVerifier
	trusted := s.signer.Public().(ed25519.PublicKey)
	if err := record.Package.Verify(expected, trusted, s.now()); err != nil {
		return errNativeShareEpochSourceStore
	}
	digest, err := transport.NativeShareEpochPackageDigest(record.Package)
	if err != nil {
		return errNativeShareEpochSourceStore
	}
	metadata := transport.NativeShareEpochSourceMetadata{Recipient: expected, Source: a.Source, RecipientPackageDigest: digest}
	key, err := hostcrypto.OpenNativeShareEpochSource(record.SourceEnvelope, metadata, trusted, private, s.now())
	if err != nil {
		return errNativeShareEpochSourceStore
	}
	key.Destroy()
	return nil
}

// Prepare serializes registry -> operation flock -> network authority -> SQLite.
// No SQLite connection is acquired before entering the network authority lock.
// A durable empty pending marker precedes all randomness. Every pending state is
// terminal, including a complete save or a published file with pending still present.
func (s *NativeShareEpochSourceStore) Prepare(a NativeShareEpochSourceAuthorization, sourceHolderPrivate []byte) (transport.NativeShareEpochPackage, error) {
	var empty transport.NativeShareEpochPackage
	if s == nil || s.registry == nil || s.now == nil || s.sync == nil || s.fresh == nil || len(s.signer) != ed25519.PrivateKeySize || a.Reauthorize == nil {
		return empty, errNativeShareEpochSourceStore
	}
	a.NativeShareEpochSourceIntent = nativeShareEpochSourceCopy(a.NativeShareEpochSourceIntent)
	private := bytes.Clone(sourceHolderPrivate)
	defer clear(private)
	if err := s.validate(a.NativeShareEpochSourceIntent, private); err != nil {
		return empty, err
	}
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()
	root, err := nativeShareHolderDirectory(s.registry.root)
	if err != nil {
		return empty, err
	}
	defer root.Close()
	namespace, err := nativeShareHolderChild(root, "prepared-share-epochs")
	if err != nil {
		return empty, err
	}
	defer namespace.Close()
	if err := nativeShareEpochStageChildren(namespace); err != nil {
		return empty, err
	}
	directory, err := nativeShareHolderChild(namespace, string(a.Expected.OperationID))
	if err != nil {
		return empty, err
	}
	defer directory.Close()
	lock, err := s.lock(directory)
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	var result transport.NativeShareEpochPackage
	err = hostcrypto.WithNetworkKeyring(context.Background(), filepath.Dir(s.registry.root), string(a.Expected.NetworkID), func(ring *hostcrypto.Keyring) error {
		defer func() {
			for i := range ring.Epochs {
				clear(ring.Epochs[i].Key)
			}
		}()
		if err := nativeShareEpochSourceAuthority(ring, a.NativeShareEpochSourceIntent); err != nil {
			return err
		}
		conn, err := s.registry.db.Conn(context.Background())
		if err != nil {
			return err
		}
		defer conn.Close()
		if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
			return err
		}
		defer func() { _, _ = conn.ExecContext(context.Background(), "ROLLBACK") }()
		if err := s.authorize(conn, a); err != nil {
			return err
		}
		if err := nativeShareHolderEntries(directory, "source.lock", "source.json"); err != nil {
			return err
		}
		record := nativeShareEpochSourceRecord{Version: 1, Intent: a.NativeShareEpochSourceIntent}
		file, err := nativeShareHolderOpen(directory, "source.json", false)
		if err == nil {
			raw, readErr := io.ReadAll(io.LimitReader(file, nativeShareEpochSourceMaxBytes+1))
			closeErr := file.Close()
			if readErr != nil || closeErr != nil || len(raw) > nativeShareEpochSourceMaxBytes || json.Unmarshal(raw, &record) != nil || record.Version != 1 {
				return errNativeShareEpochSourceStore
			}
			canonical, err := json.Marshal(record)
			want, _ := json.Marshal(a.NativeShareEpochSourceIntent)
			got, _ := json.Marshal(record.Intent)
			if err != nil || !bytes.Equal(raw, canonical) || !bytes.Equal(want, got) {
				return errNativeShareEpochSourceStore
			}
		} else if errors.Is(err, unix.ENOENT) {
			pending, err := nativeShareHolderOpen(directory, "source.pending", true)
			if err != nil {
				return err
			}
			defer pending.Close()
			// Sync both marker inode and directory before generating a prospective key.
			if err := s.sync(pending); err != nil {
				return err
			}
			if err := s.sync(directory); err != nil {
				return err
			}
			fresh, err := s.fresh()
			if err != nil {
				return err
			}
			defer fresh.Destroy()
			metadata := a.Expected
			metadata.EpochID = fresh.ID()
			verifier, err := fresh.PossessionVerifier(metadata.NetworkID)
			if err != nil {
				return err
			}
			metadata.EpochPossessionVerifier = hex.EncodeToString(verifier)
			record.Package, record.SourceEnvelope, err = hostcrypto.SealNativeShareEpochWithSource(fresh, metadata, a.Source, s.signer, s.now())
			if err != nil {
				return err
			}
			if err := s.verify(record, a.NativeShareEpochSourceIntent, private); err != nil {
				return err
			}
			raw, err := json.Marshal(record)
			if err != nil || len(raw) > nativeShareEpochSourceMaxBytes {
				return errNativeShareEpochSourceStore
			}
			n, err := pending.Write(raw)
			if err != nil {
				return err
			}
			if n != len(raw) {
				return io.ErrShortWrite
			}
			if err := s.sync(pending); err != nil {
				return err
			}
			if err := pending.Close(); err != nil {
				return err
			}
			if err := s.authorize(conn, a); err != nil {
				return err
			}
			if err := unix.Linkat(int(directory.Fd()), "source.pending", int(directory.Fd()), "source.json", 0); err != nil {
				return err
			}
			// Persist the final link before removing the durable generation marker.
			// Otherwise a crash could retain the unlink while losing the final link,
			// permitting a second generation under the same operation identifier.
			if err := s.sync(directory); err != nil {
				return err
			}
			if err := unix.Unlinkat(int(directory.Fd()), "source.pending", 0); err != nil {
				return err
			}
		} else {
			return err
		}
		if err := s.verify(record, a.NativeShareEpochSourceIntent, private); err != nil {
			return err
		}
		for _, dir := range []*os.File{directory, namespace, root} {
			if err := s.sync(dir); err != nil {
				return err
			}
		}
		if err := s.authorize(conn, a); err != nil {
			return err
		}
		if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
			return err
		}
		if err := s.authorize(conn, a); err != nil {
			return err
		}
		if err := nativeShareEpochSourceAuthority(ring, a.NativeShareEpochSourceIntent); err != nil {
			return err
		}
		result = record.Package
		return s.deadline(a.NativeShareEpochSourceIntent)
	})
	if err != nil {
		return empty, err
	}
	return result, nil
}
func (s *NativeShareEpochSourceStore) lock(directory *os.File) (*os.File, error) {
	fd, err := unix.Openat(int(directory.Fd()), "source.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "source.lock")
	if err = nativeShareHolderPrivate(file, false); err == nil {
		for {
			err = unix.Flock(fd, unix.LOCK_EX)
			if err != unix.EINTR {
				break
			}
		}
	}
	if err == nil {
		err = s.sync(file)
	}
	if err == nil {
		err = s.sync(directory)
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}
