//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
	"golang.org/x/sys/unix"
)

// ManagedDirectCredentialScopeCheck independently authenticates the server,
// complete issue (including budget) and exact current native worker. It runs
// outside all locks, including on replay and after every blocking acquisition.
type ManagedDirectCredentialScopeCheck func(transport.ManagedDirectCredentialIssue, string, transport.HostSessionPayload) error

// ManagedDirectCredentialPublicationFence acquires current authority while
// the final key lock and SQLite reservation are held. It receives that reserved
// connection and must return a non-nil release on success. The store calls release
// exactly once after COMMIT or ROLLBACK, including when publication fails. It also
// releases any non-nil release returned with an error. Acquisition must fail fast
// and must not acquire registry, namespace or key locks, or call remote services.
// The richer scope verifier stays outside these locks.
type ManagedDirectCredentialPublicationFence func(*sql.Conn, transport.ManagedDirectCredentialIssue, string, transport.HostSessionPayload) (func(), error)

// ManagedDirectCredentialEvidence is public, closed installation evidence.
// It grants no channel or activation authority and contains no credential bytes.
type ManagedDirectCredentialEvidence struct {
	State          string
	IssueDigest    string
	CredentialHash string
	ACK            []byte
}

type managedDirectCredentialFile struct {
	IssueDigest string `json:"issueDigest"`
	Secret      []byte `json:"secret"`
	ACK         []byte `json:"ack"`
}

func (s *ManagedEndpointKeyStore) credentialValid(p transport.ManagedDirectCredentialIssue) bool {
	now := s.now()
	return !now.Before(p.IssuedAt) && now.Before(p.InstallExpiresAt) && now.Before(p.CredentialExpiresAt) && now.Before(p.Budget.ExpiresAt) && now.Before(p.PoP.Authorization.ExpiresAt)
}

func (s *ManagedEndpointKeyStore) credentialUseValid(p transport.ManagedDirectCredentialIssue) bool {
	now := s.now()
	return !now.Before(p.IssuedAt) && now.Before(p.CredentialExpiresAt) && now.Before(p.Budget.ExpiresAt) && now.Before(p.PoP.Authorization.ExpiresAt)
}

func (s *ManagedEndpointKeyStore) credentialInput(p transport.ManagedDirectCredentialIssue, configuredServer string, session transport.HostSessionPayload, verify ManagedDirectCredentialScopeCheck) (transport.ManagedDirectCredentialIssue, string, []byte, error) {
	if s == nil || s.registry == nil || s.now == nil || s.sync == nil || verify == nil {
		return p, "", nil, errManagedEndpointKey
	}
	raw, err := p.CanonicalBytes()
	if err != nil {
		return p, "", nil, errManagedEndpointKey
	}
	p, err = transport.DecodeManagedDirectCredentialIssue(raw)
	server := managedPrepareServerOrigin(configuredServer)
	if err != nil || len(raw) > 96*1024 || p.ChannelGeneration != 1 || server == "" || len(server) > 2048 || legacyTextServiceServer(configuredServer) != server || p.PoP.ACK.Reservation.ServerURL != server || p.PoP.ACK.Reservation.InstallationID != s.installation || !managedPrepareSessionMatches(p.PoP.Prepare.Subject, session) || !s.credentialUseValid(p) {
		return p, "", nil, errManagedEndpointKey
	}
	if err = verify(p, server, session); err != nil {
		return p, "", nil, err
	}
	return p, server, raw, nil
}

// validateCredentialEvidence reads successful Prepare and exact locally retained
// PoP evidence in the same SQLite snapshot. It never takes their namespace locks.
func (s *ManagedEndpointKeyStore) validateCredentialEvidence(conn *sql.Conn, p transport.ManagedDirectCredentialIssue, server string) error {
	// Installation has its own deadline. Validate immutable historical Prepare
	// and PoP evidence without calling live ConfirmPoP or changing the clock.
	if !s.credentialUseValid(p) {
		return errManagedEndpointKey
	}
	var currentInstallation string
	if err := conn.QueryRowContext(context.Background(), `SELECT value FROM native_registry_metadata WHERE name='installation_id'`).Scan(&currentInstallation); err != nil || currentInstallation != s.installation.String() {
		return errManagedEndpointKey
	}
	request, _ := p.PoP.Prepare.CanonicalBytes()
	requestDigest := sha256.Sum256(request)
	var bindingID, installationID, origin, expiry, state string
	var retainedRequest, retainedDigest, retainedACK []byte
	var keyStarted int
	err := conn.QueryRowContext(context.Background(), `SELECT enrollment_id,installation_id,server_url,request,request_digest,expires_at,state,ack,key_started FROM native_managed_endpoint_prepare_commands WHERE command_id=?`, p.PoP.Prepare.CommandID).Scan(&bindingID, &installationID, &origin, &retainedRequest, &retainedDigest, &expiry, &state, &retainedACK, &keyStarted)
	ack, _ := p.PoP.ACK.CanonicalBytes()
	if err != nil || bindingID != p.PoP.Prepare.Subject.ID.String() || installationID != s.installation.String() || origin != server || expiry != p.PoP.Prepare.Subject.ExpiresAt.Format(time.RFC3339Nano) || state != "succeeded" || keyStarted != 1 || !bytes.Equal(request, retainedRequest) || !bytes.Equal(requestDigest[:], retainedDigest) || !bytes.Equal(ack, retainedACK) || !managedEndpointPrepareSuccessForScope(retainedACK, p.PoP.Prepare, server, s.installation) {
		return errManagedEndpointKey
	}
	var enrollment, direct, installation string
	var popRequest, digest, proof []byte
	if err := conn.QueryRowContext(context.Background(), `SELECT enrollment_id,direct_intent_id,installation_id,request,request_digest,proof FROM native_managed_endpoint_pop_challenges WHERE challenge_id=?`, p.PoP.ChallengeID).Scan(&enrollment, &direct, &installation, &popRequest, &digest, &proof); err != nil {
		return errManagedEndpointKey
	}
	canonical, _ := p.PoP.CanonicalBytes()
	sum := sha256.Sum256(canonical)
	decoded, _, err := transport.DecodeManagedEndpointPoPProofVerifier(proof)
	proofDigest := sha256.Sum256(proof)
	if err != nil || enrollment != p.PoP.Prepare.Subject.ID.String() || direct != p.PoP.Prepare.Subject.DirectIntentID.String() || installation != s.installation.String() || !bytes.Equal(popRequest, canonical) || !bytes.Equal(digest, sum[:]) || decoded.ChallengeID != p.PoPReceipt.ChallengeID || decoded.TranscriptHash != p.PoPReceipt.TranscriptHash || hex.EncodeToString(proofDigest[:]) != p.PoPReceipt.ProofDigest {
		return errManagedEndpointKey
	}
	return nil
}

func (s *ManagedEndpointKeyStore) credentialRow(conn *sql.Conn, p transport.ManagedDirectCredentialIssue, raw []byte) (ManagedDirectCredentialEvidence, bool, error) {
	var result ManagedDirectCredentialEvidence
	var binding, direct, installation string
	var retained, digest []byte
	sum := sha256.Sum256(raw)
	var hash sql.NullString
	err := conn.QueryRowContext(context.Background(), `SELECT enrollment_id,direct_intent_id,installation_id,issue,issue_digest,state,credential_hash,ack FROM native_managed_direct_v1_credentials WHERE credential_id=?`, p.CredentialID).Scan(&binding, &direct, &installation, &retained, &digest, &result.State, &hash, &result.ACK)
	if errors.Is(err, sql.ErrNoRows) {
		return result, false, nil
	}
	if err != nil {
		return result, false, err
	}
	if binding != p.PoP.Prepare.Subject.ID.String() || direct != p.PoP.Prepare.Subject.DirectIntentID.String() || installation != s.installation.String() || !bytes.Equal(raw, retained) || !bytes.Equal(sum[:], digest) || (result.State != "attempted" && result.State != "installed") || (result.State == "attempted" && (hash.Valid || result.ACK != nil)) || (result.State == "installed" && (!hash.Valid || result.ACK == nil)) {
		return result, false, errManagedEndpointKey
	}
	result.IssueDigest = hex.EncodeToString(sum[:])
	result.CredentialHash = hash.String
	return result, true, nil
}

// InstallCredential commits an immutable attempt before publishing a separate
// restrictive secret file. Interrupted exact attempts may recover only after
// validating independent successful Prepare, PoP and live authority again.
// Installed missing or damaged secrets fail closed and are never regenerated.
func (s *ManagedEndpointKeyStore) InstallCredential(issue transport.ManagedDirectCredentialIssue, configuredServer string, session transport.HostSessionPayload, verify ManagedDirectCredentialScopeCheck, fence ManagedDirectCredentialPublicationFence) ([]byte, error) {
	if fence == nil || s == nil {
		return nil, errManagedEndpointKey
	}
	p, server, raw, err := s.credentialInput(issue, configuredServer, session, verify)
	if err != nil {
		return nil, err
	}
	if !s.credentialValid(p) {
		return nil, errManagedEndpointKey
	}
	sum := sha256.Sum256(raw)
	err = s.withPoPLocked(func(conn *sql.Conn, dir *os.File) error {
		if !s.credentialValid(p) {
			return errManagedEndpointKey
		}
		if err := s.validateCredentialEvidence(conn, p, server); err != nil {
			return err
		}
		_, exists, err := s.credentialRow(conn, p, raw)
		if err != nil || exists {
			return err
		}
		_, err = conn.ExecContext(context.Background(), `INSERT INTO native_managed_direct_v1_credentials(credential_id,enrollment_id,direct_intent_id,installation_id,issue,issue_digest,state) VALUES(?,?,?,?,?,?,'attempted')`, p.CredentialID, p.PoP.Prepare.Subject.ID, p.PoP.Prepare.Subject.DirectIntentID, s.installation, raw, sum[:])
		return err
	})
	if err != nil {
		return nil, err
	}
	if err = verify(p, server, session); err != nil {
		return nil, err
	}
	// Capture exact custody after any contention, then authenticate current authority
	// again before deriving or writing secret material.
	var private []byte
	defer func() { clear(private) }()
	err = s.withPoPLocked(func(conn *sql.Conn, dir *os.File) error {
		if !s.credentialValid(p) {
			return errManagedEndpointKey
		}
		if err := s.validateCredentialEvidence(conn, p, server); err != nil {
			return err
		}
		var err error
		private, err = s.loadPoPKey(conn, dir, p.PoP.ACK.Reservation)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err = verify(p, server, session); err != nil {
		return nil, err
	}
	secret, ack, err := transport.DeriveManagedDirectCredentialHost(p, private, s.now())
	defer clear(secret)
	if err != nil {
		return nil, err
	}
	canonical, err := ack.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	hash, err := transport.ManagedDirectCredentialHash(ack.TranscriptHash, secret)
	if err != nil {
		return nil, err
	}
	record, err := json.Marshal(managedDirectCredentialFile{hex.EncodeToString(sum[:]), secret, canonical})
	defer clear(record)
	if err != nil {
		return nil, err
	}
	err = s.withCredentialLockedScoped(func(conn *sql.Conn, dir *os.File, release *func()) error {
		if !s.credentialValid(p) {
			return errManagedEndpointKey
		}
		if err := s.validateCredentialEvidence(conn, p, server); err != nil {
			return err
		}
		row, exists, err := s.credentialRow(conn, p, raw)
		if err != nil || !exists {
			return errManagedEndpointKey
		}
		retained, err := s.loadPoPKey(conn, dir, p.PoP.ACK.Reservation)
		defer clear(retained)
		if err != nil || !bytes.Equal(private, retained) {
			return errManagedEndpointKey
		}
		if row.State == "installed" && (row.CredentialHash != hash || !bytes.Equal(row.ACK, canonical)) {
			return errManagedEndpointKey
		}
		name := managedDirectCredentialName(s.installation, server, p)
		*release, err = fence(conn, p, server, session)
		if err != nil {
			return err
		}
		if *release == nil {
			return errManagedEndpointKey
		}
		if err := s.publishCredential(dir, name, record, row.State == "installed"); err != nil {
			return err
		}
		if !s.credentialValid(p) {
			return errManagedEndpointKey
		}
		result, err := conn.ExecContext(context.Background(), `UPDATE native_managed_direct_v1_credentials SET state='installed',credential_hash=?,ack=? WHERE credential_id=? AND issue=? AND installation_id=? AND (state='attempted' OR (state='installed' AND credential_hash=? AND ack=?))`, hash, canonical, p.CredentialID, raw, s.installation, hash, canonical)
		if err != nil {
			return err
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return errManagedEndpointKey
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err = verify(p, server, session); err != nil {
		return nil, err
	}
	if !s.credentialValid(p) {
		return nil, errManagedEndpointKey
	}
	return bytes.Clone(canonical), nil
}

// publishCredential compares complete canonical bytes, including secret bytes,
// before replay. No existing file is replaced; symlinks and unsafe modes fail.
func (s *ManagedEndpointKeyStore) publishCredential(dir *os.File, name string, raw []byte, installed bool) error {
	compare := func(suffix string, durable bool) error {
		file, err := nativeShareHolderOpen(dir, name+suffix, false)
		if err != nil {
			return err
		}
		defer file.Close()
		retained, err := io.ReadAll(io.LimitReader(file, 4097))
		defer clear(retained)
		if err != nil || len(retained) > 4096 || !bytes.Equal(retained, raw) {
			return errManagedEndpointKey
		}
		if durable {
			return s.sync(file)
		}
		return nil
	}
	err := compare(".json", !installed)
	if err != nil && !installed && !errors.Is(err, unix.ENOENT) {
		// Only an exact attempted installation may repair the two-link window
		// between publication and removal of its pending name.
		if err := recoverManagedDirectCredentialLinks(dir, name, raw); err != nil {
			return err
		}
		err = compare(".json", true)
	}
	if err == nil {
		var stat unix.Stat_t
		if err := unix.Fstatat(int(dir.Fd()), name+".pending", &stat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
			return errManagedEndpointKey
		}
		if !installed {
			return s.sync(dir)
		}
		return nil
	}
	if installed || !errors.Is(err, unix.ENOENT) {
		return errManagedEndpointKey
	}
	file, err := nativeShareHolderOpen(dir, name+".pending", true)
	if errors.Is(err, unix.EEXIST) {
		if err = compare(".pending", true); err != nil {
			return errManagedEndpointKey
		}
	} else {
		if err != nil {
			return err
		}
		n, writeErr := file.Write(raw)
		if writeErr == nil && n != len(raw) {
			writeErr = io.ErrShortWrite
		}
		if writeErr == nil {
			writeErr = s.sync(file)
		}
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if err = unix.Linkat(int(dir.Fd()), name+".pending", int(dir.Fd()), name+".json", 0); err != nil {
		return err
	}
	if err = unix.Unlinkat(int(dir.Fd()), name+".pending", 0); err != nil {
		return err
	}
	return s.sync(dir)
}

func recoverManagedDirectCredentialLinks(dir *os.File, name string, raw []byte) error {
	open := func(suffix string) (*os.File, unix.Stat_t, error) {
		var stat unix.Stat_t
		fd, err := unix.Openat(int(dir.Fd()), name+suffix, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			return nil, stat, err
		}
		file := os.NewFile(uintptr(fd), name+suffix)
		if err = unix.Fstat(fd, &stat); err != nil || uint32(stat.Mode)&unix.S_IFMT != unix.S_IFREG || uint32(stat.Mode)&07777 != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 2 {
			file.Close()
			return nil, stat, errManagedEndpointKey
		}
		return file, stat, nil
	}
	published, first, err := open(".json")
	if err != nil {
		return errManagedEndpointKey
	}
	defer published.Close()
	pending, second, err := open(".pending")
	if err != nil {
		return errManagedEndpointKey
	}
	defer pending.Close()
	if first.Dev != second.Dev || first.Ino != second.Ino {
		return errManagedEndpointKey
	}
	retained, err := io.ReadAll(io.LimitReader(published, 4097))
	defer clear(retained)
	if err != nil || len(retained) > 4096 || !bytes.Equal(retained, raw) {
		return errManagedEndpointKey
	}
	for _, suffix := range []string{".json", ".pending"} {
		var current unix.Stat_t
		if err := unix.Fstatat(int(dir.Fd()), name+suffix, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil || current.Dev != first.Dev || current.Ino != first.Ino || current.Nlink != 2 || current.Mode != first.Mode || current.Uid != first.Uid {
			return errManagedEndpointKey
		}
	}
	return unix.Unlinkat(int(dir.Fd()), name+".pending", 0)
}

// CredentialEvidence verifies custody and completed installation through exact
// replay, returning only public evidence. It never exposes secret material.
func (s *ManagedEndpointKeyStore) CredentialEvidence(issue transport.ManagedDirectCredentialIssue, configuredServer string, session transport.HostSessionPayload, verify ManagedDirectCredentialScopeCheck) (ManagedDirectCredentialEvidence, error) {
	p, server, raw, err := s.credentialInput(issue, configuredServer, session, verify)
	if err != nil {
		return ManagedDirectCredentialEvidence{}, err
	}
	var result ManagedDirectCredentialEvidence
	err = s.withPoPLocked(func(conn *sql.Conn, dir *os.File) error {
		if err := s.validateCredentialEvidence(conn, p, server); err != nil {
			return err
		}
		row, exists, err := s.credentialRow(conn, p, raw)
		if err != nil || !exists || row.State != "installed" {
			return errManagedEndpointKey
		}
		private, err := s.loadPoPKey(conn, dir, p.PoP.ACK.Reservation)
		clear(private)
		if err != nil {
			return err
		}
		name := managedDirectCredentialName(s.installation, server, p)
		file, err := nativeShareHolderOpen(dir, name+".json", false)
		if err != nil {
			return err
		}
		record, err := io.ReadAll(io.LimitReader(file, 4097))
		closeErr := file.Close()
		defer clear(record)
		var retained managedDirectCredentialFile
		defer func() { clear(retained.Secret) }()
		if err != nil || closeErr != nil || len(record) > 4096 || json.Unmarshal(record, &retained) != nil {
			return errManagedEndpointKey
		}
		canonical, err := json.Marshal(retained)
		defer clear(canonical)
		ack, ackErr := transport.DecodeManagedDirectCredentialACK(row.ACK)
		transcript := sha256.Sum256(append([]byte("pagnet/managed-direct-credential/transcript/v1/"), raw...))
		hash, hashErr := transport.ManagedDirectCredentialHash(ack.TranscriptHash, retained.Secret)
		if err != nil || ackErr != nil || hashErr != nil || !bytes.Equal(canonical, record) || retained.IssueDigest != row.IssueDigest || !bytes.Equal(retained.ACK, row.ACK) || ack.CredentialID != p.CredentialID || ack.TranscriptHash != hex.EncodeToString(transcript[:]) || hash != row.CredentialHash {
			return errManagedEndpointKey
		}
		if err := s.publishCredential(dir, name, canonical, true); err != nil {
			return err
		}
		result = row
		return nil
	})
	if err != nil {
		return ManagedDirectCredentialEvidence{}, err
	}
	if err = verify(p, server, session); err != nil {
		return ManagedDirectCredentialEvidence{}, err
	}
	if !s.credentialUseValid(p) {
		return ManagedDirectCredentialEvidence{}, errManagedEndpointKey
	}
	return result, nil
}

// The credential scope includes the enrollment and credential, because endpoint
// private-key slots may be shared by independent target enrollments.
func managedDirectCredentialName(installation domain.ID, server string, p transport.ManagedDirectCredentialIssue) string {
	raw, _ := json.Marshal([]string{installation.String(), server, p.PoP.Prepare.Subject.ID.String(), p.PoP.Prepare.Subject.DirectIntentID.String(), p.CredentialID.String()})
	sum := sha256.Sum256(raw)
	return "credential-v1-" + hex.EncodeToString(sum[:])
}

// Lock order is registry mutex, target key namespace flock, SQLite reservation.
func (s *ManagedEndpointKeyStore) withCredentialLockedScoped(fn func(*sql.Conn, *os.File, *func()) error) error {
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()
	root, err := nativeShareHolderDirectory(s.registry.root)
	if err != nil {
		return err
	}
	defer root.Close()
	dir, err := nativeShareHolderExistingChild(root, nativeManagedEndpointKeyNamespace)
	if err != nil {
		return err
	}
	defer dir.Close()
	lock, err := nativeShareHolderLockMode(dir, false)
	if err != nil {
		return err
	}
	defer lock.Close()
	conn, err := s.registry.db.Conn(context.Background())
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	var release func()
	committed := false
	defer func() {
		if !committed {
			if _, rollbackErr := conn.ExecContext(context.Background(), "ROLLBACK"); rollbackErr != nil {
				_ = conn.Raw(func(any) error { return driver.ErrBadConn })
				_ = conn.Close()
			}
		}
		if release != nil {
			release()
		}
	}()
	if err = fn(conn, dir, &release); err != nil {
		return err
	}
	_, err = conn.ExecContext(context.Background(), "COMMIT")
	committed = err == nil
	return err
}
