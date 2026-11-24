//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/pagnet-code/pagnet/transport"
	"golang.org/x/sys/unix"
)

// DirectManagedSourceCredentialScopeCheck independently authenticates the server,
// complete issue (including budget) and exact current native worker. It runs
// outside all locks, including on replay and after every blocking acquisition.
type DirectManagedSourceCredentialScopeCheck func(transport.DirectManagedSourceCredentialIssue, string, transport.HostSessionPayload) error

// DirectManagedSourceCredentialEvidence is public, closed installation evidence.
// It grants no channel or activation authority and contains no credential bytes.
type DirectManagedSourceCredentialEvidence struct {
	State          string
	IssueDigest    string
	CredentialHash string
	ACK            []byte
}

type directManagedSourceCredentialFile struct {
	IssueDigest string `json:"issueDigest"`
	Secret      []byte `json:"secret"`
}

func (s *DirectManagedSourceKeyStore) credentialValid(p transport.DirectManagedSourceCredentialIssue) bool {
	now := s.now()
	return !now.Before(p.IssuedAt) && now.Before(p.InstallExpiresAt) && now.Before(p.CredentialExpiresAt) && now.Before(p.BudgetExpiresAt)
}

func (s *DirectManagedSourceKeyStore) credentialInput(p transport.DirectManagedSourceCredentialIssue, configuredServer string, session transport.HostSessionPayload, verify DirectManagedSourceCredentialScopeCheck) (transport.DirectManagedSourceCredentialIssue, string, []byte, error) {
	if s == nil || s.registry == nil || s.now == nil || s.sync == nil || verify == nil {
		return p, "", nil, errDirectManagedSourceKey
	}
	raw, err := p.CanonicalBytes()
	if err != nil {
		return p, "", nil, errDirectManagedSourceKey
	}
	p, err = transport.DecodeDirectManagedSourceCredentialIssue(raw)
	server := managedPrepareServerOrigin(configuredServer)
	if err != nil || server == "" || legacyTextServiceServer(configuredServer) != server || p.PoP.ACK.Reservation.ServerURL != server || p.PoP.ACK.Reservation.InstallationID != s.installation || !directManagedSourceSessionMatches(p.PoP.Prepare.Subject, session) || !s.credentialValid(p) {
		return p, "", nil, errDirectManagedSourceKey
	}
	if err = verify(p, server, session); err != nil {
		return p, "", nil, err
	}
	return p, server, raw, nil
}

// validateCredentialEvidence reads successful Prepare and exact locally retained
// PoP evidence in the same SQLite snapshot. It never takes their namespace locks.
func (s *DirectManagedSourceKeyStore) validateCredentialEvidence(conn *sql.Conn, p transport.DirectManagedSourceCredentialIssue, server string) error {
	if !s.credentialValid(p) || s.validatePoPPrepare(conn, p.PoP, server) != nil {
		return errDirectManagedSourceKey
	}
	var binding, direct, installation string
	var request, digest, proof []byte
	if err := conn.QueryRowContext(context.Background(), `SELECT binding_id,direct_intent_id,installation_id,request,request_digest,proof FROM native_direct_managed_source_pop_challenges WHERE challenge_id=?`, p.PoP.ChallengeID).Scan(&binding, &direct, &installation, &request, &digest, &proof); err != nil {
		return errDirectManagedSourceKey
	}
	canonical, _ := p.PoP.CanonicalBytes()
	sum := sha256.Sum256(canonical)
	decoded, _, err := transport.DecodeDirectManagedSourcePoPProofVerifier(proof)
	proofDigest := sha256.Sum256(proof)
	if err != nil || binding != p.PoP.Prepare.Subject.ID.String() || direct != p.PoP.Prepare.Subject.DirectIntentID.String() || installation != s.installation.String() || !bytes.Equal(request, canonical) || !bytes.Equal(digest, sum[:]) || decoded.ChallengeID != p.PoPReceipt.ChallengeID || decoded.TranscriptHash != p.PoPReceipt.TranscriptHash || hex.EncodeToString(proofDigest[:]) != p.PoPReceipt.ProofDigest {
		return errDirectManagedSourceKey
	}
	return nil
}

func (s *DirectManagedSourceKeyStore) credentialRow(conn *sql.Conn, p transport.DirectManagedSourceCredentialIssue, raw []byte) (DirectManagedSourceCredentialEvidence, bool, error) {
	var result DirectManagedSourceCredentialEvidence
	var binding, installation string
	var retained, digest []byte
	sum := sha256.Sum256(raw)
	var hash sql.NullString
	err := conn.QueryRowContext(context.Background(), `SELECT binding_id,installation_id,issue,issue_digest,state,credential_hash,ack FROM native_direct_managed_source_credentials WHERE credential_id=?`, p.CredentialID).Scan(&binding, &installation, &retained, &digest, &result.State, &hash, &result.ACK)
	if errors.Is(err, sql.ErrNoRows) {
		return result, false, nil
	}
	if err != nil {
		return result, false, err
	}
	if binding != p.PoP.Prepare.Subject.ID.String() || installation != s.installation.String() || !bytes.Equal(raw, retained) || !bytes.Equal(sum[:], digest) || (result.State != "attempted" && result.State != "installed") || (result.State == "attempted" && (hash.Valid || result.ACK != nil)) || (result.State == "installed" && (!hash.Valid || result.ACK == nil)) {
		return result, false, errDirectManagedSourceKey
	}
	result.IssueDigest = hex.EncodeToString(sum[:])
	result.CredentialHash = hash.String
	return result, true, nil
}

// InstallCredential commits an immutable attempt before publishing a separate
// restrictive secret file. Interrupted exact attempts may recover only after
// validating independent successful Prepare, PoP and live authority again.
// Installed missing or damaged secrets fail closed and are never regenerated.
func (s *DirectManagedSourceKeyStore) InstallCredential(issue transport.DirectManagedSourceCredentialIssue, configuredServer string, session transport.HostSessionPayload, verify DirectManagedSourceCredentialScopeCheck) ([]byte, error) {
	p, server, raw, err := s.credentialInput(issue, configuredServer, session, verify)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	err = s.withKeyLocked(false, func(conn *sql.Conn, dir *os.File) error {
		if err := s.validateCredentialEvidence(conn, p, server); err != nil {
			return err
		}
		_, exists, err := s.credentialRow(conn, p, raw)
		if err != nil || exists {
			return err
		}
		_, err = conn.ExecContext(context.Background(), `INSERT INTO native_direct_managed_source_credentials(credential_id,binding_id,installation_id,issue,issue_digest,state) VALUES(?,?,?,?,?,'attempted')`, p.CredentialID, p.PoP.Prepare.Subject.ID, s.installation, raw, sum[:])
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
	err = s.withKeyLocked(false, func(conn *sql.Conn, dir *os.File) error {
		if err := s.validateCredentialEvidence(conn, p, server); err != nil {
			return err
		}
		var err error
		private, err = s.loadPoPKey(conn, dir, p.PoP.ACK.Reservation, p.PoP.Prepare)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err = verify(p, server, session); err != nil {
		return nil, err
	}
	secret, ack, err := transport.DeriveDirectManagedSourceCredentialHost(p, private, s.now())
	defer clear(secret)
	if err != nil {
		return nil, err
	}
	canonical, err := ack.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	hash, err := transport.DirectManagedSourceCredentialHash(ack.TranscriptHash, secret)
	if err != nil {
		return nil, err
	}
	record, err := json.Marshal(directManagedSourceCredentialFile{hex.EncodeToString(sum[:]), secret})
	defer clear(record)
	if err != nil {
		return nil, err
	}
	err = s.withKeyLocked(false, func(conn *sql.Conn, dir *os.File) error {
		if err := s.validateCredentialEvidence(conn, p, server); err != nil {
			return err
		}
		row, exists, err := s.credentialRow(conn, p, raw)
		if err != nil || !exists {
			return errDirectManagedSourceKey
		}
		retained, err := s.loadPoPKey(conn, dir, p.PoP.ACK.Reservation, p.PoP.Prepare)
		defer clear(retained)
		if err != nil || !bytes.Equal(private, retained) {
			return errDirectManagedSourceKey
		}
		if row.State == "installed" && (row.CredentialHash != hash || !bytes.Equal(row.ACK, canonical)) {
			return errDirectManagedSourceKey
		}
		name := directManagedSourceKeyScope(s.installation, server, p.PoP.Prepare.Subject) + ".credential"
		if err := s.publishCredential(dir, name, record, row.State == "installed"); err != nil {
			return err
		}
		if !s.credentialValid(p) {
			return errDirectManagedSourceKey
		}
		result, err := conn.ExecContext(context.Background(), `UPDATE native_direct_managed_source_credentials SET state='installed',credential_hash=?,ack=? WHERE credential_id=? AND issue=? AND installation_id=? AND (state='attempted' OR (state='installed' AND credential_hash=? AND ack=?))`, hash, canonical, p.CredentialID, raw, s.installation, hash, canonical)
		if err != nil {
			return err
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return errDirectManagedSourceKey
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
		return nil, errDirectManagedSourceKey
	}
	return bytes.Clone(canonical), nil
}

// publishCredential compares complete canonical bytes, including secret bytes,
// before replay. No existing file is replaced; symlinks and unsafe modes fail.
func (s *DirectManagedSourceKeyStore) publishCredential(dir *os.File, name string, raw []byte, installed bool) error {
	compare := func(suffix string, durable bool) error {
		file, err := nativeShareHolderOpen(dir, name+suffix, false)
		if err != nil {
			return err
		}
		defer file.Close()
		retained, err := io.ReadAll(io.LimitReader(file, 4097))
		defer clear(retained)
		if err != nil || len(retained) > 4096 || !bytes.Equal(retained, raw) {
			return errDirectManagedSourceKey
		}
		if durable {
			return s.sync(file)
		}
		return nil
	}
	err := compare(".json", !installed)
	if err == nil {
		var stat unix.Stat_t
		if err := unix.Fstatat(int(dir.Fd()), name+".pending", &stat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
			return errDirectManagedSourceKey
		}
		if !installed {
			return s.sync(dir)
		}
		return nil
	}
	if installed || !errors.Is(err, unix.ENOENT) {
		return errDirectManagedSourceKey
	}
	file, err := nativeShareHolderOpen(dir, name+".pending", true)
	if errors.Is(err, unix.EEXIST) {
		if err = compare(".pending", true); err != nil {
			return errDirectManagedSourceKey
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

// CredentialEvidence verifies custody and completed installation through exact
// replay, returning only public evidence. It never exposes secret material.
func (s *DirectManagedSourceKeyStore) CredentialEvidence(issue transport.DirectManagedSourceCredentialIssue, configuredServer string, session transport.HostSessionPayload, verify DirectManagedSourceCredentialScopeCheck) (DirectManagedSourceCredentialEvidence, error) {
	p, server, raw, err := s.credentialInput(issue, configuredServer, session, verify)
	if err != nil {
		return DirectManagedSourceCredentialEvidence{}, err
	}
	var result DirectManagedSourceCredentialEvidence
	err = s.withKeyLocked(false, func(conn *sql.Conn, dir *os.File) error {
		if err := s.validateCredentialEvidence(conn, p, server); err != nil {
			return err
		}
		row, exists, err := s.credentialRow(conn, p, raw)
		if err != nil || !exists || row.State != "installed" {
			return errDirectManagedSourceKey
		}
		private, err := s.loadPoPKey(conn, dir, p.PoP.ACK.Reservation, p.PoP.Prepare)
		defer clear(private)
		if err != nil {
			return err
		}
		secret, ack, err := transport.DeriveDirectManagedSourceCredentialHost(p, private, s.now())
		defer clear(secret)
		if err != nil {
			return err
		}
		canonical, _ := ack.CanonicalBytes()
		hash, _ := transport.DirectManagedSourceCredentialHash(ack.TranscriptHash, secret)
		if hash != row.CredentialHash || !bytes.Equal(canonical, row.ACK) {
			return errDirectManagedSourceKey
		}
		record, err := json.Marshal(directManagedSourceCredentialFile{row.IssueDigest, secret})
		defer clear(record)
		if err != nil {
			return err
		}
		name := directManagedSourceKeyScope(s.installation, server, p.PoP.Prepare.Subject) + ".credential"
		if err = s.publishCredential(dir, name, record, true); err != nil {
			return err
		}
		result = row
		return nil
	})
	if err != nil {
		return DirectManagedSourceCredentialEvidence{}, err
	}
	if err = verify(p, server, session); err != nil {
		return DirectManagedSourceCredentialEvidence{}, err
	}
	if !s.credentialValid(p) {
		return DirectManagedSourceCredentialEvidence{}, errDirectManagedSourceKey
	}
	return result, nil
}
