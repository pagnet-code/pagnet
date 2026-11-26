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
	"time"

	"github.com/pagnet-code/pagnet/transport"
	"golang.org/x/sys/unix"
)

// DirectManagedSourceCredentialScopeCheckV2 independently authenticates the server,
// complete issue (including budget) and exact current native worker. It runs
// outside all locks, including on replay and after every blocking acquisition.
type DirectManagedSourceCredentialScopeCheckV2 func(transport.DirectManagedSourceCredentialIssueV2, string, transport.HostSessionPayload) error

// DirectManagedSourceCredentialPublicationFenceV2 acquires current authority while
// the final key lock and SQLite reservation are held. It receives that reserved
// connection and must return a non-nil release on success. The store calls release
// exactly once after COMMIT or ROLLBACK, including when publication fails. It also
// releases any non-nil release returned with an error. Acquisition must fail fast
// and must not acquire registry, namespace or key locks, or call remote services.
// The richer scope verifier stays outside these locks.
type DirectManagedSourceCredentialPublicationFenceV2 func(*sql.Conn, transport.DirectManagedSourceCredentialIssueV2, string, transport.HostSessionPayload) (func(), error)

// DirectManagedSourceCredentialEvidenceV2 is public, closed installation evidence.
// It grants no channel or activation authority and contains no credential bytes.
type DirectManagedSourceCredentialEvidenceV2 struct {
	State          string
	IssueDigest    string
	CredentialHash string
	ACK            []byte
}

type directManagedSourceCredentialFileV2 struct {
	IssueDigest string `json:"issueDigest"`
	Secret      []byte `json:"secret"`
	ACK         []byte `json:"ack"`
}

func (s *DirectManagedSourceKeyStoreV2) credentialValid(p transport.DirectManagedSourceCredentialIssueV2) bool {
	now := s.now()
	return !now.Before(p.IssuedAt) && now.Before(p.InstallExpiresAt) && now.Before(p.CredentialExpiresAt) && now.Before(p.BudgetExpiresAt) && now.Before(p.PoP.Prepare.Subject.AuthorizationExpiresAt)
}

func (s *DirectManagedSourceKeyStoreV2) credentialUseValid(p transport.DirectManagedSourceCredentialIssueV2) bool {
	now := s.now()
	return !now.Before(p.IssuedAt) && now.Before(p.CredentialExpiresAt) && now.Before(p.BudgetExpiresAt) && now.Before(p.PoP.Prepare.Subject.AuthorizationExpiresAt)
}

func (s *DirectManagedSourceKeyStoreV2) credentialInput(p transport.DirectManagedSourceCredentialIssueV2, configuredServer string, session transport.HostSessionPayload, verify DirectManagedSourceCredentialScopeCheckV2) (transport.DirectManagedSourceCredentialIssueV2, string, []byte, error) {
	if s == nil || s.registry == nil || s.now == nil || s.sync == nil || verify == nil {
		return p, "", nil, errDirectManagedSourceKeyV2
	}
	raw, err := p.CanonicalBytes()
	if err != nil {
		return p, "", nil, errDirectManagedSourceKeyV2
	}
	p, err = transport.DecodeDirectManagedSourceCredentialIssueV2(raw)
	server := managedPrepareServerOrigin(configuredServer)
	if err != nil || len(raw) > 96*1024 || !directManagedSourceInitialBindingV2(p.PoP.Prepare.Subject) || server == "" || len(server) > 2048 || legacyTextServiceServer(configuredServer) != server || p.PoP.ACK.Reservation.ServerURL != server || p.PoP.ACK.Reservation.InstallationID != s.installation || !directManagedSourceSessionMatchesV2(p.PoP.Prepare.Subject, session) || !s.credentialUseValid(p) {
		return p, "", nil, errDirectManagedSourceKeyV2
	}
	if err = verify(p, server, session); err != nil {
		return p, "", nil, err
	}
	return p, server, raw, nil
}

// validateCredentialEvidence reads successful Prepare and exact locally retained
// PoP evidence in the same SQLite snapshot. It never takes their namespace locks.
func (s *DirectManagedSourceKeyStoreV2) validateCredentialEvidence(conn *sql.Conn, p transport.DirectManagedSourceCredentialIssueV2, server string) error {
	// Installation has its own deadline. Validate immutable historical Prepare
	// and PoP evidence without calling live ConfirmPoP or changing the clock.
	if !s.credentialUseValid(p) {
		return errDirectManagedSourceKeyV2
	}
	var currentInstallation string
	if err := conn.QueryRowContext(context.Background(), `SELECT value FROM native_registry_metadata WHERE name='installation_id'`).Scan(&currentInstallation); err != nil || currentInstallation != s.installation.String() {
		return errDirectManagedSourceKeyV2
	}
	request, _ := p.PoP.Prepare.CanonicalBytes()
	requestDigest := sha256.Sum256(request)
	var bindingID, installationID, origin, expiry, state string
	var retainedRequest, retainedDigest, retainedACK []byte
	var keyStarted int
	err := conn.QueryRowContext(context.Background(), `SELECT binding_id,installation_id,server_url,request,request_digest,expires_at,state,ack,key_started FROM native_direct_managed_source_v2_prepare_commands WHERE command_id=?`, p.PoP.Prepare.CommandID).Scan(&bindingID, &installationID, &origin, &retainedRequest, &retainedDigest, &expiry, &state, &retainedACK, &keyStarted)
	ack, _ := p.PoP.ACK.CanonicalBytes()
	if err != nil || bindingID != p.PoP.Prepare.Subject.ID.String() || installationID != s.installation.String() || origin != server || expiry != p.PoP.Prepare.Subject.EnrollmentExpiresAt.Format(time.RFC3339Nano) || state != "succeeded" || keyStarted != 1 || !bytes.Equal(request, retainedRequest) || !bytes.Equal(requestDigest[:], retainedDigest) || !bytes.Equal(ack, retainedACK) || !directManagedSourcePrepareSuccessForScopeV2(retainedACK, p.PoP.Prepare, server, s.installation) {
		return errDirectManagedSourceKeyV2
	}
	var binding, direct, installation string
	var popRequest, digest, proof []byte
	var storedProofDigest string
	if err := conn.QueryRowContext(context.Background(), `SELECT binding_id,direct_intent_id,installation_id,request,request_digest,proof,proof_digest FROM native_direct_managed_source_v2_pop_challenges WHERE challenge_id=?`, p.PoP.ChallengeID).Scan(&binding, &direct, &installation, &popRequest, &digest, &proof, &storedProofDigest); err != nil {
		return errDirectManagedSourceKeyV2
	}
	canonical, _ := p.PoP.CanonicalBytes()
	sum := sha256.Sum256(append([]byte("pagnet/direct-managed-source-host-custody-pop/transcript/v2/"), canonical...))
	decoded, _, err := transport.DecodeDirectManagedSourcePoPProofVerifierV2(proof)
	receipt, receiptErr := transport.NewDirectManagedSourceCredentialPoPReceiptV2(decoded)
	if err != nil || receiptErr != nil || receipt != p.PoPReceipt || storedProofDigest != receipt.ProofDigest || binding != p.PoP.Prepare.Subject.ID.String() || direct != p.PoP.Prepare.Subject.DirectIntentID.String() || installation != s.installation.String() || !bytes.Equal(popRequest, canonical) || !bytes.Equal(digest, sum[:]) || decoded.ChallengeID != p.PoPReceipt.ChallengeID || decoded.TranscriptHash != p.PoPReceipt.TranscriptHash {
		return errDirectManagedSourceKeyV2
	}
	return nil
}

func (s *DirectManagedSourceKeyStoreV2) credentialRow(conn *sql.Conn, p transport.DirectManagedSourceCredentialIssueV2, raw []byte) (DirectManagedSourceCredentialEvidenceV2, bool, error) {
	var result DirectManagedSourceCredentialEvidenceV2
	var binding, direct, installation string
	var retained, digest []byte
	sum := sha256.Sum256(raw)
	var hash sql.NullString
	err := conn.QueryRowContext(context.Background(), `SELECT binding_id,direct_intent_id,installation_id,issue,issue_digest,state,credential_hash,ack FROM native_direct_managed_source_v2_credentials WHERE credential_id=?`, p.CredentialID).Scan(&binding, &direct, &installation, &retained, &digest, &result.State, &hash, &result.ACK)
	if errors.Is(err, sql.ErrNoRows) {
		return result, false, nil
	}
	if err != nil {
		return result, false, err
	}
	if binding != p.PoP.Prepare.Subject.ID.String() || direct != p.PoP.Prepare.Subject.DirectIntentID.String() || installation != s.installation.String() || !bytes.Equal(raw, retained) || !bytes.Equal(sum[:], digest) || (result.State != "attempted" && result.State != "installed") || (result.State == "attempted" && (hash.Valid || result.ACK != nil)) || (result.State == "installed" && (!hash.Valid || result.ACK == nil)) {
		return result, false, errDirectManagedSourceKeyV2
	}
	result.IssueDigest = hex.EncodeToString(sum[:])
	result.CredentialHash = hash.String
	return result, true, nil
}

// InstallCredential commits an immutable attempt before publishing a separate
// restrictive secret file. Interrupted exact attempts may recover only after
// validating independent successful Prepare, PoP and live authority again.
// Installed missing or damaged secrets fail closed and are never regenerated.
func (s *DirectManagedSourceKeyStoreV2) InstallCredential(issue transport.DirectManagedSourceCredentialIssueV2, configuredServer string, session transport.HostSessionPayload, verify DirectManagedSourceCredentialScopeCheckV2, fence DirectManagedSourceCredentialPublicationFenceV2) ([]byte, error) {
	if fence == nil || s == nil {
		return nil, errDirectManagedSourceKeyV2
	}
	p, server, raw, err := s.credentialInput(issue, configuredServer, session, verify)
	if err != nil {
		return nil, err
	}
	if !s.credentialValid(p) {
		return nil, errDirectManagedSourceKeyV2
	}
	sum := sha256.Sum256(raw)
	err = s.withKeyLocked(false, func(conn *sql.Conn, dir *os.File) error {
		if !s.credentialValid(p) {
			return errDirectManagedSourceKeyV2
		}
		if err := s.validateCredentialEvidence(conn, p, server); err != nil {
			return err
		}
		_, exists, err := s.credentialRow(conn, p, raw)
		if err != nil || exists {
			return err
		}
		_, err = conn.ExecContext(context.Background(), `INSERT INTO native_direct_managed_source_v2_credentials(credential_id,binding_id,direct_intent_id,installation_id,issue,issue_digest,state) VALUES(?,?,?,?,?,?,'attempted')`, p.CredentialID, p.PoP.Prepare.Subject.ID, p.PoP.Prepare.Subject.DirectIntentID, s.installation, raw, sum[:])
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
		if !s.credentialValid(p) {
			return errDirectManagedSourceKeyV2
		}
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
	secret, ack, err := transport.DeriveDirectManagedSourceCredentialHostV2(p, private, s.now())
	defer clear(secret)
	if err != nil {
		return nil, err
	}
	canonical, err := ack.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	hash, err := transport.DirectManagedSourceCredentialHashV2(ack.TranscriptHash, secret)
	if err != nil {
		return nil, err
	}
	record, err := json.Marshal(directManagedSourceCredentialFileV2{hex.EncodeToString(sum[:]), secret, canonical})
	defer clear(record)
	if err != nil {
		return nil, err
	}
	err = s.withKeyLockedScoped(false, func(conn *sql.Conn, dir *os.File, release *func()) error {
		if !s.credentialValid(p) {
			return errDirectManagedSourceKeyV2
		}
		if err := s.validateCredentialEvidence(conn, p, server); err != nil {
			return err
		}
		row, exists, err := s.credentialRow(conn, p, raw)
		if err != nil || !exists {
			return errDirectManagedSourceKeyV2
		}
		retained, err := s.loadPoPKey(conn, dir, p.PoP.ACK.Reservation, p.PoP.Prepare)
		defer clear(retained)
		if err != nil || !bytes.Equal(private, retained) {
			return errDirectManagedSourceKeyV2
		}
		if row.State == "installed" && (row.CredentialHash != hash || !bytes.Equal(row.ACK, canonical)) {
			return errDirectManagedSourceKeyV2
		}
		name := directManagedSourceKeyScopeV2(s.installation, server, p.PoP.Prepare.Subject) + ".credential"
		*release, err = fence(conn, p, server, session)
		if err != nil {
			return err
		}
		if *release == nil {
			return errDirectManagedSourceKeyV2
		}
		if err := s.publishCredential(dir, name, record, row.State == "installed"); err != nil {
			return err
		}
		if !s.credentialValid(p) {
			return errDirectManagedSourceKeyV2
		}
		result, err := conn.ExecContext(context.Background(), `UPDATE native_direct_managed_source_v2_credentials SET state='installed',credential_hash=?,ack=? WHERE credential_id=? AND issue=? AND installation_id=? AND (state='attempted' OR (state='installed' AND credential_hash=? AND ack=?))`, hash, canonical, p.CredentialID, raw, s.installation, hash, canonical)
		if err != nil {
			return err
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return errDirectManagedSourceKeyV2
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
		return nil, errDirectManagedSourceKeyV2
	}
	return bytes.Clone(canonical), nil
}

// publishCredential compares complete canonical bytes, including secret bytes,
// before replay. No existing file is replaced; symlinks and unsafe modes fail.
func (s *DirectManagedSourceKeyStoreV2) publishCredential(dir *os.File, name string, raw []byte, installed bool) error {
	compare := func(suffix string, durable bool) error {
		file, err := nativeShareHolderOpen(dir, name+suffix, false)
		if err != nil {
			return err
		}
		defer file.Close()
		retained, err := io.ReadAll(io.LimitReader(file, 4097))
		defer clear(retained)
		if err != nil || len(retained) > 4096 || !bytes.Equal(retained, raw) {
			return errDirectManagedSourceKeyV2
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
		if err := recoverDirectManagedSourceCredentialLinks(dir, name, raw); err != nil {
			return err
		}
		err = compare(".json", true)
	}
	if err == nil {
		var stat unix.Stat_t
		if err := unix.Fstatat(int(dir.Fd()), name+".pending", &stat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
			return errDirectManagedSourceKeyV2
		}
		if !installed {
			return s.sync(dir)
		}
		return nil
	}
	if installed || !errors.Is(err, unix.ENOENT) {
		return errDirectManagedSourceKeyV2
	}
	file, err := nativeShareHolderOpen(dir, name+".pending", true)
	if errors.Is(err, unix.EEXIST) {
		if err = compare(".pending", true); err != nil {
			return errDirectManagedSourceKeyV2
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
func (s *DirectManagedSourceKeyStoreV2) CredentialEvidence(issue transport.DirectManagedSourceCredentialIssueV2, configuredServer string, session transport.HostSessionPayload, verify DirectManagedSourceCredentialScopeCheckV2) (DirectManagedSourceCredentialEvidenceV2, error) {
	return s.withCredentialEvidence(issue, configuredServer, session, verify, nil, nil)
}

func (s *DirectManagedSourceKeyStoreV2) withCredentialEvidence(issue transport.DirectManagedSourceCredentialIssueV2, configuredServer string, session transport.HostSessionPayload, verify DirectManagedSourceCredentialScopeCheckV2, fence endpointMaterialFence, use func(endpointMaterial) error) (DirectManagedSourceCredentialEvidenceV2, error) {
	p, server, raw, err := s.credentialInput(issue, configuredServer, session, verify)
	if err != nil {
		return DirectManagedSourceCredentialEvidenceV2{}, err
	}
	var result DirectManagedSourceCredentialEvidenceV2
	err = s.withKeyLockedScoped(false, func(conn *sql.Conn, dir *os.File, release *func()) error {
		if err := s.validateCredentialEvidence(conn, p, server); err != nil {
			return err
		}
		row, exists, err := s.credentialRow(conn, p, raw)
		if err != nil || !exists || row.State != "installed" {
			return errDirectManagedSourceKeyV2
		}
		private, err := s.loadPoPKey(conn, dir, p.PoP.ACK.Reservation, p.PoP.Prepare)
		defer clear(private)
		if err != nil {
			return err
		}
		name := directManagedSourceKeyScopeV2(s.installation, server, p.PoP.Prepare.Subject) + ".credential"
		file, err := nativeShareHolderOpen(dir, name+".json", false)
		if err != nil {
			return err
		}
		record, err := io.ReadAll(io.LimitReader(file, 4097))
		closeErr := file.Close()
		defer clear(record)
		var retained directManagedSourceCredentialFileV2
		defer func() { clear(retained.Secret) }()
		if err != nil || closeErr != nil || len(record) > 4096 || json.Unmarshal(record, &retained) != nil {
			return errDirectManagedSourceKeyV2
		}
		canonical, err := json.Marshal(retained)
		defer clear(canonical)
		ack, ackErr := transport.DecodeDirectManagedSourceCredentialACKV2(row.ACK)
		transcript := sha256.Sum256(append([]byte("pagnet/direct-managed-source-credential/transcript/v2/"), raw...))
		hash, hashErr := transport.DirectManagedSourceCredentialHashV2(ack.TranscriptHash, retained.Secret)
		if err != nil || ackErr != nil || hashErr != nil || !bytes.Equal(canonical, record) || retained.IssueDigest != row.IssueDigest || !bytes.Equal(retained.ACK, row.ACK) || ack.CredentialID != p.CredentialID || ack.TranscriptHash != hex.EncodeToString(transcript[:]) || hash != row.CredentialHash {
			return errDirectManagedSourceKeyV2
		}
		if err := s.publishCredential(dir, name, canonical, true); err != nil {
			return err
		}
		// Recompute immutable installation evidence only after validating both
		// retained files. IssuedAt selects the original transcript; it grants no
		// live authority and never repairs or publishes missing material.
		derived, derivedACK, deriveErr := transport.DeriveDirectManagedSourceCredentialHostV2(p, private, p.IssuedAt)
		defer clear(derived)
		derivedCanonical, derivedACKErr := derivedACK.CanonicalBytes()
		if deriveErr != nil || derivedACKErr != nil || !bytes.Equal(derived, retained.Secret) || !bytes.Equal(derivedCanonical, row.ACK) {
			return errDirectManagedSourceKeyV2
		}

		if use != nil {
			var check func() error
			*release, check, err = fence(conn)
			if err != nil || *release == nil || check == nil || !s.credentialUseValid(p) {
				return errDirectManagedSourceKeyV2
			}
			if check() != nil {
				return errDirectManagedSourceKeyV2
			}
			useErr := use(endpointMaterial{secret: retained.Secret, private: private})
			checkErr := check()
			if useErr != nil || checkErr != nil || !s.credentialUseValid(p) {
				return errDirectManagedSourceKeyV2
			}
		}

		result = row
		return nil
	})
	if err != nil {
		return DirectManagedSourceCredentialEvidenceV2{}, err
	}
	if err = verify(p, server, session); err != nil {
		return DirectManagedSourceCredentialEvidenceV2{}, err
	}
	if !s.credentialUseValid(p) {
		return DirectManagedSourceCredentialEvidenceV2{}, errDirectManagedSourceKeyV2
	}
	return result, nil
}

// withDirectManagedSourceEndpointMaterialV2 grants temporary daemon-only use of installed material.
// The future daemon coordinator must authenticate the exact session, worker and
// ownership before calling, and pin that authority through fence. No callback
// may retain material, perform worker IPC, or log it. This does not install keys.
func (s *DirectManagedSourceKeyStoreV2) withDirectManagedSourceEndpointMaterialV2(issue transport.DirectManagedSourceCredentialIssueV2, configuredServer string, session transport.HostSessionPayload, scope endpointMaterialScope, verify DirectManagedSourceCredentialScopeCheckV2, fence endpointMaterialFence, use func(endpointMaterial) error) error {
	if s == nil || scope.installation != s.installation || scope.credential != issue.CredentialID || scope.role != "S" || scope.use != endpointMaterialLiveUse || fence == nil || use == nil {
		return errDirectManagedSourceKeyV2
	}
	_, err := s.withCredentialEvidence(issue, configuredServer, session, verify, fence, use)
	// Callback and filesystem errors must never carry private bytes to callers.
	if err != nil {
		return errDirectManagedSourceKeyV2
	}
	return nil
}
