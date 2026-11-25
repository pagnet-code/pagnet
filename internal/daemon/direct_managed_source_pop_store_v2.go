//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"

	"github.com/pagnet-code/pagnet/transport"
	"golang.org/x/sys/unix"
)

// DirectManagedSourcePoPScopeCheckV2 authenticates the exact challenge and current
// native source ownership. It runs outside all store locks on every retry.
type DirectManagedSourcePoPScopeCheckV2 func(transport.DirectManagedSourcePoPChallengeV2, string, transport.HostSessionPayload) error

// ConfirmPoP creates or resumes only a live V2 proof. Expiry never removes its
// immutable association, successful proof, receipt digest or source key. Future
// credential installation must validate that historical evidence independently
// of this live creation deadline; it must never call ConfirmPoP to recreate it.
func (s *DirectManagedSourceKeyStoreV2) ConfirmPoP(challenge transport.DirectManagedSourcePoPChallengeV2, configuredServer string, session transport.HostSessionPayload, verify DirectManagedSourcePoPScopeCheckV2) ([]byte, error) {
	if s == nil || s.registry == nil || s.now == nil || verify == nil {
		return nil, errDirectManagedSourceKeyV2
	}
	raw, err := challenge.CanonicalBytes()
	defer clear(raw)
	if err != nil || len(raw) > 65536 {
		return nil, errDirectManagedSourceKeyV2
	}
	challenge, err = transport.DecodeDirectManagedSourcePoPChallengeV2(raw)
	server := managedPrepareServerOrigin(configuredServer)
	if err != nil || server == "" || len(server) > 2048 || !directManagedSourceInitialBindingV2(challenge.Prepare.Subject) || legacyTextServiceServer(configuredServer) != server || challenge.ACK.Reservation.ServerURL != server || challenge.ACK.Reservation.InstallationID != s.installation || !directManagedSourceSessionMatchesV2(challenge.Prepare.Subject, session) {
		return nil, errDirectManagedSourceKeyV2
	}
	digest := sha256.Sum256(append([]byte("pagnet/direct-managed-source-host-custody-pop/transcript/v2/"), raw...))
	if err = verify(challenge, server, session); err != nil {
		return nil, err
	}
	// Commit the immutable association before computing a proof. A NULL proof may
	// resume: deriving it is deterministic and never creates a key or reference.
	var proof []byte
	err = s.withPoPLocked(func(conn *sql.Conn, dir *os.File) error {
		if err := s.validatePoPPrepare(conn, challenge, server); err != nil {
			return err
		}
		var enrollment, direct, installation string
		var retained, hash []byte
		var proofDigest sql.NullString
		err := conn.QueryRowContext(context.Background(), `SELECT binding_id,direct_intent_id,installation_id,request,request_digest,proof,proof_digest FROM native_direct_managed_source_v2_pop_challenges WHERE challenge_id=?`, challenge.ChallengeID).Scan(&enrollment, &direct, &installation, &retained, &hash, &proof, &proofDigest)
		if err == nil {
			if enrollment != challenge.Prepare.Subject.ID.String() || direct != challenge.Prepare.Subject.DirectIntentID.String() || installation != s.installation.String() || !bytes.Equal(retained, raw) || !bytes.Equal(hash, digest[:]) {
				return errDirectManagedSourceKeyV2
			}
			if proof != nil {
				decoded, err := transport.DecodeDirectManagedSourcePoPProofV2(proof)
				receipt, receiptErr := transport.NewDirectManagedSourceCredentialPoPReceiptV2(decoded)
				if err != nil || receiptErr != nil || !proofDigest.Valid || proofDigest.String != receipt.ProofDigest || decoded.ChallengeID != challenge.ChallengeID || decoded.TranscriptHash != hex.EncodeToString(digest[:]) {
					return errDirectManagedSourceKeyV2
				}
			} else if proofDigest.Valid {
				return errDirectManagedSourceKeyV2
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		private, err := s.loadPoPKey(conn, dir, challenge.ACK.Reservation, challenge.Prepare)
		clear(private)
		if err != nil {
			return err
		}
		_, err = conn.ExecContext(context.Background(), `INSERT INTO native_direct_managed_source_v2_pop_challenges(challenge_id,binding_id,direct_intent_id,installation_id,request,request_digest,proof) VALUES(?,?,?,?,?,?,NULL)`, challenge.ChallengeID, challenge.Prepare.Subject.ID, challenge.Prepare.Subject.DirectIntentID, s.installation, raw, digest[:])
		return err
	})
	if err != nil {
		return nil, err
	}
	if err = verify(challenge, server, session); err != nil {
		return nil, err
	}
	// Load custody under the store locks, then release them before checking live
	// authority again. Lock contention must not turn a stale check into a proof.
	var private []byte
	defer func() { clear(private) }()
	err = s.withPoPLocked(func(conn *sql.Conn, dir *os.File) error {
		if err := s.validatePoPPrepare(conn, challenge, server); err != nil {
			return err
		}
		var err error
		private, err = s.loadPoPKey(conn, dir, challenge.ACK.Reservation, challenge.Prepare)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err = verify(challenge, server, session); err != nil {
		return nil, err
	}
	confirmed, err := transport.ConfirmDirectManagedSourceHostCustodyV2(challenge, private, s.now())
	if err != nil {
		return nil, err
	}
	canonical, err := confirmed.CanonicalBytes()
	if err != nil || (proof != nil && !bytes.Equal(proof, canonical)) {
		return nil, errDirectManagedSourceKeyV2
	}
	receipt, err := transport.NewDirectManagedSourceCredentialPoPReceiptV2(confirmed)
	if err != nil {
		return nil, err
	}
	// Reacquiring the locks may block too. Revalidate the exact Prepare and key
	// before storing against the immutable retained challenge association.
	err = s.withPoPLocked(func(conn *sql.Conn, dir *os.File) error {
		if err := s.validatePoPPrepare(conn, challenge, server); err != nil {
			return err
		}
		retainedPrivate, err := s.loadPoPKey(conn, dir, challenge.ACK.Reservation, challenge.Prepare)
		defer clear(retainedPrivate)
		if err != nil || !bytes.Equal(private, retainedPrivate) {
			return errDirectManagedSourceKeyV2
		}
		result, err := conn.ExecContext(context.Background(), `UPDATE native_direct_managed_source_v2_pop_challenges SET proof=?,proof_digest=? WHERE challenge_id=? AND binding_id=? AND direct_intent_id=? AND installation_id=? AND request=? AND request_digest=? AND (proof IS NULL OR proof=?)`, canonical, receipt.ProofDigest, challenge.ChallengeID, challenge.Prepare.Subject.ID, challenge.Prepare.Subject.DirectIntentID, s.installation, raw, digest[:], canonical)
		if err != nil {
			return err
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return errDirectManagedSourceKeyV2
		}
		proof = canonical
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err = verify(challenge, server, session); err != nil {
		return nil, err
	}
	if s.now().Before(challenge.IssuedAt) || !s.now().Before(challenge.ExpiresAt) {
		return nil, errDirectManagedSourceKeyV2
	}
	return bytes.Clone(proof), nil
}

func (s *DirectManagedSourceKeyStoreV2) validatePoPPrepare(conn *sql.Conn, p transport.DirectManagedSourcePoPChallengeV2, server string) error {
	if s.now().Before(p.IssuedAt) || !s.now().Before(p.ExpiresAt) {
		return errDirectManagedSourceKeyV2
	}
	request, _ := p.Prepare.CanonicalBytes()
	digest := sha256.Sum256(request)
	// Read immutable successful Prepare evidence in this SQLite snapshot; never
	// acquire the journal namespace lock while holding the key-store lock.
	j := DirectManagedSourcePrepareJournalV2{registry: s.registry, installation: s.installation, now: s.now}
	row, err := j.read(conn, p.Prepare, server, request, digest[:])
	ack, _ := p.ACK.CanonicalBytes()
	if err != nil || !row.Exists || row.State != "succeeded" || !bytes.Equal(row.ACK, ack) {
		return errDirectManagedSourceKeyV2
	}
	return nil
}

func (s *DirectManagedSourceKeyStoreV2) withPoPLocked(fn func(*sql.Conn, *os.File) error) error {
	return s.withKeyLocked(false, fn)
}

// Private bytes stay within this operation and are cleared by its caller.
func (s *DirectManagedSourceKeyStoreV2) loadPoPKey(conn *sql.Conn, dir *os.File, reservation transport.DirectManagedSourceKeyReservationV2, expected transport.DirectManagedSourcePrepareCommandV2) ([]byte, error) {
	p := reservation.Subject
	name := directManagedSourceKeyScopeV2(s.installation, reservation.ServerURL, p)
	var scope, installation string
	var request, retained, requestDigest []byte
	if err := conn.QueryRowContext(context.Background(), `SELECT scope,installation_id,request,reservation,request_digest FROM native_direct_managed_source_v2_keys WHERE binding_id=?`, p.ID).Scan(&scope, &installation, &request, &retained, &requestDigest); err != nil {
		return nil, errDirectManagedSourceKeyV2
	}
	command, err := transport.DecodeDirectManagedSourcePrepareCommandV2(request)
	canonical, _ := reservation.CanonicalBytes()
	expectedRequest, _ := expected.CanonicalBytes()
	sum := sha256.Sum256(expectedRequest)
	if err != nil || !bytes.Equal(requestDigest, sum[:]) || !bytes.Equal(request, expectedRequest) || command.Subject != p || scope != name || installation != s.installation.String() || !bytes.Equal(retained, canonical) {
		return nil, errDirectManagedSourceKeyV2
	}
	var stat unix.Stat_t
	if err = unix.Fstatat(int(dir.Fd()), name+".pending", &stat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return nil, errDirectManagedSourceKeyV2
	}
	file, err := nativeShareHolderOpen(dir, name+".json", false)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	record, err := loadDirectManagedSourceKeyV2(file)
	raw, _ := record.Reservation.CanonicalBytes()
	if err != nil || !bytes.Equal(raw, canonical) {
		clear(record.Private)
		return nil, errDirectManagedSourceKeyV2
	}
	return record.Private, nil
}
