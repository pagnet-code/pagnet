//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"os"

	"github.com/pagnet-code/pagnet/transport"
	"golang.org/x/sys/unix"
)

// DirectManagedSourcePoPScopeCheck authenticates the exact challenge and current
// native source ownership. It runs outside all store locks on every retry.
type DirectManagedSourcePoPScopeCheck func(transport.DirectManagedSourcePoPChallenge, string, transport.HostSessionPayload) error

func (s *DirectManagedSourceKeyStore) ConfirmPoP(challenge transport.DirectManagedSourcePoPChallenge, configuredServer string, session transport.HostSessionPayload, verify DirectManagedSourcePoPScopeCheck) ([]byte, error) {
	if s == nil || s.registry == nil || s.now == nil || verify == nil {
		return nil, errDirectManagedSourceKey
	}
	raw, err := challenge.CanonicalBytes()
	defer clear(raw)
	if err != nil || len(raw) > 65536 {
		return nil, errDirectManagedSourceKey
	}
	challenge, err = transport.DecodeDirectManagedSourcePoPChallenge(raw)
	server := managedPrepareServerOrigin(configuredServer)
	if err != nil || server == "" || legacyTextServiceServer(configuredServer) != server || challenge.ACK.Reservation.ServerURL != server || challenge.ACK.Reservation.InstallationID != s.installation || !directManagedSourceSessionMatches(challenge.Prepare.Subject, session) {
		return nil, errDirectManagedSourceKey
	}
	digest := sha256.Sum256(raw)
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
		err := conn.QueryRowContext(context.Background(), `SELECT binding_id,direct_intent_id,installation_id,request,request_digest,proof FROM native_direct_managed_source_pop_challenges WHERE challenge_id=?`, challenge.ChallengeID).Scan(&enrollment, &direct, &installation, &retained, &hash, &proof)
		if err == nil {
			if enrollment != challenge.Prepare.Subject.ID.String() || direct != challenge.Prepare.Subject.DirectIntentID.String() || installation != s.installation.String() || !bytes.Equal(retained, raw) || !bytes.Equal(hash, digest[:]) {
				return errDirectManagedSourceKey
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		_, err = conn.ExecContext(context.Background(), `INSERT INTO native_direct_managed_source_pop_challenges(challenge_id,binding_id,direct_intent_id,installation_id,request,request_digest,proof) VALUES(?,?,?,?,?,?,NULL)`, challenge.ChallengeID, challenge.Prepare.Subject.ID, challenge.Prepare.Subject.DirectIntentID, s.installation, raw, digest[:])
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
	confirmed, err := transport.ConfirmDirectManagedSourceHostCustody(challenge, private, s.now())
	if err != nil {
		return nil, err
	}
	canonical, err := confirmed.CanonicalBytes()
	if err != nil || (proof != nil && !bytes.Equal(proof, canonical)) {
		return nil, errDirectManagedSourceKey
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
			return errDirectManagedSourceKey
		}
		result, err := conn.ExecContext(context.Background(), `UPDATE native_direct_managed_source_pop_challenges SET proof=? WHERE challenge_id=? AND binding_id=? AND direct_intent_id=? AND installation_id=? AND request=? AND request_digest=? AND (proof IS NULL OR proof=?)`, canonical, challenge.ChallengeID, challenge.Prepare.Subject.ID, challenge.Prepare.Subject.DirectIntentID, s.installation, raw, digest[:], canonical)
		if err != nil {
			return err
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return errDirectManagedSourceKey
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
		return nil, errDirectManagedSourceKey
	}
	return bytes.Clone(proof), nil
}

func (s *DirectManagedSourceKeyStore) validatePoPPrepare(conn *sql.Conn, p transport.DirectManagedSourcePoPChallenge, server string) error {
	if s.now().Before(p.IssuedAt) || !s.now().Before(p.ExpiresAt) {
		return errDirectManagedSourceKey
	}
	request, _ := p.Prepare.CanonicalBytes()
	digest := sha256.Sum256(request)
	// Read immutable successful Prepare evidence in this SQLite snapshot; never
	// acquire the journal namespace lock while holding the key-store lock.
	j := DirectManagedSourcePrepareJournal{registry: s.registry, installation: s.installation, now: s.now}
	row, err := j.read(conn, p.Prepare, server, request, digest[:])
	ack, _ := p.ACK.CanonicalBytes()
	if err != nil || !row.Exists || row.State != "succeeded" || !bytes.Equal(row.ACK, ack) {
		return errDirectManagedSourceKey
	}
	return nil
}

func (s *DirectManagedSourceKeyStore) withPoPLocked(fn func(*sql.Conn, *os.File) error) error {
	return s.withKeyLocked(false, fn)
}

// Private bytes stay within this operation and are cleared by its caller.
func (s *DirectManagedSourceKeyStore) loadPoPKey(conn *sql.Conn, dir *os.File, reservation transport.DirectManagedSourceKeyReservation, expected transport.DirectManagedSourcePrepareCommand) ([]byte, error) {
	p := reservation.Subject
	name := directManagedSourceKeyScope(s.installation, reservation.ServerURL, p)
	var scope, installation string
	var request, retained []byte
	if err := conn.QueryRowContext(context.Background(), `SELECT scope,installation_id,request,reservation FROM native_direct_managed_source_keys WHERE binding_id=?`, p.ID).Scan(&scope, &installation, &request, &retained); err != nil {
		return nil, errDirectManagedSourceKey
	}
	command, err := transport.DecodeDirectManagedSourcePrepareCommand(request)
	canonical, _ := reservation.CanonicalBytes()
	expectedRequest, _ := expected.CanonicalBytes()
	if err != nil || !bytes.Equal(request, expectedRequest) || command.Subject != p || scope != name || installation != s.installation.String() || !bytes.Equal(retained, canonical) {
		return nil, errDirectManagedSourceKey
	}
	var stat unix.Stat_t
	if err = unix.Fstatat(int(dir.Fd()), name+".pending", &stat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return nil, errDirectManagedSourceKey
	}
	file, err := nativeShareHolderOpen(dir, name+".json", false)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	record, err := loadDirectManagedSourceKey(file)
	raw, _ := record.Reservation.CanonicalBytes()
	if err != nil || !bytes.Equal(raw, canonical) {
		clear(record.Private)
		return nil, errDirectManagedSourceKey
	}
	return record.Private, nil
}
