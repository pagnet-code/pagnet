//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"os"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
	"golang.org/x/sys/unix"
)

// ConfirmPoP returns only canonical proof bytes for an authenticated current host
// session. It has no transport dispatch or key allocation path. Worker IPC runs
// outside store locks, including on retries and immediately before publication.
func (s *ManagedEndpointKeyStore) ConfirmPoP(ctx context.Context, d *Daemon, captured ManagedEndpointPrepareScope, configuredServer string, challenge transport.ManagedEndpointPoPChallenge) ([]byte, error) {
	if s == nil || d == nil || captured.Socket == nil || captured.Connection == nil || s.registry != d.nativeRegistry || managedPrepareServerOrigin(configuredServer) == "" || managedPrepareServerOrigin(configuredServer) != managedPrepareServerOrigin(d.ServerURL) {
		return nil, errManagedEndpointKey
	}
	j, err := d.newManagedEndpointPrepareJournal()
	if err != nil {
		return nil, err
	}
	e := &localManagedEndpointPrepare{d: d, keys: s, journal: j}
	verify := func(command transport.ManagedEndpointPrepareCommand, server string) error {
		_, err := e.verifyPublication(ctx, captured.Socket, captured.Connection, captured.Session, server, command)
		return err
	}
	return s.confirmPoP(challenge, configuredServer, captured.Session, verify)
}

func (s *ManagedEndpointKeyStore) confirmPoP(challenge transport.ManagedEndpointPoPChallenge, configuredServer string, session transport.HostSessionPayload, verify ManagedEndpointPrepareScopeCheck) ([]byte, error) {
	if s == nil || s.registry == nil || s.now == nil || verify == nil {
		return nil, errManagedEndpointKey
	}
	raw, err := challenge.CanonicalBytes()
	defer clear(raw)
	if err != nil || len(raw) > 65536 {
		return nil, errManagedEndpointKey
	}
	challenge, err = transport.DecodeManagedEndpointPoPChallenge(raw)
	server := managedPrepareServerOrigin(configuredServer)
	if err != nil || server == "" || legacyTextServiceServer(configuredServer) != server || challenge.ACK.Reservation.ServerURL != server || challenge.ACK.Reservation.InstallationID != s.installation || !managedPrepareSessionMatches(challenge.Prepare.Subject, session) {
		return nil, errManagedEndpointKey
	}
	digest := sha256.Sum256(raw)
	if err = verify(challenge.Prepare, server); err != nil {
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
		err := conn.QueryRowContext(context.Background(), `SELECT enrollment_id,direct_intent_id,installation_id,request,request_digest,proof FROM native_managed_endpoint_pop_challenges WHERE challenge_id=?`, challenge.ChallengeID).Scan(&enrollment, &direct, &installation, &retained, &hash, &proof)
		if err == nil {
			if enrollment != challenge.Prepare.Subject.ID.String() || direct != challenge.Prepare.Subject.DirectIntentID.String() || installation != s.installation.String() || !bytes.Equal(retained, raw) || !bytes.Equal(hash, digest[:]) {
				return errManagedEndpointKey
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		_, err = conn.ExecContext(context.Background(), `INSERT INTO native_managed_endpoint_pop_challenges(challenge_id,enrollment_id,direct_intent_id,installation_id,request,request_digest,proof) VALUES(?,?,?,?,?,?,NULL)`, challenge.ChallengeID, challenge.Prepare.Subject.ID, challenge.Prepare.Subject.DirectIntentID, s.installation, raw, digest[:])
		return err
	})
	if err != nil {
		return nil, err
	}
	if err = verify(challenge.Prepare, server); err != nil {
		return nil, err
	}
	err = s.withPoPLocked(func(conn *sql.Conn, dir *os.File) error {
		if err := s.validatePoPPrepare(conn, challenge, server); err != nil {
			return err
		}
		private, err := s.loadPoPKey(conn, dir, challenge.ACK.Reservation)
		if err != nil {
			return err
		}
		defer clear(private)
		confirmed, err := transport.ConfirmManagedEndpointHostCustody(challenge, private, s.now())
		if err != nil {
			return err
		}
		canonical, err := confirmed.CanonicalBytes()
		if err != nil || (proof != nil && !bytes.Equal(proof, canonical)) {
			return errManagedEndpointKey
		}
		result, err := conn.ExecContext(context.Background(), `UPDATE native_managed_endpoint_pop_challenges SET proof=? WHERE challenge_id=? AND enrollment_id=? AND direct_intent_id=? AND installation_id=? AND request=? AND request_digest=? AND (proof IS NULL OR proof=?)`, canonical, challenge.ChallengeID, challenge.Prepare.Subject.ID, challenge.Prepare.Subject.DirectIntentID, s.installation, raw, digest[:], canonical)
		if err != nil {
			return err
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return errManagedEndpointKey
		}
		proof = canonical
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err = verify(challenge.Prepare, server); err != nil {
		return nil, err
	}
	if s.now().Before(challenge.IssuedAt) || !s.now().Before(challenge.ExpiresAt) {
		return nil, errManagedEndpointKey
	}
	return bytes.Clone(proof), nil
}

func (s *ManagedEndpointKeyStore) validatePoPPrepare(conn *sql.Conn, p transport.ManagedEndpointPoPChallenge, server string) error {
	if s.now().Before(p.IssuedAt) || !s.now().Before(p.ExpiresAt) {
		return errManagedEndpointKey
	}
	request, _ := p.Prepare.CanonicalBytes()
	digest := sha256.Sum256(request)
	// Read immutable successful Prepare evidence in this SQLite snapshot; never
	// acquire the journal namespace lock while holding the key-store lock.
	j := ManagedEndpointPrepareJournal{registry: s.registry, installation: s.installation, now: s.now}
	row, err := j.read(conn, p.Prepare, server, request, digest[:])
	ack, _ := p.ACK.CanonicalBytes()
	if err != nil || !row.Exists || row.State != "succeeded" || !bytes.Equal(row.ACK, ack) {
		return errManagedEndpointKey
	}
	return nil
}

func (s *ManagedEndpointKeyStore) withPoPLocked(fn func(*sql.Conn, *os.File) error) error {
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
	defer func() { _, _ = conn.ExecContext(context.Background(), "ROLLBACK") }()
	if err = fn(conn, dir); err != nil {
		return err
	}
	_, err = conn.ExecContext(context.Background(), "COMMIT")
	return err
}

// Private bytes stay within this operation and are cleared by its caller.
func (s *ManagedEndpointKeyStore) loadPoPKey(conn *sql.Conn, dir *os.File, reservation transport.ManagedEndpointKeyReservation) ([]byte, error) {
	p := reservation.Subject
	name := managedEndpointKeyScope(s.installation, reservation.ServerURL, p)
	identity := managedEndpointSlotIdentity(s.installation, reservation.ServerURL, p)
	var scope, installation string
	var request, retained []byte
	if err := conn.QueryRowContext(context.Background(), `SELECT scope,installation_id,request,reservation FROM native_managed_endpoint_keys WHERE enrollment_id=?`, p.ID).Scan(&scope, &installation, &request, &retained); err != nil {
		return nil, errManagedEndpointKey
	}
	subject, server, err := validateManagedEndpointRequest(request)
	canonical, _ := reservation.CanonicalBytes()
	if err != nil || subject != p || server != reservation.ServerURL || scope != name || installation != s.installation.String() || !bytes.Equal(retained, canonical) {
		return nil, errManagedEndpointKey
	}
	var slotInstallation, public, anchor string
	var slotIdentity []byte
	var generation, format int
	if err = conn.QueryRowContext(context.Background(), `SELECT installation_id,identity,key_generation,file_format,legacy_enrollment_id,x25519 FROM native_managed_endpoint_key_slots WHERE scope=?`, name).Scan(&slotInstallation, &slotIdentity, &generation, &format, &anchor, &public); err != nil || slotInstallation != installation || !bytes.Equal(identity, slotIdentity) || generation != 1 || public != reservation.X25519 {
		return nil, errManagedEndpointKey
	}
	var stat unix.Stat_t
	if err = unix.Fstatat(int(dir.Fd()), name+".pending", &stat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return nil, errManagedEndpointKey
	}
	file, err := nativeShareHolderOpen(dir, name+".json", false)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if format == 2 && anchor == "" {
		r, err := loadManagedEndpointSlotRecord(file, identity)
		if err != nil || r.X25519 != public {
			clear(r.Private)
			return nil, errManagedEndpointKey
		}
		return r.Private, nil
	}
	if format != 1 || anchor == "" {
		return nil, errManagedEndpointKey
	}
	var anchorScope, anchorInstallation string
	var anchorRequest, anchorReserved []byte
	if err = conn.QueryRowContext(context.Background(), `SELECT scope,installation_id,request,reservation FROM native_managed_endpoint_keys WHERE enrollment_id=?`, anchor).Scan(&anchorScope, &anchorInstallation, &anchorRequest, &anchorReserved); err != nil {
		return nil, errManagedEndpointKey
	}
	anchorSubject, anchorServer, err := validateManagedEndpointRequest(anchorRequest)
	if err != nil || anchorSubject.ID != domain.ID(anchor) || anchorScope != name || anchorInstallation != installation || !bytes.Equal(managedEndpointSlotIdentity(s.installation, anchorServer, anchorSubject), identity) {
		return nil, errManagedEndpointKey
	}
	r, err := loadManagedEndpointKey(file)
	if err != nil {
		return nil, err
	}
	raw, _ := r.Reservation.CanonicalBytes()
	if !bytes.Equal(raw, anchorReserved) || r.Reservation.Subject != anchorSubject || r.Reservation.ServerURL != anchorServer || r.Reservation.InstallationID != s.installation || r.Reservation.X25519 != public {
		clear(r.Private)
		return nil, errManagedEndpointKey
	}
	return r.Private, nil
}
