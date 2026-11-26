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
	"fmt"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

var errInstalledCredentialIssues = errors.New("installed credential issues unavailable or conflicting")

// This cursor is local pagination state, never remote authority. The first page
// pins a rowid high watermark so concurrent installations cannot extend a pass.
type installedCredentialIssueCursor struct {
	scopeDigest [32]byte
	table       string
	afterRowID  int64
	maxRowID    int64
}

type installedCredentialIssueRow struct {
	rowID                       int64
	credential, binding, direct string
	state                       string
	issue                       []byte
}

func installedIssueSubject(subject nativeManagedSubject) nativeManagedSubject {
	subject.ExpiresAt = time.Time{}
	subject.RunnerConnectedAt = subject.RunnerConnectedAt.UTC()
	return subject
}

func installedIssueScope(configuredServer string, session transport.HostSessionPayload, subject nativeManagedSubject, installation domain.ID, table string) (string, [32]byte, error) {
	server := managedPrepareServerOrigin(configuredServer)
	if server == "" || len(server) > 2048 || legacyTextServiceServer(configuredServer) != server || !nativeShareEpochStageID(installation) || !nativeManagedSessionMatches(subject, session) {
		return "", [32]byte{}, errInstalledCredentialIssues
	}
	raw, err := json.Marshal(struct {
		Server       string
		Session      transport.HostSessionPayload
		Subject      nativeManagedSubject
		Installation domain.ID
		Table        string
	}{server, session, installedIssueSubject(subject), installation, table})
	if err != nil {
		return "", [32]byte{}, errInstalledCredentialIssues
	}
	return server, sha256.Sum256(raw), nil
}

// Only public SQL evidence is read. The registry mutex precedes the bounded SQL
// reservation; no namespace, private file, worker, or network is consulted.
func installedCredentialIssuePage(ctx context.Context, registry *NativeWorkerRegistry, installation domain.ID, table, bindingColumn string, digest [32]byte, cursor installedCredentialIssueCursor, visit func(*sql.Conn, installedCredentialIssueRow) error) (installedCredentialIssueCursor, bool, error) {
	if ctx == nil || registry == nil || registry.db == nil {
		return installedCredentialIssueCursor{}, false, errInstalledCredentialIssues
	}
	if err := ctx.Err(); err != nil {
		return installedCredentialIssueCursor{}, false, err
	}
	if cursor != (installedCredentialIssueCursor{}) && (cursor.table != table || cursor.scopeDigest != digest || cursor.afterRowID < 0 || cursor.maxRowID < cursor.afterRowID) {
		return installedCredentialIssueCursor{}, false, errInstalledCredentialIssues
	}
	unlock, err := directEndpointTryLock(ctx, &registry.mu)
	if err != nil {
		return installedCredentialIssueCursor{}, false, err
	}
	defer unlock()
	next := cursor
	err = withDirectEndpointSQLContext(ctx, registry.db, true, func(conn *sql.Conn, _ *func()) error {
		var current string
		if err := conn.QueryRowContext(ctx, `SELECT value FROM native_registry_metadata WHERE name='installation_id'`).Scan(&current); err != nil {
			return err
		}
		if current != installation.String() {
			return errInstalledCredentialIssues
		}
		if cursor == (installedCredentialIssueCursor{}) {
			next = installedCredentialIssueCursor{scopeDigest: digest, table: table}
			if err := conn.QueryRowContext(ctx, `SELECT COALESCE(MAX(rowid),0) FROM `+table+` WHERE installation_id=?`, installation).Scan(&next.maxRowID); err != nil {
				return err
			}
		}
		rows, err := conn.QueryContext(ctx, `SELECT rowid,credential_id,`+bindingColumn+`,direct_intent_id,issue,state FROM `+table+` WHERE installation_id=? AND rowid>? AND rowid<=? ORDER BY rowid LIMIT 64`, installation, next.afterRowID, next.maxRowID)
		if err != nil {
			return err
		}
		var page []installedCredentialIssueRow
		for rows.Next() {
			var r installedCredentialIssueRow
			if err = rows.Scan(&r.rowID, &r.credential, &r.binding, &r.direct, &r.issue, &r.state); err != nil {
				rows.Close()
				return err
			}
			page = append(page, r)
		}
		err = rows.Err()
		closeErr := rows.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		for _, r := range page {
			if err := ctx.Err(); err != nil {
				return err
			}
			next.afterRowID = r.rowID
			if r.state == "attempted" {
				continue
			}
			if r.state != "installed" {
				return errInstalledCredentialIssues
			}
			if err := visit(conn, r); err != nil {
				return err
			}
		}
		if len(page) < 64 {
			next.afterRowID = next.maxRowID
		}
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		} else if !errors.Is(err, errDirectEndpointLocalBusy) {
			err = errInstalledCredentialIssues
		}
		return installedCredentialIssueCursor{}, false, err
	}
	return next, next.afterRowID < next.maxRowID, nil
}

func installedIssueUnique(ctx context.Context, conn *sql.Conn, table, bindingColumn string, r installedCredentialIssueRow) error {
	var count int
	if err := conn.QueryRowContext(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE credential_id=? OR %s=? OR direct_intent_id=?`, table, bindingColumn), r.credential, r.binding, r.direct).Scan(&count); err != nil {
		return err
	}
	if count != 1 {
		return errInstalledCredentialIssues
	}
	return nil
}

// Candidates establish retained public evidence only. Callers must independently
// authenticate current server authority, revocation, consent and native ownership.
func (s *DirectManagedSourceKeyStoreV2) installedCredentialIssuesContext(ctx context.Context, configuredServer string, session transport.HostSessionPayload, subject nativeManagedSubject, cursor installedCredentialIssueCursor) ([]transport.DirectManagedSourceCredentialIssueV2, installedCredentialIssueCursor, bool, error) {
	const table = "native_direct_managed_source_v2_credentials"
	if ctx == nil || s == nil || s.registry == nil || s.now == nil {
		return nil, installedCredentialIssueCursor{}, false, errInstalledCredentialIssues
	}
	if err := ctx.Err(); err != nil {
		return nil, installedCredentialIssueCursor{}, false, err
	}
	server, digest, err := installedIssueScope(configuredServer, session, subject, s.installation, table)
	if err != nil {
		return nil, installedCredentialIssueCursor{}, false, err
	}
	var result []transport.DirectManagedSourceCredentialIssueV2
	next, more, err := installedCredentialIssuePage(ctx, s.registry, s.installation, table, "binding_id", digest, cursor, func(conn *sql.Conn, r installedCredentialIssueRow) error {
		if len(r.issue) > 96*1024 {
			return errInstalledCredentialIssues
		}
		p, err := transport.DecodeDirectManagedSourceCredentialIssueV2(r.issue)
		if err != nil {
			return errInstalledCredentialIssues
		}
		if p.PoP.ACK.Reservation.ServerURL != server || installedIssueSubject(nativeManagedSubjectFromSourceV2(p.PoP.Prepare.Subject)) != installedIssueSubject(subject) {
			return nil
		}
		raw, err := p.CanonicalBytes()
		if err != nil || !bytes.Equal(raw, r.issue) || p.CredentialID.String() != r.credential || p.PoP.Prepare.Subject.ID.String() != r.binding || p.PoP.Prepare.Subject.DirectIntentID.String() != r.direct || p.PoP.ACK.Reservation.InstallationID != s.installation || !directManagedSourceSessionMatchesV2(p.PoP.Prepare.Subject, session) || !directManagedSourceInitialBindingV2(p.PoP.Prepare.Subject) {
			return errInstalledCredentialIssues
		}
		if !s.credentialUseValid(p) {
			return nil
		}
		if err := installedIssueUnique(ctx, conn, table, "binding_id", r); err != nil {
			return err
		}
		row, exists, err := s.credentialRowContext(ctx, conn, p, raw)
		if err != nil || !exists || row.State != "installed" {
			return errInstalledCredentialIssues
		}
		if err := s.validateCredentialEvidenceContext(ctx, conn, p, server); err != nil {
			return err
		}
		ack, err := transport.DecodeDirectManagedSourceCredentialACKV2(row.ACK)
		transcript := sha256.Sum256(append([]byte("pagnet/direct-managed-source-credential/transcript/v2/"), raw...))
		hash, hashErr := hex.DecodeString(row.CredentialHash)
		if err != nil || ack.CredentialID != p.CredentialID || ack.TranscriptHash != hex.EncodeToString(transcript[:]) || hashErr != nil || len(hash) != 32 || hex.EncodeToString(hash) != row.CredentialHash {
			return errInstalledCredentialIssues
		}
		result = append(result, p)
		return nil
	})
	if err != nil {
		return nil, installedCredentialIssueCursor{}, false, err
	}
	return result, next, more, nil
}

func (s *ManagedEndpointKeyStore) installedCredentialIssuesContext(ctx context.Context, configuredServer string, session transport.HostSessionPayload, subject nativeManagedSubject, cursor installedCredentialIssueCursor) ([]transport.ManagedDirectCredentialIssue, installedCredentialIssueCursor, bool, error) {
	const table = "native_managed_direct_v1_credentials"
	if ctx == nil || s == nil || s.registry == nil || s.now == nil {
		return nil, installedCredentialIssueCursor{}, false, errInstalledCredentialIssues
	}
	if err := ctx.Err(); err != nil {
		return nil, installedCredentialIssueCursor{}, false, err
	}
	server, digest, err := installedIssueScope(configuredServer, session, subject, s.installation, table)
	if err != nil {
		return nil, installedCredentialIssueCursor{}, false, err
	}
	var result []transport.ManagedDirectCredentialIssue
	next, more, err := installedCredentialIssuePage(ctx, s.registry, s.installation, table, "enrollment_id", digest, cursor, func(conn *sql.Conn, r installedCredentialIssueRow) error {
		if len(r.issue) > 96*1024 {
			return errInstalledCredentialIssues
		}
		p, err := transport.DecodeManagedDirectCredentialIssue(r.issue)
		if err != nil {
			return errInstalledCredentialIssues
		}
		if p.PoP.ACK.Reservation.ServerURL != server || installedIssueSubject(nativeManagedSubjectFromEndpoint(p.PoP.Prepare.Subject)) != installedIssueSubject(subject) {
			return nil
		}
		raw, err := p.CanonicalBytes()
		if err != nil || !bytes.Equal(raw, r.issue) || p.CredentialID.String() != r.credential || p.PoP.Prepare.Subject.ID.String() != r.binding || p.PoP.Prepare.Subject.DirectIntentID.String() != r.direct || p.PoP.ACK.Reservation.InstallationID != s.installation || !managedPrepareSessionMatches(p.PoP.Prepare.Subject, session) || p.ChannelGeneration != 1 {
			return errInstalledCredentialIssues
		}
		if !s.credentialUseValid(p) {
			return nil
		}
		if err := installedIssueUnique(ctx, conn, table, "enrollment_id", r); err != nil {
			return err
		}
		row, exists, err := s.credentialRowContext(ctx, conn, p, raw)
		if err != nil || !exists || row.State != "installed" {
			return errInstalledCredentialIssues
		}
		if err := s.validateCredentialEvidenceContext(ctx, conn, p, server); err != nil {
			return err
		}
		ack, err := transport.DecodeManagedDirectCredentialACK(row.ACK)
		transcript := sha256.Sum256(append([]byte("pagnet/managed-direct-credential/transcript/v1/"), raw...))
		hash, hashErr := hex.DecodeString(row.CredentialHash)
		if err != nil || ack.CredentialID != p.CredentialID || ack.TranscriptHash != hex.EncodeToString(transcript[:]) || hashErr != nil || len(hash) != 32 || hex.EncodeToString(hash) != row.CredentialHash {
			return errInstalledCredentialIssues
		}
		result = append(result, p)
		return nil
	})
	if err != nil {
		return nil, installedCredentialIssueCursor{}, false, err
	}
	return result, next, more, nil
}
