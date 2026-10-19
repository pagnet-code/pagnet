package daemon

import (
	"context"
	"database/sql"
	"errors"
	"slices"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func (d *Daemon) nativeRecoveryConnection(conn *websocket.Conn) (*NativeObservationConnection, transport.HostSessionPayload, error) {
	d.connMu.Lock()
	c := d.nativeConn
	current := d.curConn == conn
	d.connMu.Unlock()
	if !current || c == nil || d.nativeRegistry == nil {
		return nil, transport.HostSessionPayload{}, ErrNativeOriginAdmissionDeferred
	}
	session, err := c.AuthenticatedNativeHostSession()
	if err != nil {
		return nil, session, err
	}
	if !slices.Contains(session.ProtocolFeatures, transport.NativeWorkerRecoveryProtocol) {
		return nil, session, ErrNativeSourceUnsupported
	}
	return c, session, nil
}

func nativeRecoveryIdentity(p transport.NativeWorkerRecoveryState) (NativeWorkerRecovery, error) {
	for _, id := range []string{p.RecoveryID, p.InstanceID, p.DefinitionID, p.HostID, p.TenantID, p.AccountID} {
		if _, err := domain.ParseID(id); err != nil {
			return NativeWorkerRecovery{}, ErrNativeObservationConflict
		}
	}
	if (p.OwnershipID == "") != (p.OwnershipGeneration == "") || p.LastDispatchSequence < 0 || p.RetiredFloor < 0 || p.RetiredFloor > p.LastDispatchSequence || (p.OwnershipID == "" && (p.LastDispatchSequence != 0 || p.RetiredFloor != 0)) {
		return NativeWorkerRecovery{}, ErrNativeObservationConflict
	}
	if p.OwnershipID != "" {
		if _, err := domain.ParseID(p.OwnershipID); err != nil {
			return NativeWorkerRecovery{}, ErrNativeObservationConflict
		}
	}
	if p.Action != "replace" && p.Action != "delete" || p.State != "prepared" && p.State != "committed" && p.State != "cleaned" || !p.PrepareBoot.Valid() {
		return NativeWorkerRecovery{}, ErrNativeObservationConflict
	}
	r := NativeWorkerRecovery{RecoveryID: p.RecoveryID, InstanceID: p.InstanceID, DefinitionID: p.DefinitionID, HostID: p.HostID, TenantID: p.TenantID, AccountID: p.AccountID, OwnershipID: p.OwnershipID, OriginalGeneration: p.OwnershipGeneration, Action: p.Action, PrepareBoot: p.PrepareBoot, LastDispatchSequence: p.LastDispatchSequence, RetiredFloor: p.RetiredFloor, Phase: "prepared"}
	if p.OriginalBoot != nil {
		if !p.OriginalBoot.Valid() {
			return NativeWorkerRecovery{}, ErrNativeObservationConflict
		}
		r.OriginalBoot = *p.OriginalBoot
	}
	return r, nil
}

func (d *Daemon) handleNativeWorkerRecoveryState(conn *websocket.Conn, p transport.NativeWorkerRecoveryState, readBoot func() (transport.KernelBootEvidence, error)) error {
	c, session, err := d.nativeRecoveryConnection(conn)
	if err != nil {
		return err
	}
	expected, err := nativeRecoveryIdentity(p)
	if err != nil {
		return err
	}
	if p.HostID != session.HostID || p.TenantID != session.TenantID || p.AccountID != session.AccountID {
		return ErrNativeObservationConflict
	}
	record, err := d.nativeRegistry.LookupRecovery(p.RecoveryID)
	if errors.Is(err, sql.ErrNoRows) {
		// A committed state cannot create missing local preparation evidence.
		if p.State != "prepared" {
			return ErrNativeObservationConflict
		}
		current, bootErr := readBoot()
		if bootErr != nil || !current.Valid() {
			return ErrNativeOriginAdmissionDeferred
		}
		expected.FenceBoot = current
		local, lookupErr := d.nativeRegistry.Lookup(p.InstanceID)
		if lookupErr == nil {
			if local.Scope.HostID != session.HostID || local.Scope.TenantID != session.TenantID || local.Scope.AccountID != session.AccountID || local.Scope.ServerURL != d.ServerURL {
				return ErrNativeObservationConflict
			}
			expected.LocalGeneration = local.Scope.Generation
		} else if !errors.Is(lookupErr, sql.ErrNoRows) {
			return lookupErr
		}
		record, err = d.nativeRegistry.PrepareRecovery(expected)
	} else if err == nil {
		expected.FenceBoot = record.FenceBoot
		expected.LocalGeneration = record.LocalGeneration
		identity := record
		identity.Phase = "prepared"
		identity.ServerCleaned = false
		if identity != expected {
			return ErrNativeObservationConflict
		}
	}
	if err != nil {
		return err
	}
	if p.State == "cleaned" {
		if record.Phase != "collected" {
			return ErrNativeObservationConflict
		}
		return d.nativeRegistry.confirmRecoveryCleaned(record.RecoveryID)
	}
	if record.ServerCleaned {
		return nil
	}
	current, err := readBoot()
	if err != nil || !record.ProvesNewBoot(current) {
		return ErrNativeOriginAdmissionDeferred
	}
	if p.State == "prepared" {
		if record.Phase != "prepared" {
			return ErrNativeObservationConflict
		}
		return d.sendNativeWorkerRecoveryAck(c, record, "prepared")
	}
	if record.Phase == "prepared" {
		if err = d.nativeRegistry.AdvanceRecoveryPhase(record.RecoveryID, "prepared", "committed"); err != nil {
			return err
		}
		record.Phase = "committed"
	}
	if record.Phase == "committed" {
		if err = d.nativeRegistry.collectRecovery(record); err != nil {
			return err
		}
		record.Phase = "collected"
	}
	if record.Phase != "collected" {
		return ErrNativeObservationConflict
	}
	return d.sendNativeWorkerRecoveryAck(c, record, "collected")
}

func (d *Daemon) sendNativeWorkerRecoveryAck(c *NativeObservationConnection, r NativeWorkerRecovery, phase string) error {
	// The writer belongs to this exact authenticated socket; it cannot silently
	// move evidence to a replacement runner. No source command is acknowledged.
	return c.send(context.Background(), transport.MsgNativeWorkerRecoveryAck, transport.NativeWorkerRecoveryAck{RecoveryID: r.RecoveryID, InstanceID: r.InstanceID, OwnershipGeneration: r.OriginalGeneration, Action: r.Action, LocalPhase: phase, LocalFenceBoot: r.FenceBoot})
}

func (d *Daemon) resumeNativeWorkerRecoveryAcks(conn *websocket.Conn) {
	c, session, err := d.nativeRecoveryConnection(conn)
	if err != nil {
		return
	}
	records, err := d.nativeRegistry.pendingCollectedRecoveries()
	if err != nil {
		return
	}
	for _, r := range records {
		if r.HostID != session.HostID || r.TenantID != session.TenantID || r.AccountID != session.AccountID {
			continue
		}
		if _, _, err = d.nativeRecoveryConnection(conn); err != nil {
			return
		}
		if err = d.sendNativeWorkerRecoveryAck(c, r, "collected"); err != nil {
			return
		}
	}
}
