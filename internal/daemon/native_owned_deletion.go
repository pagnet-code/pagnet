//go:build linux || darwin

package daemon

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func (d *Daemon) doNativeForget(conn *websocket.Conn, p transport.ForgetInstancePayload) (err error) {
	stage := "registry"
	defer func() {
		if err != nil {
			if d.Log != nil {
				d.Log.Warn("owned deletion remains pending", "stage", stage, "reason", err)
			}
			err = fmt.Errorf("native_forget/%s: %w", stage, err)
		}
	}()
	record, err := d.nativeRegistry.Lookup(p.InstanceID)
	if err != nil {
		return err
	}
	d.connMu.Lock()
	connection := d.nativeConn
	current := d.curConn == conn
	d.connMu.Unlock()
	if !current || connection == nil {
		return ErrNativeOriginAdmissionDeferred
	}
	if _, err = connection.NativeWorkerAdmission(record.Scope, record.Spec.NetworkID, record.Spec.Kind); err != nil {
		return err
	}
	gc, err := d.nativeRegistry.beginGC(record, p)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(d.turnCtx, 2*time.Second)
	defer cancel()
	if gc.Phase == "waiting" {
		proxy, err := d.nativeWorkerFor(conn, p.InstanceID)
		if err != nil {
			return errors.Join(ErrDeferred, err)
		}
		stage = "source_drain"
		if err = proxy.DrainDeletionSources(ctx, p.DeleteRequestID); err != nil {
			return errors.Join(ErrDeferred, err)
		}
		d.nativeWorkersMu.Lock()
		link := d.nativeWorkers[p.InstanceID]
		d.nativeWorkersMu.Unlock()
		if link == nil || link.proxy != proxy {
			return ErrDeferred
		}
		link.mu.Lock()
		owned := link.ownership
		link.mu.Unlock()
		stage = "deletion_proof"
		if p.DeletionProof != nil {
			if p.DeletionProof.DeleteRequestID != p.DeleteRequestID || p.DeletionProof.StopProof.OwnershipID != owned.ID || p.DeletionProof.StopProof.OwnershipGeneration != record.Scope.Generation {
				return ErrNativeObservationConflict
			}
			if _, err = proxy.call(ctx, sessionworker.Request{Type: "deletion_quarantines", DeletionProof: p.DeletionProof}); err != nil {
				return errors.Join(ErrDeferred, err)
			}
		}
		stage = "dispatch_settlement"
		settled, err := proxy.SettleDispatches(ctx, owned)
		if err != nil {
			return errors.Join(ErrDeferred, err)
		}
		if settled.LastDispatchSequence != settled.RetiredFloor {
			return ErrDeferred
		}
		stage = "native_snapshot"
		snapshot, err := proxy.Snapshot(ctx)
		if err != nil {
			return errors.Join(ErrDeferred, err)
		}
		if snapshot.IdentityPending || snapshot.PID != 0 || snapshot.HasTerminal || len(snapshot.Pending) != 0 {
			return ErrDeferred
		}
		stage = "backend_retirement"
		retired, err := connection.RetireNativeWorkerOwnership(ctx, record.Scope, record.Spec, record.Profile, *settled, settled.RetiredFloor, nil, true, nil)
		if err != nil {
			return errors.Join(ErrDeferred, err)
		}
		gc, err = d.nativeRegistry.advanceGC(p.InstanceID, gc, "backend_retired", retired)
		if err != nil {
			return err
		}
	}
	if gc.Phase == "backend_retired" {
		// Replaying after controller loss authenticates the same private bootstrap;
		// no activation or new ownership registration is possible on this lane.
		_, key, err := sessionworker.LoadControllerBootstrap(record.Dir, record.Scope)
		if err != nil {
			return err
		}
		controller, err := sessionworker.DialOwnerController(ctx, record.Dir, record.Scope, key, d.bootID)
		clear(key)
		if err == nil {
			response, callErr := controller.Call(ctx, sessionworker.Request{Type: "worker_retire", Ownership: &gc.Ownership})
			_ = controller.Close()
			if callErr == nil && response.Error != "" {
				callErr = errors.New(response.Error)
			}
			if callErr != nil {
				return errors.Join(ErrDeferred, callErr)
			}
		}
		// Even a lost retirement reply is recoverable only from its durable private
		// receipt under the exclusive lifetime lock, never from socket absence.
		if err == nil {
			gc, err = d.nativeRegistry.advanceGC(p.InstanceID, gc, "worker_retired", nil)
			if err != nil {
				return err
			}
		}
	}
	if gc.Phase == "backend_retired" || gc.Phase == "worker_retired" || gc.Phase == "collecting" {
		if gc.Phase == "collecting" {
			err = sessionworker.CompleteRetiredWorkerCollection(record.Dir)
		} else {
			err = sessionworker.CollectRetiredWorker(ctx, record.Dir, record.Scope, gc.Ownership, func() error {
				var phaseErr error
				gc, phaseErr = d.nativeRegistry.advanceGC(p.InstanceID, gc, "collecting", nil)
				return phaseErr
			})
		}
		if err != nil {
			return errors.Join(ErrDeferred, err)
		}

		gc, err = d.nativeRegistry.advanceGC(p.InstanceID, gc, "collected", nil)
		if err != nil {
			return err
		}
	}
	if gc.Phase != "collected" {
		return ErrNativeObservationConflict
	}
	row, ok, err := d.state.GetInstance(p.InstanceID)
	if err != nil {
		return err
	}
	if ok {
		d.removeWorktree(row)
	}
	if err = d.state.DeleteInstance(p.InstanceID); err != nil {
		return err
	}
	d.invalidateBridgeNonce(p.InstanceID)
	d.removeSessionGuidance(p.InstanceID)
	d.finishQueue(p.InstanceID)
	return nil
}

func (d *Daemon) confirmNativeForgotten(conn *websocket.Conn, p transport.NativeInstanceForgottenPayload) error {
	d.connMu.Lock()
	connection := d.nativeConn
	current := d.curConn == conn
	d.connMu.Unlock()
	if !current || connection == nil || d.nativeRegistry == nil {
		return ErrNativeOriginAdmissionDeferred
	}
	record, err := d.nativeRegistry.Lookup(p.InstanceID)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err = connection.AuthenticatedNativeHostSession(); err != nil {
			return err
		}
		if p.Disposition != "forgotten" || p.CommandID == "" || p.DeleteRequestID == "" || p.InstanceID == "" || p.OwnershipID == "" || p.OwnershipGeneration == "" {
			return ErrNativeObservationConflict
		}
		return nil
	}
	if err != nil {
		return err
	}
	if _, err = connection.NativeWorkerAdmission(record.Scope, record.Spec.NetworkID, record.Spec.Kind); err != nil {
		return err
	}
	return d.nativeRegistry.confirmGC(d.turnCtx, p)
}
