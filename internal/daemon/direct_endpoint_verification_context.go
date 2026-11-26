//go:build linux || darwin

package daemon

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/pagnet-code/pagnet/transport"
)

func authenticatedNativeHostSessionContext(ctx context.Context, c *NativeObservationConnection) (transport.HostSessionPayload, error) {
	unlock, err := directEndpointTryLock(ctx, &c.mu)
	if err != nil {
		return transport.HostSessionPayload{}, err
	}
	defer unlock()
	select {
	case <-c.closed:
		return transport.HostSessionPayload{}, ErrNativeOriginAdmissionDeferred
	default:
	}
	if c.session == nil {
		return transport.HostSessionPayload{}, ErrNativeOriginAdmissionDeferred
	}
	result := *c.session
	result.ProtocolFeatures = append([]string(nil), c.session.ProtocolFeatures...)
	return result, nil
}

// These endpoint-only reads borrow the connection exclusively so SQLite busy
// handling is bounded without changing the registry/state legacy read paths.
func directEndpointRegistryLookupContext(ctx context.Context, registry *NativeWorkerRegistry, id string) (NativeWorkerRecord, error) {
	var record NativeWorkerRecord
	err := withDirectEndpointSQLContext(ctx, registry.db, false, func(conn *sql.Conn, _ *func()) error {
		var raw []byte
		var state string
		if err := conn.QueryRowContext(ctx, `SELECT payload,launch_state FROM native_workers WHERE instance_id=?`, id).Scan(&raw, &state); err != nil {
			return err
		}
		var err error
		record, err = registry.decodeRecord(id, raw, state)
		return err
	})
	return record, err
}

func directEndpointRegistryRecoveryFenceContext(ctx context.Context, registry *NativeWorkerRegistry, id, generation string) error {
	return withDirectEndpointSQLContext(ctx, registry.db, false, func(conn *sql.Conn, _ *func()) error {
		var count int
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM native_worker_recoveries WHERE instance_id=? AND (original_generation=? OR original_generation='')`, id, generation).Scan(&count); err != nil {
			return err
		}
		if count > 0 {
			return errNativeWorkerRecoveryFenced
		}
		return nil
	})
}

func directEndpointRegistryGCContext(ctx context.Context, registry *NativeWorkerRegistry, id string) (nativeWorkerGC, error) {
	var gc nativeWorkerGC
	err := withDirectEndpointSQLContext(ctx, registry.db, false, func(conn *sql.Conn, _ *func()) error {
		var raw []byte
		if err := conn.QueryRowContext(ctx, `SELECT payload FROM native_worker_gc WHERE instance_id=?`, id).Scan(&raw); err != nil {
			return err
		}
		if len(raw) > 32<<10 || json.Unmarshal(raw, &gc) != nil || gc.Ownership.InstanceID != id {
			return ErrNativeObservationConflict
		}
		return nil
	})
	return gc, err
}

func directEndpointStateInstanceContext(ctx context.Context, state *State, id string) (*InstanceRow, bool, error) {
	var row InstanceRow
	exists := false
	err := withDirectEndpointSQLContext(ctx, state.db, false, func(conn *sql.Conn, _ *func()) error {
		err := scanInstanceRow(conn.QueryRowContext(ctx, instanceSelectCols+` FROM instances WHERE instance_id = ?`, id), &row)
		if err == sql.ErrNoRows {
			return nil
		}
		exists = err == nil
		return err
	})
	if err != nil || !exists {
		return nil, false, err
	}
	return &row, true, nil
}
