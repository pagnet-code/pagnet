package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"path/filepath"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/agentbridge"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

type nativeWorkerLink struct {
	proxy     *NativeWorkerProxy
	conn      *websocket.Conn
	mu        sync.Mutex
	ownership transport.NativeWorkerOwnership
	// sideportPushed/sideportPushedPresent track the last sideport value
	// this link was successfully pushed (guarded by mu). The pump compares
	// the daemon registry against this per-link state every tick and
	// re-pushes only on mismatch, so a transient push failure self-heals
	// within one tick.
	sideportPushed        agentbridge.HostedFabricSideport
	sideportPushedPresent bool
}

func (d *Daemon) nativeOwned(instanceID string) bool {
	return d.nativeRegistry != nil && d.nativeRegistry.Owns(instanceID)
}
func (d *Daemon) nativeWorkerFor(conn *websocket.Conn, instanceID string) (*NativeWorkerProxy, error) {
	d.nativeWorkersMu.Lock()
	link := d.nativeWorkers[instanceID]
	d.nativeWorkersMu.Unlock()
	if link == nil || link.conn != conn {
		return nil, ErrNativeOriginAdmissionDeferred
	}
	if _, err := link.proxy.connection.AuthenticatedNativeHostSession(); err != nil {
		return nil, err
	}
	select {
	case <-link.proxy.done:
		return nil, ErrNativeOriginAdmissionDeferred
	default:
	}
	return link.proxy, nil
}
func (d *Daemon) nativeAcceptActivate(conn *websocket.Conn, instanceID string, proof *transport.NativeDispatchProof) error {
	return d.nativeAcceptOperation(conn, instanceID, proof, "attach", sessionworker.Operation{InputKind: "user_input"})
}
func (d *Daemon) nativeAcceptOperation(conn *websocket.Conn, instanceID string, proof *transport.NativeDispatchProof, kind string, operation sessionworker.Operation) error {
	if proof == nil {
		return ErrNativeObservationConflict
	}
	p, err := d.nativeWorkerFor(conn, instanceID)
	if err != nil {
		return errors.Join(ErrDeferred, err)
	}
	d.nativeWorkersMu.Lock()
	link := d.nativeWorkers[instanceID]
	d.nativeWorkersMu.Unlock()
	if link == nil || link.proxy != p {
		return ErrDeferred
	}
	link.mu.Lock()
	o := link.ownership
	link.mu.Unlock()
	if _, err = p.AcceptDispatch(d.turnCtx, o, *proof, kind, operation); err != nil {
		if errors.Is(err, ErrNativeOriginAdmissionDeferred) {
			return errors.Join(ErrDeferred, err)
		}
		return err
	}
	return nil
}
func (d *Daemon) nativeConfiguration(row *InstanceRow, scope sessionworker.Scope) (sessionworker.NativeSpec, error) {
	var binary string
	var env = []string(nil)
	var prefix, dirs []string
	rn := domain.RuntimeName(row.Runtime)
	if row.Profile != "" {
		profile := d.runtimeProfiles[row.Profile]
		if profile == nil || profile.config.Runtime != rn {
			return sessionworker.NativeSpec{}, ErrNativeObservationConflict
		}
		var available bool
		binary, available = profile.config.ResolvedExecutable()
		if !available {
			return sessionworker.NativeSpec{}, fmt.Errorf("runtime profile executable unavailable")
		}
		prefix = append([]string(nil), profile.config.Args...)
		dirs = profile.config.Directories()
		env = profile.config.Environment()
	} else if a := d.adapters[rn]; a != nil {
		var available bool
		binary, available = a.BinaryPath()
		if !available {
			return sessionworker.NativeSpec{}, fmt.Errorf("runtime executable unavailable")
		}
	} else if drv := d.sessionDriverFor(row); drv != nil {
		if p, ok := drv.(interface{ BinaryPath() (string, bool) }); ok {
			var available bool
			binary, available = p.BinaryPath()
			if !available {
				return sessionworker.NativeSpec{}, fmt.Errorf("runtime executable unavailable")
			}
		}
	}
	if !filepath.IsAbs(binary) {
		return sessionworker.NativeSpec{}, fmt.Errorf("runtime executable unavailable")
	}
	_, standing, err := d.writeStandingDocument(row)
	if err != nil {
		return sessionworker.NativeSpec{}, err
	}
	spec := sessionworker.NativeSpec{Runtime: rn, Binary: binary, PrefixArgs: prefix, NativeDirs: dirs, Env: append(append([]string(nil), d.RuntimeEnv...), env...), Workspace: row.Workspace, Model: row.Model, StandingInstructions: standing, MCPExecutable: d.selfExe, NetworkID: row.NetworkID, Kind: row.Kind, TenantID: scope.TenantID, ContextStateDir: d.StateDir, NetworkStateDir: d.StateDir}
	spec.InitialNativeSessionID = row.SessionID
	if row.NetworkID != "" {
		m := d.cryptoManager()
		m.mu.Lock()
		state := m.netCrypto[row.NetworkID]
		m.mu.Unlock()
		if state.TenantID == "" || state.Status != "active" {
			return sessionworker.NativeSpec{}, ErrNativeOriginAdmissionDeferred
		}
		spec.NetworkTenantID = state.TenantID
	} else if c, ok := d.contextForInstance(row.InstanceID); ok {
		spec.ProtectedContext = &c
	}
	return spec, nil
}

// prepareNativeOwnership registers configuration without starting a runtime
// turn. Execution requires the separately allocated original dispatch proof.
func (d *Daemon) prepareNativeOwnership(conn *websocket.Conn, p transport.NativeOwnershipPreparePayload) error {
	if p.InstanceID == "" || p.SourceCommandID == "" {
		return ErrNativeObservationConflict
	}
	d.connMu.Lock()
	connection := d.nativeConn
	current := d.curConn == conn
	d.connMu.Unlock()
	if connection == nil || !current {
		return ErrNativeOriginAdmissionDeferred
	}
	session, err := connection.AuthenticatedNativeHostSession()
	if err != nil {
		return err
	}
	if d.nativeRegistry == nil {
		return ErrNativeSourceUnsupported
	}
	record, err := d.nativeRegistry.Lookup(p.InstanceID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if errors.Is(err, sql.ErrNoRows) {
		// The launch is configuration, not the source of this pending operation.
		// An attach/wake may bootstrap ownership long after the original launch
		// was acknowledged. Preserve both command identities and all sealed AAD.
		if p.Launch == nil {
			return fmt.Errorf("original launch configuration unavailable: %w", ErrNativeOriginAdmissionDeferred)
		}
		if p.Launch.InstanceID != p.InstanceID || p.Launch.NativeDispatch != nil || p.Launch.Runtime != p.Runtime || p.Launch.Profile != p.Profile {
			return ErrNativeObservationConflict
		}
		if _, err := domain.ParseID(p.Launch.CommandID); err != nil {
			return ErrNativeObservationConflict
		}
		if p.SourceCommandType == transport.MsgLaunchAgent && p.Launch.CommandID != p.SourceCommandID {
			return ErrNativeObservationConflict
		}
		row, exists, err := d.state.GetInstance(p.InstanceID)
		if err != nil {
			return err
		}
		if exists {
			// Replaying launch preparation would replace the existing workspace,
			// standing configuration and native session with a fresh idle row.
			if row.Runtime != p.Runtime || row.Profile != p.Profile || row.NetworkID != p.Launch.NetworkID || row.DefinitionID != p.Launch.DefinitionID || row.AgentPrincipalID != p.Launch.AgentPrincipalID {
				return ErrNativeObservationConflict
			}
		} else {
			row, _, _, err = d.prepareLaunch(*p.Launch)
			if err != nil {
				return err
			}
		}
		if p.ProtectedContextRequired {
			local, ready := d.contextForInstance(p.InstanceID)
			if !p.ProtectedContextReady || p.ProtectedContext == nil || !ready || local != *p.ProtectedContext {
				return ErrNativeOriginAdmissionDeferred
			}
			ring, err := crypto.LoadContextKeyring(d.StateDir, local)
			if err != nil {
				return ErrNativeOriginAdmissionDeferred
			}
			epoch, err := ring.ActiveEpoch()
			if err != nil || epoch.ID != p.ProtectedContextEpochID {
				return ErrNativeOriginAdmissionDeferred
			}
		}
		generation := domain.NewID().String()
		previous := ""
		if p.Ownership != nil {
			generation = p.Ownership.OwnershipGeneration
			previous = p.Ownership.ID
		}
		scope := sessionworker.Scope{ServerURL: d.ServerURL, TenantID: session.TenantID, AccountID: session.AccountID, HostID: d.HostID, InstanceID: p.InstanceID, Generation: generation}
		spec, err := d.nativeConfiguration(row, scope)
		if err != nil {
			return err
		}
		record, err = d.nativeRegistry.Reserve(scope, spec, row.Profile, previous)
		if err != nil {
			return err
		}
	}
	return d.connectNativeWorker(conn, connection, record)
}

func (d *Daemon) connectNativeWorker(conn *websocket.Conn, connection *NativeObservationConnection, record NativeWorkerRecord) error {
	if gc, gcErr := d.nativeRegistry.lookupGC(record.Scope.InstanceID); !errors.Is(gcErr, sql.ErrNoRows) && (gcErr != nil || gc.Phase != "waiting") {
		return ErrNativeOriginAdmissionDeferred
	}

	hash := fnv.New32a()
	_, _ = hash.Write([]byte(record.Scope.InstanceID))
	lock := &d.nativeConnectLocks[hash.Sum32()%uint32(len(d.nativeConnectLocks))]
	lock.Lock()
	defer lock.Unlock()
	if existing, err := d.nativeWorkerFor(conn, record.Scope.InstanceID); err == nil && existing.scope == record.Scope {
		return nil
	}
	ownership, err := connection.RegisterNativeWorkerOwnership(d.turnCtx, record.Scope, record.Spec, record.Profile, record.OriginalOwnershipID)
	if err != nil {
		return err
	}
	env := append([]string(nil), d.RuntimeEnv...)
	if record.Profile != "" {
		profile := d.runtimeProfiles[record.Profile]
		if profile == nil {
			return ErrNativeObservationConflict
		}
		env = append(env, profile.config.Environment()...)
	}
	if err = EnsureNativeWorker(d.turnCtx, d.nativeRegistry, record, d.selfExe, env); err != nil {
		return err
	}
	proxy, err := AttachNativeWorker(d.turnCtx, connection, record.Dir, record.Scope, d.bootID)
	if err != nil {
		return err
	}
	if err = proxy.BindOwnership(d.turnCtx, *ownership); err != nil {
		_ = proxy.Close()
		return err
	}
	if err = d.nativeRegistry.BindOwnership(record, *ownership); err != nil {
		_ = proxy.Close()
		return err
	}
	if d.HostedOwnerGuard != nil {
		if err = d.HostedOwnerGuard.Register(proxy); err != nil {
			_ = proxy.Close()
			return err
		}
	}
	link := &nativeWorkerLink{proxy: proxy, conn: conn, ownership: *ownership}
	d.nativeWorkersMu.Lock()
	if d.nativeWorkers == nil {
		d.nativeWorkers = map[string]*nativeWorkerLink{}
	}
	old := d.nativeWorkers[record.Scope.InstanceID]
	d.nativeWorkers[record.Scope.InstanceID] = link
	d.nativeWorkersMu.Unlock()
	if old != nil {
		_ = old.proxy.Close()
	}
	d.Log.Info("native session worker connected", "instance", record.Scope.InstanceID, "runtime", record.Spec.Runtime)
	// Attach-time restore (Phase A step 6d): the daemon's association
	// registry survives worker restart, the worker's in-memory advertisement
	// does not. Push any pre-existing association to the freshly attached
	// worker. Best-effort: a transient failure is self-healed by the pump's
	// reconciliation within one tick. (The registry does NOT survive a
	// DAEMON restart — the association is a live authorization, and the
	// owner re-associates after one.)
	if sp, ok := d.hostedFabricSideportFor(record.Scope.InstanceID); ok {
		if err := d.pushHostedSideportToWorker(d.turnCtx, record.Scope.InstanceID, &sp); err != nil {
			if d.Log != nil {
				d.Log.Warn("hosted sideport attach restore deferred to reconciliation", "instance", record.Scope.InstanceID, "err", err.Error())
			}
		}
	}
	go d.pumpNativeWorker(link)
	return nil
}

func (d *Daemon) pumpNativeWorker(link *nativeWorkerLink) {
	ctx, cancel := context.WithCancel(d.turnCtx)
	defer cancel()
	go func() {
		select {
		case <-link.proxy.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	go d.pumpNativeBridge(ctx, link)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var nextCancellation time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		// The admission gate belongs to this exact authenticated connection. A
		// disconnect stops forwarding; the independently owned session survives.
		_ = link.proxy.Reconcile(ctx)
		_ = link.proxy.DrainSources(ctx)
		d.reconcileHostedSideport(ctx, link)

		link.mu.Lock()
		ownership := link.ownership
		link.mu.Unlock()
		if !time.Now().Before(nextCancellation) {
			_ = link.proxy.ReconcileDispatchCancellations(ctx, ownership)
			nextCancellation = time.Now().Add(2 * time.Second)
		}
		if updated, err := link.proxy.SettleDispatches(ctx, ownership); err == nil && updated != nil {
			link.mu.Lock()
			link.ownership = *updated
			link.mu.Unlock()
		}
	}
}

// reconcileHostedSideport is the pump's per-tick sideport reconciliation
// (Phase A step 6d): one compare of the daemon registry against the link's
// tracked last-pushed state, and a wire frame only on mismatch. It closes
// both residual drift paths the event pushes cannot — a stale advertisement
// after a failed clear, and a missed attach-time restore. With no sideport
// composition the daemon has no association, so no push ever happens
// (fail-closed, like the rest of the composition).
func (d *Daemon) reconcileHostedSideport(ctx context.Context, link *nativeWorkerLink) {
	if d == nil || link == nil || d.HostedFabricSideports == nil {
		return
	}
	instanceID := link.proxy.scope.InstanceID
	sp, present := d.hostedFabricSideportFor(instanceID)
	link.mu.Lock()
	needSet := present && (!link.sideportPushedPresent || link.sideportPushed != sp)
	needClear := !present && link.sideportPushedPresent
	link.mu.Unlock()
	switch {
	case needSet:
		_ = d.pushHostedSideportToWorker(ctx, instanceID, &sp)
	case needClear:
		_ = d.pushHostedSideportToWorker(ctx, instanceID, nil)
	}
}

// Native tools can wait for network replies without starving the separate
// activation, receipt and approval delivery lane.
func (d *Daemon) pumpNativeBridge(ctx context.Context, link *nativeWorkerLink) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		response, err := link.proxy.call(ctx, sessionworker.Request{Type: "bridge_poll"})
		if err == nil && response.Bridge != nil {
			call := response.Bridge
			row, ok, rowErr := d.state.GetInstance(link.proxy.scope.InstanceID)
			result := sessionworker.BridgeResult{ID: call.ID}
			sourceSettled := false
			if rowErr != nil || !ok || call.Scope != link.proxy.scope {
				result.Error = "native bridge scope unavailable"
			} else {
				result.Result, result.Error = d.executeBridgeToolWithRead(row, call.Tool, call.Args, func(tool string, args json.RawMessage) (json.RawMessage, string) {
					raw, message, settled := d.relayNativeBridgeWithRefusal(ctx, link, row, call, tool, args)
					sourceSettled = settled
					return raw, message
				}, func(args, raw json.RawMessage) (json.RawMessage, string) {
					return d.nativeTaskReadForBridge(ctx, link.proxy, row, call, args, raw)
				})
				result.OK = result.Error == ""
				if sourceSettled && !result.OK {
					result.ErrorCode = "source_settled"
					result.Retryable = true
				}
			}
			_, _ = link.proxy.call(ctx, sessionworker.Request{Type: "bridge_result", Relay: &result})
		}
	}
}

func (d *Daemon) recoverNativeWorkers(conn *websocket.Conn, connection *NativeObservationConnection) {
	if d.nativeRegistry == nil {
		return
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		records, err := d.nativeRegistry.List()
		if err != nil {
			return
		}
		jobs := make(chan NativeWorkerRecord, 16)
		var workers sync.WaitGroup
		for range 16 {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for record := range jobs {
					select {
					case <-connection.closed:
						return
					case <-d.turnCtx.Done():
						return
					default:
					}
					if _, err := d.nativeWorkerFor(conn, record.Scope.InstanceID); err != nil {
						_ = d.connectNativeWorker(conn, connection, record)
					}
				}
			}()
		}
		stopped := false
		for _, record := range records {
			if _, err := d.nativeWorkerFor(conn, record.Scope.InstanceID); err == nil {
				continue
			}
			select {
			case jobs <- record:
			case <-connection.closed:
				stopped = true
			case <-d.turnCtx.Done():
				stopped = true
			}
			if stopped {
				break
			}
		}
		close(jobs)
		workers.Wait()
		if stopped {
			return
		}
		// A fresh/recovered host session also resumes the consumed hosted
		// final outputs: a daemon restart (or controller replacement) must
		// retain the SAME original source. Rows with a live consumer are
		// skipped; deterministic conflicts finalize the row, transient
		// failures retry on the next pass.
		d.resumeHostedSourceConsumers(conn)
		select {
		case <-d.turnCtx.Done():
			return
		case <-connection.closed:
			return
		case <-ticker.C:
		}
	}
}
