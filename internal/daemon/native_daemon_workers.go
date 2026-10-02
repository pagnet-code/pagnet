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
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

type nativeWorkerLink struct {
	proxy     *NativeWorkerProxy
	conn      *websocket.Conn
	mu        sync.Mutex
	ownership transport.NativeWorkerOwnership
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
		if p.Launch == nil || p.Launch.InstanceID != p.InstanceID || p.Launch.CommandID != p.SourceCommandID || p.Launch.NativeDispatch != nil {
			return ErrNativeOriginAdmissionDeferred
		}
		row, _, _, err := d.prepareLaunch(*p.Launch)
		if err != nil {
			return err
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

		link.mu.Lock()
		ownership := link.ownership
		link.mu.Unlock()
		if updated, err := link.proxy.SettleDispatches(ctx, ownership); err == nil && updated != nil {
			link.mu.Lock()
			link.ownership = *updated
			link.mu.Unlock()
		}
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
			if rowErr != nil || !ok || call.Scope != link.proxy.scope {
				result.Error = "native bridge scope unavailable"
			} else {
				result.Result, result.Error = d.executeBridgeTool(row, call.Tool, call.Args, func(tool string, args json.RawMessage) (json.RawMessage, string) {
					return d.relayToConnection(ctx, link.conn, row.InstanceID, row.AgentPrincipalID, tool, args)
				})
				result.OK = result.Error == ""
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
		select {
		case <-d.turnCtx.Done():
			return
		case <-connection.closed:
			return
		case <-ticker.C:
		}
	}
}
