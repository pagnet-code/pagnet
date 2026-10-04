package fabricnative

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"strconv"
	"sync"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

type managedKey struct {
	endpoint           fabric.EndpointRef
	worker, generation string
}
type managedSelectorKey struct {
	endpoint fabric.EndpointRef
	worker   string
}
type managedWorker struct {
	client  *sessionworker.LocalClient
	scope   nativeauthority.Scope
	process localpeer.ProcessSnapshot
}

// ManagedPeers binds private worker IPC, the same actual registry, and kernel
// process trees. It never accepts a process identity or principal from wire JSON.
type ManagedPeers struct {
	mu        sync.RWMutex
	workers   map[managedKey]*managedWorker
	selectors map[managedSelectorKey]managedKey
	store     *registry.Store
	authority *identity.Authority
	owner     fabric.ExecutionContext
	guard     *OwnerGuard
}

func NewManagedPeers(store *registry.Store, authority *identity.Authority, owner fabric.ExecutionContext) (*ManagedPeers, error) {
	if store == nil || authority == nil {
		return nil, guardDenied()
	}
	root, err := store.CurrentAuthorityIdentity(context.Background())
	if err != nil || owner.VerifyAuthenticated(root.Namespace) != nil || owner.PrincipalView() != root.Owner || authority.Identity().StoreID != root.StoreID || authority.Identity().Namespace != root.Namespace {
		return nil, guardDenied()
	}
	return &ManagedPeers{workers: make(map[managedKey]*managedWorker), selectors: make(map[managedSelectorKey]managedKey), store: store, authority: authority, owner: owner, guard: NewOwnerGuard()}, nil
}

// Register precedes native intent admission. Ownership is pinned to the real
// mutually authenticated worker IPC peer, including before native PID/SID exist.
func (m *ManagedPeers) Register(ctx context.Context, client *sessionworker.LocalClient, ownership nativeauthority.Scope) error {
	if m == nil || client == nil || ctx == nil {
		return guardDenied()
	}
	local, ok := ownership.Local()
	if !ok || ownership.Validate() != nil || local.StoreID != m.authority.Identity().StoreID {
		return guardDenied()
	}
	process, err := client.OwnerProcess()
	if err != nil {
		return guardDenied()
	}
	response, err := client.Call(ctx, sessionworker.LocalRequest{Type: "snapshot"})
	if err != nil || response.Snapshot == nil || response.Snapshot.Authority != ownership {
		return guardDenied()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := managedKey{local.Endpoint, local.WorkerID, local.OwnershipGeneration}
	selector := managedSelectorKey{local.Endpoint, local.WorkerID}
	if old, exists := m.selectors[selector]; exists && old != key {
		return guardDenied()
	}
	if old := m.workers[key]; old != nil {
		if old.scope != ownership || old.process != process {
			return guardDenied()
		}
		if old.client != client {
			if client.Lease <= old.client.Lease {
				return guardDenied()
			}
			// The same authenticated physical worker can explicitly accept a
			// newer controller lease; this does not adopt a replacement process.
			m.workers[key] = &managedWorker{client, ownership, process}
		}
		return nil
	}
	if len(m.workers) >= 4096 {
		return fabric.NewError(fabric.CodeTargetUnavailable, "Managed worker capacity unavailable")
	}
	if err = m.guard.Register(ctx, process); err != nil {
		return err
	}
	m.workers[key] = &managedWorker{client, ownership, process}
	m.selectors[selector] = key
	return nil
}

func (m *ManagedPeers) ValidateOwner(ctx context.Context, peer localpeer.ProcessSnapshot) error {
	if m == nil {
		return guardDenied()
	}
	return m.guard.Validate(ctx, peer)
}

func (m *ManagedPeers) lookup(key managedKey) *managedWorker {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.workers[key]
}

func (m *ManagedPeers) checked(ctx context.Context, key managedKey) (fabricauth.Activation, fabric.Principal, error) {
	if m == nil || ctx == nil || ctx.Err() != nil {
		return fabricauth.Activation{}, fabric.Principal{}, guardDenied()
	}
	w := m.lookup(key)
	if w == nil {
		return fabricauth.Activation{}, fabric.Principal{}, guardDenied()
	}
	process, err := w.client.OwnerProcess()
	if err != nil || process != w.process {
		return fabricauth.Activation{}, fabric.Principal{}, guardDenied()
	}
	r, err := w.client.Call(ctx, sessionworker.LocalRequest{Type: "snapshot"})
	if err != nil || r.Snapshot == nil {
		return fabricauth.Activation{}, fabric.Principal{}, guardDenied()
	}
	s := r.Snapshot
	local, _ := w.scope.Local()
	if s.Authority != w.scope || s.IdentityPending || s.PID <= 1 || s.NativeGeneration == "" || s.NativeSessionID == "" || s.ActivationNonce == "" || string(s.ActualRuntime) != local.ActualRuntime || s.ProfileFingerprint != hex.EncodeToString(local.ProfileDigest[:]) || s.State != session.StateBusy && s.State != session.StateIdle && s.State != session.StateActivating {
		return fabricauth.Activation{}, fabric.Principal{}, guardDenied()
	}
	var origin identity.Origin
	if fabric.DecodeJSON(s.Origin, &origin) != nil || origin.NativeGeneration != s.NativeGeneration {
		return fabricauth.Activation{}, fabric.Principal{}, guardDenied()
	}
	descriptor, err := m.store.GetEndpoint(ctx, local.Endpoint, "")
	if err != nil {
		return fabricauth.Activation{}, fabric.Principal{}, guardDenied()
	}
	currentScope := identity.Scope{Endpoint: local.Endpoint, DescriptorRevision: descriptor.Revision, BindingID: local.BindingID}
	_, binding, err := m.authority.VerifyCurrentNativeOrigin(ctx, m.owner, currentScope, origin)
	if err != nil {
		return fabricauth.Activation{}, fabric.Principal{}, guardDenied()
	}
	currentOwnership, err := nativeauthority.NewLocalScope(m.authority.Identity(), binding)
	if err != nil || !w.scope.SamePhysical(currentOwnership) {
		return fabricauth.Activation{}, fabric.Principal{}, guardDenied()
	}
	read := func(pid int) (localpeer.ProcessSnapshot, error) {
		p, err := localpeer.ReadProcess(pid)
		if err != nil {
			return p, err
		}
		if pid == w.process.PID && p != w.process || pid == s.PID && strconv.FormatInt(p.Start, 10) != s.NativeStartIdentity {
			return p, guardDenied()
		}
		return p, nil
	}
	if localpeer.VerifyProcessTree(s.PID, w.process.PID, w.process.UID, read) != nil {
		return fabricauth.Activation{}, fabric.Principal{}, guardDenied()
	}
	if _, err = w.client.OwnerProcess(); err != nil || ctx.Err() != nil {
		return fabricauth.Activation{}, fabric.Principal{}, guardDenied()
	}
	err = m.authority.FenceCurrentNativeOrigin(ctx, m.owner, currentScope, origin, func(checked context.Context) error {
		fresh, e := w.client.Call(checked, sessionworker.LocalRequest{Type: "snapshot"})
		if e != nil || fresh.Snapshot == nil {
			return guardDenied()
		}
		n := fresh.Snapshot
		if n.Authority != s.Authority || n.IdentityPending || n.PID != s.PID || n.NativeStartIdentity != s.NativeStartIdentity || n.NativeGeneration != s.NativeGeneration || n.NativeSessionID != s.NativeSessionID || n.ActualRuntime != s.ActualRuntime || n.ProfileFingerprint != s.ProfileFingerprint || !bytes.Equal(n.Origin, s.Origin) || subtle.ConstantTimeCompare([]byte(n.ActivationNonce), []byte(s.ActivationNonce)) != 1 || n.State != session.StateBusy && n.State != session.StateIdle && n.State != session.StateActivating {
			return guardDenied()
		}
		if localpeer.VerifyProcessTree(n.PID, w.process.PID, w.process.UID, read) != nil {
			return guardDenied()
		}
		_, e = w.client.OwnerProcess()
		return e
	})
	if err != nil {
		return fabricauth.Activation{}, fabric.Principal{}, guardDenied()
	}
	if m.lookup(key) != w {
		return fabricauth.Activation{}, fabric.Principal{}, guardDenied()
	}
	activation := fabricauth.Activation{Scope: w.scope, RootPID: s.PID, StartIdentity: s.NativeStartIdentity, Nonce: s.ActivationNonce, NativeGeneration: s.NativeGeneration, NativeSessionID: s.NativeSessionID}
	return activation, fabric.Principal{Ref: local.Endpoint.String(), Kind: descriptor.Kind, Issuer: local.Namespace}, nil
}

func (m *ManagedPeers) ResolveManaged(ctx context.Context, selector fabrichost.ManagedSelector) (fabricauth.Activation, error) {
	if m == nil {
		return fabricauth.Activation{}, guardDenied()
	}
	m.mu.RLock()
	key, exists := m.selectors[managedSelectorKey{selector.Endpoint, selector.WorkerID}]
	m.mu.RUnlock()
	if !exists {
		return fabricauth.Activation{}, guardDenied()
	}
	a, _, err := m.checked(ctx, key)
	if err == nil && a.NativeGeneration != selector.Generation {
		return fabricauth.Activation{}, guardDenied()
	}
	return a, err
}

// RetireJoined is only for the trusted supervisor AFTER joining the complete
// owned tree. Connection loss, native PID disappearance and frontend detach
// never remove ownership roots or make a descendant an independent owner.
func (m *ManagedPeers) RetireJoined(ownership nativeauthority.Scope, process localpeer.ProcessSnapshot) error {
	if m == nil {
		return guardDenied()
	}
	local, ok := ownership.Local()
	if !ok {
		return guardDenied()
	}
	key := managedKey{local.Endpoint, local.WorkerID, local.OwnershipGeneration}
	m.mu.Lock()
	defer m.mu.Unlock()
	w := m.workers[key]
	if w == nil || w.scope != ownership || w.process != process {
		return guardDenied()
	}
	if err := m.guard.RetireJoined(process); err != nil {
		return err
	}
	delete(m.workers, key)
	delete(m.selectors, managedSelectorKey{local.Endpoint, local.WorkerID})
	return nil
}

// ValidateManaged runs again for each original envelope and compares the actual
// activation captured at connection admission. Descriptor renewal may preserve
// the same physical conversation, but retired origins and new generations deny.
func (m *ManagedPeers) ValidateManaged(ctx context.Context, peer fabricauth.ManagedPeer) (fabric.Principal, error) {
	local, ok := peer.Activation.Scope.Local()
	if !ok {
		return fabric.Principal{}, guardDenied()
	}
	a, p, err := m.checked(ctx, managedKey{local.Endpoint, local.WorkerID, local.OwnershipGeneration})
	if err != nil || a.Scope != peer.Activation.Scope || a.RootPID != peer.Activation.RootPID || a.StartIdentity != peer.Activation.StartIdentity || a.NativeGeneration != peer.Activation.NativeGeneration || a.NativeSessionID != peer.Activation.NativeSessionID || subtle.ConstantTimeCompare([]byte(a.Nonce), []byte(peer.Activation.Nonce)) != 1 {
		return fabric.Principal{}, guardDenied()
	}
	return p, nil
}
