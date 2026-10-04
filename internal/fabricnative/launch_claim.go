package fabricnative

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

type launchClaim struct {
	Version   string                     `json:"version"`
	Ownership nativeauthority.Scope      `json:"ownership"`
	Attempt   string                     `json:"attempt"`
	Phase     string                     `json:"phase"`
	Process   *localpeer.ProcessSnapshot `json:"process,omitempty"`
}

// LaunchState is retained infrastructure history, never process liveness.
// Only actual authenticated worker IPC/kernel observation can establish that.
type LaunchState struct {
	Exists    bool
	Ownership nativeauthority.Scope
	Observed  *localpeer.ProcessSnapshot
}

func (c *Checkpoints) LookupLaunch(ctx context.Context, physical nativeauthority.Scope) (LaunchState, error) {
	if c == nil || ctx == nil {
		return LaunchState{}, checkpointDenied()
	}
	local, ok := physical.Local()
	if !ok || local.Namespace != c.root.Namespace || local.StoreID != c.root.StoreID || local.Owner != c.root.Owner {
		return LaunchState{}, checkpointDenied()
	}
	key, err := launchClaimKey(physical)
	if err != nil {
		return LaunchState{}, err
	}
	var state LaunchState
	err = c.store.WithNativeAuthority(ctx, c.owner, registry.AuthorityScope{}, func(tx *registry.AuthorityTx) error {
		record, err := tx.Get(key)
		if err != nil {
			var missing *fabric.Error
			if errors.As(err, &missing) && missing.Code == fabric.CodeNotFound {
				return nil
			}
			return err
		}
		var claim launchClaim
		if record.Retired || decodeCheckpoint(record.Value, &claim) != nil || claim.Version != "pagnet.native.launch-claim.v1" || claim.Ownership.Validate() != nil || !claim.Ownership.SamePhysical(physical) || claim.Attempt == "" || len(claim.Attempt) > 256 || !utf8.ValidString(claim.Attempt) {
			return checkpointDenied()
		}
		if claim.Phase != "launching" && claim.Phase != "observed" || claim.Phase == "launching" && claim.Process != nil || claim.Phase == "observed" && (claim.Process == nil || claim.Process.PID <= 0 || claim.Process.Start <= 0) {
			return checkpointDenied()
		}
		state = LaunchState{Exists: true, Ownership: claim.Ownership}
		if claim.Process != nil {
			process := *claim.Process
			state.Observed = &process
		}
		return nil
	})
	if err != nil {
		return LaunchState{}, err
	}
	return state, nil
}

// LaunchTicket permits one local launch attempt after the real FULL claim.
// Neither a lost reply nor a failed spawn erases its retained uncertainty.
// Launching an idle worker grants no native effect authority; native intent
// admission still goes through the independent current execution fence.
type LaunchTicket struct {
	mu        sync.Mutex
	used      bool
	committed bool
}

func (t *LaunchTicket) Run(ctx context.Context, launch func(context.Context) error) error {
	if t == nil || ctx == nil || launch == nil {
		return checkpointDenied()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.committed || t.used {
		return fabric.NewError(fabric.CodeTargetUnavailable, "Native launch already attempted; recover the original worker")
	}
	t.used = true
	if err := ctx.Err(); err != nil {
		return err
	}
	return launch(ctx)
}

func launchClaimKey(scope nativeauthority.Scope) (registry.AuthorityKey, error) {
	local, ok := scope.Local()
	if !ok || scope.Validate() != nil {
		return registry.AuthorityKey{}, checkpointDenied()
	}
	// Descriptor renewal does not invent another physical worker launch slot.
	local.DescriptorRevision = ""
	local.BindingDigest = [32]byte{}
	raw, err := json.Marshal(local)
	if err != nil {
		return registry.AuthorityKey{}, err
	}
	h := sha256.Sum256(raw)
	return registry.AuthorityKey{Kind: registry.AuthorityNativeCheckpoint, ID: "launch/" + hex.EncodeToString(h[:])}, nil
}

// BeginLaunch never reissues a permit for an existing physical ownership slot,
// including a retry with the SAME attempt. Explicit authenticated recovery must
// observe the retained worker; absence of a socket is not proof it never ran.
func (c *Checkpoints) BeginLaunch(ctx context.Context, ownership nativeauthority.Scope, attempt string) (*LaunchTicket, error) {
	if c == nil || ctx == nil || attempt == "" || len(attempt) > 256 || !utf8.ValidString(attempt) {
		return nil, checkpointDenied()
	}
	local, ok := ownership.Local()
	if !ok || local.Namespace != c.root.Namespace || local.StoreID != c.root.StoreID || local.Owner != c.root.Owner {
		return nil, checkpointDenied()
	}
	key, err := launchClaimKey(ownership)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(launchClaim{Version: "pagnet.native.launch-claim.v1", Ownership: ownership, Attempt: attempt, Phase: "launching"})
	if err != nil {
		return nil, err
	}
	err = c.store.WithNativeAuthority(ctx, c.owner, registry.AuthorityScope{}, func(tx *registry.AuthorityTx) error {
		_, e := tx.Get(key)
		if e == nil {
			return fabric.NewError(fabric.CodeTargetUnavailable, "Native launch outcome requires original worker recovery")
		}
		var fe *fabric.Error
		if !errors.As(e, &fe) || fe.Code != fabric.CodeNotFound {
			return e
		}
		_, e = tx.CAS(key, 0, raw, false)
		return e
	})
	if err != nil {
		return nil, err
	}
	return &LaunchTicket{committed: true}, nil
}

// ObserveLaunched authenticates actual private worker IPC and kernel birth;
// a PID from a journal/frontend cannot mark a worker launched. Startup must do
// this and ManagedPeers.Register BEFORE exposing the root-owner listener.
func (c *Checkpoints) ObserveLaunched(ctx context.Context, ownership nativeauthority.Scope, client *sessionworker.LocalClient) (localpeer.ProcessSnapshot, error) {
	if c == nil || ctx == nil || client == nil {
		return localpeer.ProcessSnapshot{}, checkpointDenied()
	}
	key, err := launchClaimKey(ownership)
	if err != nil {
		return localpeer.ProcessSnapshot{}, err
	}
	process, err := client.OwnerProcess()
	if err != nil {
		return process, err
	}
	r, err := client.Call(ctx, sessionworker.LocalRequest{Type: "snapshot"})
	if err != nil || r.Snapshot == nil || r.Snapshot.Authority != ownership {
		return localpeer.ProcessSnapshot{}, checkpointDenied()
	}
	fresh, err := client.OwnerProcess()
	if err != nil || fresh != process {
		return localpeer.ProcessSnapshot{}, checkpointDenied()
	}
	err = c.store.WithNativeAuthority(ctx, c.owner, registry.AuthorityScope{}, func(tx *registry.AuthorityTx) error {
		record, e := tx.Get(key)
		if e != nil {
			return e
		}
		var claim launchClaim
		if record.Retired || decodeCheckpoint(record.Value, &claim) != nil || claim.Version != "pagnet.native.launch-claim.v1" || claim.Ownership != ownership || claim.Attempt == "" {
			return checkpointDenied()
		}
		if claim.Phase == "observed" {
			// Parent changes when the original daemon exits. Actual IPC + the
			// immutable PID/UID/birth still identify the SAME surviving worker.
			if claim.Process == nil || claim.Process.PID != process.PID || claim.Process.UID != process.UID || claim.Process.Start != process.Start {
				return checkpointDenied()
			}
			return nil
		}
		if claim.Phase != "launching" || claim.Process != nil {
			return checkpointDenied()
		}
		claim.Phase = "observed"
		claim.Process = &process
		raw, e := json.Marshal(claim)
		if e != nil {
			return e
		}
		_, e = tx.CAS(key, record.Revision, raw, false)
		return e
	})
	return process, err
}
