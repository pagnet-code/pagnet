package fabricnative

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
)

func jsonLocalScope(local nativeauthority.LocalScope) (nativeauthority.Scope, error) {
	raw, e := json.Marshal(struct {
		Format string                     `json:"format"`
		Local  nativeauthority.LocalScope `json:"local"`
	}{"pagnet.native-authority.local.v1", local})
	if e != nil {
		return nativeauthority.Scope{}, e
	}
	var scope nativeauthority.Scope
	e = json.Unmarshal(raw, &scope)
	return scope, e
}

func TestLaunchClaimAllowsOneAttemptAndSurvivesActualRootRestart(t *testing.T) {
	c, value, dir := checkpointFixture(t, registry.DefaultOptions())
	scope, e := nativeauthority.NewLocalScope(c.root, value.OriginalBinding)
	if e != nil {
		t.Fatal(e)
	}
	state, e := c.LookupLaunch(t.Context(), scope)
	if e != nil || state.Exists {
		t.Fatal("fresh claim invented", e)
	}
	ticket, e := c.BeginLaunch(t.Context(), scope, "launch-original")
	if e != nil {
		t.Fatal(e)
	}
	var calls atomic.Int32
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			_ = ticket.Run(t.Context(), func(context.Context) error { calls.Add(1); return errors.New("uncertain spawn outcome") })
		})
	}
	group.Wait()
	if calls.Load() != 1 {
		t.Fatal("launch permit reused", calls.Load())
	}
	if (&LaunchTicket{}).Run(t.Context(), func(context.Context) error { t.Fatal("zero ticket launched"); return nil }) == nil {
		t.Fatal("uncommitted ticket admitted")
	}
	if _, e = c.BeginLaunch(t.Context(), scope, "launch-original"); e == nil {
		t.Fatal("same attempt relaunched uncertain effect")
	}
	if _, e = c.BeginLaunch(t.Context(), scope, "launch-another"); e == nil {
		t.Fatal("new attempt replayed same physical worker")
	}
	if e = c.store.Close(); e != nil {
		t.Fatal(e)
	}
	store, e := registry.Open(t.Context(), dir)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	authority, e := identity.New(store, checkpointFence{})
	if e != nil {
		t.Fatal(e)
	}
	reopened, e := NewCheckpoints(store, authority, c.owner, c.protector)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = reopened.BeginLaunch(t.Context(), scope, "launch-after-restart"); e == nil {
		t.Fatal("root restart erased uncertain physical claim")
	}
	// A descriptor renewal preserves the physical slot, rather than creating
	// a new process for the same worker after a metadata edit.
	local, _ := scope.Local()
	local.DescriptorRevision = "renewed"
	local.BindingDigest[0] ^= 1
	b, e := jsonLocalScope(local)
	if e != nil {
		t.Fatal(e)
	}
	state, e = reopened.LookupLaunch(t.Context(), b)
	if e != nil || !state.Exists || state.Ownership != scope || state.Observed != nil {
		t.Fatal("retained claim lost original ownership", e)
	}
	if _, e = reopened.BeginLaunch(t.Context(), b, "launch-renamed"); e == nil {
		t.Fatal("descriptor renewal reminted launch permit")
	}
}

func TestCancelledLaunchPermitCannotBeReused(t *testing.T) {
	c, value, _ := checkpointFixture(t, registry.DefaultOptions())
	scope, e := nativeauthority.NewLocalScope(c.root, value.OriginalBinding)
	if e != nil {
		t.Fatal(e)
	}
	ticket, e := c.BeginLaunch(t.Context(), scope, "launch-cancelled")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if ticket.Run(ctx, func(context.Context) error { t.Fatal("cancelled ticket spawned worker"); return nil }) == nil {
		t.Fatal("cancelled ticket ignored deadline")
	}
	if ticket.Run(t.Context(), func(context.Context) error { t.Fatal("cancelled ticket reused"); return nil }) == nil {
		t.Fatal("cancelled launch reminted permit")
	}
}
