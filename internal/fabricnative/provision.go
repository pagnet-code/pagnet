package fabricnative

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// ProvisionInitialControl explicitly installs the retained profile's control
// rows. It never starts a runtime, invents a session, replaces a physical worker,
// or assumes missing binding means there was no native effect. A crash between
// controller and binding commits is recovered from the actual partial rows.
func (s *ProfileStore) ProvisionInitialControl(ctx context.Context, authority *identity.Authority, scope registry.DescriptorBatchScope) (identity.Controller, identity.Binding, error) {
	if s == nil || ctx == nil || authority == nil || authority.Identity().StoreID != s.root.StoreID || authority.Identity().Namespace != s.root.Namespace {
		return identity.Controller{}, identity.Binding{}, checkpointDenied()
	}
	profile, _, err := s.Get(ctx, scope)
	if err != nil {
		return identity.Controller{}, identity.Binding{}, err
	}
	selected := identity.Scope{Endpoint: scope.Endpoint, DescriptorRevision: scope.ExpectedEndpointRevision, BindingID: scope.BindingID}
	state, err := authority.RetainedNativeControlState(ctx, s.owner, selected)
	if err != nil {
		return identity.Controller{}, identity.Binding{}, err
	}
	if state.Binding != nil {
		if state.Binding.Worker != profile.Worker || state.Controller.Scope != selected || state.Binding.Scope != selected {
			return identity.Controller{}, identity.Binding{}, checkpointDenied()
		}
		return *state.Controller, *state.Binding, nil
	}
	if state.Controller == nil {
		raw, _ := json.Marshal(struct {
			Scope  identity.Scope
			Worker identity.WorkerBinding
		}{selected, profile.Worker})
		digest := sha256.Sum256(raw)
		id := "initial-" + hex.EncodeToString(digest[:])
		current, e := authority.AcquireController(ctx, s.owner, selected, 0, id, id)
		if e != nil {
			return identity.Controller{}, identity.Binding{}, e
		}
		state.Controller = &current
	}
	if state.Controller.Scope != selected {
		return identity.Controller{}, identity.Binding{}, checkpointDenied()
	}
	binding, err := authority.BindWorker(ctx, s.owner, *state.Controller, 0, profile.Worker)
	if err != nil {
		return identity.Controller{}, identity.Binding{}, err
	}
	return *state.Controller, binding, nil
}
