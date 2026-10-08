// The installed federation product's private owner-administration surface.
// This slice composes ONLY the retained signed exposure configuration
// (federation.exposure.put/get): the per-link boundary+runtime, the relay
// listener and the pinned link registry are a subsequent slice and are
// deliberately absent here. The handlers merge into the node's existing admin
// server (the same handlers-map pattern as AgentAdministration /
// ServiceAdministration / InstalledHosted.Administration); duplicate operation
// names are startup errors, as today. Every act runs under the genuine owner
// session and the exposure surface's own owner fence.

package fabricnode

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/fabricadmin"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
)

// InstalledFederationConfig is the explicit installed federation exposure
// surface. A nil InstalledConfig.Federation means the surface is unavailable
// (explicit, never implicit). The config carries no per-peer list: the pinned
// link registry is a subsequent slice.
type InstalledFederationConfig struct{}

// InstalledFederation is the composed installed federation exposure surface
// over the loaded installation: the retained signed exposure record and its
// private owner administration.
type InstalledFederation struct {
	node      *InstalledNode
	Exposures *FederationExposures
}

// newInstalledFederation composes the exposure surface from the installation's
// actual store, owner, operator and keys. A missing exposure record is not an
// error: the first declared configuration creates it.
func newInstalledFederation(ctx context.Context, n *InstalledNode) (*InstalledFederation, error) {
	if ctx == nil || n == nil || n.Installation == nil {
		return nil, localDenied()
	}
	installation := n.Installation
	owner := func(ctx context.Context) (fabric.ExecutionContext, error) { return installation.Operator(ctx) }
	exposures, err := NewFederationExposures(ctx, installation.Store, owner, installation, installation.Keys)
	if err != nil {
		return nil, err
	}
	return &InstalledFederation{node: n, Exposures: exposures}, nil
}

// Administration returns the federation product's private owner-administration
// handlers. A nil product contributes no operations.
func (f *InstalledFederation) Administration() map[string]fabricadmin.Handler {
	if f == nil {
		return nil
	}
	return map[string]fabricadmin.Handler{
		"federation.exposure.put": f.federationExposurePut,
		"federation.exposure.get": f.federationExposureGet,
	}
}

// federationExposurePutInput is the private owner input for declaring the
// node's signed exposure configuration. The CAS base is an explicit JSON
// number in the input; the generic request-level expectedRevision string is
// rejected, as by every other operation.
type federationExposurePutInput struct {
	ExpectedRevision uint64               `json:"expectedRevision"`
	Exposures        []FederationExposure `json:"exposures"`
}

func (f *InstalledFederation) federationExposurePut(ctx context.Context, access *fabricauth.OwnerAdministration, request fabricadmin.Request) (json.RawMessage, error) {
	if f == nil || f.node == nil || f.Exposures == nil || access == nil || request.Operation != "federation.exposure.put" || request.ExpectedRevision != "" || access.VerifyCurrent(ctx) != nil {
		return nil, localDenied()
	}
	var input federationExposurePutInput
	if err := fabric.DecodeJSON(request.Input, &input); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(request.Input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Federation exposure put contains unsupported fields")
	}
	revision, err := f.Exposures.Put(ctx, input.ExpectedRevision, FederationExposureConfiguration{Exposures: input.Exposures})
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Revision uint64 `json:"revision"`
	}{revision})
}

func (f *InstalledFederation) federationExposureGet(ctx context.Context, access *fabricauth.OwnerAdministration, request fabricadmin.Request) (json.RawMessage, error) {
	if f == nil || f.node == nil || f.Exposures == nil || access == nil || request.Operation != "federation.exposure.get" || request.ExpectedRevision != "" || access.VerifyCurrent(ctx) != nil {
		return nil, localDenied()
	}
	var input struct{}
	if err := fabric.DecodeJSON(request.Input, &input); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(request.Input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Federation exposure get contains unsupported fields")
	}
	configuration, revision, err := f.Exposures.Current(ctx)
	if err != nil {
		return nil, err
	}
	exposures := configuration.Exposures
	if exposures == nil {
		exposures = []FederationExposure{}
	}
	return json.Marshal(struct {
		Revision  uint64               `json:"revision"`
		Exposures []FederationExposure `json:"exposures"`
	}{revision, exposures})
}
