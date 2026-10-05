package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// PreparedInvocationTarget owns a compiled, self-contained schema. Preparation
// occurs before any authority transaction; its exact metadata is rechecked under
// the admission lock. Private fields prevent caller-supplied schema substitution.
type PreparedInvocationTarget struct {
	target        fabric.EndpointRef
	revision      fabric.Revision
	bindingID     string
	schemaDigest  [32]byte
	schema        *jsonschema.Schema
	payloadDigest [32]byte
}

func (s *Store) PrepareInvocationTarget(ctx context.Context, target fabric.EndpointRef, revision fabric.Revision, payload json.RawMessage) (*PreparedInvocationTarget, error) {
	if ctx == nil {
		return nil, invalid("Missing selected invocation preparation context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !target.IsOffer() {
		return &PreparedInvocationTarget{target: target, revision: revision}, nil
	}
	offer, err := s.GetOffer(ctx, target, revision)
	if err != nil {
		return nil, err
	}
	prepared := &PreparedInvocationTarget{target: target, revision: revision, bindingID: offer.BindingID}
	if len(offer.InputSchema) == 0 {
		return prepared, nil
	}
	limits := fabric.DefaultWireLimits
	limits.MaxBytes = s.options.Limits.MaxPayloadBytes
	var bounded any
	if fabric.DecodeJSONWithLimits(offer.InputSchema, &bounded, limits) != nil {
		return nil, invalid("Selected offer schema exceeds bounded grammar")
	}
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(offer.InputSchema))
	if err != nil {
		return nil, invalid("Selected offer schema is invalid")
	}
	compiler := jsonschema.NewCompiler()
	compiler.UseLoader(jsonschema.SchemeURLLoader{})
	const resource = "urn:pagnet:native-offer-schema"
	if compiler.AddResource(resource, document) != nil {
		return nil, invalid("Selected offer schema is invalid")
	}
	prepared.schema, err = compiler.Compile(resource)
	if err != nil {
		return nil, invalid("Selected offer schema is unsupported or invalid")
	}
	prepared.schemaDigest = sha256.Sum256(offer.InputSchema)
	if fabric.DecodeJSON(payload, &bounded) != nil {
		return nil, invalid("Selected offer input exceeds bounded JSON grammar")
	}
	input, err := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
	if err != nil || prepared.schema.Validate(input) != nil {
		return nil, invalid("Selected offer input does not match its registered schema")
	}
	prepared.payloadDigest = sha256.Sum256(payload)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return prepared, nil
}

// VerifyInvocationTarget verifies the selected target in the SAME transaction
// as native admission. Historical receipts use retained signed selection.
func (a *AuthorityTx) VerifyInvocationTarget(target fabric.EndpointRef, revision fabric.Revision, payload json.RawMessage, prepared ...*PreparedInvocationTarget) ([32]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.guard(); err != nil {
		return [32]byte{}, err
	}
	return a.verifyInvocationTarget(target, revision, payload, prepared...)
}

func (a *AuthorityTx) verifyInvocationTarget(target fabric.EndpointRef, revision fabric.Revision, payload json.RawMessage, prepared ...*PreparedInvocationTarget) ([32]byte, error) {
	if a.scope.HistoryOnly || target.String() == "" || target.Endpoint() != a.scope.Endpoint || revision == "" {
		return [32]byte{}, invalid("Selected invocation target outside current native scope")
	}
	if !target.IsOffer() {
		if revision != a.scope.ExpectedRevision {
			return [32]byte{}, conflict("Selected endpoint revision is stale")
		}
		return [32]byte{}, nil
	}
	o, err := loadObject(a.ctx, a.tx, target.String())
	if errors.Is(err, sql.ErrNoRows) {
		return [32]byte{}, fabric.NewError(fabric.CodeNotFound, "Selected offer unavailable")
	}
	if err != nil {
		return [32]byte{}, err
	}
	if o.retired || o.revision != revision {
		return [32]byte{}, conflict("Selected offer is retired or stale")
	}
	if o.kind != "offer" || o.parent != a.scope.Endpoint.String() {
		return [32]byte{}, invalid("Selected offer has a different physical endpoint")
	}
	var offer fabric.OfferDescriptor
	if err = a.store.decode(o.payload, &offer); err != nil {
		return [32]byte{}, err
	}
	if offer.Ref != target || offer.Revision != revision || offer.BindingID != a.scope.BindingID {
		return [32]byte{}, invalid("Selected offer binding differs from native ownership")
	}
	if len(offer.InputSchema) == 0 {
		return [32]byte{}, nil
	}
	if len(prepared) != 1 || prepared[0] == nil {
		return [32]byte{}, invalid("Selected offer requires prepared schema")
	}
	p := prepared[0]
	schemaDigest := sha256.Sum256(offer.InputSchema)
	if p.target != target || p.revision != revision || p.bindingID != offer.BindingID || p.schemaDigest != schemaDigest || p.schema == nil || p.payloadDigest != sha256.Sum256(payload) {
		return [32]byte{}, conflict("Prepared offer schema differs from current selection")
	}
	return sha256.Sum256(offer.InputSchema), nil
}
