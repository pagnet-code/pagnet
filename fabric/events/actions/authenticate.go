package actions

import (
	"context"
	"encoding/json"

	"github.com/pagnet-code/pagnet/fabric"
)

// ActionGrant is the transport-private verified evidence carried by the
// installed adapter association. It binds the exact admitted action and its
// original source to one node.Service execution. It is never inserted into an
// envelope, descriptor, event, search index or extension wire payload.
type ActionGrant struct{ Request AdmissionRequest }

// AuthenticateAction is the trusted dispatch boundary for the installed adapter
// association. It re-verifies the exact retained action against the store's
// CURRENT source/definition authority and retained lineage, and returns a
// freshly authenticated forward context. It never trusts a caller context
// carried on the queue and never re-derives the action from mutable event data.
func (s *Store) AuthenticateAction(ctx context.Context, action Action, source SourceInput, exactEnvelope []byte, audience string) (fabric.ExecutionContext, error) {
	if ctx == nil || s == nil || len(exactEnvelope) == 0 || audience == "" || string(exactEnvelope) != string(action.ExactEnvelope) {
		return fabric.ExecutionContext{}, denied()
	}
	original, v, e := s.verifySource(ctx, SourceInput{bytesClone(source.ExactEvent), bytesClone(source.Proof)})
	if e != nil {
		return fabric.ExecutionContext{}, e
	}
	var envelope fabric.Envelope
	if fabric.DecodeJSON(exactEnvelope, &envelope) != nil || envelope.Principal != v.Caller.PrincipalView() || envelope.Source != v.Caller.PrincipalView().Ref {
		return fabric.ExecutionContext{}, denied()
	}
	key := "emit"
	var definition *TriggerDefinition
	if action.DefinitionID != "" {
		d, ok := s.definitions[action.DefinitionID]
		if !ok || d.Revision != action.DefinitionRevision || s.config.DefinitionAuthority.Verify(ctx, s.config.Scope, cloneDefinition(d)) != nil {
			return fabric.ExecutionContext{}, denied()
		}
		key = d.ID + "@" + d.Revision
		definition = &d
	}
	id, lineage, e := actionIdentity(s.config.Scope, original, v, key, definition)
	expected, _ := json.Marshal(lineage)
	actual, _ := json.Marshal(envelope.Context)
	if e != nil || id != action.ID || envelope.ID != id || string(expected) != string(actual) || s.config.Authorizer.Check(ctx, v.Caller, cloneAction(action)) != nil {
		return fabric.ExecutionContext{}, denied()
	}
	p := fabric.Provenance{Origin: lineage.Origin, ParentID: lineage.ParentID, Hops: lineage.Hops, Ancestry: lineage.Ancestry, ExtensionChain: lineage.ExtensionChain, TriggerLineage: lineage.TriggerLineage}
	return fabric.NewAuthenticatedForwardContext(v.Caller.PrincipalView(), audience, exactEnvelope, p)
}
