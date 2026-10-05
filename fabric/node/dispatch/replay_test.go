package dispatch

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/node"
)

func TestUnsupportedIdempotencyDeniedBeforeAdmissionAndEffects(t *testing.T) {
	for _, mode := range []string{"unsupported", "other-binding-only", "stale-offer", "foreign-offer", "supported"} {
		t.Run(mode, func(t *testing.T) {
			s, _, e, store, _, admission, endpoint := setup(t)
			e.Context.IdempotencyKey = "same-request"
			switch mode {
			case "other-binding-only":
				store.endpoint.Bindings = append(store.endpoint.Bindings, fabric.BindingSummary{ID: "other", Idempotency: true})
			case "stale-offer":
				store.offer.Revision = "stale"
			case "foreign-offer":
				foreign, _ := fabric.NewEndpointRef([]byte("another real domain root key!!!!"))
				store.offer.Ref = foreign
			case "supported":
				store.endpoint.Bindings[0].Idempotency = true
			}
			raw, _ := json.Marshal(e)
			result, err := s.Execute(t.Context(), raw, "owned-peer")
			if mode == "supported" {
				if err != nil {
					t.Fatal(err)
				}
				_ = result.Stream.Close()
				return
			}
			if err == nil || admission.calls != 0 || endpoint.calls != 0 {
				t.Fatal("unsupported/stale binding reached paid admission", err, admission.calls, endpoint.calls)
			}
		})
	}
}

// Genuine node -> current selection -> admission wrapper must retain optional
// replay metadata. Otherwise node would silently treat old output as fresh.
func TestAdmissionWrapperRetainsReplayMetadataForDefaultDeny(t *testing.T) {
	s, _, e, store, res, adm, _ := setup(t)
	store.endpoint.Bindings[0].Idempotency = true
	e.Context.IdempotencyKey = "original-operation"
	endpoint := &associatedAdapter{}
	res.selection.Adapter = endpoint
	raw, _ := json.Marshal(e)
	_, err := s.Execute(t.Context(), raw, "owned-peer")
	if err == nil || adm.calls != 1 || endpoint.calls != 1 || endpoint.source.reads != 0 || endpoint.source.closed != 1 {
		t.Fatal("lost replay metadata across admitted stream", err, endpoint.calls, endpoint.source)
	}
}

type associatedAdapter struct {
	calls  int
	source *associatedSource
}

func (a *associatedAdapter) Invoke(ctx context.Context, c fabric.ExecutionContext, _ fabric.EndpointDescriptor, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
	a.calls++
	_, original, final, ok := node.FinalizedRequestFromContext(ctx)
	if !ok {
		panic("missing actual node facts")
	}
	h := sha256.Sum256([]byte("original receipt"))
	association := fabric.ReplayAssociation{Version: 1, AuthorityNamespace: r.Target.Domain(), AuthorityStoreID: "real-store", AuthorityKeyRevision: 1, Principal: c.PrincipalView(), RequestID: r.InvocationID, ExecutionID: "original-execution", Target: r.Target, ExpectedRevision: r.ExpectedRevision, OriginalRequestSHA: sha256.Sum256(original), FinalizedRequestSHA: sha256.Sum256(final), InputSHA: sha256.Sum256(r.Input), IdempotencySHA: sha256.Sum256([]byte(r.IdempotencyKey)), BindingFingerprint: h, OriginalReceiptSHA: h, Proof: []byte("signed alias")}
	a.source = &associatedSource{association: association}
	return a.source, nil
}

type associatedSource struct {
	association   fabric.ReplayAssociation
	reads, closed int
}

func (s *associatedSource) ReplayAssociation() *fabric.ReplayAssociation {
	a := s.association.Clone()
	return &a
}
func (s *associatedSource) Next(context.Context) (fabric.InvocationFrame, error) {
	s.reads++
	return fabric.InvocationFrame{InvocationID: s.association.ExecutionID, Kind: fabric.FrameStart}, nil
}
func (s *associatedSource) Close() error { s.closed++; return nil }
