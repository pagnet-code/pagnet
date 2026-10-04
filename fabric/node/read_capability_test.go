package node

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

type capabilitySearch struct{ ctx context.Context }

func (s *capabilitySearch) Search(ctx context.Context, _ fabric.DiscoverRequest) (fabric.DiscoverResult, error) {
	s.ctx = ctx
	return fabric.DiscoverResult{}, nil
}

type capabilityStore struct {
	*fixtureStore
	ctx context.Context
}

func (s *capabilityStore) GetEndpoint(ctx context.Context, ref fabric.EndpointRef, revision fabric.Revision) (fabric.EndpointDescriptor, error) {
	s.ctx = ctx
	return s.fixtureStore.GetEndpoint(ctx, ref, revision)
}

func TestFinalizedReadCapabilityComesOnlyFromNodeBoundary(t *testing.T) {
	for _, operation := range []fabric.Operation{fabric.OperationDiscover, fabric.OperationDescribe} {
		t.Run(string(operation), func(t *testing.T) {
			s, env, _, store, dispatcher := setup(t)
			search := &capabilitySearch{}
			descriptors := &capabilityStore{fixtureStore: store}
			s.config.Search = search
			s.config.Descriptors = descriptors
			env.Operation = operation
			if operation == fabric.OperationDiscover {
				env.Payload = json.RawMessage(`{"query":"invoice","limit":10,"scope":{}}`)
			} else {
				env.Payload, _ = json.Marshal(fabric.DescribeRequest{Selections: []fabric.DescribeSelection{{Ref: store.endpoint.Ref}}})
			}
			exact, _ := json.Marshal(env)
			exact = append(exact, '\n')
			if _, err := s.Execute(t.Context(), exact, "verified-local-peer"); err != nil {
				t.Fatal(err)
			}
			ctx := search.ctx
			if operation == fabric.OperationDescribe {
				ctx = descriptors.ctx
			}
			caller, original, final, ok := FinalizedRequestFromContext(ctx)
			var admitted fabric.Envelope
			if !ok || !bytes.Equal(original, exact) || caller.PrincipalView() != env.Principal || fabric.DecodeJSON(final, &admitted) != nil || admitted.Operation != operation || !bytes.Equal(admitted.Payload, env.Payload) || len(dispatcher.requests) != 0 {
				t.Fatal("read lost exact original or finalized boundary")
			}
			original[0], final[0] = '!', '!'
			_, freshOriginal, freshFinal, _ := FinalizedRequestFromContext(ctx)
			if freshOriginal[0] == '!' || freshFinal[0] == '!' {
				t.Fatal("capability exposed mutable engine bytes")
			}
			if _, _, _, ok = FinalizedRequestFromContext(context.Background()); ok {
				t.Fatal("untrusted context manufactured finalized read")
			}
		})
	}
}
