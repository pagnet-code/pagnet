package node

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension"
)

func installReadEngine(t *testing.T, service *Service, operation fabric.Operation, handler inlineHandler) {
	t.Helper()
	manifest := extension.ExtensionManifest{ManifestVersion: "1.0", ID: "test.read", Version: "1", MinProtocol: "1.0", MaxProtocol: "1.0"}
	for _, stage := range []string{"request", "response"} {
		manifest.Interceptors = append(manifest.Interceptors, extension.Registration{ID: "test.read." + stage, Binding: "private.read", Placement: extension.PlacementSource, Match: extension.Match{Operation: operation, Stage: string(operation) + "." + stage}, Phases: []extension.Phase{extension.PhaseRequest, extension.PhaseResponse, extension.PhaseError}, TimeoutMillis: 1000})
	}
	plan, err := extension.Compile([]extension.ExtensionManifest{manifest}, 10)
	if err != nil {
		t.Fatal(err)
	}
	handlers := extension.NewHandlerRegistry()
	if err := handlers.Set("private.read", handler); err != nil {
		t.Fatal(err)
	}
	executor, _ := extension.NewExecutor(2)
	engine, err := extension.NewEngine(plan, handlers, executor, func(context.Context, fabric.ExecutionContext, fabric.Envelope, string, extension.Placement) (extension.MatchContext, error) {
		return extension.MatchContext{}, nil
	}, func(context.Context, fabric.ExecutionContext, fabric.Envelope) error { return nil }, nil, 8)
	if err != nil {
		t.Fatal(err)
	}
	service.config.Interceptors = engine
}

func TestReadCacheStillPassesResponseAndCurrentDisclosureBarriers(t *testing.T) {
	for _, operation := range []fabric.Operation{fabric.OperationDiscover, fabric.OperationDescribe} {
		t.Run(string(operation), func(t *testing.T) {
			service, envelope, search, store, dispatcher := setup(t)
			envelope.Operation = operation
			var cached json.RawMessage
			if operation == fabric.OperationDiscover {
				envelope.Payload = json.RawMessage(`{"query":"invoice","scope":{},"limit":10}`)
				cached, _ = json.Marshal(search.result)
			} else {
				envelope.Payload, _ = json.Marshal(fabric.DescribeRequest{Selections: []fabric.DescribeSelection{{Ref: store.endpoint.Ref, ExpectedRevision: "r1"}}})
				cached, _ = json.Marshal(fabric.DescribeResult{Descriptions: []fabric.Description{{Ref: store.endpoint.Ref, Endpoint: &store.endpoint}}})
			}
			var calls []string
			installReadEngine(t, service, operation, func(ctx context.Context, r extension.InterceptRequest) (extension.Decision, error) {
				caller, original, ok := OriginalRequestFromContext(ctx)
				if !ok || len(original) == 0 || caller.PrincipalView() != envelope.Principal {
					t.Error("missing genuine original request")
				}
				calls = append(calls, r.Stage+":"+string(r.Phase))
				if r.Stage == string(operation)+".request" && r.Phase == extension.PhaseRequest {
					return extension.Decision{Action: extension.Respond, Response: cached}, nil
				}
				return extension.Decision{Action: extension.Continue}, nil
			})
			checks := 0
			service.config.ValidateReadResult = func(_ context.Context, c fabric.ExecutionContext, e fabric.Envelope, r Result) error {
				checks++
				if c.PrincipalView() != envelope.Principal || e.Operation != operation {
					t.Fatal("authority changed")
				}
				return nil
			}
			result, err := execute(t, service, envelope)
			if err != nil || operation == fabric.OperationDiscover && result.Discover == nil || operation == fabric.OperationDescribe && result.Describe == nil {
				t.Fatal(result, err)
			}
			want := []string{string(operation) + ".request:request", string(operation) + ".response:request", string(operation) + ".response:response"}
			if !reflect.DeepEqual(calls, want) || checks != 2 || search.calls != 0 || store.headers != 0 || store.schemas != 0 || len(dispatcher.requests) != 0 {
				t.Fatal(calls, checks, search.calls, store.headers, len(dispatcher.requests))
			}
			service.config.ValidateReadResult = func(context.Context, fabric.ExecutionContext, fabric.Envelope, Result) error {
				return fabric.NewError(fabric.CodeStaleReference, "Current disclosure no longer permitted")
			}
			_, err = execute(t, service, envelope)
			var failure *fabric.Error
			if !errors.As(err, &failure) || failure.Code != fabric.CodeStaleReference || len(dispatcher.requests) != 0 {
				t.Fatal("cache bypassed current authority", err)
			}
		})
	}
}

func TestReadResponseMutationCannotChangeRequestedDescriptionOrInvoke(t *testing.T) {
	service, envelope, _, store, dispatcher := setup(t)
	envelope.Operation = fabric.OperationDescribe
	envelope.Payload, _ = json.Marshal(fabric.DescribeRequest{Selections: []fabric.DescribeSelection{{Ref: store.endpoint.Ref, ExpectedRevision: "r1"}}})
	installReadEngine(t, service, envelope.Operation, func(_ context.Context, r extension.InterceptRequest) (extension.Decision, error) {
		if r.Stage == "describe.response" && r.Phase == extension.PhaseRequest {
			patch, _ := json.Marshal([]map[string]any{{"op": "replace", "path": "/payload/descriptions/0/ref", "value": store.offer.Ref.String()}})
			return extension.Decision{Action: extension.Modify, Patch: patch}, nil
		}
		return extension.Decision{Action: extension.Continue}, nil
	})
	service.config.ValidateReadResult = func(context.Context, fabric.ExecutionContext, fabric.Envelope, Result) error { return nil }
	_, err := execute(t, service, envelope)
	var failure *fabric.Error
	if !errors.As(err, &failure) || failure.Code != fabric.CodeProtocolError || len(dispatcher.requests) != 0 {
		t.Fatal(err, dispatcher.requests)
	}
}

func TestReadInterceptionWithoutExplicitDisclosureValidatorFailsBeforeRead(t *testing.T) {
	service, envelope, search, _, dispatcher := setup(t)
	envelope.Operation = fabric.OperationDiscover
	envelope.Payload = json.RawMessage(`{"query":"invoice","scope":{},"limit":10}`)
	installReadEngine(t, service, envelope.Operation, func(context.Context, extension.InterceptRequest) (extension.Decision, error) {
		t.Fatal("unconfigured disclosure reached extension")
		return extension.Decision{}, nil
	})
	_, err := execute(t, service, envelope)
	if err == nil || search.calls != 0 || len(dispatcher.requests) != 0 {
		t.Fatal(err, search.calls)
	}
}
