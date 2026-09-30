package sdk

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pagnet-code/pagnet/internal/jev"
)

type jevTransport func(*http.Request) (*http.Response, error)

func (f jevTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestJevEncryptedNetworkInvocation(t *testing.T) {
	fs := newFakeServer(t)
	network := fs.createNetwork("jev-network", true)
	callerID, callerCredential := fs.createPrincipal("agent", "triage", network)
	serviceID, serviceCredential := fs.createPrincipal("service", "Jev", network)
	var providerCalls atomic.Int32
	provider, err := jev.NewWithTransport("host-only-provider-key", "jev-latest", jevTransport(func(r *http.Request) (*http.Response, error) {
		providerCalls.Add(1)
		if r.URL.String() != jev.Endpoint || r.Header.Get("Authorization") != "Bearer host-only-provider-key" {
			t.Error("provider route/auth contract violated")
		}
		raw, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(raw), "Route this support ticket") || strings.Contains(string(raw), "host-only-provider-key") {
			t.Error("invalid provider input or leaked key")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"model":"jev-1.13.0","answers":{"route":{"type":"choice","choice":"billing","probabilities":{"billing":0.9,"other":0.1},"confidence":0.7}},"usage":{"input_tokens":120,"output_tokens":10}}`))}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	target := mustConnect(t, fs, serviceCredential, t.TempDir())
	waitForCryptoReady(t, fs, serviceID)
	svc := target.Service("Jev")
	if err := svc.Handle(jev.CapabilityID, func(ctx context.Context, inv *Invocation) (any, error) { return provider.EvaluateValue(ctx, inv.Input) }); err != nil {
		t.Fatal(err)
	}
	if err := svc.Capability(jev.Capability()); err != nil {
		t.Fatal(err)
	}
	caller := mustConnect(t, fs, callerCredential, t.TempDir())
	waitForCryptoReady(t, fs, callerID)
	input := map[string]any{"state": map[string]any{"ticket": "Duplicate charge"}, "questions": map[string]any{"route": map[string]any{"type": "choice", "instructions": "Route this support ticket", "criteria": map[string]any{"billing": "Payments", "other": nil}}}}
	result, err := caller.Invoke(testCtx(t), Invocation{NetworkID: network, TargetPrincipalID: serviceID, CapabilityID: jev.CapabilityID, Input: input})
	if err != nil {
		fs.mu.Lock()
		states := map[string]string{}
		for id, inv := range fs.invocations {
			states[id] = inv.state
		}
		fs.mu.Unlock()
		t.Fatalf("invoke %v; providerCalls%d states%v", err, providerCalls.Load(), states)
	}
	raw, _ := json.Marshal(result.Output)
	var typed jev.Result
	if json.Unmarshal(raw, &typed) != nil || typed.Answers["route"].Choice != "billing" || typed.Usage.InputTokens != 120 || providerCalls.Load() != 1 {
		t.Fatalf("typed network result %s calls%d", raw, providerCalls.Load())
	}
	// Only the fake crypto authority decodes input/output; no local provider key
	// belongs in the control-plane encrypted invocation record or result.
	if strings.Contains(fs.invocationOutputPlain(result.ID), "host-only-provider-key") {
		t.Fatal("provider key leaked into durable result")
	}
	other := fs.createNetwork("outside", true)
	if _, err := caller.Invoke(testCtx(t), Invocation{NetworkID: other, TargetPrincipalID: serviceID, CapabilityID: jev.CapabilityID, Input: input}); err == nil {
		t.Fatal("foreign network invocation succeeded")
	}
	if providerCalls.Load() != 1 {
		t.Fatal("foreign network reached paid provider")
	}
}
