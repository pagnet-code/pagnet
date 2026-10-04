package extension

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

func TestConfiguredPlanBindsActualInstallationWithoutChangingManifestRevision(t *testing.T) {
	manifests := []ExtensionManifest{manifestWith("a")}
	normal, err := Compile(manifests, 100)
	if err != nil {
		t.Fatal(err)
	}
	first, err := CompileConfigured(manifests, 100, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	retry, err := CompileConfigured(manifests, 100, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	changed, err := CompileConfigured(manifests, 100, strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision() != retry.Revision() || first.Revision() == changed.Revision() || first.Revision() == normal.Revision() {
		t.Fatal("configuration identity not independently committed")
	}
	unchanged, _ := Compile(manifests, 100)
	if unchanged.Revision() != normal.Revision() {
		t.Fatal("ordinary manifest compilation changed")
	}
	for _, invalid := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("g", 64)} {
		if _, err = CompileConfigured(manifests, 100, invalid); err == nil {
			t.Fatal("invalid configuration digest accepted")
		}
	}
}

func TestConfiguredBindingChangeRejectsGenuineSavedContinuationBeforeTarget(t *testing.T) {
	caller, raw, _ := engineEnvelope(t)
	manifest := manifestWith("a")
	var saved PipelineState
	engine := makeEngine(t, manifest, handlerFunc(func(context.Context, InterceptRequest) (Decision, error) {
		return Decision{Action: Defer, Deferral: &Deferral{ExpiresAt: time.Now().Add(time.Hour), ResumePrincipals: []string{"human"}, Durable: true}}, nil
	}), nil, recorderFunc(func(_ context.Context, _ fabric.ExecutionContext, _ []byte, s PipelineState, _ Deferral, _ CompiledRegistration) (string, error) {
		saved = s
		return "retained-continuation", nil
	}))
	var err error
	engine.plan, err = CompileConfigured([]ExtensionManifest{manifest}, 100, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	downstream := func(context.Context, fabric.ExecutionContext, fabric.Envelope) (Outcome, error) {
		calls++
		return Outcome{}, nil
	}
	out, err := engine.ExecuteStage(t.Context(), caller, raw, "test.audience", "invoke.dispatch", PlacementSource, downstream)
	if err != nil || out.DeferredID != "retained-continuation" || calls != 0 {
		t.Fatal(out, err, calls)
	}
	permit, err := NewVerifiedResumePermit(caller, raw, saved)
	if err != nil {
		t.Fatal(err)
	}
	engine.plan, err = CompileConfigured([]ExtensionManifest{manifest}, 100, strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.ResumeStage(t.Context(), permit, caller, raw, saved, downstream)
	var failure *fabric.Error
	if !errors.As(err, &failure) || failure.Code != fabric.CodeStaleContinuation || calls != 0 {
		t.Fatal("changed provider resumed old continuation", err, calls)
	}
}
