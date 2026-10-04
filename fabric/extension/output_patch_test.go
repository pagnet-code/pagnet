package extension

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

func TestUnaryResponseModifyReverseOrderExactNumbersAndProtectedPointers(t *testing.T) {
	caller, raw, _ := engineEnvelope(t)
	var seen []string
	engine := makeEngine(t, manifestWith("a", "b"), handlerFunc(func(_ context.Context, r InterceptRequest) (Decision, error) {
		if r.Phase != PhaseResponse {
			return Decision{Action: Continue}, nil
		}
		seen = append(seen, r.InterceptorID)
		if r.InterceptorID == "acme.security.b" {
			return Decision{Action: Modify, Patch: json.RawMessage(`[{"op":"test","path":"/response/big","value":900719925474099312345.0},{"op":"copy","from":"/response/value","path":"/response/copied"},{"op":"replace","path":"/response/value","value":2}]`)}, nil
		}
		if !bytes.Contains(r.Response, []byte(`"value":2`)) {
			t.Error("outer response did not see prior projection")
		}
		return Decision{Action: Modify, Patch: json.RawMessage(`[{"op":"move","from":"/response/copied","path":"/response/final"},{"op":"add","path":"/response/items/-","value":3},{"op":"remove","path":"/response/items/0"}]`)}, nil
	}), nil, nil)
	original := json.RawMessage(`{"big":900719925474099312345,"value":1,"items":[1,2]}`)
	out, e := engine.ExecuteStage(t.Context(), caller, raw, "test.audience", "invoke.dispatch", PlacementSource, func(context.Context, fabric.ExecutionContext, fabric.Envelope) (Outcome, error) {
		return Outcome{Response: original}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	var result map[string]any
	if fabric.DecodeJSON(out.Response, &result) != nil || result["big"] != json.Number("900719925474099312345") || result["final"] != json.Number("1") || !reflect.DeepEqual(seen, []string{"acme.security.b", "acme.security.a"}) {
		t.Fatal("unary mutation order/precision failed", string(out.Response), seen)
	}
	if string(original) != `{"big":900719925474099312345,"value":1,"items":[1,2]}` {
		t.Fatal("original response mutated")
	}
	for _, patch := range []string{
		`[{"op":"copy","from":"/envelope/principal","path":"/response/stolen"}]`,
		`[{"op":"replace","path":"/response/value","value":2},{"op":"remove","path":"/response/missing"}]`,
		`[{"op":"replace","path":"/Response","value":null}]`,
		`[{"op":"move","from":"/response/items","path":"/response/items/0"}]`,
	} {
		got, e := applyOutputJSON(patchEnvelope(), "acme.security", "response", original, []byte(patch), MaxOutputResponseBytes)
		if e == nil || got != nil {
			t.Fatal("invalid output mutation accepted", patch)
		}
	}
}
func TestFrameOutputEncodingImmutableFieldsAndOriginalBytes(t *testing.T) {
	cases := []struct {
		name, mime            string
		data                  []byte
		patch, want, encoding string
	}{
		{"json", "application/problem+json", []byte(`{"n":900719925474099312345,"v":1}`), `[{"op":"test","path":"/content/n","value":900719925474099312345},{"op":"replace","path":"/content/v","value":2}]`, `{"n":900719925474099312345,"v":2}`, "json"},
		{"text", "text/plain; charset=utf-8", []byte("original"), `[{"op":"replace","path":"/content","value":"Olá 🌍"}]`, "Olá 🌍", "text"},
		{"binary", "application/octet-stream", []byte{0, 255, 1}, `[{"op":"replace","path":"/content","value":"AP4C"}]`, string([]byte{0, 254, 2}), "base64"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			original := fabric.InvocationFrame{InvocationID: "original", Sequence: 11, Kind: fabric.FrameChunk, ContentType: c.mime, Data: bytes.Clone(c.data)}
			content, encoding := frameContent(original)
			if len(content) == 0 || encoding != c.encoding {
				t.Fatal("encoding not explicit")
			}
			got, e := applyFrameOutput(patchEnvelope(), "acme.security", original, []byte(c.patch))
			if e != nil || string(got.Data) != c.want {
				t.Fatal(e, string(got.Data))
			}
			if !bytes.Equal(original.Data, c.data) {
				t.Fatal("source bytes mutated")
			}
			got.Data = original.Data
			if !reflect.DeepEqual(got, original) {
				t.Fatal("immutable frame metadata changed")
			}
		})
	}
	for _, patch := range []string{
		`[{"op":"replace","path":"/frame/sequence","value":"99"}]`,
		`[{"op":"copy","from":"/frame/error","path":"/content"}]`,
		`[{"op":"replace","path":"/content","value":"AB=="}]`, // noncanonical padding bits
		`[{"op":"replace","path":"/content","value":"AP4C\n"}]`,
	} {
		f := fabric.InvocationFrame{InvocationID: "original", Kind: fabric.FrameChunk, ContentType: "application/octet-stream", Data: []byte{0, 1}}
		if _, e := applyFrameOutput(patchEnvelope(), "acme.security", f, []byte(patch)); e == nil {
			t.Fatal("invalid binary/metadata mutation accepted", patch)
		}
	}
	for _, kind := range []fabric.FrameKind{fabric.FrameStart, fabric.FrameComplete, fabric.FrameError} {
		f := fabric.InvocationFrame{InvocationID: "original", Kind: kind, Data: []byte("original")}
		if _, e := applyFrameOutput(patchEnvelope(), "acme.security", f, []byte(`[{"op":"replace","path":"/content","value":""}]`)); e == nil {
			t.Fatal("terminal receipt rewritten")
		}
	}
}
func TestModifiedStreamPreservesPullAndRejectsOversizeAfterPartialDelivery(t *testing.T) {
	caller, raw, _ := engineEnvelope(t)
	m := manifestWith("a", "b")
	for i := range m.Interceptors {
		m.Interceptors[i].Phases = append(m.Interceptors[i].Phases, PhaseChunk)
	}
	var seen []string
	engine := makeEngine(t, m, handlerFunc(func(_ context.Context, r InterceptRequest) (Decision, error) {
		if r.Phase != PhaseChunk {
			return Decision{Action: Continue}, nil
		}
		seen = append(seen, r.InterceptorID)
		if r.Frame.Sequence == 2 {
			return Decision{Action: Modify, Patch: json.RawMessage(`[{"op":"copy","from":"/content/data","path":"/content/duplicate"}]`)}, nil
		}
		if r.InterceptorID == "acme.security.b" {
			return Decision{Action: Modify, Patch: json.RawMessage(`[{"op":"replace","path":"/content/v","value":2}]`)}, nil
		}
		if !bytes.Contains(r.Content, []byte(`"v":2`)) {
			t.Error("outer chunk did not see prior projection")
		}
		return Decision{Action: Modify, Patch: json.RawMessage(`[{"op":"add","path":"/content/checked","value":true}]`)}, nil
	}), nil, nil)
	first := []byte(`{"v":1}`)
	large, _ := json.Marshal(map[string]string{"data": strings.Repeat("x", 40000)})
	upstream := &testFrames{frames: []fabric.InvocationFrame{{InvocationID: "original", Sequence: 0, Kind: fabric.FrameStart}, {InvocationID: "original", Sequence: 1, Kind: fabric.FrameChunk, ContentType: "application/json", Data: first}, {InvocationID: "original", Sequence: 2, Kind: fabric.FrameChunk, ContentType: "application/json", Data: large}, {InvocationID: "original", Sequence: 3, Kind: fabric.FrameComplete}}}
	out, e := engine.ExecuteStage(t.Context(), caller, raw, "test.audience", "invoke.dispatch", PlacementSource, func(context.Context, fabric.ExecutionContext, fabric.Envelope) (Outcome, error) {
		return Outcome{Stream: upstream}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if upstream.reads != 0 {
		t.Fatal("eager read")
	}
	if _, e = out.Stream.Next(t.Context()); e != nil {
		t.Fatal(e)
	}
	frame, e := out.Stream.Next(t.Context())
	if e != nil || string(frame.Data) != `{"checked":true,"v":2}` && string(frame.Data) != `{"v":2,"checked":true}` {
		t.Fatal(e, string(frame.Data))
	}
	if frame.InvocationID != "original" || frame.Sequence != 1 || frame.Kind != fabric.FrameChunk || frame.ContentType != "application/json" || upstream.reads != 2 || string(first) != `{"v":1}` {
		t.Fatal("pull or source identity changed")
	}
	frame, e = out.Stream.Next(t.Context())
	if e == nil || len(frame.Data) != 0 || upstream.reads != 3 || !upstream.closed {
		t.Fatal("oversize projection escaped or read ahead", e)
	}
	if _, e = out.Stream.Next(t.Context()); !errors.Is(e, io.EOF) {
		t.Fatal("rejected partial stream not terminal", e)
	}
}
func TestInvalidJSONFragmentObserveAllowedMutationDenied(t *testing.T) {
	frame := fabric.InvocationFrame{InvocationID: "original", Kind: fabric.FrameChunk, ContentType: "application/json", Data: []byte(`{"unfinished":`)}
	_, encoding := frameContent(frame)
	if encoding != "unavailable" {
		t.Fatal("partial JSON reclassified")
	}
	request := InterceptRequest{Operation: fabric.OperationInvoke, Phase: PhaseChunk, Frame: &frame, ContentEncoding: encoding}
	if e := ValidateDecision(request, Decision{Action: Continue}, true, time.Now()); e != nil {
		t.Fatal("observation rejected", e)
	}
	if e := ValidateDecision(request, Decision{Action: Modify, Patch: json.RawMessage(`[{"op":"replace","path":"/content","value":{}}]`)}, true, time.Now()); e == nil {
		t.Fatal("partial source disguised as complete JSON")
	}
}

func TestChunkMutationCancellationCannotPublishLateContentOrCompletion(t *testing.T) {
	caller, raw, _ := engineEnvelope(t)
	manifest := manifestWith("a")
	manifest.Interceptors[0].Phases = append(manifest.Interceptors[0].Phases, PhaseChunk)
	returned := make(chan struct{})
	engine := makeEngine(t, manifest, handlerFunc(func(ctx context.Context, r InterceptRequest) (Decision, error) {
		if r.Phase != PhaseChunk {
			return Decision{Action: Continue}, nil
		}
		<-ctx.Done()
		r.Frame.Sequence = 999 // callback only owns the executor's isolated request
		close(returned)
		return Decision{Action: Modify, Patch: json.RawMessage(`[{"op":"replace","path":"/content","value":"late"}]`)}, nil
	}), nil, nil)
	original := []byte("original")
	source := &testFrames{frames: []fabric.InvocationFrame{{InvocationID: "original", Sequence: 0, Kind: fabric.FrameStart}, {InvocationID: "original", Sequence: 1, Kind: fabric.FrameChunk, ContentType: "text/plain", Data: original}, {InvocationID: "original", Sequence: 2, Kind: fabric.FrameComplete}}}
	outcome, e := engine.ExecuteStage(t.Context(), caller, raw, "test.audience", "invoke.dispatch", PlacementSource, func(context.Context, fabric.ExecutionContext, fabric.Envelope) (Outcome, error) {
		return Outcome{Stream: source}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = outcome.Stream.Next(t.Context()); e != nil {
		t.Fatal(e)
	}
	bounded, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	frame, e := outcome.Stream.Next(bounded)
	if !errors.Is(e, context.DeadlineExceeded) || len(frame.Data) != 0 {
		t.Fatal("late projection escaped cancellation", e)
	}
	<-returned
	if source.reads != 2 || !source.closed || string(original) != "original" {
		t.Fatal("cancel mutated source or read future completion")
	}
	if _, e = outcome.Stream.Next(t.Context()); !errors.Is(e, io.EOF) {
		t.Fatal("canceled stream resurrected", e)
	}
}
func FuzzOutputPatchCannotAlterFrameMetadata(f *testing.F) {
	f.Add([]byte(`[{"op":"replace","path":"/content/value","value":2}]`))
	f.Add([]byte(`[{"op":"copy","from":"/frame/invocationId","path":"/content"}]`))
	f.Fuzz(func(t *testing.T, patch []byte) {
		original := fabric.InvocationFrame{InvocationID: "original", Sequence: 17, Kind: fabric.FrameChunk, ContentType: "application/json", Data: []byte(`{"value":1}`)}
		projected, e := applyFrameOutput(patchEnvelope(), "acme.security", original, patch)
		if e != nil {
			return
		}
		if len(projected.Data) > fabric.MaxFrameBytes || !bytes.Equal(original.Data, []byte(`{"value":1}`)) {
			t.Fatal("budget or source mutation")
		}
		projected.Data = original.Data
		if !reflect.DeepEqual(projected, original) {
			t.Fatal("immutable metadata mutated")
		}
	})
}

func TestEngineStartMutationRejectedBeforeOuterCheckedStreamDelivery(t *testing.T) {
	caller, raw, _ := engineEnvelope(t)
	engine := makeEngine(t, manifestWith("a"), handlerFunc(func(_ context.Context, r InterceptRequest) (Decision, error) {
		if r.Phase == PhaseResponse && r.Frame != nil {
			return Decision{Action: Modify, Patch: json.RawMessage(`[{"op":"replace","path":"/content","value":"aW5qZWN0ZWQ="}]`)}, nil
		}
		return Decision{Action: Continue}, nil
	}), nil, nil)
	source := &testFrames{frames: []fabric.InvocationFrame{{InvocationID: "original", Sequence: 0, Kind: fabric.FrameStart}, {InvocationID: "original", Sequence: 1, Kind: fabric.FrameComplete}}}
	outcome, e := engine.ExecuteStage(t.Context(), caller, raw, "test.audience", "invoke.dispatch", PlacementSource, func(context.Context, fabric.ExecutionContext, fabric.Envelope) (Outcome, error) {
		return Outcome{Stream: source}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	checked, e := fabric.NewCheckedStream(t.Context(), "original", outcome.Stream)
	if e != nil {
		t.Fatal(e)
	}
	defer checked.Close()
	frame, e := checked.Next(t.Context())
	if e == nil || len(frame.Data) != 0 || frame.Kind != "" || source.reads != 1 || !source.closed {
		t.Fatal("injected start content escaped engine before checked consumer", frame, e)
	}
	if _, e = checked.Next(t.Context()); !errors.Is(e, io.EOF) {
		t.Fatal("rejected start resurrected", e)
	}
}
