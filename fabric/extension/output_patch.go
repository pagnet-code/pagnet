package extension

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"mime"
	"strings"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/fabric"
)

const MaxOutputResponseBytes = 1 << 20

// applyOutputJSON reuses the strict atomic RFC6902 implementation while exposing
// exactly one application projection root. Identity/transport/source evidence is
// never part of the patch document; both move/copy pointers stay inside that root.
func applyOutputJSON(envelope fabric.Envelope, id, root string, content, raw []byte, max int) (json.RawMessage, error) {
	fail := func() (json.RawMessage, error) {
		return nil, fabric.NewError(fabric.CodeInvalidMutation, "Invalid output projection mutation")
	}
	if len(content) == 0 || len(content) > max || len(raw) > MaxPatchBytes {
		return fail()
	}
	var ops []map[string]json.RawMessage
	if fabric.DecodeJSON(raw, &ops) != nil || len(ops) < 1 || len(ops) > MaxPatchOperations {
		return fail()
	}
	convert := func(value json.RawMessage) (json.RawMessage, bool) {
		var path string
		if json.Unmarshal(value, &path) != nil || !(path == "/"+root || strings.HasPrefix(path, "/"+root+"/")) {
			return nil, false
		}
		rewritten := "/payload" + strings.TrimPrefix(path, "/"+root)
		if _, ok := allowedPointer(rewritten, id); !ok {
			return nil, false
		}
		b, e := json.Marshal(rewritten)
		return b, e == nil
	}
	for _, op := range ops {
		path, ok := convert(op["path"])
		if !ok {
			return fail()
		}
		op["path"] = path
		var kind string
		if json.Unmarshal(op["op"], &kind) != nil {
			return fail()
		}
		if kind == "move" || kind == "copy" {
			from, ok := convert(op["from"])
			if !ok {
				return fail()
			}
			op["from"] = from
		}
	}
	patch, e := json.Marshal(ops)
	if e != nil {
		return fail()
	}
	envelope.Payload = bytes.Clone(content)
	result, e := ApplyPatch(envelope, id, patch)
	if e != nil || len(result.Payload) > max {
		return fail()
	}
	return bytes.Clone(result.Payload), nil
}

// frameContent is an explicit representation of one original frame's content.
// Partial/invalid declared JSON or text remains observable via Frame, but cannot
// be silently reclassified or patched as a complete valid application document.
func frameContent(frame fabric.InvocationFrame) (json.RawMessage, string) {
	media, _, err := mime.ParseMediaType(frame.ContentType)
	if err == nil && (media == "application/json" || strings.HasSuffix(media, "+json")) {
		var value any
		if fabric.DecodeJSONWithLimits(frame.Data, &value, fabric.WireLimits{MaxBytes: fabric.MaxFrameBytes, MaxDepth: 64, MaxMembers: 4096}) != nil {
			return nil, "unavailable"
		}
		return bytes.Clone(frame.Data), "json"
	}
	if err == nil && strings.HasPrefix(media, "text/") {
		if !utf8.Valid(frame.Data) {
			return nil, "unavailable"
		}
		raw, _ := json.Marshal(string(frame.Data))
		return raw, "text"
	}
	raw, _ := json.Marshal(base64.StdEncoding.EncodeToString(frame.Data))
	return raw, "base64"
}
func applyFrameOutput(envelope fabric.Envelope, id string, frame fabric.InvocationFrame, patch []byte) (fabric.InvocationFrame, error) {
	if (frame.Kind != fabric.FrameChunk && frame.Kind != fabric.FrameProgress) || len(frame.Data) > fabric.MaxFrameBytes {
		return fabric.InvocationFrame{}, fabric.NewError(fabric.CodeInvalidMutation, "Immutable terminal frame or invalid original content")
	}
	content, encoding := frameContent(frame)
	if encoding == "unavailable" {
		return fabric.InvocationFrame{}, fabric.NewError(fabric.CodeInvalidMutation, "Frame is not a complete mutable content projection")
	}
	// Base64/text JSON representations have finite escaping expansion. Final bytes
	// are still separately limited to the unchanged native frame budget.
	projected, e := applyOutputJSON(envelope, id, "content", content, patch, 6*fabric.MaxFrameBytes+2)
	if e != nil {
		return fabric.InvocationFrame{}, e
	}
	var data []byte
	switch encoding {
	case "json":
		data = bytes.Clone(projected)
	case "text":
		var value string
		if fabric.DecodeJSON(projected, &value) != nil || !utf8.ValidString(value) {
			return fabric.InvocationFrame{}, fabric.NewError(fabric.CodeInvalidMutation, "Invalid text projection")
		}
		data = []byte(value)
	case "base64":
		var value string
		if fabric.DecodeJSON(projected, &value) != nil {
			return fabric.InvocationFrame{}, fabric.NewError(fabric.CodeInvalidMutation, "Invalid binary projection")
		}
		data, e = base64.StdEncoding.Strict().DecodeString(value)
		if e != nil || base64.StdEncoding.EncodeToString(data) != value {
			return fabric.InvocationFrame{}, fabric.NewError(fabric.CodeInvalidMutation, "Invalid binary projection")
		}
	}
	if len(data) > fabric.MaxFrameBytes {
		return fabric.InvocationFrame{}, fabric.NewError(fabric.CodeInvalidMutation, "Output frame exceeds size limit")
	}
	frame.Data = data
	return frame, nil
}
