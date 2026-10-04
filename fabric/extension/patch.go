// Package extension implements the trusted node's extension boundary. Remote
// extension responses are untrusted input; they do not confer identity or routing
// authority. Events and triggers have separate contracts from inline middleware.
package extension

import (
	"encoding/json"
	"math/big"
	"reflect"
	"strconv"
	"strings"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/pagnet-code/pagnet/fabric"
)

const MaxPatchOperations = 64
const MaxPatchBytes = 64 << 10
const MaxPatchedEnvelopeBytes = 1 << 20

// ApplyPatch is atomic: a failure returns no replacement envelope. Both sides of
// move/copy are constrained. Target changes require the separate REDIRECT action;
// neither identity, provenance nor another extension's metadata can be patched.
func ApplyPatch(original fabric.Envelope, extensionID string, raw []byte) (fabric.Envelope, error) {
	fail := func() (fabric.Envelope, error) {
		return fabric.Envelope{}, fabric.NewError(fabric.CodeInvalidMutation, "Invalid extension mutation")
	}
	if !fabric.ValidNamespacedName(extensionID) || extensionID == "pagnet" || strings.HasPrefix(extensionID, "pagnet.") || len(raw) > MaxPatchBytes {
		return fail()
	}
	var operations []map[string]json.RawMessage
	if err := fabric.DecodeJSON(raw, &operations); err != nil || len(operations) == 0 || len(operations) > MaxPatchOperations {
		return fail()
	}
	document, err := json.Marshal(original)
	if err != nil || len(document) > MaxPatchedEnvelopeBytes {
		return fail()
	}
	for _, operation := range operations {
		var kind, path string
		if json.Unmarshal(operation["op"], &kind) != nil || json.Unmarshal(operation["path"], &path) != nil {
			return fail()
		}
		tokens, ok := allowedPointer(path, extensionID)
		if !ok {
			return fail()
		}
		switch kind {
		case "add", "remove", "replace", "move", "copy", "test":
		default:
			return fail()
		}
		var current any
		if fabric.DecodeJSON(document, &current) != nil || !validArrayIndices(current, tokens, kind == "add" || kind == "move" || kind == "copy") {
			return fail()
		}
		if kind == "move" || kind == "copy" {
			var from string
			if json.Unmarshal(operation["from"], &from) != nil {
				return fail()
			}
			source, allowed := allowedPointer(from, extensionID)
			if !allowed || !validArrayIndices(current, source, false) {
				return fail()
			}
			if kind == "move" && len(tokens) > len(source) && reflect.DeepEqual(tokens[:len(source)], source) {
				return fail()
			}
		}
		if kind == "test" {
			value, exists := operation["value"]
			var expected any
			if !exists || fabric.DecodeJSON(value, &expected) != nil {
				return fail()
			}
			actual, exists := pointerValue(current, tokens)
			// RFC 6902 numeric equality is exact mathematical equality. The library
			// compares number spellings, so handle test without converting to float64.
			if !exists || !equalJSON(actual, expected) {
				return fail()
			}
			continue
		}
		if kind == "add" || kind == "replace" {
			if _, exists := operation["value"]; !exists {
				return fail()
			}
		}
		single, err := json.Marshal([]map[string]json.RawMessage{operation})
		if err != nil {
			return fail()
		}
		patch, err := jsonpatch.DecodePatch(single)
		if err != nil {
			return fail()
		}
		options := jsonpatch.NewApplyOptions()
		options.SupportNegativeIndices = false
		options.AccumulatedCopySizeLimit = MaxPatchedEnvelopeBytes
		options.AllowMissingPathOnRemove = false
		options.EnsurePathExistsOnAdd = false
		document, err = patch.ApplyWithOptions(document, options)
		if err != nil || len(document) > MaxPatchedEnvelopeBytes {
			return fail()
		}
	}
	var result fabric.Envelope
	if fabric.DecodeJSON(document, &result) != nil || result.Validate() != nil {
		return fail()
	}
	return result, nil
}

func allowedPointer(path, id string) ([]string, bool) {
	if !strings.HasPrefix(path, "/") || len(path) > 4096 {
		return nil, false
	}
	parts := strings.Split(path[1:], "/")
	for i, part := range parts {
		var decoded strings.Builder
		for j := 0; j < len(part); j++ {
			if part[j] != '~' {
				decoded.WriteByte(part[j])
				continue
			}
			j++
			if j >= len(part) {
				return nil, false
			}
			switch part[j] {
			case '0':
				decoded.WriteByte('~')
			case '1':
				decoded.WriteByte('/')
			default:
				return nil, false
			}
		}
		parts[i] = decoded.String()
	}
	if parts[0] == "payload" {
		return parts, true
	}
	if len(parts) >= 2 && parts[0] == "metadata" && strings.HasPrefix(parts[1], "extensions."+id+".") && fabric.ValidNamespacedName(parts[1]) {
		return parts, true
	}
	return nil, false
}

func validArrayIndices(root any, tokens []string, insertion bool) bool {
	current := root
	for i, token := range tokens {
		switch node := current.(type) {
		case map[string]any:
			var exists bool
			current, exists = node[token]
			if !exists {
				return i == len(tokens)-1
			}
		case []any:
			if insertion && i == len(tokens)-1 && token == "-" {
				return true
			}
			if token == "" || (len(token) > 1 && token[0] == '0') {
				return false
			}
			for _, c := range token {
				if c < '0' || c > '9' {
					return false
				}
			}
			n, err := strconv.ParseUint(token, 10, 64)
			if err != nil {
				return false
			}
			if insertion && i == len(tokens)-1 && n == uint64(len(node)) {
				return true
			}
			if n >= uint64(len(node)) {
				return false
			}
			current = node[int(n)]
		default:
			return false
		}
	}
	return true
}

func pointerValue(root any, tokens []string) (any, bool) {
	current := root
	for _, token := range tokens {
		switch node := current.(type) {
		case map[string]any:
			var found bool
			current, found = node[token]
			if !found {
				return nil, false
			}
		case []any:
			n, err := strconv.ParseUint(token, 10, 64)
			if err != nil || n >= uint64(len(node)) {
				return nil, false
			}
			current = node[int(n)]
		default:
			return nil, false
		}
	}
	return current, true
}

func equalJSON(a, b any) bool {
	if number, ok := a.(json.Number); ok {
		other, ok := b.(json.Number)
		if !ok {
			return false
		}
		ac, ae := normalizeNumber(string(number))
		bc, be := normalizeNumber(string(other))
		return ac == bc && ae.Cmp(be) == 0
	}
	switch left := a.(type) {
	case map[string]any:
		right, ok := b.(map[string]any)
		if !ok || len(left) != len(right) {
			return false
		}
		for key, value := range left {
			other, exists := right[key]
			if !exists || !equalJSON(value, other) {
				return false
			}
		}
		return true
	case []any:
		right, ok := b.([]any)
		if !ok || len(left) != len(right) {
			return false
		}
		for i := range left {
			if !equalJSON(left[i], right[i]) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(a, b)
	}
}

// Normalize decimal coefficient/exponent without allocating 10^exponent. All
// inputs have already passed bounded JSON validation, including exponent text.
func normalizeNumber(number string) (string, *big.Int) {
	exponent := new(big.Int)
	if split := strings.IndexAny(number, "eE"); split >= 0 {
		exponent.SetString(strings.TrimPrefix(number[split+1:], "+"), 10)
		number = number[:split]
	}
	negative := strings.HasPrefix(number, "-")
	number = strings.TrimPrefix(number, "-")
	if dot := strings.IndexByte(number, '.'); dot >= 0 {
		exponent.Sub(exponent, big.NewInt(int64(len(number)-dot-1)))
		number = number[:dot] + number[dot+1:]
	}
	number = strings.TrimLeft(number, "0")
	if number == "" {
		return "0", new(big.Int)
	}
	trimmed := strings.TrimRight(number, "0")
	exponent.Add(exponent, big.NewInt(int64(len(number)-len(trimmed))))
	if negative {
		trimmed = "-" + trimmed
	}
	return trimmed, exponent
}
