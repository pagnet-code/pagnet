package fabric

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

// WireLimits bounds an entire JSON document, not each individual collection.
// Depth counts nested objects/arrays; Members counts object members and array
// elements together. Positive explicit limits are required; zero is not unlimited.
type WireLimits struct {
	MaxBytes   int
	MaxDepth   int
	MaxMembers int
}

// DefaultWireLimits is the bounded default for protocol documents. Adapters
// accepting larger schemas must select their own explicit, bounded limits.
var DefaultWireLimits = WireLimits{MaxBytes: 1 << 20, MaxDepth: 64, MaxMembers: 4096}

// DecodeJSON validates one complete bounded document before decoding into out.
// Known typed struct fields require their exact JSON spelling; application
// objects retain case-sensitive keys. Unknown optional fields are accepted.
// Interface-valued application numbers become json.Number; json.RawMessage retains original JSON bytes. Typed numeric
// fields follow the caller's requested type. No signed input is normalized or
// rewritten; signature verification must authenticate the original bytes.
func DecodeJSON(data []byte, out any) error {
	return DecodeJSONWithLimits(data, out, DefaultWireLimits)
}

func DecodeJSONWithLimits(data []byte, out any, limits WireLimits) error {
	if limits.MaxBytes <= 0 || limits.MaxDepth <= 0 || limits.MaxMembers <= 0 {
		return NewError(CodeInvalidInput, "JSON limits must be positive.")
	}
	// Reject oversized bodies before decoder/token/key allocations.
	if len(data) > limits.MaxBytes {
		return NewError(CodeProtocolError, "JSON document exceeds its byte limit.")
	}
	if !utf8.Valid(data) {
		return NewError(CodeProtocolError, "JSON document contains invalid UTF-8.")
	}
	validate := json.NewDecoder(bytes.NewReader(data))
	validate.UseNumber()
	members := 0
	if err := validateJSONValue(validate, 0, &members, limits, reflect.TypeOf(out), make(map[reflect.Type]map[string]reflect.Type)); err != nil {
		return err
	}
	if _, err := validate.Token(); !errors.Is(err, io.EOF) {
		return NewError(CodeProtocolError, "JSON document has trailing input.")
	}
	decode := json.NewDecoder(bytes.NewReader(data))
	decode.UseNumber()
	if err := decode.Decode(out); err != nil {
		var invalidTarget *json.InvalidUnmarshalError
		if errors.As(err, &invalidTarget) {
			return NewError(CodeInvalidInput, "JSON output target must be a non-nil pointer.")
		}
		return NewError(CodeProtocolError, "JSON document does not match the requested shape.")
	}
	return nil
}

func validateJSONValue(decoder *json.Decoder, depth int, members *int, limits WireLimits, expected reflect.Type, cache map[reflect.Type]map[string]reflect.Type) error {
	expected = wireShapeType(expected)
	token, err := decoder.Token()
	if err != nil {
		return NewError(CodeProtocolError, "Invalid JSON document.")
	}
	delimiter, collection := token.(json.Delim)
	if !collection {
		return nil
	}
	if depth >= limits.MaxDepth {
		return NewError(CodeProtocolError, "JSON document exceeds its nesting limit.")
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		fields := wireStructFields(expected, cache)
		for decoder.More() {
			if *members >= limits.MaxMembers {
				return NewError(CodeProtocolError, "JSON document exceeds its member limit.")
			}
			*members += 1
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return NewError(CodeProtocolError, "Invalid JSON object.")
			}
			// Token decodes escapes first: "id" and "\u0069d" are the same key.
			if _, duplicate := seen[key]; duplicate {
				return NewError(CodeProtocolError, "Duplicate JSON object member.")
			}
			seen[key] = struct{}{}
			fieldType := fields[key]
			if fieldType == nil {
				for name := range fields {
					if strings.EqualFold(name, key) {
						return NewError(CodeProtocolError, "JSON member spelling does not match the requested shape.")
					}
				}
			}
			if err = validateJSONValue(decoder, depth+1, members, limits, fieldType, cache); err != nil {
				return err
			}
		}
	case '[':
		var elementType reflect.Type
		if expected != nil && (expected.Kind() == reflect.Slice || expected.Kind() == reflect.Array) {
			elementType = expected.Elem()
		}
		for decoder.More() {
			if *members >= limits.MaxMembers {
				return NewError(CodeProtocolError, "JSON document exceeds its member limit.")
			}
			*members += 1
			if err = validateJSONValue(decoder, depth+1, members, limits, elementType, cache); err != nil {
				return err
			}
		}
	default:
		return NewError(CodeProtocolError, "Invalid JSON document.")
	}
	closing, err := decoder.Token()
	if err != nil || delimiter == '{' && closing != json.Delim('}') || delimiter == '[' && closing != json.Delim(']') {
		return NewError(CodeProtocolError, "Invalid JSON document.")
	}
	return nil
}

// Application maps, interfaces and custom JSON representations have their own
// key namespace. Only ordinary typed struct fields participate in spelling checks.
func wireShapeType(t reflect.Type) reflect.Type {
	unmarshaler := reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	for t != nil {
		if t.Implements(unmarshaler) || t.Kind() != reflect.Pointer && reflect.PointerTo(t).Implements(unmarshaler) {
			return nil
		}
		if t.Kind() != reflect.Pointer {
			return t
		}
		t = t.Elem()
	}
	return nil
}

// Match encoding/json's promoted-field dominance: the shallowest field wins;
// at equal depth a sole explicitly tagged field wins, otherwise ambiguity hides
// the field. Recursive anonymous pointers cannot create an unbounded type walk.
func wireStructFields(t reflect.Type, cache map[reflect.Type]map[string]reflect.Type) map[string]reflect.Type {
	if t == nil || t.Kind() != reflect.Struct {
		return nil
	}
	if fields, ok := cache[t]; ok {
		return fields
	}
	type candidate struct {
		typ    reflect.Type
		depth  int
		tagged bool
	}
	candidates := make(map[string][]candidate)
	var visit func(reflect.Type, int, map[reflect.Type]bool)
	visit = func(current reflect.Type, depth int, path map[reflect.Type]bool) {
		if path[current] {
			return
		}
		path[current] = true
		defer delete(path, current)
		for i := 0; i < current.NumField(); i++ {
			f := current.Field(i)
			embedded := f.Type
			if embedded.Kind() == reflect.Pointer {
				embedded = embedded.Elem()
			}
			if f.PkgPath != "" && (!f.Anonymous || embedded.Kind() != reflect.Struct) {
				continue
			}
			tag := strings.Split(f.Tag.Get("json"), ",")[0]
			if tag == "-" {
				continue
			}
			if tag == "" && f.Anonymous && embedded.Kind() == reflect.Struct {
				visit(embedded, depth+1, path)
				continue
			}
			name := tag
			if name == "" {
				name = f.Name
			}
			candidates[name] = append(candidates[name], candidate{f.Type, depth, tag != ""})
		}
	}
	visit(t, 0, make(map[reflect.Type]bool))
	fields := make(map[string]reflect.Type)
	for name, list := range candidates {
		minimum := list[0].depth
		for _, c := range list {
			if c.depth < minimum {
				minimum = c.depth
			}
		}
		var winner candidate
		count, tagged := 0, 0
		for _, c := range list {
			if c.depth != minimum {
				continue
			}
			count++
			if c.tagged {
				tagged++
				winner = c
			} else if tagged == 0 {
				winner = c
			}
		}
		if tagged == 1 || tagged == 0 && count == 1 {
			fields[name] = winner.typ
		}
	}
	cache[t] = fields
	return fields
}
