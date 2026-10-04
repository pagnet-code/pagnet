package fabric

import (
	"strconv"
	"strings"
)

type ProtocolVersion string

const CurrentProtocolVersion ProtocolVersion = "1.0"

// Validate accepts future minor versions in the same semantic major. Required
// features are negotiated separately; optional unknown fields may be ignored.
func (v ProtocolVersion) Validate() error {
	parts := strings.Split(string(v), ".")
	if len(parts) != 2 {
		return NewError(CodeProtocolError, "Invalid protocol version")
	}
	for _, p := range parts {
		if p == "" || len(p) > 9 || (len(p) > 1 && p[0] == '0') {
			return NewError(CodeProtocolError, "Invalid protocol version")
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return NewError(CodeProtocolError, "Invalid protocol version")
			}
		}
	}
	major, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return NewError(CodeProtocolError, "Invalid protocol version")
	}
	if major != 1 {
		return NewError(CodeUnsupported, "Unsupported protocol major")
	}
	return nil
}

// Namespaced names are extensible identifiers, not closed implementation enums.
func ValidNamespacedName(s string) bool {
	if len(s) == 0 || len(s) > 256 || !strings.Contains(s, ".") {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if part == "" || part[0] < 'a' || part[0] > 'z' {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}
