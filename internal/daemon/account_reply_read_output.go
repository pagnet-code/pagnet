package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

var errAccountReplyOutput = errors.New("invalid account reply output")

// decodeAccountReplyOutput accepts only the native final-output v1 document.
// Validate Unicode before encoding/json can replace malformed input, preserving
// the original answer's exact ordered text and block boundaries.
func decodeAccountReplyOutput(raw []byte) (session.FinalOutput, error) {
	var output session.FinalOutput
	if len(raw) == 0 || len(raw) > transport.NativeContentMaxPlaintextBytes || !accountReplyJSONUnicode(raw) {
		return output, errAccountReplyOutput
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return output, errAccountReplyOutput
	}
	seen := make(map[string]bool, 2)
	for d.More() {
		token, err = d.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return session.FinalOutput{}, errAccountReplyOutput
		}
		seen[name] = true
		switch name {
		case "version":
			token, err = d.Token()
			if err != nil || token != json.Number("1") {
				return session.FinalOutput{}, errAccountReplyOutput
			}
			output.Version = 1
		case "textBlocks":
			token, err = d.Token()
			if err != nil || token != json.Delim('[') {
				return session.FinalOutput{}, errAccountReplyOutput
			}
			output.TextBlocks = []string{}
			for d.More() {
				token, err = d.Token()
				text, ok := token.(string)
				if err != nil || !ok {
					return session.FinalOutput{}, errAccountReplyOutput
				}
				output.TextBlocks = append(output.TextBlocks, text)
			}
			if token, err = d.Token(); err != nil || token != json.Delim(']') {
				return session.FinalOutput{}, errAccountReplyOutput
			}
		default:
			return session.FinalOutput{}, errAccountReplyOutput
		}
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') || !seen["version"] || !seen["textBlocks"] {
		return session.FinalOutput{}, errAccountReplyOutput
	}
	if _, err = d.Token(); err != io.EOF {
		return session.FinalOutput{}, errAccountReplyOutput
	}
	return output, nil
}

func accountReplyJSONUnicode(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		n, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
