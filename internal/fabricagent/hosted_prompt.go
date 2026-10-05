package fabricagent

import (
	"encoding/json"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
)

// BindHostedPrompt uses the same explicit prompt grammar as native agents,
// while keeping original CLOUD ownership/profile bytes unchanged. The binder
// performs no admission, instance adoption, wake or execution. Only the prompt
// text is delivered to the original runtime; local-native tags are never sent
// as cloud input, and opaque protocol IDs are never prompt decoration.
func BindHostedPrompt(finalized fabric.Envelope, original HostedProfile) (string, error) {
	if original.Validate() != nil {
		return "", hostedProfileError()
	}
	prepared, err := (nativeauthority.JSONPromptBinder{ProfileDigest: original.NativeProfile}).Bind(finalized)
	if err != nil {
		return "", fabric.NewError(fabric.CodeInvalidInput, "Native agent input must be an object with only a nonempty input string (up to 128 KiB)")
	}
	if prepared.Kind != "prompt" || prepared.SpecDigest != original.NativeProfile {
		return "", hostedProfileError()
	}
	var value struct {
		Input     string `json:"input"`
		InputKind string `json:"inputKind"`
	}
	if json.Unmarshal(prepared.Payload, &value) != nil || value.InputKind != "local-native" {
		return "", hostedProfileError()
	}
	return value.Input, nil
}
