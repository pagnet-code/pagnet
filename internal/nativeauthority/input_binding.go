package nativeauthority

import (
	"encoding/json"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/fabric"
)

const (
	InputBindingPromptV1 = "pagnet.native.input.prompt.v1"
	InputBindingJSONV1   = "pagnet.native.input.json.v1"
)

func EffectiveInputBindingProfile(profile string) string {
	if profile == "" {
		return InputBindingPromptV1
	}
	return profile
}

// NewInputBinder selects only operator-declared native input formats. It never
// interprets offer descriptions, caller fields or schemas as runtime authority.
func NewInputBinder(profile string, profileDigest [32]byte) (OperationBinder, error) {
	switch EffectiveInputBindingProfile(profile) {
	case InputBindingPromptV1:
		return JSONPromptBinder{ProfileDigest: profileDigest}, nil
	case InputBindingJSONV1:
		return structuredInputBinder{ProfileDigest: profileDigest}, nil
	default:
		return nil, fabric.NewError(fabric.CodeUnsupported, "Native input binding profile is unsupported")
	}
}

type structuredInputBinder struct{ ProfileDigest [32]byte }

func (b structuredInputBinder) Bind(final fabric.Envelope) (PreparedOperation, error) {
	// Standard agent prompts keep their explicit grammar, even for a worker with
	// an operator-selected structured offer format.
	if final.Target == nil || !final.Target.IsOffer() {
		return (JSONPromptBinder{ProfileDigest: b.ProfileDigest}).Bind(final)
	}
	var value any
	if final.Operation != fabric.OperationInvoke || !utf8.Valid(final.Payload) || len(final.Payload) > 128<<10 || fabric.DecodeJSONWithLimits(final.Payload, &value, fabric.WireLimits{MaxBytes: 128 << 10, MaxDepth: 64, MaxMembers: 4096}) != nil {
		return PreparedOperation{}, fabric.NewError(fabric.CodeInvalidInput, "Structured native input exceeds bounded JSON grammar")
	}
	// Exact JSON bytes are prompt data. No values become executable selectors,
	// environment, roles, tools, source identity or admission assertions.
	payload, err := json.Marshal(struct {
		Input     string `json:"input"`
		InputKind string `json:"inputKind"`
	}{string(final.Payload), "local-native"})
	if err != nil || len(payload) > MaxNativeOperationBytes {
		return PreparedOperation{}, fabric.NewError(fabric.CodeInvalidInput, "Structured native prompt exceeds operation bound")
	}
	return PreparedOperation{Kind: "prompt", Payload: payload, SpecDigest: b.ProfileDigest}, nil
}
