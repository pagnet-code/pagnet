package fabricagent

import "encoding/json"

// NativePromptMetadata describes the ordinary endpoint's existing input binder.
// It is progressive-disclosure metadata, not an offer, authority or executable
// configuration. Schema maxLength counts characters; the byte limit is separate
// because the binder validates UTF-8 bytes, not Unicode code points.
func NativePromptMetadata() map[string]json.RawMessage {
	return map[string]json.RawMessage{
		"extensions.pagnet.agent.input_schema": json.RawMessage(`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"input":{"type":"string","minLength":1,"maxLength":131072}},"required":["input"],"additionalProperties":false}`),
		"extensions.pagnet.agent.input_limits": json.RawMessage(`{"inputUtf8Bytes":131072,"format":"pagnet.native.input.prompt.v1"}`),
	}
}
