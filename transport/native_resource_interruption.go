package transport

// ResourceInterruption is owner protection of an actually accepted source.
// It is carried only by a genuine supervised EOF; it is never a vendor terminal.
type NativeResourceInterruption struct {
	Cause  string            `json:"cause"`
	Source NativeAgentSource `json:"source"`
}

const NativeResourceInterruptionProtocol = "native-resource-interruption-v1"

const (
	NativeResourceOutputLimit  = "output_limit"
	NativeResourceCaptureLimit = "capture_limit"
	NativeResourceEventLimit   = "event_limit"
)
