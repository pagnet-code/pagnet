package transport

// NativeTurnSourcePayload preserves the original accepted operation identity.
// The server derives its runtime turn ID and task/channel from that original
// command. It never accepts caller-selected task IDs, output or failure bodies.
type NativeTurnSourcePayload struct {
	InstanceID         string `json:"instanceId"`
	Runtime            string `json:"runtime"`
	NativeGeneration   string `json:"nativeGeneration"`
	SessionID          string `json:"sessionId"`
	SourceSequence     int64  `json:"sourceSequence"`
	LogicalTurnID      string `json:"logicalTurnId"`
	NativeTurnSequence int64  `json:"nativeTurnSequence"`
	SourceCommandID    string `json:"sourceCommandId"`
	SourceAdmissionID  string `json:"sourceAdmissionId"`
	InputKind          string `json:"inputKind"`
	Kind               string `json:"kind,omitempty"`
	RetryAt            string `json:"retryAt,omitempty"`
	Model              string `json:"model,omitempty"`
	InputTokens        *int   `json:"inputTokens,omitempty"`
	OutputTokens       *int   `json:"outputTokens,omitempty"`
	CachedTokens       *int   `json:"cachedTokens,omitempty"`
}
