package transport

const NativeAgentSourceProtocol = "native-agent-source-v1"
const NativeEndpointAgentSourceProtocol = "native-endpoint-agent-source-v1"

// NativeEndpointAgentSource proves the original live endpoint without claiming
// an accepted managed turn. It authorizes only that instance's fixed network.
type NativeEndpointAgentSource struct {
	OriginID         string `json:"originId"`
	NativeGeneration string `json:"nativeGeneration"`
	SessionID        string `json:"sessionId"`
}

// NativeAgentSource is the actual turn capability derived by the independent
// worker bridge. Source command/admission and private operation ordinal remain
// original across replacement transports. It contains no body or task key/AAD.
type NativeAgentSource struct {
	OriginID           string `json:"originId"`
	NativeGeneration   string `json:"nativeGeneration"`
	SessionID          string `json:"sessionId"`
	LogicalTurnID      string `json:"logicalTurnId"`
	NativeTurnSequence int64  `json:"nativeTurnSequence"`
	InputKind          string `json:"inputKind"`
	SourceCommandID    string `json:"sourceCommandId"`
	SourceAdmissionID  string `json:"sourceAdmissionId"`
}
