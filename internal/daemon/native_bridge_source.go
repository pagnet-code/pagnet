package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

// A controller replacement changes the transport, never the context of the
// actual worker turn. Only the authenticated worker can supply this source.
func nativeBridgeSource(call *sessionworker.BridgeCall) (*transport.NativeAgentSource, error) {
	if call == nil || call.TurnSource == nil {
		return nil, nil
	}
	var origin transport.NativeObservationOrigin
	if err := json.Unmarshal(call.Origin, &origin); err != nil {
		return nil, errors.New("native bridge origin unavailable")
	}
	source := call.TurnSource
	if origin.ID == "" || origin.InstanceID != call.Scope.InstanceID || origin.TenantID != call.Scope.TenantID || origin.HostID != call.Scope.HostID || origin.NativeGeneration != call.NativeGeneration || source.NativeGeneration != call.NativeGeneration || source.Sequence <= 0 || source.LogicalTurnID == "" || source.NativeSessionID == "" || source.SourceCommandID == "" || source.SourceAdmissionID == "" {
		return nil, errors.New("native bridge source unavailable")
	}
	if origin.NativeSessionID != "" && origin.NativeSessionID != source.NativeSessionID {
		return nil, errors.New("native bridge session mismatch")
	}
	return &transport.NativeAgentSource{OriginID: origin.ID, NativeGeneration: source.NativeGeneration, SessionID: source.NativeSessionID, LogicalTurnID: source.LogicalTurnID, NativeTurnSequence: source.Sequence, InputKind: source.InputKind, SourceCommandID: source.SourceCommandID, SourceAdmissionID: source.SourceAdmissionID}, nil
}

func (d *Daemon) relayNativeBridge(ctx context.Context, link *nativeWorkerLink, row *InstanceRow, call *sessionworker.BridgeCall, tool string, args json.RawMessage) (json.RawMessage, string) {
	admission, err := link.proxy.connection.AuthenticatedNativeHostSession()
	if err != nil || !slices.Contains(admission.ProtocolFeatures, transport.NativeAgentSourceProtocol) {
		return nil, "native source-aware tools are not supported by this connection"
	}
	source, err := nativeBridgeSource(call)
	if err != nil {
		return nil, err.Error()
	}
	request := transport.AgentRequestPayload{InstanceID: row.InstanceID, PrincipalID: row.AgentPrincipalID, Tool: tool, Args: args, NativeSource: source}
	if source == nil && row.NetworkID != "" && slices.Contains(admission.ProtocolFeatures, transport.NativeEndpointAgentSourceProtocol) {
		endpoint, err := nativeBridgeEndpointSource(call)
		if err != nil {
			return nil, err.Error()
		}
		request.NativeEndpointSource = endpoint
	}
	return d.relayNativeSourceRequest(ctx, link, request)
}

func nativeBridgeEndpointSource(call *sessionworker.BridgeCall) (*transport.NativeEndpointAgentSource, error) {
	if call == nil || call.TurnSource != nil || call.NativeSessionID == "" || call.NativeGeneration == "" || call.Scope.InstanceID == "" || call.Scope.HostID == "" || call.Scope.TenantID == "" {
		return nil, errors.New("native endpoint source unavailable")
	}
	var origin transport.NativeObservationOrigin
	if json.Unmarshal(call.Origin, &origin) != nil || origin.ID == "" || origin.InstanceID != call.Scope.InstanceID || origin.HostID != call.Scope.HostID || origin.TenantID != call.Scope.TenantID || origin.NativeGeneration != call.NativeGeneration || (origin.NativeSessionID != "" && origin.NativeSessionID != call.NativeSessionID) {
		return nil, errors.New("native endpoint source binding invalid")
	}
	return &transport.NativeEndpointAgentSource{OriginID: origin.ID, NativeGeneration: call.NativeGeneration, SessionID: call.NativeSessionID}, nil
}

func (d *Daemon) relayNativeSourceRequest(ctx context.Context, link *nativeWorkerLink, request transport.AgentRequestPayload) (json.RawMessage, string) {
	// Only a typed, pre-effect refusal may be repeated. A timeout, disconnect,
	// generic error or ambiguous delivery must never duplicate an operation.
	deadline := time.Now().Add(2 * time.Second)
	for {
		response, err := d.relayConnectionResponse(ctx, link.conn, request)
		if err != nil {
			return nil, err.Error()
		}
		if response.OK {
			return response.Result, ""
		}
		if response.ErrorCode != "source_not_ready" || !response.Retryable || time.Now().After(deadline) {
			if response.Error == "" {
				return nil, "control plane error (no detail)"
			}
			return nil, response.Error
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, errConnInterrupted
		case <-link.proxy.connection.closed:
			timer.Stop()
			return nil, errConnInterrupted
		case <-timer.C:
		}
	}
}
