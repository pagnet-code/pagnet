package transport

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/e2ee"
)

// MarshalNativeAccountJSON preserves validated canonical account contracts in
// enclosing records. Records without account contracts retain legacy bytes.
func MarshalNativeAccountJSON(value any, sources []*NativeAccountMessageSource, aads []e2ee.AAD) ([]byte, error) {
	account := false
	for _, source := range sources {
		if source != nil {
			if err := source.Validate(); err != nil {
				return nil, err
			}
			account = true
		}
	}
	for _, aad := range aads {
		if aad.BrowserAccountReply != nil || aad.ObjectType == e2ee.ObjectTypeBrowserAccountReply || aad.NativeContent != nil && aad.NativeContent.Purpose == e2ee.ObjectTypeBrowserAccountReply {
			if aad.BrowserAccountReply == nil || aad.ValidateScope() != nil {
				return nil, errors.New("invalid account reply AAD")
			}
			account = true
		}
	}
	if !account {
		return json.Marshal(value)
	}
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// MarshalNativeJSON encodes known transport records without changing unrelated
// application JSON. Raw payloads are interpreted only by their declared type.
func MarshalNativeJSON(value any) ([]byte, error) {
	sources, aads, err := NativeAccountJSONContracts(value)
	if err != nil {
		return nil, err
	}
	return MarshalNativeAccountJSON(value, sources, aads)
}

// NativeAccountJSONContracts collects canonical contracts from transport records
// so worker persistence wrappers can use the same typed provenance rules.
func NativeAccountJSONContracts(value any) ([]*NativeAccountMessageSource, []e2ee.AAD, error) {
	var sources []*NativeAccountMessageSource
	var aads []e2ee.AAD
	var collect func(any) error
	collect = func(value any) error {
		switch v := value.(type) {
		case NativeAccountMessageSource:
			sources = append(sources, &v)
		case *NativeAccountMessageSource:
			if v != nil {
				return collect(*v)
			}
		case e2ee.AAD:
			aads = append(aads, v)
		case *e2ee.AAD:
			if v != nil {
				return collect(*v)
			}
		case NativeDispatchProof:
			if v.AccountMessageSource != nil && !ValidNativeSourceUnion(v.TaskSource, v.InvocationSource, v.AccountMessageSource) {
				return errors.New("mixed native account source")
			}
			sources = append(sources, v.AccountMessageSource)
		case *NativeDispatchProof:
			if v != nil {
				return collect(*v)
			}
		case NativeWorkerOwnership:
			return collect(v.DeletionProof)
		case *NativeWorkerOwnership:
			if v != nil {
				return collect(*v)
			}
		case NativeOwnershipDeletionProof:
			return collect(v.StopProof)
		case *NativeOwnershipDeletionProof:
			if v != nil {
				return collect(*v)
			}
		case NativeOwnershipRetirePayload:
			return collect(v.UnstartedStop)
		case *NativeOwnershipRetirePayload:
			if v != nil {
				return collect(*v)
			}
		case NativeOwnershipRegisteredPayload:
			if err := collect(v.Ownership); err != nil {
				return err
			}
			return collect(v.UnstartedStop)
		case *NativeOwnershipRegisteredPayload:
			if v != nil {
				return collect(*v)
			}
		case NativeDispatchCancellationProposal:
			return collect(v.Proof)
		case *NativeDispatchCancellationProposal:
			if v != nil {
				return collect(*v)
			}
		case NativeDispatchCancelProposedPayload:
			for _, p := range v.Proposals {
				if err := collect(p); err != nil {
					return err
				}
			}
		case *NativeDispatchCancelProposedPayload:
			if v != nil {
				return collect(*v)
			}
		case NativeDispatchCancelledPayload:
			return collect(v.Proof)
		case *NativeDispatchCancelledPayload:
			if v != nil {
				return collect(*v)
			}
		case NativeTurnSourcePayload:
			if err := collect(v.OutputContent); err != nil {
				return err
			}
			return collect(v.PlanContent)
		case *NativeTurnSourcePayload:
			if v != nil {
				return collect(*v)
			}
		case NativeContentDescriptor:
			return collect(v.Reference)
		case *NativeContentDescriptor:
			if v != nil {
				return collect(*v)
			}
		case FabricHostedResult:
			return collect(v.Proof)
		case *FabricHostedResult:
			if v != nil {
				return collect(*v)
			}
		case NativeContentReference:
			return collect(v.ManifestAAD)
		case *NativeContentReference:
			if v != nil {
				return collect(*v)
			}
		case NativeContentFragment:
			return collect(v.AAD)
		case *NativeContentFragment:
			if v != nil {
				return collect(*v)
			}
		case NativeContentFragmentPage:
			for _, f := range v.Fragments {
				if err := collect(f); err != nil {
					return err
				}
			}
		case *NativeContentFragmentPage:
			if v != nil {
				return collect(*v)
			}
		case InteractionEventPayload:
			if err := collect(v.DetailAAD); err != nil {
				return err
			}
			return collect(v.DetailContent)
		case *InteractionEventPayload:
			if v != nil {
				return collect(*v)
			}
		case ForgetInstancePayload:
			if err := collect(v.DeletionProof); err != nil {
				return err
			}
			return collect(v.NativeOwnership)
		case *ForgetInstancePayload:
			if v != nil {
				return collect(*v)
			}
		case LaunchAgentPayload:
			for _, part := range []any{v.NativeDispatch, v.MissionAAD, v.InstructionAAD} {
				if err := collect(part); err != nil {
					return err
				}
			}
		case *LaunchAgentPayload:
			if v != nil {
				return collect(*v)
			}
		case WakeAgentPayload:
			return collect(v.NativeDispatch)
		case *WakeAgentPayload:
			if v != nil {
				return collect(*v)
			}
		case StopAgentPayload:
			return collect(v.NativeDispatch)
		case *StopAgentPayload:
			if v != nil {
				return collect(*v)
			}
		case RestartAgentPayload:
			return collect(v.NativeDispatch)
		case *RestartAgentPayload:
			if v != nil {
				return collect(*v)
			}
		case NetworkEventPayload:
			if err := collect(v.NativeDispatch); err != nil {
				return err
			}
			return collect(v.AAD)
		case AccountMessagePayload:
			return collect(v.NativeDispatch)
		case *AccountMessagePayload:
			if v != nil {
				return collect(*v)
			}
		case *NetworkEventPayload:
			if v != nil {
				return collect(*v)
			}
		case TerminalAttachPayload:
			return collect(v.NativeDispatch)
		case *TerminalAttachPayload:
			if v != nil {
				return collect(*v)
			}
		case TerminalStopPayload:
			return collect(v.NativeDispatch)
		case *TerminalStopPayload:
			if v != nil {
				return collect(*v)
			}
		case ResolveRuntimeInteractionPayload:
			return collect(v.NativeDispatch)
		case *ResolveRuntimeInteractionPayload:
			if v != nil {
				return collect(*v)
			}
		case Envelope:
			return collectNativePayload(v.Type, v.Payload, collect)
		case *Envelope:
			if v != nil {
				return collect(*v)
			}
		case NativeObservationPayload:
			return collectNativePayload(v.MessageType, v.Payload, collect)
		case *NativeObservationPayload:
			if v != nil {
				return collect(*v)
			}
		}
		return nil
	}
	err := collect(value)
	return sources, aads, err
}

func collectNativePayload(kind string, raw json.RawMessage, collect func(any) error) error {
	var target any
	switch kind {
	case MsgLaunchAgent:
		target = new(LaunchAgentPayload)
	case MsgWakeAgent:
		target = new(WakeAgentPayload)
	case MsgStopAgent:
		target = new(StopAgentPayload)
	case MsgRestartAgent:
		target = new(RestartAgentPayload)
	case MsgDeliverNetworkEvent:
		target = new(NetworkEventPayload)
	case MsgAccountMessage:
		target = new(AccountMessagePayload)
	case MsgAttachTerminal:
		target = new(TerminalAttachPayload)
	case MsgTerminalStop:
		target = new(TerminalStopPayload)
	case MsgResolveRuntimeInteraction:
		target = new(ResolveRuntimeInteractionPayload)
	case MsgForgetInstance:
		target = new(ForgetInstancePayload)
	case MsgNativeDispatchCancelProposed:
		target = new(NativeDispatchCancelProposedPayload)
	case MsgNativeDispatchCancelled:
		target = new(NativeDispatchCancelledPayload)
	case MsgNativeContentBegin, MsgAccountReplyBegin:
		target = new(NativeContentReference)
	case MsgNativeContentFragment, MsgAccountReplyFragment:
		target = new(NativeContentFragment)
	case MsgNativeOwnershipRegistered:
		target = new(NativeOwnershipRegisteredPayload)
	case MsgNativeOwnershipRetired:
		target = new(NativeOwnershipRegisteredPayload)
	case MsgNativeOwnershipRetire:
		target = new(NativeOwnershipRetirePayload)
	case "interaction.started", "interaction.resolved":
		target = new(InteractionEventPayload)
	case MsgRuntimeTurnStarted, MsgRuntimeTurnCompleted, MsgRuntimeTurnFailed, MsgRuntimeTurnOutput, MsgRuntimeTurnPlan:
		target = new(NativeTurnSourcePayload)
	case MsgFabricHostedInvoked, MsgFabricHostedPublished:
		target = new(FabricHostedResult)
	case MsgNativeObservation, MsgAccountReplyCommit:
		target = new(NativeObservationPayload)
	default:
		return nil
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return err
	}
	return collect(target)
}

// A raw payload has provenance only through its declared envelope message type.
func marshalNativeEnvelopePayload(kind string, value any) ([]byte, error) {
	var raw json.RawMessage
	switch v := value.(type) {
	case json.RawMessage:
		raw = v
	case *json.RawMessage:
		if v != nil {
			raw = *v
		}
	default:
		return MarshalNativeJSON(value)
	}
	if len(raw) == 0 {
		return MarshalNativeJSON(value)
	}
	sources, aads, err := NativeAccountJSONContracts(Envelope{Type: kind, Payload: raw})
	if err != nil {
		return nil, err
	}
	return MarshalNativeAccountJSON(value, sources, aads)
}
