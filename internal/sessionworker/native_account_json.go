package sessionworker

import (
	"encoding/json"
	"errors"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

// MarshalNativeJSON preserves canonical account contracts in worker records and
// private IPC frames while retaining the exact encoding of legacy records.
func MarshalNativeJSON(value any) ([]byte, error) {
	var sources []*transport.NativeAccountMessageSource
	var aads []e2ee.AAD
	var collect func(any) error
	collect = func(value any) error {
		switch v := value.(type) {
		case BridgeCall:
			return collect(v.TurnSource)
		case *BridgeCall:
			if v != nil {
				return collect(*v)
			}
		case CloudInvocationSourceResult:
			return collect(v.Source)
		case *CloudInvocationSourceResult:
			if v != nil {
				return collect(*v)
			}
		case NativeSourceDisposition:
			return collect(v.Observation)
		case *NativeSourceDisposition:
			if v != nil {
				return collect(*v)
			}
		case NativeSourceDispositionPage:
			for _, source := range v.Sources {
				if err := collect(source); err != nil {
					return err
				}
			}
		case *NativeSourceDispositionPage:
			if v != nil {
				return collect(*v)
			}
		case InvocationStreamState:
			return collect(v.Terminal)
		case *InvocationStreamState:
			if v != nil {
				return collect(*v)
			}
		case InvocationStreamProjection:
			return collect(v.AAD)
		case *InvocationStreamProjection:
			if v != nil {
				return collect(*v)
			}
		case InvocationStreamRange:
			if err := collect(v.Source); err != nil {
				return err
			}
			return collect(v.Terminal)
		case *InvocationStreamRange:
			if v != nil {
				return collect(*v)
			}
		case invocationStreamCheckpoint:
			for _, part := range []any{v.Source, v.Terminal, v.Pending} {
				if err := collect(part); err != nil {
					return err
				}
			}
		case *invocationStreamCheckpoint:
			if v != nil {
				return collect(*v)
			}
		case LocalStreamSource:
			return collect(v.Turn)
		case *LocalStreamSource:
			if v != nil {
				return collect(*v)
			}
		case LocalInvocationPage:
			return collect(v.Source)
		case *LocalInvocationPage:
			if v != nil {
				return collect(*v)
			}
		case LocalResponse:
			for _, observation := range v.Observations {
				if err := collect(observation); err != nil {
					return err
				}
			}
			return collect(v.Stream)
		case *LocalResponse:
			if v != nil {
				return collect(*v)
			}
		case Operation:
			if v.SourceAccountMessage != nil && !transport.ValidNativeSourceUnion(v.SourceTask, v.SourceInvocation, v.SourceAccountMessage) {
				return errors.New("mixed native account source")
			}
			sources = append(sources, v.SourceAccountMessage)
		case *Operation:
			if v != nil {
				return collect(*v)
			}
		case NativeTurnSource:
			if v.SourceAccountMessage != nil && !transport.ValidNativeSourceUnion(v.SourceTask, v.SourceInvocation, v.SourceAccountMessage) {
				return errors.New("mixed native account source")
			}
			sources = append(sources, v.SourceAccountMessage)
		case *NativeTurnSource:
			if v != nil {
				return collect(*v)
			}
		case NativeObservation:
			for _, part := range []any{v.TurnSource, v.OutputContent, v.PlanContent, v.OriginalNativePayloadContent, v.Resolution, v.Inspection} {
				if err := collect(part); err != nil {
					return err
				}
			}
		case *NativeObservation:
			if v != nil {
				return collect(*v)
			}
		case NativeResolution:
			if err := collect(v.DetailAAD); err != nil {
				return err
			}
			return collect(v.DetailContent)
		case *NativeResolution:
			if v != nil {
				return collect(*v)
			}
		case Inspection:
			if err := collect(v.DetailAAD); err != nil {
				return err
			}
			return collect(v.DetailContent)
		case *Inspection:
			if v != nil {
				return collect(*v)
			}
		case DispatchCancellationPreparation:
			return collect(v.Proposal)
		case *DispatchCancellationPreparation:
			if v != nil {
				return collect(*v)
			}
		case NativeDispatchRecord:
			return collect(v.Proof)
		case *NativeDispatchRecord:
			if v != nil {
				return collect(*v)
			}
		case resourceSettlement:
			if err := collect(v.Observation); err != nil {
				return err
			}
			return collect(v.Proof)
		case *resourceSettlement:
			if v != nil {
				return collect(*v)
			}
		case stoppedReceipt:
			return collect(v.Observation)
		case *stoppedReceipt:
			if v != nil {
				return collect(*v)
			}
		case ownerStopSettlement:
			for _, part := range []any{v.Stopped, v.Deletion, v.Turn, v.Proof} {
				if err := collect(part); err != nil {
					return err
				}
			}
		case *ownerStopSettlement:
			if v != nil {
				return collect(*v)
			}
		case Request:
			for _, part := range []any{v.NativeDispatch, v.CancelProposal, v.CancelReceipt, v.Ownership, v.DeletionProof} {
				if err := collect(part); err != nil {
					return err
				}
			}
			if (v.Type == "intent" || v.Type == "dispatch") && len(v.Payload) > 0 {
				var op Operation
				if err := json.Unmarshal(v.Payload, &op); err != nil {
					return err
				}
				return collect(op)
			}
		case *Request:
			if v != nil {
				return collect(*v)
			}
		case Response:
			for _, part := range []any{v.Cancellation, v.ContentFragment, v.Snapshot, v.Bridge, v.InvocationSource, v.InvocationState, v.InvocationProjection, v.SourceDispositions} {
				if err := collect(part); err != nil {
					return err
				}
			}
			for _, record := range v.Dispatches {
				if err := collect(record); err != nil {
					return err
				}
			}
			for _, observation := range v.Observations {
				if err := collect(observation); err != nil {
					return err
				}
			}
		case *Response:
			if v != nil {
				return collect(*v)
			}
		case NativeSnapshot:
			for _, i := range v.Pending {
				if err := collect(i); err != nil {
					return err
				}
			}
		case *NativeSnapshot:
			if v != nil {
				return collect(*v)
			}
		default:
			s, a, err := transport.NativeAccountJSONContracts(value)
			if err != nil {
				return err
			}
			sources = append(sources, s...)
			aads = append(aads, a...)
		}
		return nil
	}
	if err := collect(value); err != nil {
		return nil, err
	}
	return transport.MarshalNativeAccountJSON(value, sources, aads)
}
