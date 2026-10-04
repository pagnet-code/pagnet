package node

import (
	"context"
	"encoding/json"
	"math"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension"
)

func (s *Service) read(ctx context.Context, envelope fabric.Envelope) (Result, error) {
	switch envelope.Operation {
	case fabric.OperationDiscover:
		return s.discover(ctx, envelope)
	case fabric.OperationDescribe:
		return s.describe(ctx, envelope)
	default:
		return Result{}, fabric.NewError(fabric.CodeUnsupported, "Expected a read operation")
	}
}

// dispatchRead supplies only read ports to both operation stages. It contains
// no invocation dispatcher, resume operation or fallback target selection.
func (s *Service) dispatchRead(ctx context.Context, caller fabric.ExecutionContext, original []byte, envelope fabric.Envelope) (Result, error) {
	if s.config.Interceptors == nil {
		return s.read(ctx, envelope)
	}
	if s.config.ValidateReadResult == nil {
		return Result{}, fabric.NewError(fabric.CodeUnsupported, "Read interception requires current disclosure validation")
	}
	placement := s.config.InvocationPlacement
	if placement == "" {
		placement = extension.PlacementSource
	}
	current := envelope
	out, err := s.config.Interceptors.ExecuteStage(ctx, caller, original, s.config.Audience, string(envelope.Operation)+".request", placement, func(ctx context.Context, _ fabric.ExecutionContext, admitted fabric.Envelope) (extension.Outcome, error) {
		current = admitted
		result, err := s.read(ctx, admitted)
		if err != nil {
			return extension.Outcome{}, err
		}
		raw, err := encodeReadResult(admitted.Operation, result)
		return extension.Outcome{Response: raw}, err
	})
	if err != nil {
		return Result{}, publicError(err)
	}
	result, err := decodeReadOutcome(current, out)
	if err != nil {
		return Result{}, err
	}
	if err := s.config.ValidateReadResult(ctx, caller, current, result); err != nil {
		return Result{}, publicError(err)
	}
	// Even a request-stage RESPOND enters the response-stage barrier. A cache
	// shortcut cannot avoid shape, current revision or disclosure validation.
	projection, err := encodeReadResult(current.Operation, result)
	if err != nil {
		return Result{}, err
	}
	out, err = s.config.Interceptors.ExecuteReadProjection(ctx, caller, original, s.config.Audience, string(envelope.Operation)+".response", placement, projection, func(_ context.Context, _ fabric.ExecutionContext, projected fabric.Envelope) (extension.Outcome, error) {
		return extension.Outcome{Response: append(json.RawMessage(nil), projected.Payload...)}, nil
	})
	if err != nil {
		return Result{}, publicError(err)
	}
	result, err = decodeReadOutcome(current, out)
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, contextError(err)
	}
	if err := s.config.ValidateReadResult(ctx, caller, current, result); err != nil {
		return Result{}, publicError(err)
	}
	return result, nil
}

func encodeReadResult(operation fabric.Operation, result Result) (json.RawMessage, error) {
	var value any
	switch operation {
	case fabric.OperationDiscover:
		value = result.Discover
	case fabric.OperationDescribe:
		value = result.Describe
	default:
		return nil, fabric.NewError(fabric.CodeProtocolError, "Unexpected read operation")
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fabric.NewError(fabric.CodeProtocolError, "Invalid read result")
	}
	var bounded any
	if err := fabric.DecodeJSON(raw, &bounded); err != nil {
		return nil, fabric.NewError(fabric.CodeProtocolError, "Read result exceeds wire bounds")
	}
	return raw, nil
}

func decodeReadOutcome(envelope fabric.Envelope, outcome extension.Outcome) (Result, error) {
	bad := func() (Result, error) {
		return Result{}, fabric.NewError(fabric.CodeProtocolError, "Invalid intercepted read result")
	}
	if outcome.Stream != nil {
		_ = outcome.Stream.Close()
		return bad()
	}
	if outcome.DeferredID != "" || outcome.DeferredNotificationError != nil || len(outcome.Response) == 0 || string(outcome.Response) == "null" {
		return bad()
	}
	result := Result{}
	switch envelope.Operation {
	case fabric.OperationDiscover:
		var request fabric.DiscoverRequest
		if fabric.DecodeJSON(envelope.Payload, &request) != nil || request.Validate() != nil {
			return bad()
		}
		var response fabric.DiscoverResult
		if fabric.DecodeJSON(outcome.Response, &response) != nil || len(response.Candidates) > request.Limit {
			return bad()
		}
		seen := map[fabric.EndpointRef]bool{}
		for _, candidate := range response.Candidates {
			if _, err := fabric.ParseEndpointRef(candidate.Document.Ref.String()); err != nil {
				return bad()
			}
			if seen[candidate.Document.Ref] || math.IsNaN(candidate.Score) || math.IsInf(candidate.Score, 0) {
				return bad()
			}
			seen[candidate.Document.Ref] = true
		}
		result.Discover = &response
	case fabric.OperationDescribe:
		var request fabric.DescribeRequest
		if fabric.DecodeJSON(envelope.Payload, &request) != nil || request.Validate() != nil {
			return bad()
		}
		var response fabric.DescribeResult
		if fabric.DecodeJSON(outcome.Response, &response) != nil || len(response.Descriptions) != len(request.Selections) {
			return bad()
		}
		for index, description := range response.Descriptions {
			selected := request.Selections[index]
			if description.Ref != selected.Ref {
				return bad()
			}
			if description.Error != nil {
				if description.Endpoint != nil || description.Offer != nil || len(description.Offers) != 0 || description.NextOffersCursor != "" {
					return bad()
				}
				continue
			}
			if selected.Ref.IsOffer() {
				if description.Offer == nil || description.Endpoint != nil || description.Offer.Ref != selected.Ref || selected.ExpectedRevision != "" && description.Offer.Revision != selected.ExpectedRevision || len(description.Offers) != 0 || description.NextOffersCursor != "" {
					return bad()
				}
			} else {
				if description.Endpoint == nil || description.Offer != nil || description.Endpoint.Ref != selected.Ref || selected.ExpectedRevision != "" && description.Endpoint.Revision != selected.ExpectedRevision {
					return bad()
				}
				limit := selected.OffersLimit
				if limit == 0 {
					limit = 20
				}
				if len(description.Offers) > limit {
					return bad()
				}
				seen := map[fabric.EndpointRef]bool{}
				for _, offer := range description.Offers {
					if !offer.Ref.IsOffer() || offer.Ref.Endpoint() != selected.Ref || seen[offer.Ref] {
						return bad()
					}
					seen[offer.Ref] = true
				}
			}
		}
		result.Describe = &response
	default:
		return bad()
	}
	return result, nil
}
