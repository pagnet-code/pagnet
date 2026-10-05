package fabricnode

import (
	"context"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/node/dispatch"
	"github.com/pagnet-code/pagnet/fabric/telemetry"
)

type observedBindings struct {
	bindings dispatch.BindingResolver
	tracing  telemetry.Provider
}

func (r observedBindings) Select(ctx context.Context, caller fabric.ExecutionContext, endpoint fabric.EndpointDescriptor, offer *fabric.OfferDescriptor) (dispatch.Selection, error) {
	selected, err := r.bindings.Select(ctx, caller, endpoint, offer)
	if err != nil {
		return selected, err
	}
	protocol := ""
	for _, binding := range endpoint.Bindings {
		if binding.ID == selected.BindingID {
			protocol = binding.Protocol
			break
		}
	}
	selected.Adapter = telemetry.ObserveAdapter(selected.Adapter, protocol, r.tracing)
	return selected, nil
}
