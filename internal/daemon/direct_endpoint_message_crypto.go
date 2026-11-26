//go:build linux || darwin

package daemon

import (
	"context"
	"time"

	"github.com/pagnet-code/pagnet/internal/directhttp"
)

// These dormant target adapters recover material through the exact retained
// publication and live credential binding. Callers own returned plaintext/wire;
// no endpoint custody or epoch material escapes the adapter.
func openDirectTargetMessageAsk(ctx context.Context, s *DirectEndpointSubscription, b directEndpointReconcileBinding, e directhttp.Enrollment, publication []byte, registry *NativeWorkerRegistry, now func() time.Time, operate directEndpointMaterialOperation, id, root string, wire []byte) ([]byte, error) {
	material, _, err := acquireDirectTargetReconcileMaterial(ctx, s, b, e, publication, registry, now, operate)
	if err != nil {
		return nil, err
	}
	defer material.Clear()
	return material.OpenAsk(id, root, wire, now())
}

func sealDirectTargetMessageReply(ctx context.Context, s *DirectEndpointSubscription, b directEndpointReconcileBinding, e directhttp.Enrollment, publication []byte, registry *NativeWorkerRegistry, now func() time.Time, operate directEndpointMaterialOperation, id, root string, ask, plaintext []byte) ([]byte, error) {
	material, _, err := acquireDirectTargetReconcileMaterial(ctx, s, b, e, publication, registry, now, operate)
	if err != nil {
		return nil, err
	}
	defer material.Clear()
	return material.SealReply(id, root, ask, plaintext, now())
}
