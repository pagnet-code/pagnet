package daemon

import (
	"context"
	"errors"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

// InvocationStream authenticates the current private worker lease. Stream
// cancellation terminates delivery only; it never reports a native turn stopped.
func (p *NativeWorkerProxy) InvocationStream(ctx context.Context, operation string, request sessionworker.InvocationStreamRequest) (sessionworker.Response, error) {
	switch operation {
	case "invocation_subscribe", "invocation_renew", "invocation_read", "invocation_ack", "invocation_unsubscribe", "invocation_status":
	default:
		return sessionworker.Response{}, errors.New("unsupported original invocation stream operation")
	}
	return p.call(ctx, sessionworker.Request{Type: operation, InvocationStream: &request})
}
