package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

var ErrNativeSourceUnsupported = sessionworker.ErrNativeSourceUnsupported

// NativeWorkerWireObservation uses the worker's canonical immutable projection.
func NativeWorkerWireObservation(o sessionworker.NativeObservation) (transport.NativeObservationPayload, error) {
	p, err := sessionworker.NativeBackendObservation(o)
	if errors.Is(err, sessionworker.ErrConflict) {
		err = ErrNativeObservationConflict
	}
	if errors.Is(err, sessionworker.ErrFull) {
		err = ErrNativeObservationCapacity
	}
	return p, err
}

// DrainNativeWorkerSources retains the legacy one-page adapter. Controller
// integrations use DrainNativeWorkerSourcesPage and retain its per-worker cursor.
func (c *NativeObservationConnection) DrainNativeWorkerSources(ctx context.Context, call func(context.Context, sessionworker.Request) (sessionworker.Response, error)) error {
	_, err := c.drainNativeWorkerSourcesPage(ctx, call, 0, 1, "")
	return err
}

// DrainNativeWorkerSourcesPage scans at most 128 rows and writes at most 16
// ciphertext fragments per call. After is side metadata from this exact worker's
// prior result. Keep it with the pinned worker proxy, reset it on replacement.
// A zero result starts the next bounded pass from the oldest retained evidence.
// Failed or unfinished supported sources never advance beyond their page.
func (c *NativeObservationConnection) DrainNativeWorkerSourcesPage(ctx context.Context, call func(context.Context, sessionworker.Request) (sessionworker.Response, error), after int64) (int64, error) {
	return c.drainNativeWorkerSourcesPage(ctx, call, after, 4, "")
}

// DrainDeletionSourcesPage publishes immutable metadata only for an explicit
// authenticated typed Forget job. The caller must validate that job's ownership
// against its pinned worker. This grants no permission to erase private evidence.
func (c *NativeObservationConnection) DrainDeletionSourcesPage(ctx context.Context, call func(context.Context, sessionworker.Request) (sessionworker.Response, error), after int64, jobID string) (int64, error) {
	if _, err := domain.ParseID(jobID); err != nil {
		return after, ErrNativeObservationConflict
	}
	admission, err := c.AuthenticatedNativeHostSession()
	if err != nil {
		return after, err
	}
	if !slices.Contains(admission.ProtocolFeatures, transport.NativeOwnedDeletionProtocol) {
		return after, ErrNativeOriginAdmissionDeferred
	}
	return c.drainNativeWorkerSourcesPage(ctx, call, after, 4, jobID)
}
func (c *NativeObservationConnection) drainNativeWorkerSourcesPage(ctx context.Context, call func(context.Context, sessionworker.Request) (sessionworker.Response, error), after int64, maxPages int, deleteJobID string) (int64, error) {
	if after < 0 {
		return after, ErrNativeObservationConflict
	}
	c.mu.Lock()
	err := c.deliveryReadyLocked(false)
	c.mu.Unlock()
	if err != nil {
		return after, err
	}
	budget := transport.NativeContentMaxFragmentPage
	for pages := 0; pages < maxPages; pages++ {
		page, err := call(ctx, sessionworker.Request{Type: "observations", Limit: 32, Cursor: after})
		if err != nil {
			return after, err
		}
		if page.Error != "" {
			return after, errors.New(page.Error)
		}
		if len(page.Observations) > 32 {
			return after, ErrNativeObservationCapacity
		}
		cursor := page.ObservationPage
		// Old worker protocols return no page metadata and remain one-page only.
		if cursor != nil && (cursor.After != after || cursor.NextCursor < after || (len(page.Observations) > 0 && cursor.NextCursor <= after) || (cursor.More && len(page.Observations) == 0)) {
			return after, ErrNativeObservationConflict
		}
		for _, o := range page.Observations {
			var original transport.NativeObservationOrigin
			if json.Unmarshal(o.Origin, &original) != nil || original.HostID != c.hostID {
				return after, ErrNativeObservationConflict
			}
			p, err := NativeWorkerWireObservation(o)
			if errors.Is(err, ErrNativeSourceUnsupported) {
				continue
			}
			if err != nil {
				return after, err
			}
			if deleteJobID == "" && (p.MessageType == transport.MsgRuntimeTurnOutput || p.MessageType == transport.MsgRuntimeTurnPlan || o.OutputContent != nil || o.PlanContent != nil) {
				session, err := c.AuthenticatedNativeHostSession()
				if err != nil {
					return after, err
				}
				if !slices.Contains(session.ProtocolFeatures, transport.NativeTaskContentProtocol) {
					return after, ErrNativeOriginAdmissionDeferred
				}
			}
			var refs []*transport.NativeContentReference
			var ref *transport.NativeContentReference
			if o.Event.Type == session.EventInteractionStarted && o.Inspection != nil {
				ref = o.Inspection.DetailContent
			}
			if o.Event.Type == session.EventInteractionResolved && o.Resolution != nil {
				ref = o.Resolution.DetailContent
			}
			if ref != nil {
				refs = append(refs, ref)
			}
			if o.OutputContent != nil {
				refs = append(refs, o.OutputContent)
			}
			if o.PlanContent != nil {
				refs = append(refs, o.PlanContent)
			}
			// An authenticated expired receipt does not attach content. Ask
			// for it directly so backend staging quotas cannot prevent retaining
			// the terminal disposition. The server alone decides expiration.
			if time.Now().After(p.ExpiresAt) || deleteJobID != "" {
				refs = nil
			}
			for _, ref := range refs {
				ready, err := c.stageWorkerContent(ctx, o, *ref, call, &budget)
				if err != nil {
					return after, err
				}
				if !ready {
					return after, nil
				}
			}
			p.DeleteRequestID = deleteJobID
			receipt, err := c.deliverWorkerObservation(ctx, p)
			if err != nil {
				return after, err
			}
			if receipt.Disposition != "committed" {
				if receipt.Disposition != "expired" && receipt.Disposition != "stale_origin" && receipt.Disposition != transport.NativeObservationDeleteQuarantined {
					return after, ErrNativeOriginAdmissionRejected
				}
				marked, err := call(ctx, sessionworker.Request{Type: "source_disposition", ObservationID: o.ID, SourceDigest: o.SourceDigest, SourceReceipt: &receipt})
				if err != nil {
					return after, err
				}
				if marked.Error != "" {
					return after, errors.New(marked.Error)
				}
				continue
			}
			ack, err := call(ctx, sessionworker.Request{Type: "observation_ack", ObservationID: o.ID, SourceDigest: o.SourceDigest})
			if err != nil {
				return after, err
			}
			if ack.Error != "" {
				return after, errors.New(ack.Error)
			}
		}
		if cursor == nil || !cursor.More {
			return 0, nil
		}
		after = cursor.NextCursor
	}
	return after, nil
}

// Timeouts free all pending entries, and disconnect wakes every waiter. A fresh
// connection retries the worker's original payload and exact fragment bytes.
func nativeDeliveryContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 30*time.Second)
}
