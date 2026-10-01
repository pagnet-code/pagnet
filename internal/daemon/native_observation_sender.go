package daemon

import (
	"context"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

// SendNativeObservationBatch may run only on an authenticated connection which
// negotiated native-observation-receipt-v1. The caller supplies that exact
// connection's writer; reconnecting must not silently redirect an old writer.
// A successful WebSocket write never retires content: only a matching durable
// receipt (or an explicit failure diagnostic) does so.
func (s *State) SendNativeObservationBatch(ctx context.Context, now time.Time, send func(context.Context, string, any) error, failed func(NativeObservationRecord, string)) error {
	rows, err := s.DueNativeObservations(ctx, now, 32)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if !now.Before(row.ExpiresAt) {
			removed, err := s.FinishNativeObservation(ctx, row.ID, row.OriginID, row.Digest, "expired")
			if err != nil {
				return err
			}
			if removed && failed != nil {
				failed(row, "expired")
			}
			continue
		}
		payload := transport.NativeObservationPayload{ObservationID: row.ID, OriginID: row.OriginID, MessageType: row.MessageType, Digest: row.Digest, ObservedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt, Payload: row.Payload}
		if err := send(ctx, transport.MsgNativeObservation, payload); err != nil {
			return err
		}
		delay := time.Second << min(max(row.Attempts, 0), 5)
		if err := s.RetryNativeObservation(ctx, row.ID, row.Digest, now.Add(delay)); err != nil {
			return err
		}
	}
	return nil
}

// ReceiveNativeObservationDisposition is invoked only for the authenticated
// transport that published this journal. Successful receipts and permanent
// rejections use distinct frame types; a rejection never implies execution.
func (s *State) ReceiveNativeObservationDisposition(ctx context.Context, typ string, p transport.NativeObservationReceiptPayload) (bool, error) {
	reason := ""
	switch typ {
	case transport.MsgNativeObservationReceipt:
		if p.Disposition == "expired" {
			reason = "expired"
		} else if p.Disposition != "committed" {
			return false, errors.New("invalid native observation receipt")
		}
	case transport.MsgNativeObservationRejected:
		if p.Disposition != "scope_revoked" && p.Disposition != "stale_origin" && p.Disposition != "invalid_observation" {
			return false, errors.New("invalid native observation rejection")
		}
		reason = p.Disposition
	default:
		return false, errors.New("invalid native observation disposition frame")
	}
	return s.FinishNativeObservation(ctx, p.ObservationID, p.OriginID, p.Digest, reason)
}
