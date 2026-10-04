package federation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

func (l *AdmissionLedger) change(ctx context.Context, c Config, a Admission, caller fabric.ExecutionContext, action AdmissionAction, apply func(context.Context, *registry.AuthorityTx, *admissionManifest) error) (admissionManifest, error) {
	c = cloneConfig(c)
	if a.ledger != l || a.key == "" || a.digest == ([32]byte{}) {
		return admissionManifest{}, authError()
	}
	var committed admissionManifest
	e := l.withOwner(ctx, func(ctx context.Context, tx *registry.AuthorityTx) error {
		return l.current(ctx, tx, c, func(current context.Context) error {
			configRow, config, e := l.configuration(tx)
			if e != nil {
				return e
			}
			row, m, e := l.manifest(tx, a.key)
			if e != nil {
				return e
			}
			if m.Facts.BundleDigest != a.digest || !sameRoot(m.Facts.Source.Authority, c.Remote.Authority) || !sameRoot(m.Facts.Destination.Authority, c.Local.Authority) {
				return authError()
			}
			if e = l.authorize(current, tx, action, caller, m); e != nil {
				return e
			}
			before := m
			if e = apply(current, tx, &m); e != nil {
				return e
			}
			if !reflect.DeepEqual(before, m) {
				if row.Revision == math.MaxInt64 {
					return protocolError()
				}
				_, n, e := l.cas(tx, a.key, row.Revision, m)
				if e != nil {
					return e
				}
				if e = l.charge(tx, configRow, config, uint64(n), false); e != nil {
					return e
				}
			}
			committed = m
			return nil
		})
	})
	if e != nil {
		return admissionManifest{}, e
	}
	return committed, nil
}
func (l *AdmissionLedger) MarkAttempt(ctx context.Context, c Config, a Admission, caller fabric.ExecutionContext) (AttemptPermit, bool, error) {
	fresh := false
	m, e := l.change(ctx, c, a, caller, ActionAttempt, func(ctx context.Context, tx *registry.AuthorityTx, m *admissionManifest) error {
		if m.AttemptID != "" {
			return nil
		}
		if m.CancelRequested {
			return fabric.NewError(fabric.CodeCancelled, "Original federation invocation is cancelled")
		}
		expires, e := time.Parse(time.RFC3339Nano, m.ExpiresAt)
		if e != nil || !time.Now().Before(expires) {
			return fabric.NewError(fabric.CodeDeadlineExceeded, "Original federation paid-start validity expired")
		}
		if m.Deadline != "" {
			deadline, e := time.Parse(time.RFC3339Nano, m.Deadline)
			if e != nil || !time.Now().Before(deadline) {
				return fabric.NewError(fabric.CodeDeadlineExceeded, "Original invocation deadline expired")
			}
		}
		raw, _ := json.Marshal(struct {
			Purpose, Domain, Store, Key string
			Digest                      [32]byte
		}{"pagnet.fabric.federation-attempt.v1", l.root.Namespace, l.root.StoreID, a.key, a.digest})
		sum := sha256.Sum256(raw)
		m.AttemptID = "attempt:" + hex.EncodeToString(sum[:])
		fresh = true
		return nil
	})
	if e != nil {
		return AttemptPermit{}, false, e
	}
	return AttemptPermit{a, m.AttemptID}, fresh, nil
}
func validAssociation(v Association) bool {
	if !fabric.ValidNamespacedName(v.Protocol) || v.BindingDigest == ([32]byte{}) || len(v.PrivateReference) == 0 || len(v.PrivateReference) > 4096 {
		return false
	}
	var value any
	return fabric.DecodeJSONWithLimits(v.PrivateReference, &value, fabric.WireLimits{MaxBytes: 4096, MaxDepth: 16, MaxMembers: 128}) == nil
}
func (l *AdmissionLedger) Associate(ctx context.Context, c Config, a Admission, caller fabric.ExecutionContext, p AttemptPermit, association Association) error {
	if p.admission != a || p.attemptID == "" || !validAssociation(association) {
		return authError()
	}
	raw, e := json.Marshal(association)
	if e != nil {
		return e
	}
	var owned Association
	if fabric.DecodeJSONWithLimits(raw, &owned, fabric.WireLimits{MaxBytes: 8192, MaxDepth: 20, MaxMembers: 256}) != nil {
		return protocolError()
	}
	_, e = l.change(ctx, c, a, caller, ActionAssociate, func(ctx context.Context, tx *registry.AuthorityTx, m *admissionManifest) error {
		if m.AttemptID != p.attemptID {
			return authError()
		}
		if m.Association != nil {
			if !reflect.DeepEqual(*m.Association, owned) {
				return authError()
			}
			return nil
		}
		m.Association = &owned
		return nil
	})
	return e
}
func (l *AdmissionLedger) Status(ctx context.Context, c Config, a Admission, caller fabric.ExecutionContext) (AdmissionStatus, error) {
	m, e := l.change(ctx, c, a, caller, ActionRead, func(context.Context, *registry.AuthorityTx, *admissionManifest) error { return nil })
	if e != nil {
		return AdmissionStatus{}, e
	}
	return AdmissionStatus{Attempted: m.AttemptID != "", CancelRequested: m.CancelRequested, Association: m.Association, Cursor: m.Cursor}, nil
}

// RequestCancellation FULL-commits stop intent only. The caller must then invoke
// the genuine exact-source stop port; transport/marker ACK is never completion.
func (l *AdmissionLedger) RequestCancellation(ctx context.Context, c Config, a Admission, caller fabric.ExecutionContext) error {
	_, e := l.change(ctx, c, a, caller, ActionCancel, func(ctx context.Context, tx *registry.AuthorityTx, m *admissionManifest) error {
		m.CancelRequested = true
		return nil
	})
	return e
}

// CheckpointCursor is FULL BEFORE acknowledging native/adapter retained frames.
// A crash in the gap can repeat exact source ACK, never execute the endpoint or
// skip to a guessed cursor. No atomic cross-store commit is asserted.
func (l *AdmissionLedger) CheckpointCursor(ctx context.Context, c Config, a Admission, caller fabric.ExecutionContext, previous, next ConsumerCursor, verifier CursorVerifier) error {
	if verifier == nil || next.Ordinal < 0 || next.FrameDigest == ([32]byte{}) {
		return authError()
	}
	_, e := l.change(ctx, c, a, caller, ActionCheckpoint, func(ctx context.Context, tx *registry.AuthorityTx, m *admissionManifest) error {
		if m.Association == nil {
			return authError()
		}
		if m.Cursor == next {
			return nil
		}
		if m.Cursor != previous || next.Ordinal != previous.Ordinal+1 {
			return fabric.NewError(fabric.CodeStaleContinuation, "Original stream cursor does not follow retained cursor")
		}
		if e := verifier.VerifyCursorTx(ctx, tx, cloneAdmissionFacts(m.Facts), Association{Protocol: m.Association.Protocol, BindingDigest: m.Association.BindingDigest, PrivateReference: append(json.RawMessage(nil), m.Association.PrivateReference...)}, next); e != nil {
			return e
		}
		m.Cursor = next
		return nil
	})
	return e
}
