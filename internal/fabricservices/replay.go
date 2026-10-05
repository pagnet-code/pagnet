package fabricservices

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// InvocationHistoryPolicy validates the genuine CURRENT request capability and
// an explicitly associated original execution. It must not loosen AuthorizeTx
// exact-original equality, renew an original paid deadline, or run provider IO.
type InvocationHistoryPolicy interface {
	AuthorizeHistoryTx(context.Context, *registry.AuthorityTx, fabric.ExecutionContext, InvocationFacts, InvocationFacts, string) error
	WithReplayRequest(context.Context, fabric.ExecutionContext, InvocationFacts, func(context.Context) error) error
}

type idempotencyRecord struct {
	Format     int              `json:"format"`
	Principal  fabric.Principal `json:"principal"`
	KeySHA     [32]byte         `json:"keySha"`
	Facts      InvocationFacts  `json:"facts"`
	ReceiptSHA [32]byte         `json:"receiptSha"`
}
type aliasRecord struct {
	Format      int             `json:"format"`
	Current     InvocationFacts `json:"current"`
	KeySHA      [32]byte        `json:"keySha"`
	ExecutionID string          `json:"executionId"`
	ReceiptSHA  [32]byte        `json:"receiptSha"`
}

// This compact opaque proof references actual retained signed row evidence; it
// is not a standalone authorization certificate. Verification always reads the
// same-root current record, index and original receipt in one bounded FULL TX.
type aliasProof struct {
	Format    int                   `json:"format"`
	Key       registry.AuthorityKey `json:"key"`
	Revision  uint64                `json:"revision,string"`
	Sequence  uint64                `json:"sequence,string"`
	ValueSHA  [32]byte              `json:"valueSha"`
	Signature []byte                `json:"signature"`
}

func idemID(p fabric.Principal, keySHA [32]byte) string {
	raw, _ := json.Marshal(struct {
		Purpose   string
		Principal fabric.Principal
		Key       [32]byte
	}{"pagnet.service.idempotency.v1", p, keySHA})
	h := sha256.Sum256(raw)
	return "idempotency/" + hex.EncodeToString(h[:])
}
func aliasID(p fabric.Principal, id string) string { return "alias/" + invocationKey(p, id) }
func receiptSHA(r Receipt) [32]byte {
	// Frames/terminal may advance while the ORIGINAL immutable admission does
	// not. This commitment never changes or renews its original deadline.
	raw, _ := json.Marshal(struct {
		Purpose   string
		Facts     InvocationFacts
		Dispatch  fabric.DispatchAdmissionFrame
		Signature []byte
	}{"pagnet.service.receipt.v1", r.Facts, r.Dispatch, r.Signature})
	return sha256.Sum256(raw)
}
func semanticEqual(a, b InvocationFacts) bool {
	return a.Principal == b.Principal && a.Target == b.Target && a.Revision == b.Revision && a.Scope == b.Scope && a.Fingerprint == b.Fingerprint && a.InputSHA == b.InputSHA
}
func (i *Invocations) addReplayRecordTx(tx *registry.AuthorityTx, id string, v any, s *invocationState) (registry.AuthorityRecord, error) {
	value, e := i.encode(id, v)
	if e != nil {
		return registry.AuthorityRecord{}, e
	}
	if s.Invocations >= s.Config.MaxInvocations || uint64(len(value)) > s.Config.MaxBytes-s.Bytes {
		return registry.AuthorityRecord{}, fabric.NewError(fabric.CodeTargetUnavailable, "Retained service replay capacity exhausted")
	}
	row, e := tx.CAS(serviceKey(id), 0, value, false)
	if e != nil {
		return row, e
	}
	s.Invocations++
	s.Bytes += uint64(len(value))
	return row, nil
}
func (i *Invocations) installIdempotencyTx(tx *registry.AuthorityTx, f InvocationFacts, key string, r Receipt, s *invocationState) error {
	h := sha256.Sum256([]byte(key))
	_, e := i.addReplayRecordTx(tx, idemID(f.Principal, h), idempotencyRecord{1, f.Principal, h, f, receiptSHA(r)}, s)
	return e
}
func (i *Invocations) currentProfileTx(tx *registry.AuthorityTx, f InvocationFacts) error {
	p, gen, e := i.profiles.GetTx(tx, f.Scope)
	if e != nil || Fingerprint(f.Scope, p, gen) != f.Fingerprint {
		return denied()
	}
	return nil
}
func (i *Invocations) association(a aliasRecord, row registry.AuthorityRecord) fabric.ReplayAssociation {
	proof, _ := json.Marshal(aliasProof{1, row.Key, row.Revision, row.Sequence, sha256.Sum256(row.Value), bytes.Clone(row.Signature)})
	return fabric.ReplayAssociation{Version: 1, AuthorityNamespace: i.profiles.root.Namespace, AuthorityStoreID: i.profiles.root.StoreID, AuthorityKeyRevision: i.profiles.root.KeyRevision, Principal: a.Current.Principal, RequestID: a.Current.InvocationID, ExecutionID: a.ExecutionID, Target: a.Current.Target, ExpectedRevision: a.Current.Revision, OriginalRequestSHA: a.Current.OriginalSHA, FinalizedRequestSHA: a.Current.FinalizedSHA, InputSHA: a.Current.InputSHA, IdempotencySHA: a.KeySHA, BindingFingerprint: a.Current.Fingerprint, OriginalReceiptSHA: a.ReceiptSHA, Proof: proof}
}
func (i *Invocations) historyTx(ctx context.Context, tx *registry.AuthorityTx, caller fabric.ExecutionContext, current InvocationFacts, index idempotencyRecord, action string) (Receipt, error) {
	policy, ok := i.policy.(InvocationHistoryPolicy)
	if !ok {
		return Receipt{}, fabric.NewError(fabric.CodeUnsupported, "Service replay policy is not configured")
	}
	if index.Format != 1 || index.Principal != current.Principal || index.Facts.Principal != current.Principal || !semanticEqual(current, index.Facts) || index.Facts.InvocationID == "" || i.currentProfileTx(tx, current) != nil {
		return Receipt{}, denied()
	}
	var original Receipt
	if _, e := i.decode(tx, "invocation/"+invocationKey(current.Principal, index.Facts.InvocationID), &original); e != nil {
		return Receipt{}, e
	}
	if original.Facts != index.Facts || receiptSHA(original) != index.ReceiptSHA || !i.validOriginalReceipt(original) {
		return Receipt{}, denied()
	}
	if e := policy.AuthorizeHistoryTx(ctx, tx, caller, current, original.Facts, action); e != nil {
		return Receipt{}, e
	}
	return original, nil
}

// resolveAliasTx never grants a new send. New alias + index references consume
// the same O(1) root quota counters as original admissions and frame records.
func (i *Invocations) resolveAliasTx(ctx context.Context, tx *registry.AuthorityTx, caller fabric.ExecutionContext, current InvocationFacts, key string, s *invocationState, stateRow registry.AuthorityRecord) (bool, Receipt, error) {
	var alias aliasRecord
	aliasRow, aliasErr := i.decode(tx, aliasID(current.Principal, current.InvocationID), &alias)
	if aliasErr != nil && !missing(aliasErr) {
		return true, Receipt{}, aliasErr
	}
	if key == "" {
		if aliasErr == nil {
			return true, Receipt{}, denied()
		}
		return false, Receipt{}, nil
	}
	keySHA := sha256.Sum256([]byte(key))
	var index idempotencyRecord
	_, e := i.decode(tx, idemID(current.Principal, keySHA), &index)
	if missing(e) {
		if aliasErr == nil {
			return true, Receipt{}, denied()
		}
		if _, err := tx.Get(serviceKey("invocation/" + invocationKey(current.Principal, current.InvocationID))); !missing(err) {
			return true, Receipt{}, denied()
		}
		return false, Receipt{}, nil
	}
	if e != nil {
		return true, Receipt{}, e
	}
	if index.KeySHA != keySHA {
		return true, Receipt{}, denied()
	}
	if index.Facts.InvocationID == current.InvocationID {
		if aliasErr == nil || index.Facts != current {
			return true, Receipt{}, denied()
		}
		// Original-ID exact retry follows original policy and frames; the index
		// must still prove exactly the immutable original admission.
		var original Receipt
		_, e = i.decode(tx, "invocation/"+invocationKey(current.Principal, current.InvocationID), &original)
		if e != nil || original.Facts != current || receiptSHA(original) != index.ReceiptSHA {
			return true, Receipt{}, denied()
		}
		if e = i.policy.AuthorizeTx(ctx, tx, caller, current, "replay"); e != nil {
			return true, Receipt{}, e
		}
		return true, original, nil
	}
	original, e := i.historyTx(ctx, tx, caller, current, index, "alias_admit")
	if e != nil {
		return true, Receipt{}, e
	}
	if aliasErr == nil {
		if alias.Format != 1 || alias.Current != current || alias.KeySHA != keySHA || alias.ExecutionID != original.Facts.InvocationID || alias.ReceiptSHA != index.ReceiptSHA {
			return true, Receipt{}, denied()
		}
	} else {
		// Current IDs are globally exclusive with original execution IDs.
		if _, e := tx.Get(serviceKey("invocation/" + invocationKey(current.Principal, current.InvocationID))); !missing(e) {
			return true, Receipt{}, denied()
		}
		alias = aliasRecord{1, current, keySHA, original.Facts.InvocationID, index.ReceiptSHA}
		aliasRow, e = i.addReplayRecordTx(tx, aliasID(current.Principal, current.InvocationID), alias, s)
		if e != nil {
			return true, Receipt{}, e
		}
		value, e := i.encode("configuration", *s)
		if e != nil {
			return true, Receipt{}, e
		}
		if _, e = tx.CAS(serviceKey("configuration"), stateRow.Revision, value, false); e != nil {
			return true, Receipt{}, e
		}
	}
	association := i.association(alias, aliasRow)
	if e = association.Validate(); e != nil {
		return true, Receipt{}, e
	}
	original.Replay = &association
	return true, original, nil
}

func (i *Invocations) verifyReplayTx(ctx context.Context, tx *registry.AuthorityTx, caller fabric.ExecutionContext, current InvocationFacts, a fabric.ReplayAssociation, action string) (Receipt, error) {
	if a.Validate() != nil || a.AuthorityNamespace != i.profiles.root.Namespace || a.AuthorityStoreID != i.profiles.root.StoreID || a.AuthorityKeyRevision != i.profiles.root.KeyRevision || a.Principal != current.Principal || a.RequestID != current.InvocationID {
		return Receipt{}, denied()
	}
	if _, _, e := i.state(tx); e != nil {
		return Receipt{}, e
	}
	var alias aliasRecord
	row, e := i.decode(tx, aliasID(current.Principal, current.InvocationID), &alias)
	if e != nil {
		return Receipt{}, e
	}
	if alias.Format != 1 || alias.Current != current || alias.KeySHA != a.IdempotencySHA {
		return Receipt{}, denied()
	}
	expected := i.association(alias, row)
	left, _ := json.Marshal(expected)
	right, _ := json.Marshal(a)
	if !bytes.Equal(left, right) {
		return Receipt{}, denied()
	}
	var index idempotencyRecord
	_, e = i.decode(tx, idemID(current.Principal, alias.KeySHA), &index)
	if e != nil {
		return Receipt{}, e
	}
	if index.KeySHA != alias.KeySHA || index.Facts.InvocationID != alias.ExecutionID || index.ReceiptSHA != alias.ReceiptSHA {
		return Receipt{}, denied()
	}
	return i.historyTx(ctx, tx, caller, current, index, action)
}

// withCurrentReplay reconstructs fresh facts exclusively from node capability
// and actual selected private profile. The current policy mints a fresh stamp
// when verification happens outside the original dispatch callback.
func (i *Invocations) withCurrentReplay(ctx context.Context, caller fabric.ExecutionContext, a fabric.ReplayAssociation, action string, fn func(context.Context, *registry.AuthorityTx, Receipt) error) error {
	if i == nil || ctx == nil || a.Validate() != nil {
		return denied()
	}
	policy, ok := i.policy.(InvocationHistoryPolicy)
	if !ok {
		return fabric.NewError(fabric.CodeUnsupported, "Service replay policy is not configured")
	}
	// The alias supplies only an indexed locator; it is never trusted for scope.
	var retained aliasRecord
	e := i.with(ctx, registry.DescriptorBatchScope{}, func(_ context.Context, tx *registry.AuthorityTx) error {
		_, e := i.decode(tx, aliasID(caller.PrincipalView(), a.RequestID), &retained)
		return e
	})
	if e != nil {
		return e
	}
	current, env, original, final, e := i.original(ctx, caller, retained.Current.Scope, retained.Current.Fingerprint)
	defer clear(original)
	defer clear(final)
	if e != nil || env.ID != a.RequestID || env.Context.IdempotencyKey == "" || sha256.Sum256([]byte(env.Context.IdempotencyKey)) != a.IdempotencySHA {
		return denied()
	}
	if ctx.Err() != nil || env.Context.Deadline != nil && !time.Now().Before(*env.Context.Deadline) {
		return fabric.NewError(fabric.CodeCancelled, "Replay request deadline ended")
	}
	return withReplayPolicy(ctx, caller, current, policy, func(ctx context.Context) error {
		return i.with(ctx, current.Scope, func(ctx context.Context, tx *registry.AuthorityTx) error {
			r, e := i.verifyReplayTx(ctx, tx, caller, current, a, action)
			if e != nil {
				return e
			}
			return fn(ctx, tx, r)
		})
	})
}
func (i *Invocations) VerifyReplay(ctx context.Context, caller fabric.ExecutionContext, current fabric.ReplayRequest, a fabric.ReplayAssociation) error {
	return i.withCurrentReplay(ctx, caller, a, "alias_verify", func(_ context.Context, _ *registry.AuthorityTx, r Receipt) error {
		// Canonical node also checks all current request facts before this port.
		if current.Principal != a.Principal || current.RequestID != a.RequestID || current.Target != a.Target || current.ExpectedRevision != a.ExpectedRevision || current.OriginalRequestSHA != a.OriginalRequestSHA || current.FinalizedRequestSHA != a.FinalizedRequestSHA || current.InputSHA != a.InputSHA || current.IdempotencySHA != a.IdempotencySHA || !r.Terminal {
			return denied()
		}
		return nil
	})
}
func (i *Invocations) frameReplay(ctx context.Context, caller fabric.ExecutionContext, a fabric.ReplayAssociation, ordinal uint64) (fabric.InvocationFrame, error) {
	var f fabric.InvocationFrame
	e := i.withCurrentReplay(ctx, caller, a, "alias_pull", func(_ context.Context, tx *registry.AuthorityTx, r Receipt) error {
		if !r.Terminal {
			return denied()
		}
		var e error
		f, e = i.frameTx(tx, r, ordinal)
		return e
	})
	return f, e
}

var _ fabric.ReplayVerifier = (*Invocations)(nil)

// Protect callback lifetime even if a trusted policy accidentally omits,
// repeats, escapes or swallows failure from its current-request fence.
func withReplayPolicy(ctx context.Context, caller fabric.ExecutionContext, current InvocationFacts, policy InvocationHistoryPolicy, next func(context.Context) error) error {
	var gate sync.Mutex
	active, called, misused := true, false, false
	var stepError error
	err := policy.WithReplayRequest(ctx, caller, current, func(c context.Context) (result error) {
		gate.Lock()
		defer gate.Unlock()
		if !active || called {
			misused = true
			return denied()
		}
		called = true
		defer func() { stepError = result }()
		if c == nil || c.Err() != nil || ctx.Err() != nil {
			return denied()
		}
		return next(c)
	})
	gate.Lock()
	active = false
	used, bad, step := called, misused, stepError
	gate.Unlock()
	if err != nil {
		return err
	}
	if step != nil {
		return step
	}
	if !used || bad {
		return denied()
	}
	return nil
}

func (i *Invocations) validOriginalReceipt(r Receipt) bool {
	f := r.Dispatch
	id := invocationKey(r.Facts.Principal, r.Facts.InvocationID)
	if f.SourceDomain != i.profiles.root.Namespace || f.AudienceDomain != i.profiles.root.Namespace || f.CallerRef != r.Facts.Principal.Ref || f.InvocationID != r.Facts.InvocationID || f.AttemptID != id || f.ReplayID != id || f.FinalizedDispatchDigest != r.Facts.FinalizedSHA {
		return false
	}
	raw, err := f.SigningBytes()
	return err == nil && ed25519.Verify(i.profiles.root.PublicKey, raw, r.Signature)
}
