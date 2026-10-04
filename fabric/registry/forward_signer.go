package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"slices"
	"sync"

	"github.com/pagnet-code/pagnet/fabric"
)

// ForwardFacts are private trusted engine facts. The actual node composition
// must obtain its finalized request capability before calling this port; this
// method is not a public tool for signing caller-asserted engine provenance.
type ForwardFacts struct {
	Frame               fabric.ForwardFrame
	Original, Forwarded []byte
}

// ForwardGate holds the explicitly configured CURRENT owner-certified peer
// trust through the bounded signing callback. Signature verification alone is
// never a peer pin, current authorization, or durable replay admission.
type ForwardGate interface {
	WithForward(context.Context, ForwardFacts, func(context.Context) error) error
}

// ForwardTransactionGate validates peer pins retained in THIS authority ledger
// without opening a nested transaction. Its WithForward must not hold the same
// store's SQL/mutex; it may hold independent operator authorization instead.
// Independent external trust stores may use the ordinary ForwardGate fence.
type ForwardTransactionGate interface {
	CheckForwardTx(context.Context, *AuthorityTx, ForwardFacts) error
}

func forwardProvenance(e fabric.Envelope) fabric.Provenance {
	c := e.Context
	return fabric.Provenance{Origin: c.Origin, ParentID: c.ParentID, Ancestry: c.Ancestry, Hops: c.Hops, ExtensionChain: c.ExtensionChain, TriggerLineage: c.TriggerLineage}
}

func validateForwardExact(root AuthorityIdentity, caller fabric.ExecutionContext, original, forwarded []byte, f fabric.ForwardFrame) error {
	before, e := caller.DecodeVerifiedEnvelope(original, root.Namespace)
	if e != nil {
		return e
	}
	var after fabric.Envelope
	if fabric.DecodeJSON(forwarded, &after) != nil || after.Validate() != nil {
		return invalid("Forwarded envelope malformed")
	}
	if f.SourceDomain != root.Namespace || f.SourceStoreID != root.StoreID || f.SourceKeyRevision != root.KeyRevision || f.Principal != caller.PrincipalView() || f.Principal != after.Principal || f.Operation != before.Operation || f.Operation != after.Operation || f.InvocationID != before.ID || f.InvocationID != after.ID || f.OriginalEnvelopeDigest != sha256.Sum256(original) || f.ForwardedEnvelopeDigest != sha256.Sum256(forwarded) || f.Deadline != authorityDeadline(before) || f.Deadline != authorityDeadline(after) || !reflect.DeepEqual(f.OriginalProvenance, forwardProvenance(before)) || !reflect.DeepEqual(f.ForwardedProvenance, forwardProvenance(after)) {
		return invalid("Forward exact root, caller or lineage differs")
	}
	x, y := before, after
	x.Payload = nil
	y.Payload = nil
	x.Metadata = nil
	y.Metadata = nil
	x.Target = nil
	y.Target = nil
	x.ExpectedRevision = ""
	y.ExpectedRevision = ""
	x.Context.Hops = 0
	y.Context.Hops = 0
	x.Context.ExtensionChain = nil
	y.Context.ExtensionChain = nil
	if !reflect.DeepEqual(x, y) || after.Context.Hops != before.Context.Hops+1 || after.Context.Hops > 64 || len(after.Context.ExtensionChain) < len(before.Context.ExtensionChain) || !slices.Equal(before.Context.ExtensionChain, after.Context.ExtensionChain[:len(before.Context.ExtensionChain)]) {
		return invalid("Forwarded immutable fields or retained lineage changed")
	}
	if f.Operation == fabric.OperationInvoke {
		if after.Target == nil || f.Target == nil || *after.Target != *f.Target || after.ExpectedRevision != f.ExpectedRevision {
			return invalid("Forward exact target differs")
		}
	} else if after.Target != nil || after.ExpectedRevision != "" || f.Target != nil || f.ExpectedRevision != "" {
		return invalid("Forward read contains invocation target")
	}
	_, e = f.SigningBytes()
	return e
}

// SignForwardExact uses the SAME current retained registry root. Ordinary local
// CallerProof and DispatchAdmission formats remain unchanged and local-only.
// Retry/replay persistence and uncertain-delivery recovery are separate ports.
func (s *Store) SignForwardExact(ctx context.Context, owner, caller fabric.ExecutionContext, original, forwarded []byte, f fabric.ForwardFrame, gate ForwardGate) (fabric.SignedForwardProof, error) {
	if s == nil || ctx == nil || gate == nil {
		return fabric.SignedForwardProof{}, invalid("Current forwarding trust gate missing")
	}
	original = bytes.Clone(original)
	forwarded = bytes.Clone(forwarded)
	frameRaw, e := json.Marshal(f)
	if e != nil {
		return fabric.SignedForwardProof{}, e
	}
	var immutable fabric.ForwardFrame
	if fabric.DecodeJSONWithLimits(frameRaw, &immutable, fabric.WireLimits{MaxBytes: 128 << 10, MaxDepth: 16, MaxMembers: 4096}) != nil {
		return fabric.SignedForwardProof{}, invalid("Forward signing facts exceed bound")
	}
	f = immutable
	root, e := s.CurrentAuthorityIdentity(ctx)
	if e != nil {
		return fabric.SignedForwardProof{}, e
	}
	if e = validateForwardExact(root, caller, original, forwarded, f); e != nil {
		return fabric.SignedForwardProof{}, e
	}
	// Deep-copy typed lineage and exact bytes so a trusted gate cannot mutate
	// facts that will be signed or retain writable references into the caller.
	var gateFrame fabric.ForwardFrame
	if fabric.DecodeJSONWithLimits(frameRaw, &gateFrame, fabric.WireLimits{MaxBytes: 128 << 10, MaxDepth: 16, MaxMembers: 4096}) != nil {
		return fabric.SignedForwardProof{}, invalid("Forward signing facts exceed bound")
	}
	facts := ForwardFacts{gateFrame, bytes.Clone(original), bytes.Clone(forwarded)}
	lifetime, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	active, called, misused := true, false, false
	var proof fabric.SignedForwardProof
	var stepError error
	err := gate.WithForward(lifetime, facts, func(current context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		if !active || called || current == nil || current.Err() != nil || lifetime.Err() != nil {
			misused = true
			return invalid("Forward trust callback is closed or repeated")
		}
		called = true
		stepError = s.WithNativeAuthority(current, owner, AuthorityScope{}, func(tx *AuthorityTx) error {
			// Verify the gate did not modify its private copy into different facts.
			currentFrame, _ := json.Marshal(facts.Frame)
			if !bytes.Equal(currentFrame, frameRaw) || !bytes.Equal(facts.Original, original) || !bytes.Equal(facts.Forwarded, forwarded) {
				return invalid("Forward trust facts changed")
			}
			if sameStore, ok := gate.(ForwardTransactionGate); ok {
				if e := sameStore.CheckForwardTx(current, tx, facts); e != nil {
					return e
				}
				currentFrame, _ = json.Marshal(facts.Frame)
				if !bytes.Equal(currentFrame, frameRaw) || !bytes.Equal(facts.Original, original) || !bytes.Equal(facts.Forwarded, forwarded) {
					return invalid("Forward transaction facts changed")
				}
			}
			tx.mu.Lock()
			defer tx.mu.Unlock()
			if e := tx.guard(); e != nil {
				return e
			}
			if e := validateForwardExact(root, caller, original, forwarded, f); e != nil {
				return e
			}
			raw, e := f.SigningBytes()
			if e != nil {
				return e
			}
			proof = fabric.SignedForwardProof{Frame: f, Signature: ed25519.Sign(s.key, raw)}
			return nil
		})
		return stepError
	})
	mu.Lock()
	active = false
	cancel()
	complete, misuse, failed := called, misused, stepError
	mu.Unlock()
	if err != nil {
		return fabric.SignedForwardProof{}, err
	}
	if !complete || misuse || failed != nil {
		if failed != nil {
			return fabric.SignedForwardProof{}, failed
		}
		return fabric.SignedForwardProof{}, invalid("Forward trust gate did not commit")
	}
	return proof, nil
}
