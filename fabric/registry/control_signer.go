package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

type ControlFacts struct {
	Frame   fabric.ControlFrame
	Payload []byte
}

// ControlGate must hold fresh actual caller authentication/authorization through
// signing. An old invocation context cannot substitute for this control session.
type ControlGate interface {
	WithControl(context.Context, ControlFacts, func(context.Context) error) error
}

// Same-root peer pins are checked in the signing transaction, never a nested TX.
type ControlTransactionGate interface {
	CheckControlTx(context.Context, *AuthorityTx, ControlFacts) error
}

func (s *Store) SignControlExact(ctx context.Context, owner, caller fabric.ExecutionContext, payload []byte, frame fabric.ControlFrame, gate ControlGate) (fabric.SignedControlProof, error) {
	if s == nil || ctx == nil || gate == nil || len(payload) == 0 || len(payload) > 64<<10 {
		return fabric.SignedControlProof{}, invalid("Current control authentication missing")
	}
	payload = bytes.Clone(payload)
	raw, err := frame.SigningBytes()
	if err != nil {
		return fabric.SignedControlProof{}, err
	}
	root, err := s.CurrentAuthorityIdentity(ctx)
	if err != nil {
		return fabric.SignedControlProof{}, err
	}
	validate := func() error {
		if frame.SourceDomain != root.Namespace || frame.SourceStoreID != root.StoreID || frame.SourceKeyRevision != root.KeyRevision || frame.Principal != caller.PrincipalView() || frame.PayloadDigest != sha256.Sum256(payload) {
			return invalid("Control root, caller or payload differs")
		}
		if err := caller.VerifyAuthenticatedData(raw, root.Namespace); err != nil {
			return err
		}
		issued, _ := time.Parse(time.RFC3339Nano, frame.IssuedAt)
		expires, _ := time.Parse(time.RFC3339Nano, frame.ExpiresAt)
		now := time.Now()
		if now.Before(issued) || !now.Before(expires) {
			return invalid("Control authorization expired or not yet valid")
		}
		return nil
	}
	if err = validate(); err != nil {
		return fabric.SignedControlProof{}, err
	}
	facts := ControlFacts{frame, bytes.Clone(payload)}
	lifetime, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	active, called, misused := true, false, false
	var failed error
	var proof fabric.SignedControlProof
	unchanged := func() bool {
		b, e := facts.Frame.SigningBytes()
		return e == nil && bytes.Equal(b, raw) && bytes.Equal(facts.Payload, payload)
	}
	err = gate.WithControl(lifetime, facts, func(current context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		if !active || called || current == nil || current.Err() != nil || lifetime.Err() != nil {
			misused = true
			return invalid("Control callback closed or repeated")
		}
		called = true
		failed = s.WithNativeAuthority(current, owner, AuthorityScope{}, func(tx *AuthorityTx) error {
			if !unchanged() {
				return invalid("Control facts changed")
			}
			if same, ok := gate.(ControlTransactionGate); ok {
				if err := same.CheckControlTx(current, tx, facts); err != nil {
					return err
				}
			}
			if !unchanged() {
				return invalid("Control transaction facts changed")
			}
			tx.mu.Lock()
			defer tx.mu.Unlock()
			if err := tx.guard(); err != nil {
				return err
			}
			if err := validate(); err != nil {
				return err
			}
			proof = fabric.SignedControlProof{Frame: frame, Signature: ed25519.Sign(s.key, raw)}
			return nil
		})
		return failed
	})
	mu.Lock()
	active = false
	cancel()
	complete, bad, step := called, misused, failed
	mu.Unlock()
	if err != nil {
		return fabric.SignedControlProof{}, err
	}
	if step != nil {
		return fabric.SignedControlProof{}, step
	}
	if !complete || bad {
		return fabric.SignedControlProof{}, invalid("Control gate did not commit")
	}
	return proof, nil
}
