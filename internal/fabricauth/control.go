package fabricauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

// WithAuthenticatedControl binds a private fresh control to the actual current
// kernel peer and retained root. It grants no invocation or ledger permission.
// Current policy and peer pins must still be checked by the control consumer.
// Callback is synchronous and bounded; it must not re-enter this Session.
func (s *Session) WithAuthenticatedControl(ctx context.Context, frame fabric.ControlFrame, payload []byte, next func(context.Context, fabric.ExecutionContext) error) error {
	if s == nil || ctx == nil || next == nil || len(payload) == 0 || len(payload) > 64<<10 {
		return denied()
	}
	payload = bytes.Clone(payload)
	raw, err := frame.SigningBytes()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || ctx.Err() != nil {
		return denied()
	}
	current, cancel := context.WithTimeout(ctx, s.authority.config.CheckTimeout)
	defer cancel()
	principal, err := s.verify(current)
	if err != nil {
		return err
	}
	root := s.authority.config.Root
	issued, _ := time.Parse(time.RFC3339Nano, frame.IssuedAt)
	expires, _ := time.Parse(time.RFC3339Nano, frame.ExpiresAt)
	now := time.Now()
	if frame.Principal != principal || frame.SourceDomain != root.Namespace || frame.SourceStoreID != root.StoreID || frame.SourceKeyRevision != root.KeyRevision || frame.PayloadDigest != sha256.Sum256(payload) || now.Before(issued) || !now.Before(expires) {
		return denied()
	}
	caller, err := fabric.NewAuthenticatedContext(principal, root.Namespace, raw)
	if err != nil {
		return err
	}
	return next(current, caller)
}
