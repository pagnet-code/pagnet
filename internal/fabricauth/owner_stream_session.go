package fabricauth

import (
	"context"

	"github.com/pagnet-code/pagnet/fabric"
)

// OwnerStreamSession binds private paging to the same genuine kernel connection.
// It grants no invocation, resume, operator or current-caller capability. Every
// page additionally needs a fresh active OwnerAdministration callback.
type OwnerStreamSession struct{ session *Session }

var closedOwnerStreamSessionDone = func() <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}()

func (*OwnerStreamSession) MarshalJSON() ([]byte, error) { return nil, denied() }
func (*OwnerStreamSession) UnmarshalJSON([]byte) error   { return denied() }

func (a *OwnerAdministration) StreamSession(ctx context.Context) (*OwnerStreamSession, error) {
	if e := a.VerifyCurrent(ctx); e != nil {
		return nil, e
	}
	return &OwnerStreamSession{session: a.session}, nil
}

func (s *OwnerStreamSession) VerifyCurrent(ctx context.Context, a *OwnerAdministration) error {
	if s == nil || s.session == nil || a == nil || a.session != s.session || s.session.revoked.Load() {
		return fabric.NewError(fabric.CodeUnauthenticated, "Private stream belongs to a different or closed owner connection")
	}
	return a.VerifyCurrent(ctx)
}

// Revoked is a cheap cleanup hint only. False is never authentication evidence.
func (s *OwnerStreamSession) Revoked() bool {
	return s == nil || s.session == nil || s.session.revoked.Load()
}

// Done observes the actual connection close. It is a cleanup signal only;
// current kernel/root checks remain mandatory for every private page.
func (s *OwnerStreamSession) Done() <-chan struct{} {
	if s == nil || s.session == nil {
		return closedOwnerStreamSessionDone
	}
	peer := s.session
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.revocationDone == nil {
		peer.revocationDone = make(chan struct{})
		if peer.closed {
			close(peer.revocationDone)
		}
	}
	return peer.revocationDone
}
