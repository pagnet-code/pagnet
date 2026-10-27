package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pagnet-code/pagnet/internal/textbridge"
	"github.com/pagnet-code/pagnet/internal/textbridge/ledger"
	"github.com/pagnet-code/pagnet/internal/textbridge/sender"
	"github.com/pagnet-code/pagnet/sdk"
)

type textServiceRuntime struct {
	client                 *textServiceClient
	profile                textbridge.Profile
	dir                    string
	store                  *ledger.Store
	senderStore            *sender.Store
	generation             int64
	claimID                string
	cancel                 context.CancelFunc
	enabled                atomic.Bool
	stopped, release, done chan struct{}
	endpointWatch          <-chan struct{}
	endpoint               atomic.Value // stores <-chan struct{} after endpoint authentication
	finishMu               sync.Mutex
	released, disable      bool
}

func (s *textServiceSupervisor) startRuntime(parent context.Context, c *textServiceClient, dir string, p textbridge.Profile, store *ledger.Store, senderStore *sender.Store, unlock func(), a textServiceAttempt) (bool, error) {
	if (p.ServiceRole() == "sender" && s.runSender == nil) || (p.ServiceRole() == "responder" && s.runProfile == nil) {
		return false, nil
	}
	var body textServiceClaimBody
	if json.Unmarshal(a.Body, &body) != nil || a.InstallationID != p.Registration.InstallationID || a.Server != c.server || a.AdmissionID != c.session.NativeAdmissionID || body.RunnerID != c.session.RunnerID || !body.ConnectionEpoch.Equal(c.session.RunnerEpoch) || !textServiceUUID(body.ClaimID) || a.Result == nil || a.Result.InstallationID != a.InstallationID || a.Result.ClaimID == nil || *a.Result.ClaimID != body.ClaimID || a.Result.Generation != body.ExpectedGeneration+1 || a.Result.ClaimExpiresAt == nil {
		return false, errTextServiceSession
	}
	nonce, e := base64.StdEncoding.Strict().DecodeString(body.Nonce)
	if e != nil || len(nonce) != 32 {
		return false, errTextServiceSession
	}
	// The proof deadline bounds startup only; a proven connection never renews.
	if !a.Result.ClaimExpiresAt.After(time.Now()) {
		return false, errTextServiceOutstanding
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != c || c.ctx.Err() != nil || s.running[a.InstallationID] != nil {
		return false, errTextServiceSession
	}
	a.Started = true
	if e = s.savePrivate(dir, "claim-attempt.json", a); e != nil {
		return false, e
	}
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(c.ctx, cancel)
	r := &textServiceRuntime{client: c, profile: p, dir: dir, store: store, senderStore: senderStore, generation: a.Result.Generation, claimID: body.ClaimID, cancel: cancel, stopped: make(chan struct{}), release: make(chan struct{}), done: make(chan struct{})}
	s.running[a.InstallationID] = r
	proof := sdk.TextServiceInstallationProof{InstallationID: a.InstallationID, ClaimID: body.ClaimID, Generation: a.Result.Generation, Nonce: nonce}
	config := textbridge.RuntimeConfig{Connect: s.connect, NewProvider: s.newProvider, Enabled: func(string) bool {
		if done, ok := r.endpoint.Load().(<-chan struct{}); ok {
			select {
			case <-done:
				return false
			default:
			}
		}
		return r.enabled.Load() && ctx.Err() == nil && c.ctx.Err() == nil
	}}
	config.Authorize = func(authCtx context.Context, conn textbridge.RuntimeConnection) error {
		pinned, ok := conn.(interface {
			TextServiceEndpointSession() (string, <-chan struct{}, error)
		})
		if !ok {
			return errors.New("text service endpoint cannot pin its session")
		}
		endpointID, endpointDone, err := pinned.TextServiceEndpointSession()
		if err != nil || !textServiceUUID(endpointID) {
			return errTextServiceSession
		}
		// Closing this transport immediately fences Enabled, independently of
		// scheduling the cancellation watcher or the SDK's reconnect loop.
		r.endpoint.Store(endpointDone)
		watchExited := make(chan struct{})
		r.endpointWatch = watchExited
		go func() {
			defer close(watchExited)
			select {
			case <-endpointDone:
				r.enabled.Store(false)
				cancel()
			case <-ctx.Done():
			}
		}()

		endpoint, ok := conn.(interface {
			ProveTextServiceInstallation(context.Context, sdk.TextServiceInstallationProof) (sdk.TextServiceReadiness, error)
		})
		if !ok {
			return errors.New("text service endpoint cannot prove installation")
		}
		proofCtx, proofCancel := context.WithDeadline(authCtx, *a.Result.ClaimExpiresAt)
		defer proofCancel()
		for {
			current, currentDone, err := pinned.TextServiceEndpointSession()
			if err != nil || current != endpointID || currentDone != endpointDone {
				return errTextServiceSession
			}
			result, err := endpoint.ProveTextServiceInstallation(proofCtx, proof)
			if proofCtx.Err() != nil || ctx.Err() != nil || c.ctx.Err() != nil {
				return errTextServiceSession
			}
			select {
			case <-endpointDone:
				return errTextServiceSession
			default:
			}
			if err == nil {
				if result.InstallationID != proof.InstallationID || result.ClaimID == nil || *result.ClaimID != proof.ClaimID || result.Generation != proof.Generation || !result.Ready {
					return errors.New("text service endpoint proof rejected")
				}
				select {
				case <-conn.Done():
					return errTextServiceSession
				default:
				}
				r.enabled.Store(true)
				return nil
			}
			timer := time.NewTimer(s.proofRetry)
			select {
			case <-proofCtx.Done():
				timer.Stop()
				return errTextServiceSession
			case <-conn.Done():
				timer.Stop()
				return errTextServiceSession
			case <-timer.C:
			}
		}
	}
	go func() {
		defer close(r.done)
		if p.ServiceRole() == "sender" {
			s.runSender(ctx, dir, p, senderStore, config)
		} else {
			s.runProfile(ctx, dir, p, store, config)
		}
		r.enabled.Store(false)
		cancel()
		stop()
		if r.endpointWatch != nil {
			<-r.endpointWatch
		}
		close(r.stopped)
		// Completion is an outstanding recovery, never an idle polling timer.
		time.AfterFunc(s.retry, s.signal)
		<-r.release
		if store != nil {
			store.Close()
		}
		if senderStore != nil {
			senderStore.Close()
		}
		unlock()
	}()
	return true, nil
}

// Runtime exit is joined before durable disable and before releasing its ledger
// or profile lock. A failed disable retains ownership for the next retry.
func (s *textServiceSupervisor) stopRuntime(r *textServiceRuntime, disable bool) error {
	r.enabled.Store(false)
	r.cancel()
	<-r.stopped
	r.finishMu.Lock()
	defer r.finishMu.Unlock()
	if r.released {
		return nil
	}
	r.disable = r.disable || disable
	if r.disable {
		if err := s.disableProfile(r.dir, r.profile, r.store, r.senderStore); err != nil {
			return err
		}
	}
	close(r.release)
	<-r.done
	r.released = true
	return nil
}

// Attempt both writes on every reconciliation: either durable gate prevents
// standalone dispatch while the other write is retried after a partial failure.
func (s *textServiceSupervisor) disableProfile(dir string, p textbridge.Profile, store *ledger.Store, senderStore *sender.Store) error {
	p.Disabled = true
	p.Registration.DesiredState = "disabled"
	var ledgerErr error
	if senderStore != nil {
		ledgerErr = senderStore.Disable(context.Background())
	} else {
		ledgerErr = s.disableLedger(store)
	}
	profileErr := s.savePrivate(dir, "profile.json", p)
	return errors.Join(ledgerErr, profileErr)
}
