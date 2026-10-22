package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/netpolicy"
	"github.com/pagnet-code/pagnet/sdk"
	"github.com/pagnet-code/pagnet/transport"
)

const sharingBridgeProtocol = "sdk_pair_bridge_v1"
const sharingBridgeCommand = "host.reconcile_sharing_bridge"

// These DTOs deliberately keep activation material out of command envelopes.
type sharingBridgeInstallation struct {
	ID                   string `json:"id"`
	ServiceID            string `json:"serviceId"`
	DesiredState         string `json:"desiredState"`
	CredentialGeneration int64  `json:"credentialGeneration"`
}
type sharingBridgeClaim struct {
	Generation           int64     `json:"generation"`
	LeaseExpiresAt       time.Time `json:"leaseExpiresAt"`
	ActivationCredential string    `json:"activationCredential,omitempty"`
}
type sharingBridgeController struct {
	RunnerID           string    `json:"runnerId"`
	ConnectionEpoch    time.Time `json:"connectionEpoch"`
	ExpectedGeneration int64     `json:"expectedGeneration"`
	Status             string    `json:"status,omitempty"`
}
type sharingBridgeEndpoint interface {
	PrincipalID() string
	EnableSharingPairs()
	Close() error
	Done() <-chan struct{}
}
type sharingBridgeRuntime struct {
	cancel context.CancelFunc
	done   chan struct{}
	wake   chan struct{}
}
type sharingBridgeSupervisor struct {
	daemon  *Daemon
	http    *http.Client
	connect func(context.Context, sdk.Config) (sharingBridgeEndpoint, error)
	mu      sync.Mutex
	session *transport.HostSessionPayload
	wake    chan struct{}
	// owned by run only
	running map[string]*sharingBridgeRuntime
	retry   time.Duration
	renew   time.Duration
}

func newSharingBridgeSupervisor(d *Daemon) *sharingBridgeSupervisor {
	return &sharingBridgeSupervisor{daemon: d, http: netpolicy.NewHTTPClient(15*time.Second, d.InsecureRemoteHTTP), connect: func(ctx context.Context, cfg sdk.Config) (sharingBridgeEndpoint, error) { return sdk.Connect(ctx, cfg) }, wake: make(chan struct{}, 1), running: map[string]*sharingBridgeRuntime{}, retry: 5 * time.Second, renew: 30 * time.Second}
}
func (s *sharingBridgeSupervisor) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
func (s *sharingBridgeSupervisor) admit(p transport.HostSessionPayload) {
	s.mu.Lock()
	copy := p
	s.session = &copy
	s.mu.Unlock()
	s.signal()
}
func (s *sharingBridgeSupervisor) disconnect() { s.mu.Lock(); s.session = nil; s.mu.Unlock() }
func (s *sharingBridgeSupervisor) controller(generation int64, status string) (sharingBridgeController, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.session == nil {
		return sharingBridgeController{}, false
	}
	return sharingBridgeController{s.session.RunnerID, s.session.RunnerEpoch, generation, status}, true
}

// run has no idle ticker. Startup/reconnect and durable command wakes repair
// lost commands. Retries exist only while a reconciliation is outstanding.
func (s *sharingBridgeSupervisor) run(ctx context.Context) {
	defer func() {
		for _, r := range s.running {
			r.cancel()
		}
		for _, r := range s.running {
			<-r.done
		}
	}()
	var retry <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-retry:
		}
		retry = nil
		if _, ok := s.controller(0, ""); !ok {
			continue
		}
		if err := s.reconcile(ctx); err != nil {
			if ctx.Err() == nil {
				retry = time.After(s.retry)
			}
		}
	}
}
func (s *sharingBridgeSupervisor) request(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.daemon.ServerURL+"/api/v1/hosts/self/sharing-bridges"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.daemon.Credential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return errors.New("sharing bridge request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return sharingBridgeHTTPError(resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
		return errors.New("invalid sharing bridge response")
	}
	return nil
}

type sharingBridgeHTTPError int

func (e sharingBridgeHTTPError) Error() string { return fmt.Sprintf("sharing bridge HTTP %d", int(e)) }
func (s *sharingBridgeSupervisor) list(ctx context.Context) ([]sharingBridgeInstallation, error) {
	var all []sharingBridgeInstallation
	err := s.request(ctx, http.MethodGet, "", nil, &all)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, v := range all {
		if _, err := domain.ParseID(v.ID); err != nil {
			return nil, errors.New("invalid sharing bridge installation")
		}
		if _, err := domain.ParseID(v.ServiceID); err != nil {
			return nil, errors.New("invalid sharing bridge principal")
		}
		if seen[v.ID] || v.CredentialGeneration < 0 || v.DesiredState != "running" {
			return nil, errors.New("invalid sharing bridge recovery list")
		}
		seen[v.ID] = true
	}
	return all, nil
}

// A 404 can also reject an expired runner proof. Only the authenticated
// recovery list can confirm that the installation itself was removed.
func (s *sharingBridgeSupervisor) authorityRemoved(ctx context.Context, id string, err error) bool {
	if err == sharingBridgeHTTPError(http.StatusUnauthorized) || err == sharingBridgeHTTPError(http.StatusForbidden) {
		return true
	}
	if err != sharingBridgeHTTPError(http.StatusNotFound) {
		return false
	}
	all, listErr := s.list(ctx)
	if listErr != nil {
		return false
	}
	for _, v := range all {
		if v.ID == id {
			return false
		}
	}
	return true
}

func (s *sharingBridgeSupervisor) reconcile(ctx context.Context) error {
	all, err := s.list(ctx)
	if err != nil {
		return err
	}
	desired := map[string]sharingBridgeInstallation{}
	for _, v := range all {
		desired[v.ID] = v
	}
	for id, r := range s.running {
		_, exists := desired[id]
		// Completed workers are restarted only on an explicit reconciliation.
		finished := false
		select {
		case <-r.done:
			finished = true
		default:
		}
		if !exists || finished {
			r.cancel()
			<-r.done
			delete(s.running, id)
		}
	}
	// A successful list is authoritative for previously persisted installations.
	root := filepath.Join(s.daemon.StateDir, "sharing-bridges")
	entries, err := os.ReadDir(root)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			if _, err := domain.ParseID(e.Name()); err == nil {
				if _, ok := desired[e.Name()]; !ok {
					dir := filepath.Join(root, e.Name())
					release, err := lockSharingBridge(dir)
					if err != nil {
						return err
					}
					err = retireSharingBridge(dir)
					release()
					if err != nil {
						return err
					}
				}
			}
		}
	}
	for _, v := range all {
		if r := s.running[v.ID]; r != nil {
			select {
			case r.wake <- struct{}{}:
			default:
			}
			continue
		}
		child, cancel := context.WithCancel(ctx)
		r := &sharingBridgeRuntime{cancel: cancel, done: make(chan struct{}), wake: make(chan struct{}, 1)}
		s.running[v.ID] = r
		go func(v sharingBridgeInstallation) { defer close(r.done); s.runInstallation(child, v, r) }(v)
	}
	return nil
}

// The only persisted controller metadata is the generation. Activation values
// live in memory until SDK Connect saves the durable endpoint in its keyring.
type sharingBridgeState struct {
	Generation      int64 `json:"generation"`
	CredentialSaved bool  `json:"credentialSaved,omitempty"`
	Retired         bool  `json:"retired,omitempty"`
}

func saveSharingBridgeState(dir string, state sharingBridgeState) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	b, err := json.Marshal(state)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, filepath.Join(dir, "state.json")); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}
func retireSharingBridge(dir string) error {
	// Dedicated SDK state is removed only after the worker has stopped. The
	// singleton lock and nonsecret generation journal remain outside that tree.
	if err := os.RemoveAll(filepath.Join(dir, "sdk")); err != nil {
		return err
	}
	state := sharingBridgeState{Retired: true}
	if b, err := os.ReadFile(filepath.Join(dir, "state.json")); err == nil {
		var previous sharingBridgeState
		if json.Unmarshal(b, &previous) == nil {
			state.Generation = previous.Generation
		}
	}
	return saveSharingBridgeState(dir, state)
}

// recordWake stores only intent before the durable host command is ACKed.
// Recovery always re-lists authoritative server intent, including after a lost
// command or a crash between this write and the ACK.
func (s *sharingBridgeSupervisor) recordWake(id string) error {
	dir := filepath.Join(s.daemon.StateDir, "sharing-bridges", id)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "reconcile.intent"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	err = f.Sync()
	_ = f.Close()
	if err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	if err = parent.Sync(); err != nil {
		return err
	}
	s.signal()
	return nil
}

func (s *sharingBridgeSupervisor) runInstallation(ctx context.Context, v sharingBridgeInstallation, r *sharingBridgeRuntime) {
	dir := filepath.Join(s.daemon.StateDir, "sharing-bridges", v.ID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return
	}
	release, err := lockSharingBridge(dir)
	if err != nil {
		return
	}
	defer release()
	sdkDir := filepath.Join(dir, "sdk")
	generation := v.CredentialGeneration
	saved := sharingBridgeState{}
	if b, readErr := os.ReadFile(filepath.Join(dir, "state.json")); readErr == nil {
		if json.Unmarshal(b, &saved) != nil {
			return
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return
	}
	needClaim := saved.Generation != generation || !saved.CredentialSaved || saved.Retired
	var lease time.Time
	var endpoint sharingBridgeEndpoint
	var leaseTimer *time.Timer
	failures := 0
	wait := func(delay time.Duration) bool {
		t := time.NewTimer(delay)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-r.wake:
			return true
		case <-t.C:
			return true
		}
	}
	defer func() {
		if leaseTimer != nil {
			leaseTimer.Stop()
		}
		if endpoint != nil {
			_ = endpoint.Close()
		}
	}()
	closeEndpoint := func() {
		if leaseTimer != nil {
			leaseTimer.Stop()
			leaseTimer = nil
		}
		if endpoint != nil {
			_ = endpoint.Close()
			endpoint = nil
		}
	}
	for ctx.Err() == nil {
		if !lease.IsZero() && !time.Now().Before(lease) {
			closeEndpoint()
			lease = time.Time{}
		}
		status := "credential_saved"
		if needClaim {
			status = "starting"
		}
		controller, ok := s.controller(generation, status)
		if !ok {
			delay := s.retry
			if !lease.IsZero() && time.Until(lease) < delay {
				delay = max(time.Until(lease), time.Millisecond)
			}
			if !wait(delay) {
				return
			}
			continue
		}
		var claim sharingBridgeClaim
		err = s.request(ctx, http.MethodPost, "/"+url.PathEscape(v.ID)+"/renew", controller, &claim)
		credential := ""
		if err == nil && !needClaim {
			credential, err = sdk.StoredCredential(sdkDir, v.ServiceID)
			if err != nil {
				return
			}
		}
		if err != nil || credential == "" {
			if s.authorityRemoved(ctx, v.ID, err) {
				closeEndpoint()
				_ = retireSharingBridge(dir)
				return
			}
			// A live endpoint may outlast a brief host reconnect but never its lease.
			// A claim attempts the server-authorized handoff to the current epoch.
			err = s.request(ctx, http.MethodPost, "/"+url.PathEscape(v.ID)+"/claim", controller, &claim)
			if err == nil {
				if claim.Generation <= generation || claim.ActivationCredential == "" || !claim.LeaseExpiresAt.After(time.Now()) {
					return
				}
				generation = claim.Generation
				if err = saveSharingBridgeState(dir, sharingBridgeState{Generation: generation}); err != nil {
					return
				}
				// A fresh claim revokes every older durable credential. Keep the SDK's
				// keys but never present the old durable credential for this generation.
				credential = claim.ActivationCredential
			} else {
				if s.authorityRemoved(ctx, v.ID, err) {
					closeEndpoint()
					_ = retireSharingBridge(dir)
					return
				}
				if err == sharingBridgeHTTPError(http.StatusConflict) {
					// The preceding claim response may have been lost after committing.
					// Refresh the generation; never replay a possibly consumed activation.
					all, listErr := s.list(ctx)
					if listErr == nil {
						found := false
						for _, current := range all {
							if current.ID == v.ID {
								found = true
								if current.ServiceID != v.ServiceID {
									return
								}
								if generation != current.CredentialGeneration {
									closeEndpoint()
									lease = time.Time{}
									generation = current.CredentialGeneration
									needClaim = true
								}
								break
							}
						}
						if !found {
							closeEndpoint()
							_ = retireSharingBridge(dir)
							return
						}
					}
				}
				delay := s.retry
				if !lease.IsZero() && time.Until(lease) < delay {
					delay = max(time.Until(lease), time.Millisecond)
				}
				if !wait(delay) {
					return
				}
				continue
			}
		}
		if claim.Generation != generation || !claim.LeaseExpiresAt.After(time.Now()) {
			return
		}
		lease = claim.LeaseExpiresAt
		if endpoint == nil || claim.ActivationCredential != "" {
			connectCtx, cancel := context.WithTimeout(ctx, min(20*time.Second, time.Until(lease)))
			candidate, connectErr := s.connect(connectCtx, sdk.Config{Server: s.daemon.ServerURL, Credential: credential, StateDir: sdkDir, ExpectedPrincipalID: v.ServiceID})
			err = connectErr
			cancel()
			if err != nil {
				// An exchange can commit without delivering auth_ok. A new claim will
				// rotate that unreachable credential on the next attempt.
				needClaim = true
				failures++
				if failures >= 5 {
					return
				}
				if !wait(s.retry) {
					return
				}
				continue
			}
			if candidate.PrincipalID() != v.ServiceID {
				_ = candidate.Close()
				return
			}
			if err = saveSharingBridgeState(dir, sharingBridgeState{Generation: generation, CredentialSaved: true}); err != nil {
				_ = candidate.Close()
				return
			}
			closeEndpoint()
			endpoint = candidate
			failures = 0
			needClaim = false
			endpoint.EnableSharingPairs()
		}
		// The independent deadline closes transport even while an HTTP operation
		// is blocked. A failed renewal cannot keep an endpoint past its authority.
		if leaseTimer != nil {
			leaseTimer.Stop()
		}
		guardedEndpoint := endpoint
		leaseTimer = time.AfterFunc(max(time.Until(lease), 0), func() { _ = guardedEndpoint.Close() })
		delay := min(s.renew, time.Until(lease))
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-r.wake:
			t.Stop()
		case <-endpoint.Done():
			t.Stop()
			closeEndpoint()
			needClaim = true
		case <-t.C:
		}
	}
}
