package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/netpolicy"
	"github.com/pagnet-code/pagnet/transport"
)

// Browser assignments contain desired configuration only, never credentials.
type browserAssignmentNetwork struct {
	NetworkID        string   `json:"networkId"`
	Grants           []string `json:"grants"`
	MessagingTargets []string `json:"messagingTargets"`
	Events           []string `json:"events"`
}
type browserAssignment struct {
	ID              string                     `json:"id"`
	Provider        string                     `json:"provider"`
	Name            string                     `json:"name"`
	Default         bool                       `json:"default"`
	DesiredRevision int64                      `json:"desiredRevision"`
	Networks        []browserAssignmentNetwork `json:"networks"`
	HostID          string                     `json:"hostId"`
	RuntimeMode     string                     `json:"runtimeMode"`
}
type browserAssignmentsSnapshot struct {
	Revision int64               `json:"browserAssignmentsRevision"`
	Items    []browserAssignment `json:"items"`
}
type browserAssignmentsHTTPError int

func (e browserAssignmentsHTTPError) Error() string {
	return fmt.Sprintf("browser assignments HTTP %d", int(e))
}

type browserAssignmentController struct {
	assignment browserAssignment
	cancel     context.CancelFunc
	done       chan struct{}
}

// The supervisor owns one fetch and the assignment controllers. Notices may arrive
// during a fetch; generation fences responses from a previous host connection.
type browserAssignmentSupervisor struct {
	daemon      *Daemon
	fetch       func(context.Context) (browserAssignmentsSnapshot, error)
	runBinding  func(context.Context, browserAssignment)
	wake        chan struct{}
	retryDelay  func(int) time.Duration
	mu          sync.Mutex
	generation  uint64
	connected   bool
	hostID      string
	dirty       bool
	wanted      int64
	applied     int64
	cancelFetch context.CancelFunc
	running     map[string]*browserAssignmentController
}

func newBrowserAssignmentSupervisor(d *Daemon) *browserAssignmentSupervisor {
	s := &browserAssignmentSupervisor{retryDelay: browserAssignmentRetryDelay, daemon: d, wake: make(chan struct{}, 1), running: map[string]*browserAssignmentController{}}
	s.runBinding = newBrowserBindingRunner(d, uuid.NewString())
	client := netpolicy.NewHTTPClient(15*time.Second, d.InsecureRemoteHTTP)
	s.fetch = func(ctx context.Context) (browserAssignmentsSnapshot, error) {
		var snapshot browserAssignmentsSnapshot
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.ServerURL+"/api/v1/hosts/self/browser-connections", nil)
		if err != nil {
			return snapshot, err
		}
		req.Header.Set("Authorization", "Bearer "+d.Credential)
		resp, err := client.Do(req)
		if err != nil {
			return snapshot, errors.New("browser assignments request failed")
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return snapshot, browserAssignmentsHTTPError(resp.StatusCode)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
		if err != nil || len(body) > 1<<20 {
			return snapshot, errors.New("invalid browser assignments response")
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		var wire struct {
			Revision *int64               `json:"browserAssignmentsRevision"`
			Items    *[]browserAssignment `json:"items"`
		}
		if err := decoder.Decode(&wire); err != nil || wire.Revision == nil || wire.Items == nil {
			return snapshot, errors.New("invalid browser assignments response")
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			return snapshot, errors.New("invalid browser assignments response")
		}
		snapshot.Revision, snapshot.Items = *wire.Revision, *wire.Items
		return snapshot, nil
	}
	return s
}
func (s *browserAssignmentSupervisor) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
func (s *browserAssignmentSupervisor) admit(hostID string) {
	s.mu.Lock()
	if s.cancelFetch != nil {
		s.cancelFetch()
	}
	s.generation++
	s.hostID = hostID
	s.connected = true
	s.dirty = true
	s.mu.Unlock()
	s.signal()
}
func (s *browserAssignmentSupervisor) disconnect() {
	s.mu.Lock()
	s.generation++
	s.connected = false
	s.dirty = false
	if s.cancelFetch != nil {
		s.cancelFetch()
	}
	s.mu.Unlock()
	s.signal()
}
func (s *browserAssignmentSupervisor) notice(p transport.BrowserConnectionsRevisionPayload) {
	s.mu.Lock()
	if !s.connected || p.HostID != s.hostID || p.BrowserAssignmentsRevision <= s.applied || p.BrowserAssignmentsRevision < s.wanted ||
		(p.BrowserAssignmentsRevision == s.wanted && (s.dirty || s.cancelFetch != nil)) || p.BrowserAssignmentsRevision < 0 {
		s.mu.Unlock()
		return
	}
	s.wanted = p.BrowserAssignmentsRevision
	s.dirty = true
	s.mu.Unlock()
	s.signal()
}
func validateBrowserAssignments(snapshot browserAssignmentsSnapshot, hostID string) error {
	if snapshot.Revision < 0 {
		return errors.New("invalid browser assignments revision")
	}
	seen := map[string]bool{}
	for _, a := range snapshot.Items {
		if _, err := domain.ParseID(a.ID); err != nil {
			return errors.New("invalid browser assignment ID")
		}
		if seen[a.ID] || a.HostID != hostID || a.RuntimeMode != "managed" || a.DesiredRevision < 1 {
			return errors.New("invalid browser assignment")
		}
		seen[a.ID] = true
		networks := map[string]bool{}
		for _, n := range a.Networks {
			if _, err := domain.ParseID(n.NetworkID); err != nil || networks[n.NetworkID] {
				return errors.New("invalid browser assignment network")
			}
			networks[n.NetworkID] = true
		}
	}
	return nil
}

// Detach under mu, then join without holding it: cancellation and socket
// revisions remain responsive while a child releases its remote lease.
func (s *browserAssignmentSupervisor) detachAllLocked() []*browserAssignmentController {
	stopped := make([]*browserAssignmentController, 0, len(s.running))
	for id, c := range s.running {
		c.cancel()
		stopped = append(stopped, c)
		delete(s.running, id)
	}
	return stopped
}
func joinBrowserAssignmentControllers(stopped []*browserAssignmentController) {
	for _, c := range stopped {
		<-c.done
	}
}
func (s *browserAssignmentSupervisor) stopAll() {
	s.mu.Lock()
	stopped := s.detachAllLocked()
	s.mu.Unlock()
	joinBrowserAssignmentControllers(stopped)
}

// reconcileLocked returns with mu held, including while abandoning a snapshot
// superseded by a socket reconnect during the child join.
func (s *browserAssignmentSupervisor) reconcileLocked(ctx context.Context, snapshot browserAssignmentsSnapshot, generation uint64) bool {
	desired := map[string]browserAssignment{}
	for _, a := range snapshot.Items {
		desired[a.ID] = a
	}
	var stopped []*browserAssignmentController
	for id, c := range s.running {
		a, exists := desired[id]
		finished := false
		select {
		case <-c.done:
			finished = true
		default:
		}
		if !exists || finished || !reflect.DeepEqual(a, c.assignment) {
			c.cancel()
			stopped = append(stopped, c)
			delete(s.running, id)
		}
	}
	s.mu.Unlock()
	joinBrowserAssignmentControllers(stopped)
	s.mu.Lock()
	if !s.connected || s.generation != generation || ctx.Err() != nil || snapshot.Revision < s.wanted {
		return false
	}
	for id, a := range desired {
		if s.running[id] != nil {
			continue
		}
		child, cancel := context.WithCancel(ctx)
		c := &browserAssignmentController{assignment: a, cancel: cancel, done: make(chan struct{})}
		s.running[id] = c
		go func() { defer close(c.done); s.runBinding(child, c.assignment) }()
	}
	return true
}
func browserAssignmentRetryDelay(attempt int) time.Duration {
	delay := time.Second << min(attempt-1, 5)
	delay = delay*3/4 + time.Duration(rand.Int64N(int64(delay/2)))
	return min(delay, 30*time.Second)
}

func (s *browserAssignmentSupervisor) run(ctx context.Context) {
	defer s.stopAll()
	var controllerGeneration uint64
	var retry *time.Timer
	var retryC <-chan time.Time
	var retryGeneration uint64
	failures := 0
	stopRetry := func() {
		if retry != nil {
			retry.Stop()
		}
		retryC = nil
	}
	defer func() { stopRetry() }()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-retryC:
			retryC = nil
			s.mu.Lock()
			if s.connected && s.generation == retryGeneration {
				s.dirty = true
			}
			s.mu.Unlock()
		}
		for ctx.Err() == nil {
			s.mu.Lock()
			if controllerGeneration != s.generation {
				stopRetry()
				failures = 0
				stopped := s.detachAllLocked()
				controllerGeneration = s.generation
				s.mu.Unlock()
				joinBrowserAssignmentControllers(stopped)
				s.mu.Lock()
				if controllerGeneration != s.generation {
					s.mu.Unlock()
					continue
				}
			}
			if !s.connected {
				stopped := s.detachAllLocked()
				s.mu.Unlock()
				joinBrowserAssignmentControllers(stopped)
				break
			}
			if !s.dirty {
				s.mu.Unlock()
				break
			}
			stopRetry()
			generation, hostID := s.generation, s.hostID
			s.dirty = false
			requestCtx, cancel := context.WithCancel(ctx)
			s.cancelFetch = cancel
			s.mu.Unlock()
			snapshot, err := s.fetch(requestCtx)
			cancel()
			s.mu.Lock()
			s.cancelFetch = nil
			if s.generation != generation || !s.connected {
				s.mu.Unlock()
				continue
			}
			if err == nil {
				err = validateBrowserAssignments(snapshot, hostID)
			}
			if err == nil && (snapshot.Revision < s.wanted || snapshot.Revision < s.applied) {
				err = errors.New("stale browser assignments response")
			}
			if err == nil && ctx.Err() == nil {
				if !s.reconcileLocked(ctx, snapshot, generation) {
					s.mu.Unlock()
					continue
				}
				s.applied = snapshot.Revision
				s.wanted = snapshot.Revision
				// A notice received during the fetch is covered only because the
				// snapshot revision meets the latest wanted revision under mu.
				s.dirty = false
				failures = 0
			}
			if err != nil && ctx.Err() == nil && err != browserAssignmentsHTTPError(http.StatusNotFound) {
				s.daemon.Log.Warn("browser assignment sync failed", "err", err)
				failures++
				retryGeneration = generation
				retry = time.NewTimer(s.retryDelay(failures))
				retryC = retry.C
			}
			s.mu.Unlock()
		}
	}
}
