package daemon

import (
	"crypto/sha256"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
)

// DirectEndpointSubscriptionMetadata contains public identity only. Admission
// does not install a transport or restore a subscription after reconnect.
type DirectEndpointSubscriptionMetadata struct {
	InstallationID      domain.ID
	TenantID            domain.ID
	PrincipalID         domain.ID
	EndpointID          domain.ID
	OriginID            domain.ID
	IntentID            domain.ID
	CredentialID        domain.ID
	Role                string
	ServerOrigin        string
	OwnershipGeneration string
	Deadline            time.Time
}

type directEndpointBinding struct {
	metadata        DirectEndpointSubscriptionMetadata
	issueDigest     [sha256.Size]byte
	sessionIdentity string
	socket          *websocket.Conn
	native          *NativeObservationConnection
	link            *nativeWorkerLink
	proxy           *NativeWorkerProxy
	subject         nativeManagedSubject
}

// DirectEndpointSubscription is an opaque, exact admission generation. A stale
// handle can never remove a later admission of the same credential.
type DirectEndpointSubscription struct {
	owner   *directEndpointSubscriptions
	binding directEndpointBinding
	done    chan struct{}
	timer   *time.Timer // guarded by owner.mu
}

func (s *DirectEndpointSubscription) Done() <-chan struct{} { return s.done }
func (s *DirectEndpointSubscription) Metadata() DirectEndpointSubscriptionMetadata {
	return s.binding.metadata
}

// Valid checks local revocation and deadline only. It does not authorize HTTP
// or replace fresh fenced current-authority verification before material use.
func (s *DirectEndpointSubscription) Valid() bool {
	if s == nil || s.owner == nil {
		return false
	}
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	if _, ok := s.owner.entries[s]; !ok {
		return false
	}
	if !time.Now().Before(s.binding.metadata.Deadline) {
		s.owner.removeLocked(s)
		return false
	}
	return true
}

// Remove revokes exactly this generation and is idempotent.
func (s *DirectEndpointSubscription) Remove() {
	if s == nil || s.owner == nil {
		return
	}
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	s.owner.removeLocked(s)
}

// mu is a leaf lock: no registry, IPC, network, lifecycle locks or waits may be
// entered while held. Lifecycle invalidation only removes entries/closes Done.
type directEndpointSubscriptions struct {
	mu      sync.Mutex
	closed  bool
	entries map[*DirectEndpointSubscription]struct{}
}

func (o *directEndpointSubscriptions) add(binding directEndpointBinding) *DirectEndpointSubscription {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || !time.Now().Before(binding.metadata.Deadline) {
		return nil
	}
	if o.entries == nil {
		o.entries = make(map[*DirectEndpointSubscription]struct{})
	}
	s := &DirectEndpointSubscription{owner: o, binding: binding, done: make(chan struct{})}
	o.entries[s] = struct{}{}
	return s
}

// activate runs only after custody transaction completion and its final checks.
func (o *directEndpointSubscriptions) activate(s *DirectEndpointSubscription) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.entries[s]; !ok {
		return false
	}
	if !time.Now().Before(s.binding.metadata.Deadline) {
		o.removeLocked(s)
		return false
	}
	s.timer = time.AfterFunc(time.Until(s.binding.metadata.Deadline), s.Remove)
	return true
}

func (o *directEndpointSubscriptions) removeLocked(s *DirectEndpointSubscription) {
	if _, ok := o.entries[s]; !ok {
		return
	}
	delete(o.entries, s)
	if s.timer != nil {
		s.timer.Stop()
	}
	close(s.done)
}

func (o *directEndpointSubscriptions) revokeWhere(matches func(directEndpointBinding) bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for s := range o.entries {
		if matches(s.binding) {
			o.removeLocked(s)
		}
	}
}

func (o *directEndpointSubscriptions) close() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closed = true
	for s := range o.entries {
		o.removeLocked(s)
	}
}

// Lifecycle objects register owners while their authority fence is held. This
// index holds no credential material and only calls leaf owner invalidation.
type directEndpointInvalidations struct {
	mu     sync.Mutex
	owners map[*directEndpointSubscriptions]struct{}
}

func (i *directEndpointInvalidations) register(o *directEndpointSubscriptions) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.owners == nil {
		i.owners = make(map[*directEndpointSubscriptions]struct{})
	}
	i.owners[o] = struct{}{}
}
func (i *directEndpointInvalidations) revoke(matches func(directEndpointBinding) bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	for o := range i.owners {
		o.revokeWhere(matches)
	}
	i.owners = nil
}

// revokeMatching keeps registrations for lifecycle objects that remain usable
// after a generation fence (registry and native worker observations).
func (i *directEndpointInvalidations) revokeMatching(matches func(directEndpointBinding) bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	for o := range i.owners {
		o.revokeWhere(matches)
	}
}
