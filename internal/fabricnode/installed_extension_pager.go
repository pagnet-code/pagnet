package fabricnode

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension/continuation"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/internal/fabricadmin"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
)

// Each handle reserves one complete, bounded frame window before irreversible
// claim/effects. Reads are pull driven: at most one owned Next is in flight.
type ExtensionPagerOptions struct {
	MaxHandles int
	MaxBytes   int64
	TTL        time.Duration
}

func DefaultExtensionPagerOptions() ExtensionPagerOptions {
	return ExtensionPagerOptions{32, 32 << 20, 5 * time.Minute}
}

const extensionPageReservation = fabricadmin.MaxResponseBytes

type extensionResumeInput struct {
	ID      string `json:"id"`
	ClaimID string `json:"claimId"`
}
type extensionPageInput struct {
	Handle     string `json:"handle"`
	ACK        string `json:"ack,omitempty"`
	WaitMillis int    `json:"waitMillis,omitempty"`
}
type ExtensionResumeReceipt struct {
	ID      string               `json:"id"`
	State   continuation.State   `json:"state"`
	Fresh   bool                 `json:"fresh"`
	Receipt continuation.Receipt `json:"receipt"`
	Effect  fabric.EffectState   `json:"effect,omitempty"`
	Handle  string               `json:"handle,omitempty"`
}
type ExtensionStreamPage struct {
	Handle   string                   `json:"handle"`
	Cursor   uint64                   `json:"cursor,string"`
	Frames   []fabric.InvocationFrame `json:"frames,omitempty"`
	Digest   string                   `json:"digest,omitempty"`
	Pending  bool                     `json:"pending,omitempty"`
	Terminal bool                     `json:"terminal,omitempty"`
}
type extensionAdminPager struct {
	runtime      *ExtensionRuntime
	options      ExtensionPagerOptions
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.Mutex
	entries      map[string]*extensionPageEntry
	claims       map[string]*extensionPageEntry
	closing      bool
	closeAttempt *extensionPagerCloseAttempt
	work         sync.WaitGroup
}
type extensionPagerCloseAttempt struct {
	done chan struct{}
	err  error
}
type extensionPageEntry struct {
	handle, key string
	scope       *fabricauth.OwnerStreamSession
	created     chan struct{}
	ready       chan struct{}
	mu          sync.Mutex
	stream      fabric.InvocationStream
	result      ExtensionResumeReceipt
	resumeErr   error
	page        *ExtensionStreamPage
	lastACK     string
	cursor      uint64
	terminal    bool
	expired     bool
	loading     bool
	readErr     error
	closeMu     sync.Mutex
	closed      bool
	stopTimer   *time.Timer
	retired     chan struct{}
	retireOnce  sync.Once
}

func extensionHexID(s string) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == s
}
func newExtensionAdminPager(runtime *ExtensionRuntime, o ExtensionPagerOptions) (*extensionAdminPager, error) {
	if runtime == nil || o.MaxHandles < 1 || o.MaxHandles > 1024 || o.MaxBytes < int64(extensionPageReservation) || o.MaxBytes > 1<<30 || int64(o.MaxHandles) > o.MaxBytes/int64(extensionPageReservation) || o.TTL < time.Second || o.TTL > time.Hour {
		return nil, localDenied()
	}
	ctx, cancel := context.WithCancel(runtime.ctx)
	return &extensionAdminPager{runtime: runtime, options: o, ctx: ctx, cancel: cancel, entries: map[string]*extensionPageEntry{}, claims: map[string]*extensionPageEntry{}}, nil
}
func (p *extensionAdminPager) Resume(ctx context.Context, admin *fabricauth.OwnerAdministration, input extensionResumeInput, service *node.Service) (ExtensionResumeReceipt, error) {
	if ctx == nil || service == nil || !extensionHexID(input.ID) || !extensionHexID(input.ClaimID) {
		return ExtensionResumeReceipt{}, localDenied()
	}
	scope, err := admin.StreamSession(ctx)
	if err != nil {
		return ExtensionResumeReceipt{}, err
	}
	notifications, ok := any(scope).(interface{ Done() <-chan struct{} })
	if !ok {
		return ExtensionResumeReceipt{}, fabric.NewError(fabric.CodeUnsupported, "Private owner stream revocation notification unavailable")
	}
	key := input.ID + ":" + input.ClaimID
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		return ExtensionResumeReceipt{}, localDenied()
	}
	if prior := p.claims[key]; prior != nil {
		p.mu.Unlock()
		if err = prior.scope.VerifyCurrent(ctx, admin); err != nil {
			return ExtensionResumeReceipt{}, err
		}
		select {
		case <-prior.created:
		case <-ctx.Done():
			return ExtensionResumeReceipt{}, ctx.Err()
		}
		if err = prior.scope.VerifyCurrent(ctx, admin); err != nil {
			return ExtensionResumeReceipt{}, err
		}
		prior.mu.Lock()
		defer prior.mu.Unlock()
		result := prior.result
		result.Fresh = false
		if prior.expired || prior.closed {
			result.Handle = ""
		}
		return result, prior.resumeErr
	}
	if len(p.entries) >= p.options.MaxHandles {
		p.mu.Unlock()
		return ExtensionResumeReceipt{}, fabric.NewError(fabric.CodeTargetUnavailable, "Private continuation paging capacity reached")
	}
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		p.mu.Unlock()
		return ExtensionResumeReceipt{}, err
	}
	entry := &extensionPageEntry{handle: hex.EncodeToString(nonce), key: key, scope: scope, created: make(chan struct{}), ready: make(chan struct{}), retired: make(chan struct{})}
	clear(nonce)
	p.entries[entry.handle] = entry
	p.claims[key] = entry
	p.work.Add(1)
	p.mu.Unlock()
	defer p.work.Done()
	resumed, err := p.runtime.Resume(ctx, admin, input.ID, input.ClaimID, service)
	entry.mu.Lock()
	entry.stream = resumed.Outcome.Stream
	entry.resumeErr = err
	entry.result = ExtensionResumeReceipt{ID: input.ID, State: resumed.Claim.State, Fresh: resumed.Claim.Fresh, Receipt: resumed.Claim.Receipt}
	if resumed.Claim.Outcome != nil {
		entry.result.Effect = resumed.Claim.Outcome.Effect
	}
	if entry.stream != nil {
		entry.result.Handle = entry.handle
	}
	entry.stopTimer = time.AfterFunc(p.options.TTL, func() { entry.mu.Lock(); entry.expired = true; entry.mu.Unlock() })
	close(entry.created)
	result := entry.result
	entry.mu.Unlock()
	p.work.Add(1)
	go func() {
		defer p.work.Done()
		select {
		case <-notifications.Done():
			entry.mu.Lock()
			entry.expired = true
			entry.mu.Unlock()
		case <-entry.retired:
		case <-p.ctx.Done():
		}
	}()
	if entry.stream == nil {
		p.remove(entry)
	}
	return result, err
}
func (p *extensionAdminPager) entry(ctx context.Context, admin *fabricauth.OwnerAdministration, handle string) (*extensionPageEntry, error) {
	if !extensionHexID(handle) {
		return nil, localDenied()
	}
	p.mu.Lock()
	entry := p.entries[handle]
	closing := p.closing
	p.mu.Unlock()
	if entry == nil || closing {
		return nil, localDenied()
	}
	if err := entry.scope.VerifyCurrent(ctx, admin); err != nil {
		return nil, err
	}
	select {
	case <-entry.created:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return entry, nil
}
func cloneExtensionPage(page *ExtensionStreamPage) ExtensionStreamPage {
	copy := *page
	copy.Frames = append([]fabric.InvocationFrame(nil), page.Frames...)
	for i := range copy.Frames {
		copy.Frames[i].Data = append([]byte(nil), page.Frames[i].Data...)
		if copy.Frames[i].Error != nil {
			value := *copy.Frames[i].Error
			copy.Frames[i].Error = &value
		}
	}
	return copy
}
func (p *extensionAdminPager) Page(ctx context.Context, admin *fabricauth.OwnerAdministration, input extensionPageInput) (ExtensionStreamPage, error) {
	if input.WaitMillis < 0 || input.WaitMillis > 25000 {
		return ExtensionStreamPage{}, localDenied()
	}
	wait := 25 * time.Second
	if input.WaitMillis > 0 {
		wait = time.Duration(input.WaitMillis) * time.Millisecond
	}
	if err := p.beginOperation(); err != nil {
		return ExtensionStreamPage{}, err
	}
	defer p.work.Done()
	entry, err := p.entry(ctx, admin, input.Handle)
	if err != nil {
		return ExtensionStreamPage{}, err
	}
	entry.mu.Lock()
	if entry.expired || entry.closed || entry.stream == nil {
		entry.mu.Unlock()
		return ExtensionStreamPage{}, fabric.NewError(fabric.CodeTargetUnavailable, "Original continuation page delivery is unavailable")
	}
	if entry.page != nil && input.ACK != "" {
		if input.ACK != entry.page.Digest && input.ACK != entry.lastACK {
			entry.mu.Unlock()
			return ExtensionStreamPage{}, fabric.NewError(fabric.CodeProtocolError, "Private stream acknowledgement does not match original page")
		}
		if input.ACK == entry.page.Digest {
			entry.lastACK = input.ACK
			entry.page = nil
			entry.cursor++
		}
	} else if input.ACK != "" && input.ACK != entry.lastACK {
		entry.mu.Unlock()
		return ExtensionStreamPage{}, localDenied()
	}
	if entry.page != nil {
		result := cloneExtensionPage(entry.page)
		entry.mu.Unlock()
		if err = entry.scope.VerifyCurrent(ctx, admin); err != nil {
			return ExtensionStreamPage{}, err
		}
		return result, nil
	}
	if entry.readErr != nil {
		err = entry.readErr
		entry.mu.Unlock()
		return ExtensionStreamPage{}, err
	}
	if entry.terminal {
		result := ExtensionStreamPage{Handle: entry.handle, Cursor: entry.cursor, Terminal: true}
		entry.mu.Unlock()
		if err = entry.scope.VerifyCurrent(ctx, admin); err != nil {
			return ExtensionStreamPage{}, err
		}
		if err = entry.closeSource(); err != nil {
			return ExtensionStreamPage{}, err
		}
		p.remove(entry)
		return result, nil
	}
	if !entry.loading {
		entry.loading = true
		p.work.Add(1)
		go p.readOne(entry)
	}
	ready := entry.ready
	pending := ExtensionStreamPage{Handle: entry.handle, Cursor: entry.cursor, Pending: true}
	entry.mu.Unlock()
	// No source auth/SQL or provider call runs while waiting. A short API
	// timeout detaches only this wait; the single original Next stays owned.
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ready:
		return p.Page(ctx, admin, input)
	case <-timer.C:
	case <-ctx.Done():
		return ExtensionStreamPage{}, ctx.Err()
	}
	if err = entry.scope.VerifyCurrent(ctx, admin); err != nil {
		return ExtensionStreamPage{}, err
	}
	return pending, nil
}
func (p *extensionAdminPager) readOne(entry *extensionPageEntry) {
	defer p.work.Done()
	frame, err := entry.stream.Next(p.ctx)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	entry.loading = false
	if err != nil {
		if errors.Is(err, io.EOF) {
			err = fabric.NewError(fabric.CodeProtocolError, "Original source ended without a terminal page")
		}
		entry.readErr = err
	} else {
		page := ExtensionStreamPage{Handle: entry.handle, Cursor: entry.cursor, Frames: []fabric.InvocationFrame{frame}, Terminal: frame.Kind == fabric.FrameComplete || frame.Kind == fabric.FrameError}
		raw, e := json.Marshal(page)
		if e != nil || len(frame.Data) > fabric.MaxFrameBytes || len(raw) > extensionPageReservation-4096 {
			entry.readErr = fabric.NewError(fabric.CodeProtocolError, "Original private source frame exceeds reserved page bounds")
		} else {
			digest := sha256.Sum256(raw)
			page.Digest = hex.EncodeToString(digest[:])
			entry.page = &page
			entry.terminal = page.Terminal
		}
		clear(raw)
	}
	close(entry.ready)
	entry.ready = make(chan struct{})
}
func (p *extensionAdminPager) CloseSource(ctx context.Context, admin *fabricauth.OwnerAdministration, input extensionPageInput) error {
	if err := p.beginOperation(); err != nil {
		return err
	}
	defer p.work.Done()
	entry, err := p.entry(ctx, admin, input.Handle)
	if err != nil {
		return err
	}
	if input.ACK != "" {
		return localDenied()
	}
	if err = entry.closeSource(); err != nil {
		return err
	}
	p.remove(entry)
	return entry.scope.VerifyCurrent(ctx, admin)
}
func (entry *extensionPageEntry) closeSource() error {
	entry.closeMu.Lock()
	defer entry.closeMu.Unlock()
	entry.mu.Lock()
	stream, closed := entry.stream, entry.closed
	loading, readDone := entry.loading, entry.ready
	entry.mu.Unlock()
	if closed {
		return nil
	}
	if stream != nil {
		if err := stream.Close(); err != nil {
			return err
		}
	}
	if loading {
		<-readDone
	}
	entry.mu.Lock()
	entry.closed = true
	entry.expired = true
	entry.mu.Unlock()
	return nil
}
func (p *extensionAdminPager) CloseContext(ctx context.Context) error {
	if ctx == nil {
		return localDenied()
	}
	p.mu.Lock()
	p.closing = true
	attempt := p.closeAttempt
	if attempt != nil {
		select {
		case <-attempt.done:
			if attempt.err != nil {
				attempt = nil
			}
		default:
		}
	}
	if attempt == nil {
		attempt = &extensionPagerCloseAttempt{done: make(chan struct{})}
		p.closeAttempt = attempt
		entries := make([]*extensionPageEntry, 0, len(p.entries))
		for _, entry := range p.entries {
			entries = append(entries, entry)
		}
		go func() {
			p.cancel()
			for _, entry := range entries {
				<-entry.created
				entry.mu.Lock()
				timer := entry.stopTimer
				entry.mu.Unlock()
				if timer != nil {
					timer.Stop()
				}
				if err := entry.closeSource(); err != nil {
					attempt.err = err
					close(attempt.done)
					return
				}
			}
			p.work.Wait()
			close(attempt.done)
		}()
	}
	p.mu.Unlock()
	select {
	case <-attempt.done:
		return attempt.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *extensionAdminPager) beginOperation() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return localDenied()
	}
	p.work.Add(1)
	return nil
}
func (p *extensionAdminPager) remove(entry *extensionPageEntry) {
	p.mu.Lock()
	if p.entries[entry.handle] == entry {
		delete(p.entries, entry.handle)
	}
	if p.claims[entry.key] == entry {
		delete(p.claims, entry.key)
	}
	p.mu.Unlock()
	entry.retireOnce.Do(func() {
		entry.mu.Lock()
		if entry.stopTimer != nil {
			entry.stopTimer.Stop()
		}
		entry.mu.Unlock()
		close(entry.retired)
	})
}

// InspectClaim reads protected durable receipt metadata using a fresh permitted
// owner resumer. It cannot transfer the old connection's page window.
func (p *extensionAdminPager) InspectClaim(ctx context.Context, admin *fabricauth.OwnerAdministration, input extensionResumeInput) (ExtensionResumeReceipt, error) {
	if !extensionHexID(input.ID) || !extensionHexID(input.ClaimID) {
		return ExtensionResumeReceipt{}, localDenied()
	}
	var result ExtensionResumeReceipt
	err := p.runtime.administration(ctx, admin, func(current context.Context) error {
		return admin.WithResumerContext(current, func(call context.Context, resumer fabric.ExecutionContext) error {
			receipt, found, err := p.runtime.infrastructure.Continuations.ClaimReceipt(call, resumer, input.ID, input.ClaimID)
			if err != nil {
				return err
			}
			result = ExtensionResumeReceipt{ID: input.ID, State: continuation.Pending}
			if found {
				result.State = receipt.State
				result.Receipt = receipt.Receipt
				if receipt.Outcome != nil {
					result.Effect = receipt.Outcome.Effect
				}
			}
			return nil
		})
	})
	return result, err
}

// StopClaim is an explicit current-recipient request to join one exact retained
// original stream. It is independent of old delivery permission and never
// reconstructs a stream, reclaims execution, or reports completed effects.
func (p *extensionAdminPager) StopClaim(ctx context.Context, admin *fabricauth.OwnerAdministration, input extensionResumeInput) (ExtensionResumeReceipt, error) {
	if err := p.beginOperation(); err != nil {
		return ExtensionResumeReceipt{}, err
	}
	defer p.work.Done()
	result, err := p.InspectClaim(ctx, admin, input)
	if err != nil {
		return result, err
	}
	if result.Receipt.ID != input.ID || result.Receipt.ClaimID != input.ClaimID {
		return result, fabric.NewError(fabric.CodeTargetUnavailable, "Original continuation has no retained claimed source")
	}
	p.mu.Lock()
	entry := p.claims[input.ID+":"+input.ClaimID]
	p.mu.Unlock()
	if entry == nil {
		return result, fabric.NewError(fabric.CodeUnsupported, "Original claimed source is not retained in this process; no execution was recreated")
	}
	select {
	case <-entry.created:
	case <-ctx.Done():
		return result, ctx.Err()
	}
	entry.mu.Lock()
	exact := entry.result.Receipt == result.Receipt
	entry.mu.Unlock()
	if !exact {
		return result, localDenied()
	}
	if err = admin.VerifyCurrent(ctx); err != nil {
		return result, err
	}
	if err = entry.closeSource(); err != nil {
		return result, err
	}
	p.remove(entry)
	if err = admin.VerifyCurrent(ctx); err != nil {
		return result, err
	}
	return result, nil
}
