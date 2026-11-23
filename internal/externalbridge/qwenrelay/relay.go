// Package qwenrelay relays policy-validated saved ASKs to one native Qwen turn
// at a time. Admission and reply receipts are immutable durable inbox records.
package qwenrelay

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/internal/externalbridge/inbox"
	"github.com/pagnet-code/pagnet/internal/runtimeconnect"
	"github.com/pagnet-code/pagnet/sdk"
)

// Inbox must validate the saved ASK against its fixed receiving policy.
type Inbox interface {
	PendingIDs() ([]string, error)
	GetSaved(string) (*sdk.Message, error)
	Notifications() <-chan struct{}
	MarkReplied(string, string) error
}

type Store interface {
	Put(inbox.Key, []byte) (bool, error)
	Get(inbox.Key) ([]byte, error)
}

type Qwen interface {
	AdmitPrompt(context.Context, string, string) (runtimeconnect.PromptResult, error)
	ResumePrompt(context.Context, runtimeconnect.PromptResult) (runtimeconnect.PromptResult, error)
}

type ReplyClient interface {
	SendDurableReply(context.Context, *sdk.Message, string) (string, error)
}

// Status reports progress without exposing ASK or result text. A blocked native
// turn requires operator inspection; another ASK cannot bypass it.
type Status struct {
	State string `json:"state"`
	Error string `json:"error,omitempty"`
}

type Relay struct {
	inbox    Inbox
	store    Store
	qwen     Qwen
	replies  ReplyClient
	mu       sync.Mutex
	running  bool
	statuses map[string]Status
	onStatus func(string, Status)
	retryMin time.Duration
	retryMax time.Duration
}

func New(in Inbox, store Store, qwen Qwen, replies ReplyClient) (*Relay, error) {
	if in == nil || store == nil || qwen == nil || replies == nil {
		return nil, errors.New("Qwen relay requires inbox, durable store, runtime and reply client")
	}
	return &Relay{inbox: in, store: store, qwen: qwen, replies: replies, statuses: map[string]Status{}, retryMin: time.Second, retryMax: 30 * time.Second}, nil
}

func (r *Relay) Status(id string) Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.statuses[id]
}

// SetStatusObserver receives state changes for operator diagnostics. The
// callback runs outside the relay lock and must not depend on ASK contents.
func (r *Relay) SetStatusObserver(observer func(string, Status)) {
	r.mu.Lock()
	r.onStatus = observer
	r.mu.Unlock()
}

func (r *Relay) status(id, state string, err error) {
	s := Status{State: state}
	if err != nil {
		s.Error = err.Error()
	}
	r.mu.Lock()
	r.statuses[id] = s
	observer := r.onStatus
	r.mu.Unlock()
	if observer != nil {
		func() {
			defer func() { _ = recover() }()
			observer(id, s)
		}()
	}
}

// Run scans on startup and inbox delivery. Only unfinished saved work schedules
// bounded backoff retries. Saved admission markers always fence repeat POSTs.
// A Relay has one Run owner. It never automatically resubmits a started ASK.
func (r *Relay) Run(ctx context.Context) error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return errors.New("Qwen relay already running")
	}
	r.running = true
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.running = false; r.mu.Unlock() }()
	notifications := r.inbox.Notifications()
	delay := r.retryMin
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		pending, err := r.scanPending(ctx)
		if err != nil {
			return err
		}
		var timer *time.Timer
		var retry <-chan time.Time
		if pending {
			timer = time.NewTimer(delay)
			retry = timer.C
			if delay < r.retryMax {
				delay *= 2
				if delay > r.retryMax {
					delay = r.retryMax
				}
			}
		} else {
			delay = r.retryMin
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return ctx.Err()
		case <-retry:
		case _, ok := <-notifications:
			if timer != nil {
				timer.Stop()
			}
			if !ok {
				return errors.New("Qwen relay inbox notifications closed")
			}
		}
	}
}

func key(m *sdk.Message, stage string) inbox.Key {
	return inbox.Key{NetworkID: m.NetworkID, PrincipalID: m.RecipientPrincipalID, MessageID: "native-" + stage + ":" + m.ID}
}

func (r *Relay) scan(ctx context.Context) error {
	_, err := r.scanPending(ctx)
	return err
}

func (r *Relay) scanPending(ctx context.Context) (bool, error) {
	ids, err := r.inbox.PendingIDs()
	if err != nil {
		return false, err
	}
	// Recover existing turns before admitting anything new, even if an older
	// pending ASK sorts before the one whose native admission was interrupted.
	var existing, fresh []*sdk.Message
	for _, id := range ids {
		m, err := r.inbox.GetSaved(id)
		if err != nil {
			r.status(id, "blocked", err)
			return false, err
		}
		if m == nil || m.ID != id || m.Kind != "ASK" {
			return false, errors.New("invalid saved relay ASK")
		}
		_, err = r.store.Get(key(m, "started"))
		if errors.Is(err, os.ErrNotExist) {
			fresh = append(fresh, m)
		} else if err != nil {
			return false, err
		} else {
			existing = append(existing, m)
		}
	}
	retry := false
	for _, m := range append(existing, fresh...) {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		blocked := r.process(ctx, m)
		switch r.Status(m.ID).State {
		case "completion-uncertain", "reply-uncertain", "reply-pending":
			retry = true
		}
		if blocked {
			break
		}
	}
	return retry, nil
}

// process returns true while native work might still be active.
func (r *Relay) process(ctx context.Context, m *sdk.Message) bool {
	fail := func(state string, err error, blocked bool) bool { r.status(m.ID, state, err); return blocked }
	if raw, err := r.store.Get(key(m, "replied")); err == nil {
		if len(raw) == 0 {
			return fail("blocked", errors.New("empty saved reply receipt"), true)
		}
		if err := r.inbox.MarkReplied(m.ID, string(raw)); err != nil {
			return fail("reply-pending", err, false)
		}
		r.status(m.ID, "replied", nil)
		return false
	} else if !errors.Is(err, os.ErrNotExist) {
		return fail("blocked", err, true)
	}
	if raw, err := r.store.Get(key(m, "failed")); err == nil {
		return fail("terminal-error", errors.New(string(raw)), false)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fail("blocked", err, true)
	}
	if raw, err := r.store.Get(key(m, "not-admitted")); err == nil {
		return fail("not-admitted", errors.New(string(raw)), false)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fail("blocked", err, true)
	}
	text, err := r.store.Get(key(m, "result"))
	if errors.Is(err, os.ErrNotExist) {
		var receipt runtimeconnect.PromptResult
		raw, err := r.store.Get(key(m, "accepted"))
		if errors.Is(err, os.ErrNotExist) {
			body := m.TextBody()
			if strings.TrimSpace(body) == "" || len(body) > 65536 || !utf8.ValidString(body) {
				return fail("rejected", errors.New("ASK text must be 1..65536 valid UTF-8 bytes"), false)
			}
			created, err := r.store.Put(key(m, "started"), []byte("started"))
			if err != nil {
				return fail("blocked", err, true)
			}
			if !created {
				return fail("admission-uncertain", errors.New("started ASK has no accepted receipt; automatic resubmission refused"), true)
			}
			r.status(m.ID, "admitting", nil)
			// Send only the untrusted ASK text, never metadata or generated tool
			// instructions that could expand the receiving policy's authority.
			receipt, err = r.qwen.AdmitPrompt(ctx, m.ID, body)
			if err != nil || !receipt.Accepted || receipt.PromptID == "" {
				if err == nil {
					err = errors.New("native admission did not return a valid receipt")
				}
				if !receipt.Accepted && !receipt.Uncertain {
					if _, saveErr := r.store.Put(key(m, "not-admitted"), []byte(err.Error())); saveErr != nil {
						return fail("blocked", saveErr, true)
					}
					return fail("not-admitted", err, false)
				}
				return fail("admission-uncertain", err, true)
			}
			raw, err = json.Marshal(receipt)
			if err != nil {
				return fail("blocked", err, true)
			}
			if _, err = r.store.Put(key(m, "accepted"), raw); err != nil {
				return fail("blocked", err, true)
			}
		} else if err != nil {
			return fail("blocked", err, true)
		} else if err = json.Unmarshal(raw, &receipt); err != nil {
			return fail("blocked", err, true)
		}
		if !receipt.Accepted || receipt.PromptID == "" || receipt.LastEventID < 0 {
			return fail("blocked", errors.New("invalid saved admission receipt"), true)
		}
		r.status(m.ID, "observing", nil)
		result, err := r.qwen.ResumePrompt(ctx, receipt)
		if err != nil && !result.Uncertain {
			if _, saveErr := r.store.Put(key(m, "failed"), []byte(err.Error())); saveErr != nil {
				return fail("blocked", saveErr, true)
			}
			return fail("terminal-error", err, false)
		}
		if err != nil || result.Uncertain || !result.Accepted || result.PromptID != receipt.PromptID {
			if err == nil {
				err = errors.New("native completion is uncertain")
			}
			return fail("completion-uncertain", err, true)
		}
		text = []byte(result.ResultText)
		if len(text) == 0 || len(text) > 65536 || !utf8.Valid(text) {
			return fail("blocked", errors.New("native result text is empty or exceeds bounds"), true)
		}
		if _, err = r.store.Put(key(m, "result"), text); err != nil {
			return fail("completion-uncertain", err, true)
		}
	} else if err != nil {
		return fail("blocked", err, true)
	}
	if len(text) == 0 || len(text) > 65536 || !utf8.Valid(text) {
		return fail("blocked", errors.New("invalid saved native result"), true)
	}
	r.status(m.ID, "replying", nil)
	id, err := r.replies.SendDurableReply(ctx, m, string(text))
	if err != nil || id == "" {
		if err == nil {
			err = errors.New("reply confirmation missing identity")
		}
		return fail("reply-uncertain", err, false)
	}
	if _, err := r.store.Put(key(m, "replied"), []byte(id)); err != nil {
		return fail("reply-pending", err, false)
	}
	if err := r.inbox.MarkReplied(m.ID, id); err != nil {
		return fail("reply-pending", err, false)
	}
	r.status(m.ID, "replied", nil)
	return false
}
