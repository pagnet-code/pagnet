// Package textbridge coordinates durable, at-most-once text provider work.
package textbridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/textbridge/ledger"
	"github.com/pagnet-code/pagnet/internal/textbridge/provider"
	"github.com/pagnet-code/pagnet/sdk"
)

// Ledger keeps dispatch authorization and job state durable before side effects.
type Ledger interface {
	Insert(context.Context, string, string, ledger.Data) (ledger.Job, error)
	List(context.Context, ...ledger.Phase) ([]ledger.Job, error)
	Get(context.Context, string, string) (ledger.Job, error)
	CompareAndSwap(context.Context, ledger.Job, ledger.Phase, ledger.Data) (ledger.Job, error)
	ClaimProvider(context.Context, ledger.Job, time.Time) (ledger.Job, string, error)
	FinishProvider(context.Context, string, string, string, []byte, bool) (ledger.Job, error)
}

type Transport interface {
	SharingProjectStatus(context.Context, string) (sdk.SharingProjectStatus, error)
	PrepareSharingProjectMessageWithID(string, string, string, string, []byte, []byte) (sdk.PreparedSharingProjectMessage, error)
	LoadPreparedSharingProjectMessage(string, string) (sdk.PreparedSharingProjectMessage, error)
	SharingProjectMessageReceipt(context.Context, string, string) (sdk.SharingProjectMessageReceipt, error)
	SendPreparedSharingProjectMessage(context.Context, string, string) (sdk.SharingProjectMessageReceipt, error)
}

type Provider interface {
	Complete(context.Context, string) (string, error)
}

// Config contains only owner-supplied policy. Enabled must consult current local
// enablement and revocation; a nil function disables dispatch. OnError, if set,
// receives background failures and must return promptly. Configuration changes
// must use a different fingerprint to prevent old work using new credentials.
type Config struct {
	ProviderConfigFingerprint string
	Enabled                   func(projectID string) bool
	OnError                   func(error)
}

type Bridge struct {
	store     Ledger
	transport Transport
	provider  Provider
	config    Config
	wake      chan struct{}
	running   atomic.Bool
	quota     map[string]time.Time
}

func New(store Ledger, transport Transport, provider Provider, config Config) *Bridge {
	return &Bridge{store: store, transport: transport, provider: provider, config: config, wake: make(chan struct{}, 1), quota: make(map[string]time.Time)}
}

// Wake requests one recovery pass, for example when the SDK becomes ready.
// Repeated signals coalesce; there is no idle polling or automatic call replay.
func (b *Bridge) Wake() {
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

func digest(wire []byte) string { sum := sha256.Sum256(wire); return hex.EncodeToString(sum[:]) }
func validText(raw []byte, limit int) bool {
	return len(raw) <= limit*utf8.UTFMax && utf8.Valid(raw) && strings.TrimSpace(string(raw)) != "" && utf8.RuneCount(raw) <= limit
}

// HandleMessage is the SDK OnSharingProjectMessage callback. A successful return
// authorizes inbox acknowledgement only after durable storage or rejection.
func (b *Bridge) HandleMessage(ctx context.Context, message sdk.SharingProjectMessage) error {
	if message.Header.Kind == "REPLY" {
		return nil
	}
	if message.Header.Kind != "ASK" || len(message.Wire) == 0 {
		return errors.New("text bridge requires an authenticated ASK")
	}
	header, err := json.Marshal(message.Header)
	if err != nil {
		return err
	}
	job, err := b.store.Insert(ctx, message.Header.ProjectID, message.Header.ID, ledger.Data{
		Header: header, PredecessorWire: append([]byte(nil), message.Wire...), WireDigest: digest(message.Wire),
		Input: append([]byte(nil), message.Plaintext...), ProviderConfigFingerprint: b.config.ProviderConfigFingerprint,
	})
	if err != nil {
		return err
	}
	if !validText(message.Plaintext, provider.MaxInputChars) && job.Phase == ledger.Queued {
		_, err = b.store.CompareAndSwap(ctx, job, ledger.Rejected, job.Data)
		if err != nil {
			return err
		}
	}
	b.Wake()
	return nil
}

// Run serially recovers jobs at startup and on explicit wakes. A recovered
// ProviderStarted job remains unresolved, retaining its budget claim forever;
// the opaque dispatch token cannot be reconstructed and the call is not replayed.
func (b *Bridge) Run(ctx context.Context) error {
	if !b.running.CompareAndSwap(false, true) {
		return errors.New("text bridge worker already running")
	}
	defer b.running.Store(false)
	b.Wake()
	var timer *time.Timer
	var retry <-chan time.Time
	delay := time.Second
	retries := 0
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-b.wake:
			delay = time.Second
			retries = 0
		case <-retry:
		}
		if timer != nil {
			timer.Stop()
		}
		retry = nil
		jobs, err := b.store.List(ctx, ledger.Queued, ledger.OutputReady, ledger.ReplyPreparing, ledger.ReplyPrepared)
		if err != nil {
			// A failed scan cannot establish that the durable queue is empty.
			// Retry the read with backoff; no dispatch occurs before it succeeds.
			b.report(err)
			if retries < 5 {
				timer = time.NewTimer(delay)
				retry = timer.C
				delay = min(delay*2, 30*time.Second)
				retries++
			} else {
				b.report(errors.New("text bridge retry limit reached; awaiting wake"))
			}
			continue
		}
		retryNeeded := false
		var eligible time.Time
		for _, job := range jobs {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err := b.process(ctx, job); err != nil {
				var wait quotaWait
				if errors.As(err, &wait) {
					if eligible.IsZero() || wait.until.Before(eligible) {
						eligible = wait.until
					}
					continue
				}
				b.report(err)
				var transient transportError
				var storage storageError
				retryNeeded = retryNeeded || errors.As(err, &transient) || errors.As(err, &storage)
			}
		}
		// One-shot timers follow failures or quota hints; there is no idle scan.
		// Storage and ordinary transport failures get at most five retries per wake.
		// Quota hints retain their own deadline across wakes.
		var next time.Duration
		if retryNeeded && retries < 5 {
			retries++
			next = delay
			delay = min(delay*2, 30*time.Second)
		} else if retryNeeded {
			b.report(errors.New("text bridge retry limit reached; awaiting wake"))
		}
		if !eligible.IsZero() {
			quotaDelay := max(time.Until(eligible), time.Millisecond)
			if next == 0 || quotaDelay < next {
				next = quotaDelay
			}
		}
		if next > 0 {
			timer = time.NewTimer(next)
			retry = timer.C
		}
	}
}

type storageError struct{ error }

func (e storageError) Unwrap() error { return e.error }
func storageFailure(err error) error {
	if err != nil {
		return storageError{err}
	}
	return nil
}

type transportError struct{ error }

func (e transportError) Unwrap() error { return e.error }

func (b *Bridge) report(err error) {
	if b.config.OnError != nil {
		b.config.OnError(err)
	}
}

func (b *Bridge) authorized(ctx context.Context, job ledger.Job) (bool, error) {
	if job.Revoked || b.config.Enabled == nil || !b.config.Enabled(job.ProjectID) || job.Data.ProviderConfigFingerprint != b.config.ProviderConfigFingerprint {
		return false, nil
	}
	status, err := b.transport.SharingProjectStatus(ctx, job.ProjectID)
	if err != nil {
		return false, transportError{err}
	}
	return status.ProjectID == job.ProjectID && status.State == "active" && status.EndpointProved && b.config.Enabled(job.ProjectID), nil
}

func (b *Bridge) process(ctx context.Context, job ledger.Job) error {
	for {
		var err error
		// Reload before each action so a durable revocation wins over a stale scan.
		job, err = b.store.Get(ctx, job.ProjectID, job.AskID)
		if err != nil {
			return storageFailure(err)
		}
		switch job.Phase {
		case ledger.Queued:
			if !validText(job.Data.Input, provider.MaxInputChars) {
				if job.Revoked {
					return nil
				}
				_, err = b.store.CompareAndSwap(ctx, job, ledger.Rejected, job.Data)
				return storageFailure(err)
			}
			if active, err := b.authorized(ctx, job); err != nil || !active {
				return err
			}
			claimed, token, err := b.store.ClaimProvider(ctx, job, time.Now())
			if err != nil {
				if errors.Is(err, ledger.ErrLimit) || errors.Is(err, ledger.ErrStale) || errors.Is(err, ledger.ErrInvalid) {
					return err
				}
				return storageFailure(err)
			}
			output, callErr := b.provider.Complete(ctx, string(claimed.Data.Input))
			succeeded := callErr == nil && validText([]byte(output), provider.MaxOutputChars)
			// Even canceled dispatches must durably record ambiguity if storage remains
			// available. A failed finish leaves ProviderStarted, which is never replayed.
			finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			_, err = b.store.FinishProvider(finishCtx, job.ProjectID, job.AskID, token, []byte(output), succeeded)
			cancel()
			if err != nil {
				return storageFailure(err)
			}
			if !succeeded {
				return errors.New("text bridge provider result unknown")
			}
		case ledger.OutputReady:
			if active, err := b.authorized(ctx, job); err != nil || !active {
				return err
			}
			id, err := uuid.NewV7()
			if err != nil {
				return storageFailure(err)
			}
			data := job.Data
			data.ReplyID = id.String()
			job, err = b.store.CompareAndSwap(ctx, job, ledger.ReplyPreparing, data)
			if err != nil {
				return storageFailure(err)
			}
			var header sdk.SharingProjectMessageHeader
			if err = json.Unmarshal(job.Data.Header, &header); err != nil {
				return b.unknown(ctx, job)
			}
			// The ReplyID is durable before entering the SDK. This is the sole place
			// where preparation is allowed, including after any SDK error.
			prepared, prepareErr := b.transport.PrepareSharingProjectMessageWithID(job.ProjectID, header.SenderPrincipalID, "REPLY", job.Data.ReplyID, job.Data.Output, job.Data.PredecessorWire)
			if prepareErr != nil {
				prepared, err = b.transport.LoadPreparedSharingProjectMessage(job.ProjectID, job.Data.ReplyID)
				if err != nil {
					return b.loadFailure(ctx, job, err)
				}
			}
			if err = b.prepared(ctx, job, prepared); err != nil {
				return storageFailure(err)
			}
		case ledger.ReplyPreparing:
			// Missing ciphertext after a crash is ambiguous. Never prepare a second time.
			if job.Revoked {
				return nil
			}
			prepared, err := b.transport.LoadPreparedSharingProjectMessage(job.ProjectID, job.Data.ReplyID)
			if err != nil {
				return b.loadFailure(ctx, job, err)
			}
			if err = b.prepared(ctx, job, prepared); err != nil {
				return storageFailure(err)
			}
		case ledger.ReplyPrepared:
			receipt, receiptErr := b.transport.SharingProjectMessageReceipt(ctx, job.ProjectID, job.Data.ReplyID)
			if receiptErr == nil {
				if !validReceipt(job, receipt) {
					return errors.New("text bridge receipt binding mismatch")
				}
				job, err = b.store.Get(ctx, job.ProjectID, job.AskID)
				if err != nil {
					return storageFailure(err)
				}
				return b.admit(ctx, job, receipt)
			}
			key := job.ProjectID + "/" + job.AskID
			if until, limited := b.quota[key]; limited {
				if until.IsZero() {
					return nil
				}
				if time.Now().Before(until) {
					return quotaWait{until}
				}
				delete(b.quota, key)
			}
			if active, err := b.authorized(ctx, job); err != nil || !active {
				return err
			}
			// Status and receipt lookups can block while local authority changes.
			job, err = b.store.Get(ctx, job.ProjectID, job.AskID)
			if err != nil {
				return storageFailure(err)
			}
			if job.Phase != ledger.ReplyPrepared || job.Revoked || b.config.Enabled == nil || !b.config.Enabled(job.ProjectID) {
				return nil
			}
			receipt, err = b.transport.SendPreparedSharingProjectMessage(ctx, job.ProjectID, job.Data.ReplyID)
			if err != nil {
				var quota *sdk.SharingProjectMessageQuotaError
				if errors.As(err, &quota) {
					until := quotaRetryAt(quota, time.Now())
					b.quota[key] = until
					if !until.IsZero() {
						return quotaWait{until}
					}
					return err
				}
				return transportError{err}
			}
			if !validReceipt(job, receipt) {
				return errors.New("text bridge receipt binding mismatch")
			}
			// Reload because revocation may race sending; a validated receipt may still
			// reconcile admission, while CAS prevents changes to the prepared identity.
			job, err = b.store.Get(ctx, job.ProjectID, job.AskID)
			if err != nil {
				return storageFailure(err)
			}
			return b.admit(ctx, job, receipt)
		default:
			return nil
		}
	}
}

// quotaWait schedules a one-shot wake without consuming storage retry allowance.
type quotaWait struct{ until time.Time }

func (e quotaWait) Error() string { return "text bridge waiting for quota reset" }
func quotaRetryAt(q *sdk.SharingProjectMessageQuotaError, now time.Time) time.Time {
	var until time.Time
	if q.ResetAt != nil && q.ResetAt.After(now) {
		until = *q.ResetAt
	}
	if seconds, err := strconv.ParseInt(q.RetryAfter, 10, 64); err == nil && seconds > 0 && seconds <= int64((1<<63-1)/int64(time.Second)) {
		retry := now.Add(time.Duration(seconds) * time.Second)
		if retry.After(until) {
			until = retry
		}
	} else if retry, err := http.ParseTime(q.RetryAfter); err == nil && retry.After(now) && retry.After(until) {
		until = retry
	}
	return until
}
func (b *Bridge) loadFailure(ctx context.Context, job ledger.Job, err error) error {
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, sdk.ErrSharingProjectMessageAbandoned) {
		return b.unknown(ctx, job)
	}
	// SDK read errors are not evidence that ciphertext is absent or invalid.
	return storageFailure(err)
}
func (b *Bridge) unknown(ctx context.Context, job ledger.Job) error {
	_, err := b.store.CompareAndSwap(ctx, job, ledger.Unknown, job.Data)
	return storageFailure(err)
}
func (b *Bridge) prepared(ctx context.Context, job ledger.Job, prepared sdk.PreparedSharingProjectMessage) error {
	if prepared.ID != job.Data.ReplyID || len(prepared.Wire) == 0 {
		return b.unknown(ctx, job)
	}
	data := job.Data
	data.ReplyDigest = digest(prepared.Wire)
	_, err := b.store.CompareAndSwap(ctx, job, ledger.ReplyPrepared, data)
	return storageFailure(err)
}
func validReceipt(job ledger.Job, receipt sdk.SharingProjectMessageReceipt) bool {
	return receipt.MessageID == job.Data.ReplyID && receipt.AdmissionSeq > 0 && !receipt.CreatedAt.IsZero() &&
		(receipt.Status == "pending" || receipt.Status == "acknowledged") && hex.EncodeToString(receipt.RequestDigest) == job.Data.ReplyDigest
}
func (b *Bridge) admit(ctx context.Context, job ledger.Job, receipt sdk.SharingProjectMessageReceipt) error {
	if !validReceipt(job, receipt) {
		return errors.New("text bridge receipt binding mismatch")
	}
	delete(b.quota, job.ProjectID+"/"+job.AskID)
	data := job.Data
	data.Receipt, _ = json.Marshal(receipt)
	_, err := b.store.CompareAndSwap(ctx, job, ledger.Admitted, data)
	return storageFailure(err)
}
