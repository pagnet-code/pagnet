package textbridge

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/textbridge/ledger"
	"github.com/pagnet-code/pagnet/sdk"
)

var testContext = context.Background()
var boundaryError = errors.New("boundary failed")

type fakeProvider struct {
	calls    int
	complete func() (string, error)
}

func (p *fakeProvider) Complete(context.Context, string) (string, error) {
	p.calls++
	if p.complete != nil {
		return p.complete()
	}
	return "answer", nil
}

type fakeTransport struct {
	store                                    *ledger.Store
	status                                   sdk.SharingProjectStatus
	statusErr                                error
	prepares, loads, receipts, sends         int
	prepared                                 sdk.PreparedSharingProjectMessage
	prepareErr, loadErr, receiptErr, sendErr error
	receipt                                  sdk.SharingProjectMessageReceipt
	predecessor                              []byte
	onSend                                   func()
	onPrepare                                func()
	onReceipt                                func()
	onStatus                                 func()
	onLoad                                   func()
}

func (f *fakeTransport) SharingProjectStatus(context.Context, string) (sdk.SharingProjectStatus, error) {
	if f.onStatus != nil {
		f.onStatus()
	}
	return f.status, f.statusErr
}
func (f *fakeTransport) PrepareSharingProjectMessageWithID(project, recipient, kind, id string, output, predecessor []byte) (sdk.PreparedSharingProjectMessage, error) {
	f.prepares++
	job, err := f.store.Get(testContext, project, "ask")
	if err != nil || job.Phase != ledger.ReplyPreparing || job.Data.ReplyID != id || recipient != "sender" || kind != "REPLY" || string(output) != "answer" {
		panic("prepare preceded durable identity or used incorrect reply input")
	}
	f.predecessor = append([]byte(nil), predecessor...)
	f.prepared = sdk.PreparedSharingProjectMessage{ID: id, Wire: []byte("immutable encrypted reply")}
	if f.onPrepare != nil {
		f.onPrepare()
	}
	return f.prepared, f.prepareErr
}
func (f *fakeTransport) LoadPreparedSharingProjectMessage(string, string) (sdk.PreparedSharingProjectMessage, error) {
	f.loads++
	if f.onLoad != nil {
		f.onLoad()
	}
	return f.prepared, f.loadErr
}
func (f *fakeTransport) SharingProjectMessageReceipt(context.Context, string, string) (sdk.SharingProjectMessageReceipt, error) {
	f.receipts++
	if f.onReceipt != nil {
		f.onReceipt()
	}
	return f.receipt, f.receiptErr
}
func receiptFor(id string, wire []byte) sdk.SharingProjectMessageReceipt {
	raw, _ := hex.DecodeString(digest(wire))
	return sdk.SharingProjectMessageReceipt{MessageID: id, AdmissionSeq: 1, RequestDigest: raw, Status: "pending", CreatedAt: time.Now()}
}
func (f *fakeTransport) SendPreparedSharingProjectMessage(ctx context.Context, project, id string) (sdk.SharingProjectMessageReceipt, error) {
	f.sends++
	if f.receipts == 0 || id != f.prepared.ID {
		panic("send without receipt lookup or wrong ID")
	}
	if f.onSend != nil {
		f.onSend()
	}
	return receiptFor(id, f.prepared.Wire), f.sendErr
}

func setup(t *testing.T) (*Bridge, *ledger.Store, *fakeTransport, *fakeProvider, sdk.SharingProjectMessage) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := ledger.Open(filepath.Join(root, "ledger"), ledger.Binding{ServiceOrigin: "https://example.com", PrincipalID: "owner"}, ledger.Limits{CallsPerDay: 10, MaxConcurrent: 10})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	transport := &fakeTransport{store: store, status: sdk.SharingProjectStatus{ProjectID: "project", State: "active", EndpointProved: true}, receiptErr: boundaryError}
	provider := &fakeProvider{}
	bridge := New(store, transport, provider, Config{ProviderConfigFingerprint: "fixed-owner-config", Enabled: func(string) bool { return true }})
	message := sdk.SharingProjectMessage{Header: sdk.SharingProjectMessageHeader{ProjectID: "project", ID: "ask", Kind: "ASK", SenderPrincipalID: "sender"}, Plaintext: []byte("question"), Wire: []byte("exact authenticated ASK wire\n")}
	return bridge, store, transport, provider, message
}
func stored(t *testing.T, store *ledger.Store) ledger.Job {
	t.Helper()
	job, err := store.Get(testContext, "project", "ask")
	if err != nil {
		t.Fatal(err)
	}
	return job
}
func accept(t *testing.T, bridge *Bridge, message sdk.SharingProjectMessage) {
	t.Helper()
	if err := bridge.HandleMessage(testContext, message); err != nil {
		t.Fatal(err)
	}
}
func process(t *testing.T, bridge *Bridge, store *ledger.Store) {
	t.Helper()
	if err := bridge.process(testContext, stored(t, store)); err != nil {
		t.Fatal(err)
	}
}

func TestCallbackDeduplicatesAndPreservesWire(t *testing.T) {
	b, s, tr, p, m := setup(t)
	accept(t, b, m)
	accept(t, b, m)
	if p.calls != 0 || tr.prepares != 0 {
		t.Fatal("callback did external work")
	}
	m.Wire = []byte("conflicting wire")
	if err := b.HandleMessage(testContext, m); !errors.Is(err, ledger.ErrConflict) {
		t.Fatalf("conflict: %v", err)
	}
	process(t, b, s)
	job := stored(t, s)
	if job.Phase != ledger.Admitted || p.calls != 1 || tr.prepares != 1 || !bytes.Equal(tr.predecessor, job.Data.PredecessorWire) {
		t.Fatalf("job=%+v provider=%d prepare=%d", job, p.calls, tr.prepares)
	}
	id, err := uuid.Parse(job.Data.ReplyID)
	if err != nil || id.Version() != 7 {
		t.Fatal("reply ID not UUIDv7")
	}
	accept(t, b, sdk.SharingProjectMessage{Header: sdk.SharingProjectMessageHeader{Kind: "REPLY"}})
	process(t, b, s)
	if p.calls != 1 {
		t.Fatal("duplicate or REPLY dispatched")
	}
}
func TestInvalidInputDurablyRejected(t *testing.T) {
	for _, input := range [][]byte{[]byte("  "), {0xff}, bytes.Repeat([]byte("x"), 16001)} {
		t.Run(fmt.Sprint(len(input)), func(t *testing.T) {
			b, s, tr, p, m := setup(t)
			m.Plaintext = input
			accept(t, b, m)
			process(t, b, s)
			if stored(t, s).Phase != ledger.Rejected || p.calls != 0 || tr.prepares != 0 {
				t.Fatal("invalid text reached provider")
			}
		})
	}
}
func TestProviderAmbiguityNeverReplays(t *testing.T) {
	b, s, tr, p, m := setup(t)
	accept(t, b, m)
	p.complete = func() (string, error) { return "", boundaryError }
	if err := b.process(testContext, stored(t, s)); err == nil {
		t.Fatal("missing provider error")
	}
	process(t, b, s)
	if stored(t, s).Phase != ledger.Unknown || p.calls != 1 || tr.prepares != 0 {
		t.Fatal("ambiguous provider replayed")
	}
}
func TestUnresolvedClaimNotReplayed(t *testing.T) {
	b, s, tr, p, m := setup(t)
	accept(t, b, m)
	if _, _, err := s.ClaimProvider(testContext, stored(t, s), time.Now()); err != nil {
		t.Fatal(err)
	}
	process(t, b, s)
	if stored(t, s).Phase != ledger.ProviderStarted || p.calls != 0 || tr.prepares != 0 {
		t.Fatal("unresolved provider claim replayed")
	}
}
func outputReady(t *testing.T, b *Bridge, s *ledger.Store, m sdk.SharingProjectMessage) ledger.Job {
	t.Helper()
	accept(t, b, m)
	j, token, err := s.ClaimProvider(testContext, stored(t, s), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	j, err = s.FinishProvider(testContext, j.ProjectID, j.AskID, token, []byte("answer"), true)
	if err != nil {
		t.Fatal(err)
	}
	return j
}
func replyPreparing(t *testing.T, b *Bridge, s *ledger.Store, m sdk.SharingProjectMessage) ledger.Job {
	t.Helper()
	j := outputReady(t, b, s, m)
	d := j.Data
	d.ReplyID = uuid.Must(uuid.NewV7()).String()
	j, err := s.CompareAndSwap(testContext, j, ledger.ReplyPreparing, d)
	if err != nil {
		t.Fatal(err)
	}
	return j
}
func replyPrepared(t *testing.T, b *Bridge, s *ledger.Store, tr *fakeTransport, m sdk.SharingProjectMessage) ledger.Job {
	t.Helper()
	j := replyPreparing(t, b, s, m)
	tr.prepared = sdk.PreparedSharingProjectMessage{ID: j.Data.ReplyID, Wire: []byte("immutable reply")}
	if err := b.prepared(testContext, j, tr.prepared); err != nil {
		t.Fatal(err)
	}
	return stored(t, s)
}
func TestPreparingRecoveryLoadsOnlyPersistedID(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprint(missing), func(t *testing.T) {
			b, s, tr, p, m := setup(t)
			j := replyPreparing(t, b, s, m)
			tr.prepared = sdk.PreparedSharingProjectMessage{ID: j.Data.ReplyID, Wire: []byte("immutable reply")}
			if missing {
				tr.loadErr = os.ErrNotExist
			}
			process(t, b, s)
			want := ledger.Admitted
			if missing {
				want = ledger.Unknown
			}
			if stored(t, s).Phase != want || tr.prepares != 0 || tr.loads != 1 || p.calls != 0 {
				t.Fatal("preparation recovery did not fail closed")
			}
		})
	}
}
func TestPrepareErrorRecoversOnlyDurableCandidate(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprint(missing), func(t *testing.T) {
			b, s, tr, _, m := setup(t)
			outputReady(t, b, s, m)
			tr.prepareErr = boundaryError
			if missing {
				tr.loadErr = os.ErrNotExist
			}
			process(t, b, s)
			want := ledger.Admitted
			if missing {
				want = ledger.Unknown
			}
			if stored(t, s).Phase != want || tr.prepares != 1 || tr.loads != 1 {
				t.Fatal("prepare ambiguity caused reprepare")
			}
		})
	}
}
func TestSendAmbiguityReconcilesSameIDAfterRestart(t *testing.T) {
	b, s, tr, p, m := setup(t)
	accept(t, b, m)
	tr.sendErr = boundaryError
	if err := b.process(testContext, stored(t, s)); err == nil {
		t.Fatal("missing send error")
	}
	j := stored(t, s)
	if j.Phase != ledger.ReplyPrepared {
		t.Fatal(j.Phase)
	}
	tr.receipt = receiptFor(j.Data.ReplyID, tr.prepared.Wire)
	tr.receiptErr = nil
	// Successful SDK admission may retire ciphertext before the ledger commits.
	tr.prepared = sdk.PreparedSharingProjectMessage{}
	tr.loadErr = boundaryError
	restarted := New(s, tr, p, b.config)
	process(t, restarted, s)
	if stored(t, s).Phase != ledger.Admitted || p.calls != 1 || tr.prepares != 1 || tr.sends != 1 || tr.loads != 0 {
		t.Fatal("restart resent admitted reply")
	}
}
func TestReceiptReconcilesAfterRevocation(t *testing.T) {
	b, s, tr, p, m := setup(t)
	j := replyPrepared(t, b, s, tr, m)
	if _, err := s.Revoke(testContext, j); err != nil {
		t.Fatal(err)
	}
	b.config.Enabled = func(string) bool { return false }
	tr.status.State = "expired"
	tr.receipt = receiptFor(j.Data.ReplyID, tr.prepared.Wire)
	tr.receiptErr = nil
	process(t, b, s)
	if stored(t, s).Phase != ledger.Admitted || tr.sends != 0 || p.calls != 0 {
		t.Fatal("receipt recovery depended on expired authority")
	}
}
func TestInactiveAuthorityFailsClosed(t *testing.T) {
	for _, condition := range []string{"disabled", "revoked", "expired", "unproved", "offline", "config"} {
		t.Run(condition, func(t *testing.T) {
			b, s, tr, p, m := setup(t)
			accept(t, b, m)
			switch condition {
			case "disabled":
				b.config.Enabled = nil
			case "revoked":
				if _, err := s.Revoke(testContext, stored(t, s)); err != nil {
					t.Fatal(err)
				}
			case "expired":
				tr.status.State = "expired"
			case "unproved":
				tr.status.EndpointProved = false
			case "offline":
				tr.statusErr = boundaryError
			case "config":
				b.config.ProviderConfigFingerprint = "different"
			}
			err := b.process(testContext, stored(t, s))
			if condition == "offline" {
				if !errors.Is(err, boundaryError) {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if p.calls != 0 || tr.prepares != 0 || tr.sends != 0 {
				t.Fatal("inactive authority dispatched")
			}
		})
	}
}
func TestRevocationDuringProviderPreventsReply(t *testing.T) {
	b, s, tr, p, m := setup(t)
	accept(t, b, m)
	p.complete = func() (string, error) {
		if _, err := s.Revoke(testContext, stored(t, s)); err != nil {
			t.Fatal(err)
		}
		return "answer", nil
	}
	process(t, b, s)
	if p.calls != 1 || tr.prepares != 0 || tr.sends != 0 || !stored(t, s).Revoked {
		t.Fatal("revoked provider output dispatched")
	}
}
func TestInvalidReceiptCannotAdmit(t *testing.T) {
	b, s, tr, _, m := setup(t)
	j := replyPrepared(t, b, s, tr, m)
	tr.receiptErr = nil
	tr.receipt = receiptFor(j.Data.ReplyID, []byte("different wire"))
	if err := b.process(testContext, j); err == nil {
		t.Fatal("invalid receipt accepted")
	}
	if stored(t, s).Phase != ledger.ReplyPrepared || tr.sends != 0 {
		t.Fatal("invalid receipt admitted or sent")
	}
}

type claimFailure struct{ Ledger }

func (claimFailure) ClaimProvider(context.Context, ledger.Job, time.Time) (ledger.Job, string, error) {
	return ledger.Job{}, "", boundaryError
}
func TestFailedClaimCannotDispatch(t *testing.T) {
	b, s, tr, p, m := setup(t)
	accept(t, b, m)
	b.store = claimFailure{s}
	if err := b.process(testContext, stored(t, s)); !errors.Is(err, boundaryError) {
		t.Fatal(err)
	}
	if p.calls != 0 || tr.prepares != 0 {
		t.Fatal("failed claim authorized provider")
	}
}

type observedLedger struct {
	Ledger
	scans   atomic.Int32
	scanned chan struct{}
	once    sync.Once
}

func (l *observedLedger) List(ctx context.Context, phases ...ledger.Phase) ([]ledger.Job, error) {
	l.scans.Add(1)
	jobs, err := l.Ledger.List(ctx, phases...)
	l.once.Do(func() { close(l.scanned) })
	return jobs, err
}
func TestWorkerStartupWakeAndIdle(t *testing.T) {
	b, s, _, _, m := setup(t)
	accept(t, b, m)
	observed := &observedLedger{Ledger: s, scanned: make(chan struct{})}
	b.store = observed
	ctx, cancel := context.WithCancel(testContext)
	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()
	select {
	case <-observed.scanned:
	case <-time.After(time.Second):
		t.Fatal("worker did not scan at startup")
	}
	// An explicit wake is sufficient to observe durable completion without polling.
	deadline := time.Now().Add(2 * time.Second)
	for stored(t, s).Phase != ledger.Admitted {
		if time.Now().After(deadline) {
			t.Fatal("startup work not recovered")
		}
		time.Sleep(time.Millisecond)
	}
	before := observed.scans.Load()
	time.Sleep(25 * time.Millisecond)
	if observed.scans.Load() != before {
		t.Fatal("idle worker polled")
	}
	b.Wake()
	deadline = time.Now().Add(time.Second)
	for observed.scans.Load() == before {
		if time.Now().After(deadline) {
			t.Fatal("explicit wake ignored")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestPreparedReplyCannotSendWithoutAuthority(t *testing.T) {
	for _, condition := range []string{"disabled", "revoked", "expired", "unproved", "offline"} {
		t.Run(condition, func(t *testing.T) {
			b, s, tr, p, m := setup(t)
			j := replyPrepared(t, b, s, tr, m)
			switch condition {
			case "disabled":
				b.config.Enabled = nil
			case "revoked":
				if _, err := s.Revoke(testContext, j); err != nil {
					t.Fatal(err)
				}
			case "expired":
				tr.status.State = "expired"
			case "unproved":
				tr.status.EndpointProved = false
			case "offline":
				tr.statusErr = boundaryError
			}
			err := b.process(testContext, j)
			if condition == "offline" {
				if !errors.Is(err, boundaryError) {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if tr.receipts != 1 || tr.sends != 0 || tr.prepares != 0 || p.calls != 0 || stored(t, s).Phase != ledger.ReplyPrepared {
				t.Fatal("inactive authority admitted or sent prepared reply")
			}
		})
	}
}

type uncertainClaim struct{ Ledger }

func (s uncertainClaim) ClaimProvider(ctx context.Context, j ledger.Job, now time.Time) (ledger.Job, string, error) {
	if _, _, err := s.Ledger.ClaimProvider(ctx, j, now); err != nil {
		return ledger.Job{}, "", err
	}
	return ledger.Job{}, "", boundaryError
}
func TestUncertainClaimCommitCannotDispatch(t *testing.T) {
	b, s, tr, p, m := setup(t)
	accept(t, b, m)
	b.store = uncertainClaim{s}
	if err := b.process(testContext, stored(t, s)); !errors.Is(err, boundaryError) {
		t.Fatal(err)
	}
	b.store = s
	process(t, b, s)
	if stored(t, s).Phase != ledger.ProviderStarted || p.calls != 0 || tr.prepares != 0 {
		t.Fatal("uncertain claim authorized dispatch")
	}
}

func TestPendingTransportErrorRetriesWithoutNewEvent(t *testing.T) {
	b, s, tr, p, m := setup(t)
	accept(t, b, m)
	tr.sendErr = boundaryError
	tr.onSend = func() {
		if tr.sends == 2 {
			tr.sendErr = nil
		}
	}
	ctx, cancel := context.WithCancel(testContext)
	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()
	stopped := false
	defer func() {
		cancel()
		if !stopped {
			<-done
		}
	}()
	deadline := time.Now().Add(4 * time.Second)
	for stored(t, s).Phase != ledger.Admitted {
		if time.Now().After(deadline) {
			t.Fatal("pending send was not retried")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	stopped = true
	// Join before inspecting the boundary fakes.
	if p.calls != 1 || tr.prepares != 1 || tr.sends != 2 {
		t.Fatal("retry changed provider dispatch or reply identity")
	}
}

type transientListFailure struct {
	Ledger
	failures atomic.Int32
}

func (l *transientListFailure) List(ctx context.Context, phases ...ledger.Phase) ([]ledger.Job, error) {
	if l.failures.Add(1) == 1 {
		return nil, boundaryError
	}
	return l.Ledger.List(ctx, phases...)
}
func TestPendingListErrorRetriesWithoutNewEvent(t *testing.T) {
	b, s, _, _, m := setup(t)
	accept(t, b, m)
	b.store = &transientListFailure{Ledger: s}
	ctx, cancel := context.WithCancel(testContext)
	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(4 * time.Second)
	for stored(t, s).Phase != ledger.Admitted {
		if time.Now().After(deadline) {
			t.Fatal("pending ledger read was not retried")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type failedAdmission struct {
	Ledger
	transport *fakeTransport
	failed    bool
}

func (s *failedAdmission) CompareAndSwap(ctx context.Context, j ledger.Job, next ledger.Phase, d ledger.Data) (ledger.Job, error) {
	if next == ledger.Admitted && !s.failed {
		s.failed = true
		// The SDK has already admitted and retired ciphertext; only its receipt
		// survives this failed ledger write.
		s.transport.receipt = receiptFor(j.Data.ReplyID, s.transport.prepared.Wire)
		s.transport.receiptErr = nil
		s.transport.prepared = sdk.PreparedSharingProjectMessage{}
		s.transport.loadErr = boundaryError
		return ledger.Job{}, boundaryError
	}
	return s.Ledger.CompareAndSwap(ctx, j, next, d)
}
func TestPostSendLedgerErrorRetriesReceiptOnly(t *testing.T) {
	b, s, tr, p, m := setup(t)
	accept(t, b, m)
	b.store = &failedAdmission{Ledger: s, transport: tr}
	ctx, cancel := context.WithCancel(testContext)
	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()
	stopped := false
	defer func() {
		cancel()
		if !stopped {
			<-done
		}
	}()
	deadline := time.Now().Add(4 * time.Second)
	for stored(t, s).Phase != ledger.Admitted {
		if time.Now().After(deadline) {
			t.Fatal("post-send ledger write not reconciled")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	stopped = true
	if p.calls != 1 || tr.prepares != 1 || tr.sends != 1 || tr.loads != 0 {
		t.Fatal("admission write retry repeated external work")
	}
}

func TestRevocationDuringReplyLookupsPreventsSend(t *testing.T) {
	for _, boundary := range []string{"receipt", "status"} {
		t.Run(boundary, func(t *testing.T) {
			b, s, tr, _, m := setup(t)
			replyPrepared(t, b, s, tr, m)
			revoke := func() {
				if _, err := s.Revoke(testContext, stored(t, s)); err != nil {
					t.Fatal(err)
				}
			}
			if boundary == "receipt" {
				tr.onReceipt = revoke
			} else {
				tr.onStatus = revoke
			}
			process(t, b, s)
			if tr.sends != 0 || !stored(t, s).Revoked {
				t.Fatal("lookup raced revocation into send")
			}
		})
	}
}

type retryClaim struct {
	Ledger
	calls     int
	uncertain bool
	failure   error
}

func (l *retryClaim) ClaimProvider(ctx context.Context, j ledger.Job, now time.Time) (ledger.Job, string, error) {
	l.calls++
	if l.calls == 1 {
		if l.uncertain {
			if _, _, err := l.Ledger.ClaimProvider(ctx, j, now); err != nil {
				return ledger.Job{}, "", err
			}
		}
		return ledger.Job{}, "", l.failure
	}
	return l.Ledger.ClaimProvider(ctx, j, now)
}
func runUntil(t *testing.T, b *Bridge, ready func() bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(testContext)
	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(4 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatal("automatic recovery did not complete")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
func TestClaimStorageFailureRetriesFreshPhase(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(fmt.Sprint(uncertain), func(t *testing.T) {
			b, s, _, p, m := setup(t)
			accept(t, b, m)
			l := &retryClaim{Ledger: s, uncertain: uncertain, failure: boundaryError}
			b.store = l
			if uncertain {
				observed := &observedLedger{Ledger: l, scanned: make(chan struct{})}
				b.store = observed
				runUntil(t, b, func() bool { return observed.scans.Load() >= 2 })
				// Fresh recovery of an uncertain committed claim never invokes the provider.
				process(t, b, s)
				if l.calls != 1 || p.calls != 0 {
					t.Fatal("uncertain claim retried provider")
				}
			} else {
				runUntil(t, b, func() bool { return stored(t, s).Phase == ledger.Admitted })
				if l.calls != 2 || p.calls != 1 {
					t.Fatal("claim storage failure did not safely recover")
				}
			}
		})
	}
}
func TestClaimPolicyFailuresDoNotScheduleRetry(t *testing.T) {
	for _, failure := range []error{ledger.ErrLimit, ledger.ErrStale, ledger.ErrInvalid} {
		t.Run(failure.Error(), func(t *testing.T) {
			b, s, _, _, m := setup(t)
			accept(t, b, m)
			b.store = &retryClaim{Ledger: s, failure: failure}
			err := b.process(testContext, stored(t, s))
			var retry storageError
			if !errors.Is(err, failure) || errors.As(err, &retry) {
				t.Fatal("policy failure scheduled storage retry")
			}
		})
	}
}
func TestTransientPreparedReadPreservesCandidateAndRetries(t *testing.T) {
	for _, initial := range []bool{false, true} {
		t.Run(fmt.Sprint(initial), func(t *testing.T) {
			b, s, tr, p, m := setup(t)
			if initial {
				outputReady(t, b, s, m)
				tr.prepareErr = boundaryError
			} else {
				j := replyPreparing(t, b, s, m)
				tr.prepared = sdk.PreparedSharingProjectMessage{ID: j.Data.ReplyID, Wire: []byte("immutable reply")}
			}
			tr.onLoad = func() {
				if tr.loads == 1 {
					tr.loadErr = &os.PathError{Op: "read", Path: "candidate", Err: os.ErrPermission}
				} else {
					tr.loadErr = nil
				}
			}
			runUntil(t, b, func() bool { return stored(t, s).Phase == ledger.Admitted })
			want := 0
			if initial {
				want = 1
			}
			if tr.loads != 2 || tr.prepares != want || p.calls != 0 {
				t.Fatal("transient read discarded or reprepared candidate")
			}
		})
	}
}
func TestQuotaCooldownSurvivesWakeAndRetries(t *testing.T) {
	b, s, tr, p, m := setup(t)
	replyPrepared(t, b, s, tr, m)
	reset := time.Now().Add(1200 * time.Millisecond)
	tr.sendErr = &sdk.SharingProjectMessageQuotaError{StatusCode: 429, ResetAt: &reset}
	ctx, cancel := context.WithCancel(testContext)
	done := make(chan error, 1)
	var limited atomic.Bool
	b.config.OnError = func(error) {}
	// Observe the first quota send without reading the fake concurrently.
	tr.onSend = func() {
		if tr.sends == 1 {
			limited.Store(true)
		} else {
			if time.Now().Before(reset) {
				t.Error("sent before quota reset")
			}
			tr.sendErr = nil
		}
	}
	go func() { done <- b.Run(ctx) }()
	stopped := false
	defer func() {
		cancel()
		if !stopped {
			<-done
		}
	}()
	deadline := time.Now().Add(4 * time.Second)
	for stored(t, s).Phase != ledger.Admitted {
		if time.Now().After(deadline) {
			t.Fatal("quota retry did not recover")
		}
		if limited.Load() {
			b.Wake()
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	stopped = true
	if tr.sends != 2 || tr.prepares != 0 || p.calls != 0 {
		t.Fatal("quota wake repeated work")
	}
}
func TestQuotaWithoutHintDoesNotSpinAcrossWake(t *testing.T) {
	b, s, tr, _, m := setup(t)
	replyPrepared(t, b, s, tr, m)
	tr.sendErr = &sdk.SharingProjectMessageQuotaError{StatusCode: 413}
	if err := b.process(testContext, stored(t, s)); err == nil {
		t.Fatal("missing quota error")
	}
	for i := 0; i < 3; i++ {
		process(t, b, s)
	}
	if tr.sends != 1 {
		t.Fatal("permanent quota retried")
	}
}
func TestTemporaryQuotaWithoutHintRecoversOnWake(t *testing.T) {
	b, s, tr, p, m := setup(t)
	accept(t, b, m)
	var capacityRestored atomic.Bool
	var replyIDs []string
	tr.onSend = func() {
		replyIDs = append(replyIDs, tr.prepared.ID)
		tr.sendErr = nil
		if !capacityRestored.Load() {
			tr.sendErr = &sdk.SharingProjectMessageQuotaError{StatusCode: 429, Limit: "maxInFlight", Maximum: 1}
		}
	}
	reported := make(chan error, 8)
	b.config.OnError = func(err error) { reported <- err }
	ctx, cancel := context.WithCancel(testContext)
	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()
	stopped := false
	defer func() {
		cancel()
		if !stopped {
			<-done
		}
	}()
	select {
	case err := <-reported:
		var quota *sdk.SharingProjectMessageQuotaError
		if !errors.As(err, &quota) {
			t.Fatalf("expected quota error, got %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("initial quota send did not complete")
	}
	preparedID := stored(t, s).Data.ReplyID
	select {
	case err := <-reported:
		t.Fatalf("idle quota retried without a wake: %v", err)
	case <-time.After(1100 * time.Millisecond):
	}
	capacityRestored.Store(true)
	b.Wake()
	deadline := time.Now().Add(4 * time.Second)
	for stored(t, s).Phase != ledger.Admitted {
		if time.Now().After(deadline) {
			t.Fatal("quota retry did not recover after wake")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	stopped = true
	if tr.sends != 2 || tr.prepares != 1 || p.calls != 1 || len(replyIDs) != 2 || replyIDs[0] != preparedID || replyIDs[1] != preparedID {
		t.Fatal("quota wake did not reuse the prepared reply exactly once")
	}
}
func TestQuotaRetryHints(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	reset := now.Add(time.Second)
	for _, hint := range []string{"3", now.Add(3 * time.Second).UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")} {
		got := quotaRetryAt(&sdk.SharingProjectMessageQuotaError{RetryAfter: hint, ResetAt: &reset}, now)
		if !got.Equal(now.Add(3 * time.Second)) {
			t.Fatalf("retry hint: %s", got)
		}
	}
}

func TestReceiptDuringRevocationStillReconciles(t *testing.T) {
	b, s, tr, _, m := setup(t)
	j := replyPrepared(t, b, s, tr, m)
	tr.receipt = receiptFor(j.Data.ReplyID, tr.prepared.Wire)
	tr.receiptErr = nil
	tr.onReceipt = func() {
		if _, err := s.Revoke(testContext, stored(t, s)); err != nil {
			t.Fatal(err)
		}
	}
	process(t, b, s)
	if stored(t, s).Phase != ledger.Admitted || tr.sends != 0 {
		t.Fatal("revocation prevented valid receipt reconciliation")
	}
}
func TestInvalidPreparedBindingBecomesUnknown(t *testing.T) {
	for _, initial := range []bool{false, true} {
		t.Run(fmt.Sprint(initial), func(t *testing.T) {
			b, s, tr, _, m := setup(t)
			if initial {
				outputReady(t, b, s, m)
				tr.prepareErr = boundaryError
				tr.onLoad = func() { tr.prepared.ID = "wrong" }
			} else {
				replyPreparing(t, b, s, m)
				tr.prepared = sdk.PreparedSharingProjectMessage{ID: "wrong", Wire: []byte("wire")}
			}
			process(t, b, s)
			if stored(t, s).Phase != ledger.Unknown || tr.sends != 0 {
				t.Fatal("invalid candidate binding retained")
			}
		})
	}
}
