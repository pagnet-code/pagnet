//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/session"
)

func TestAccountExecutionRequiresExplicitManagedQwenProfile(t *testing.T) {
	spec := NativeSpec{AccountMessageExecutionEnabled: true, Runtime: domain.RuntimeQwenCode, Kind: "worker", NetworkID: "network", NetworkStateDir: t.TempDir()}
	owner := &SessionOwner{journal: &Journal{}, spec: spec}
	if !owner.accountExecutionEnabled() {
		t.Fatal("explicit managed Qwen profile disabled")
	}
	for name, mutate := range map[string]func(*NativeSpec){
		"default off":        func(s *NativeSpec) { s.AccountMessageExecutionEnabled = false },
		"other runtime":      func(s *NativeSpec) { s.Runtime = domain.RuntimeFakePersistent },
		"representative":     func(s *NativeSpec) { s.Kind = "representative" },
		"protected context":  func(s *NativeSpec) { s.ProtectedContext = &e2ee.ProtectedContext{} },
		"relative key state": func(s *NativeSpec) { s.NetworkStateDir = "relative" },
		"missing network":    func(s *NativeSpec) { s.NetworkID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := spec
			mutate(&copy)
			owner.spec = copy
			if owner.accountExecutionEnabled() {
				t.Fatal("unsupported profile enabled")
			}
		})
	}
}

func TestAccountDecryptionRequiresCommittedOriginalCiphertext(t *testing.T) {
	j, _ := testJournal(t)
	defer j.Close()
	l := lease(t, j)
	op, p, current := accountInputFixture(t, j, l)
	op.SourceCommandID, op.SourceAdmissionID = p.SourceCommandID, p.SourceAdmissionID
	d := op.SourceAccountMessage.Descriptor
	state := t.TempDir()
	key := make([]byte, 32)
	key[0] = 1
	ring := &hostcrypto.Keyring{NetworkID: d.NetworkID, Epochs: []hostcrypto.KeyEpoch{{ID: d.EpochID, State: hostcrypto.EpochActive, CreatedAt: time.Now().UTC(), Key: key}}}
	if err := hostcrypto.SaveKeyring(state, ring); err != nil {
		t.Fatal(err)
	}
	owner := &SessionOwner{journal: j, spec: NativeSpec{AccountMessageExecutionEnabled: true, Runtime: domain.RuntimeQwenCode, Kind: "worker", NetworkID: d.NetworkID, NetworkTenantID: d.TenantID, NetworkStateDir: state}}
	out := Outcome{Sequence: 1, CommandID: p.SourceCommandID}
	if _, err := owner.decryptAccountInput(t.Context(), out, op); err == nil {
		t.Fatal("decrypted uncommitted account input")
	}
	admitted, run, err := j.admitDispatch(t.Context(), l, 0, p.SourceCommandID, "prompt", accountInputPayload(t, op), func() (*Admission, error) { return current, nil }, &p)
	if err != nil || !run {
		t.Fatal(run, err)
	}
	plain, err := owner.decryptAccountInput(t.Context(), admitted, op)
	if err != nil || plain != "account input test" {
		t.Fatal("committed account input unavailable", err)
	}
	changed := op
	envelope := *op.SealedAccountMessage
	envelope.Ciphertext = "changed"
	changed.SealedAccountMessage = &envelope
	if _, err := owner.decryptAccountInput(t.Context(), admitted, changed); err == nil {
		t.Fatal("decrypted changed ciphertext")
	}
	if err := j.Settle(t.Context(), admitted.Sequence, "uncertain", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.decryptAccountInput(t.Context(), admitted, op); err == nil {
		t.Fatal("decrypted uncertain account input for execution")
	}
}

type accountRejectedDriver struct {
	session.Driver
	calls int
	err   error
}

func (d *accountRejectedDriver) Submit(context.Context, *session.RuntimeSession, session.SubmitRequest, chan<- session.SessionEvent) error {
	d.calls++
	return d.err
}
func TestAccountNativeSubmitDoesNotTriggerEndpointRetry(t *testing.T) {
	j, _ := testJournal(t)
	defer j.Close()
	l := lease(t, j)
	op, p, current := accountInputFixture(t, j, l)
	out, run, err := j.admitDispatch(t.Context(), l, 0, p.SourceCommandID, "prompt", accountInputPayload(t, op), func() (*Admission, error) { return current, nil }, &p)
	if err != nil || !run {
		t.Fatal(run, err)
	}
	driver := &accountRejectedDriver{err: session.ErrEndpointGone}
	owner := &SessionOwner{journal: j, spec: accountReplySpec(t, op), generation: "account-native", candidateTurnSource: NativeTurnSource{Sequence: out.Sequence, InputKind: "account_message", SourceCommandID: p.SourceCommandID, SourceAdmissionID: p.SourceAdmissionID, SourceAccountMessage: p.AccountMessageSource}}
	wrapped := &ownedDriver{Driver: driver, owner: owner}
	err = wrapped.Submit(t.Context(), &session.RuntimeSession{NativeID: "account-session"}, session.SubmitRequest{Kind: session.SubmitPrompt, TurnID: logicalWorkerTurn(out.Sequence), InputKind: "account_message", Input: "transient test plaintext"}, nil)
	if err == nil || errors.Is(err, session.ErrEndpointGone) || driver.calls != 1 {
		t.Fatal("account rejected submit eligible for retry", driver.calls, err)
	}
}

func TestAccountNativeSubmitReleasesRejectedPinAndRetainsCiphertext(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"busy", session.ErrBusy},
		{"canceled", context.Canceled},
		{"deadline", context.DeadlineExceeded},
		{"endpoint gone", session.ErrEndpointGone},
		{"other rejection", errors.New("native rejection")},
		{"accepted", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owner, _, source, _, l := accountReplyOwner(t)
			defer owner.journal.Close()
			owner.candidateTurnSource = source
			driver := &accountRejectedDriver{err: tc.err}
			wrapped := &ownedDriver{Driver: driver, owner: owner}
			var before, after []byte
			if err := owner.journal.db.QueryRow(`SELECT envelope FROM worker_account_inputs WHERE sequence=?`, source.Sequence).Scan(&before); err != nil {
				t.Fatal(err)
			}
			err := wrapped.Submit(t.Context(), &session.RuntimeSession{NativeID: source.NativeSessionID}, session.SubmitRequest{Kind: session.SubmitPrompt, TurnID: source.LogicalTurnID, InputKind: "account_message", Input: "transient test plaintext"}, nil)
			if driver.calls != 1 {
				t.Fatal("submission attempt count", driver.calls)
			}
			if tc.err == nil {
				if err != nil {
					t.Fatal(err)
				}
				if _, available := owner.originalTaskContentPin(&source); !available {
					t.Fatal("accepted turn lost terminal capture pin")
				}
			} else {
				if err == nil || errors.Is(err, session.ErrEndpointGone) {
					t.Fatal("rejection lost or became retryable", err)
				}
				if tc.err != session.ErrEndpointGone && !errors.Is(err, tc.err) {
					t.Fatal("rejection changed", err)
				}
				if _, available := owner.originalTaskContentPin(&source); available {
					t.Fatal("rejected turn retained original epoch pin")
				}
				owner.mu.Lock()
				pins := len(owner.taskContentPins)
				generation := owner.generation
				owner.mu.Unlock()
				if pins != 0 || generation != source.NativeGeneration {
					t.Fatal("rejection retained key or retired live generation", pins, generation)
				}
				// Releasing a producer key is not durable retirement of the original
				// ciphertext, dispatch, or unresolved turn authority.
				if err = owner.journal.Settle(t.Context(), source.Sequence, "uncertain", nil); err != nil {
					t.Fatal(err)
				}
				if err = owner.journal.Acknowledge(t.Context(), l, source.Sequence); err != nil {
					t.Fatal(err)
				}
				if err = owner.journal.RetireDispatches(t.Context(), l, 1); err == nil {
					t.Fatal("rejected unresolved turn retired original authority")
				}
				if _, err = owner.journal.db.Exec(`DELETE FROM worker_account_inputs WHERE sequence=?`, source.Sequence); err == nil {
					t.Fatal("rejected unresolved turn deleted ciphertext")
				}
			}
			if err := owner.journal.db.QueryRow(`SELECT envelope FROM worker_account_inputs WHERE sequence=?`, source.Sequence).Scan(&after); err != nil || !bytes.Equal(before, after) {
				t.Fatal("submission changed retained ciphertext", err)
			}
		})
	}
}
