//go:build linux || darwin

package sessionworker

import (
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
}

func (d *accountRejectedDriver) Submit(context.Context, *session.RuntimeSession, session.SubmitRequest, chan<- session.SessionEvent) error {
	d.calls++
	return session.ErrEndpointGone
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
	driver := &accountRejectedDriver{}
	owner := &SessionOwner{journal: j, generation: "account-native", candidateTurnSource: NativeTurnSource{Sequence: out.Sequence, InputKind: "account_message", SourceCommandID: p.SourceCommandID, SourceAdmissionID: p.SourceAdmissionID, SourceAccountMessage: p.AccountMessageSource}}
	wrapped := &ownedDriver{Driver: driver, owner: owner}
	err = wrapped.Submit(t.Context(), &session.RuntimeSession{NativeID: "account-session"}, session.SubmitRequest{Kind: session.SubmitPrompt, TurnID: logicalWorkerTurn(out.Sequence), InputKind: "account_message", Input: "transient test plaintext"}, nil)
	if err == nil || errors.Is(err, session.ErrEndpointGone) || driver.calls != 1 {
		t.Fatal("account rejected submit eligible for retry", driver.calls, err)
	}
}
