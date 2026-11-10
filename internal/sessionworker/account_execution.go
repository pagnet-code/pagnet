package sessionworker

import (
	"context"
	"errors"
	"path/filepath"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/accountmessage"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
)

func (o *SessionOwner) accountExecutionEnabled() bool {
	return o.spec.AccountMessageExecutionEnabled && !o.journal.isLocal() && o.spec.Runtime == domain.RuntimeQwenCode && o.spec.Kind == "worker" && o.spec.ProtectedContext == nil && o.spec.NetworkID != "" && filepath.IsAbs(o.spec.NetworkStateDir)
}

// The ciphertext and original authority must already be durably admitted before
// loading a key or recovering transient plaintext. Recovery never calls Execute.
func (o *SessionOwner) decryptAccountInput(ctx context.Context, out Outcome, op Operation) (string, error) {
	if !o.accountExecutionEnabled() || op.SourceAccountMessage == nil || op.SealedAccountMessage == nil || op.Input != "" {
		return "", ErrFenced
	}
	if err := o.journal.verifyAccountInputForExecution(ctx, out.Sequence, out.CommandID, op); err != nil {
		return "", err
	}
	s := op.SourceAccountMessage
	if s.Descriptor.NetworkID != o.spec.NetworkID || s.Descriptor.TenantID != o.spec.NetworkTenantID {
		return "", ErrFenced
	}
	ring, err := hostcrypto.LoadKeyring(o.spec.NetworkStateDir, o.spec.NetworkID)
	if err != nil {
		return "", errors.New("original account input crypto authority unavailable")
	}
	epoch, found := ring.EpochByID(s.Descriptor.EpochID)
	if !found || (epoch.State != hostcrypto.EpochActive && epoch.State != hostcrypto.EpochRotated) {
		return "", errors.New("original account input epoch unavailable")
	}
	key, err := epoch.KeyArray()
	if err != nil {
		return "", errors.New("original account input key unavailable")
	}
	defer clear(key[:])
	plain, err := e2ee.Decrypt(*op.SealedAccountMessage, key, s.InputAAD)
	if err != nil {
		return "", errors.New("account input authentication failed")
	}
	defer clear(plain)
	if len(plain) == 0 || len(plain) > accountmessage.MaxTextBytes || !utf8.Valid(plain) {
		return "", errors.New("invalid account input text")
	}
	return string(plain), nil
}
