//go:build linux || darwin

package daemon

import (
	"crypto/ed25519"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

// StageCommand is a dormant integration boundary. The caller supplies retained
// local authorization separately from wire data; no production socket uses it.
// Reauthorize has the same independent-state and non-reentrancy requirements as
// Stage. Successful staging grants no epoch activation or key installation.
func (s *NativeShareEpochStore) StageCommand(commandID domain.ID, raw []byte, a NativeShareEpochStageAuthorization) (transport.NativeShareEpochStageResult, error) {
	var empty transport.NativeShareEpochStageResult
	if s == nil || s.now == nil || a.Reauthorize == nil {
		return empty, errNativeShareEpochStage
	}
	// Own retained mutable fields before any trusted callback runs.
	a.TrustedSource = append(ed25519.PublicKey(nil), a.TrustedSource...)
	a.Prepared.Signature = append([]byte(nil), a.Prepared.Signature...)
	a.Session.ProtocolFeatures = append([]string(nil), a.Session.ProtocolFeatures...)
	command, err := transport.DecodeNativeShareEpochStageCommand(raw, commandID, a.Prepared.Prepare.Binding.BindingID, a.Expected, a.TrustedSource, s.now())
	if err != nil {
		return empty, errNativeShareEpochStage
	}
	// Reauthorize against independently owned authority before calling the store.
	checked := a
	checked.TrustedSource = append(ed25519.PublicKey(nil), a.TrustedSource...)
	checked.Prepared.Signature = append([]byte(nil), a.Prepared.Signature...)
	checked.Session.ProtocolFeatures = append([]string(nil), a.Session.ProtocolFeatures...)
	if err := a.Reauthorize(checked); err != nil {
		return empty, errNativeShareEpochStage
	}
	// Stage repeats current authorization checks before publication and return.
	// Never construct authorization from command fields.
	receipt, err := s.Stage(command.BindingID, command.Package, a)
	if err != nil {
		return empty, err
	}
	digest, err := command.Digest()
	if err != nil {
		return empty, errNativeShareEpochStage
	}
	result := transport.NativeShareEpochStageResult{Version: transport.NativeShareEpochVersion, CommandID: commandID, CommandDigest: digest, Receipt: receipt}
	transcript, err := result.SignatureBytes()
	if err != nil {
		return empty, errNativeShareEpochStage
	}
	result.Signature = ed25519.Sign(s.signer, transcript)
	return result, nil
}
