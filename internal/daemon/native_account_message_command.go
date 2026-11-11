package daemon

import (
	"errors"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/accountmessage"
	"github.com/pagnet-code/pagnet/transport"
)

var errAccountMessageCommand = errors.New("account message command unavailable")

// preflightAccountMessageCommand checks only the original, ciphertext-only
// command. The independent native worker rechecks its durable ownership and
// source at admission; this local projection cannot grant replacement work.
func (d *Daemon) preflightAccountMessageCommand(conn *websocket.Conn, p transport.AccountMessagePayload) (*transport.NativeAccountMessageSource, error) {
	source, err := validateAccountMessagePayload(p)
	if err != nil || !d.AccountMessageExecutionEnabled {
		return nil, errAccountMessageCommand
	}
	proof := p.NativeDispatch
	worker, err := d.nativeWorkerFor(conn, p.InstanceID)
	if err != nil {
		return nil, errors.Join(ErrDeferred, err)
	}
	session, err := worker.connection.AuthenticatedNativeHostSession()
	if err != nil {
		return nil, errors.Join(ErrDeferred, err)
	}
	if session.TenantID != source.Descriptor.TenantID || session.AccountID != source.Descriptor.OwnerUserID ||
		session.HostID != source.Descriptor.HostID || d.HostID != session.HostID ||
		session.RunnerID != proof.SourceRunnerID || !session.RunnerEpoch.Equal(proof.SourceRunnerEpoch) ||
		session.NativeAdmissionID != proof.SourceAdmissionID || session.BootID != proof.SourceBootID {
		return nil, errAccountMessageCommand
	}
	row, ok, err := d.state.GetInstance(p.InstanceID)
	if err != nil {
		return nil, errAccountMessageCommand
	}
	if !ok || row.NetworkID != source.Descriptor.NetworkID || row.DefinitionID != source.Descriptor.TargetDefinitionID ||
		row.AgentPrincipalID != source.Descriptor.TargetPrincipalID || row.Runtime != string(domain.RuntimeQwenCode) ||
		(row.Status != "idle" && row.Status != "working") {
		return nil, errAccountMessageCommand
	}
	return source, nil
}

func validateAccountMessagePayload(p transport.AccountMessagePayload) (*transport.NativeAccountMessageSource, error) {
	proof := p.NativeDispatch
	if proof == nil || proof.AccountMessageSource == nil ||
		proof.TaskSource != nil || proof.InvocationSource != nil || p.CommandID == "" ||
		p.CommandID != proof.SourceCommandID || p.InstanceID == "" ||
		proof.SourceAdmissionID == "" || proof.SourceBootID == "" || proof.SourceRunnerID == "" ||
		proof.OwnershipID == "" || proof.OwnershipGeneration == "" || proof.DispatchSequence <= 0 {
		return nil, errAccountMessageCommand
	}
	source := proof.AccountMessageSource
	if source.Validate() != nil || source.Descriptor.TargetInstanceID != p.InstanceID ||
		source.Descriptor.RunnerID != proof.SourceRunnerID ||
		source.Descriptor.RunnerConnectedAt != proof.SourceRunnerEpoch.UTC().Format(time.RFC3339Nano) {
		return nil, errAccountMessageCommand
	}
	sealed := accountmessage.Sealed{V: 1, MessageID: source.MessageID,
		BindingDigest: source.BindingDigest, SealedDigest: source.SealedDigest,
		Envelope: p.Envelope, Descriptor: accountmessage.Descriptor(source.Descriptor)}
	if sealed.Validate() != nil {
		return nil, errAccountMessageCommand
	}
	return source, nil
}
