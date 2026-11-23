package textbridge

import (
	"context"
	"errors"
	"sync"

	"github.com/pagnet-code/pagnet/internal/textbridge/sender"
	"github.com/pagnet-code/pagnet/sdk"
)

// ownerProjectEndpoint is deliberately independent of every sharing-v2 method.
// The legacy method names below are internal engine DTO ports, never SDK wire.
type ownerProjectEndpoint interface {
	TextServiceEndpointSession() (string, <-chan struct{}, error)
	ListOwnerTextProjects(context.Context) ([]sdk.OwnerTextProjectStatus, error)
	EnrollOwnerTextProject(context.Context, string, string) (sdk.OwnerTextProjectEnrollment, error)
	PrepareOwnerTextProjectMessageWithID(string, string, string, string, []byte, []byte) (sdk.PreparedOwnerTextProjectMessage, error)
	LoadPreparedOwnerTextProjectMessage(string, string) (sdk.PreparedOwnerTextProjectMessage, error)
	OwnerTextProjectMessageReceipt(context.Context, string, string) (sdk.OwnerTextProjectMessageReceipt, error)
	SendPreparedOwnerTextProjectMessage(context.Context, string, string) (sdk.OwnerTextProjectMessageReceipt, error)
	OnOwnerTextProjectMessage(func(context.Context, sdk.OwnerTextProjectMessage) error)
	OnOwnerTextProjectReady(func(string))
	EnableOwnerTextProjects(string) error
}
type ownerProjectAdapter struct {
	raw        ownerProjectEndpoint
	connection RuntimeConnection
	profile    Profile
	identity   sdk.Identity
	ctx        context.Context
	endpoint   string
	done       <-chan struct{}
	mu         sync.Mutex
	ready      map[string]bool
}

var _ sender.Connection = (*ownerProjectAdapter)(nil)

func ownerEndpointSession(conn RuntimeConnection, p Profile) (string, <-chan struct{}, error) {
	if p.ProjectContract != OwnerTextProjectContract {
		return "", nil, nil
	}
	raw, ok := conn.(ownerProjectEndpoint)
	if !ok {
		return "", nil, errors.New("SDK connection does not support owner project transport")
	}
	endpoint, done, err := raw.TextServiceEndpointSession()
	if err != nil || endpoint == "" || done == nil {
		return "", nil, errors.New("owner project requires an authenticated endpoint session")
	}
	select {
	case <-done:
		return "", nil, errors.New("owner project endpoint session ended")
	default:
	}
	return endpoint, done, nil
}
func selectOwnerProjectAdapter(ctx context.Context, conn RuntimeConnection, p Profile, identity *sdk.Identity, endpoint string, done <-chan struct{}) (*ownerProjectAdapter, error) {
	if err := p.validateProjectContract(); err != nil {
		return nil, err
	}
	if p.ProjectContract != OwnerTextProjectContract {
		return nil, nil
	}
	if !ownerIdentityMatches(p, identity) {
		return nil, errors.New("owner project service identity mismatch")
	}
	raw, ok := conn.(ownerProjectEndpoint)
	if !ok {
		return nil, errors.New("SDK connection does not support owner project transport")
	}
	a := &ownerProjectAdapter{raw: raw, connection: conn, profile: p, identity: *identity, ctx: ctx, endpoint: endpoint, done: done, ready: map[string]bool{}}
	if err := a.current(); err != nil {
		return nil, err
	}
	return a, nil
}
func (a *ownerProjectAdapter) current() error {
	if err := a.ctx.Err(); err != nil {
		return err
	}
	select {
	case <-a.done:
		return errors.New("owner project endpoint session ended")
	default:
	}
	endpoint, done, err := a.raw.TextServiceEndpointSession()
	if err != nil || endpoint != a.endpoint || done != a.done {
		return errors.New("owner project endpoint session changed")
	}
	return nil
}
func (a *ownerProjectAdapter) Ready(project string) bool {
	if a.current() != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ready[project]
}
func (a *ownerProjectAdapter) Done() <-chan struct{} { return a.done }
func (a *ownerProjectAdapter) WhoAmI(context.Context) (*sdk.Identity, error) {
	if err := a.current(); err != nil {
		return nil, err
	}
	identity := a.identity
	return &identity, nil
}
func (a *ownerProjectAdapter) validateStatus(status sdk.OwnerTextProjectStatus, project string, active bool) (string, error) {
	if status.ProjectID != project || len(status.Roles) != 2 || status.RosterSize != 2 || status.Roles[0].Role != "sender" || status.Roles[1].Role != "responder" || status.Roles[0].PrincipalID == status.Roles[1].PrincipalID || status.Roles[0].InstallationID == status.Roles[1].InstallationID {
		return "", errors.New("owner project role binding mismatch")
	}
	index := 0
	if a.profile.ServiceRole() == "responder" {
		index = 1
	}
	own, peer := status.Roles[index], status.Roles[1-index]
	if own.PrincipalID != a.profile.Service || own.InstallationID != a.profile.Registration.InstallationID || own.Role != a.profile.ServiceRole() || peer.PrincipalID == "" || peer.InstallationID == "" {
		return "", errors.New("owner project installation binding mismatch")
	}
	if active && (status.State != "active" || !status.EndpointProved) {
		return "", errors.New("owner project requires active caller endpoint proof")
	}
	return peer.PrincipalID, nil
}
func (a *ownerProjectAdapter) status(ctx context.Context, project string, active bool) (sdk.OwnerTextProjectStatus, string, error) {
	if err := a.current(); err != nil {
		return sdk.OwnerTextProjectStatus{}, "", err
	}
	enrollment, err := a.raw.EnrollOwnerTextProject(ctx, project, a.profile.Registration.InstallationID)
	if err != nil {
		return enrollment.Status, "", ownerProjectError(err)
	}
	peer, err := a.validateStatus(enrollment.Status, project, active)
	if err == nil {
		err = a.current()
	}
	return enrollment.Status, peer, err
}

// EnrollProjects returns real startup failures before publication. Pending
// consent/pins are retained as pending, with dispatch gated until post-ACK Ready.
func (a *ownerProjectAdapter) EnrollProjects(ctx context.Context) error {
	if err := a.current(); err != nil {
		return err
	}
	projects, err := a.raw.ListOwnerTextProjects(ctx)
	if err != nil {
		return ownerProjectError(err)
	}
	for _, project := range projects {
		if _, _, err = a.status(ctx, project.ProjectID, false); err != nil {
			return err
		}
	}
	if err = a.current(); err != nil {
		return err
	}
	return a.raw.EnableOwnerTextProjects(a.profile.Registration.InstallationID)
}

// Only EnrollProjects enables the owner coordinator; the legacy port is inert.
func (a *ownerProjectAdapter) EnableSharingProjects() {}
func (a *ownerProjectAdapter) SharingProjectStatus(ctx context.Context, project string) (sdk.SharingProjectStatus, error) {
	status, _, err := a.status(ctx, project, true)
	return sdk.SharingProjectStatus{ProjectID: status.ProjectID, NetworkID: status.NetworkID, State: status.State, Descriptor: status.Descriptor, DescriptorHash: status.DescriptorHash, KeysPinned: status.KeysPinned, PrincipalsProved: status.PrincipalsProved, RosterSize: status.RosterSize, EndpointProved: status.EndpointProved}, err
}
func (a *ownerProjectAdapter) PrepareSharingProjectMessageWithID(project, to, kind, id string, input, previous []byte) (sdk.PreparedSharingProjectMessage, error) {
	_, peer, err := a.status(a.ctx, project, true)
	if err != nil {
		return sdk.PreparedSharingProjectMessage{ID: id}, err
	}
	expected := "ASK"
	if a.profile.ServiceRole() == "responder" {
		expected = "REPLY"
	}
	if kind != expected || to != peer {
		return sdk.PreparedSharingProjectMessage{ID: id}, errors.New("owner project message direction mismatch")
	}
	prepared, err := a.raw.PrepareOwnerTextProjectMessageWithID(project, to, kind, id, input, previous)
	if err == nil {
		err = a.current()
	}
	return sdk.PreparedSharingProjectMessage{ID: prepared.ID, Wire: prepared.Wire}, ownerProjectError(err)
}
func (a *ownerProjectAdapter) LoadPreparedSharingProjectMessage(project, id string) (sdk.PreparedSharingProjectMessage, error) {
	if _, _, err := a.status(a.ctx, project, true); err != nil {
		return sdk.PreparedSharingProjectMessage{ID: id}, err
	}
	prepared, err := a.raw.LoadPreparedOwnerTextProjectMessage(project, id)
	if err == nil {
		err = a.current()
	}
	return sdk.PreparedSharingProjectMessage{ID: prepared.ID, Wire: prepared.Wire}, ownerProjectError(err)
}
func ownerProjectReceipt(receipt sdk.OwnerTextProjectMessageReceipt) sdk.SharingProjectMessageReceipt {
	return sdk.SharingProjectMessageReceipt{MessageID: receipt.MessageID, AdmissionSeq: receipt.AdmissionSeq, RequestDigest: receipt.RequestDigest, Status: receipt.Status, CreatedAt: receipt.CreatedAt, AcknowledgedAt: receipt.AcknowledgedAt}
}
func (a *ownerProjectAdapter) SharingProjectMessageReceipt(ctx context.Context, project, id string) (sdk.SharingProjectMessageReceipt, error) {
	if _, _, err := a.status(ctx, project, true); err != nil {
		return sdk.SharingProjectMessageReceipt{}, err
	}
	receipt, err := a.raw.OwnerTextProjectMessageReceipt(ctx, project, id)
	if err == nil {
		err = a.current()
	}
	return ownerProjectReceipt(receipt), ownerProjectError(err)
}
func (a *ownerProjectAdapter) SendPreparedSharingProjectMessage(ctx context.Context, project, id string) (sdk.SharingProjectMessageReceipt, error) {
	if _, _, err := a.status(ctx, project, true); err != nil {
		return sdk.SharingProjectMessageReceipt{}, err
	}
	receipt, err := a.raw.SendPreparedOwnerTextProjectMessage(ctx, project, id)
	if err == nil {
		err = a.current()
	}
	return ownerProjectReceipt(receipt), ownerProjectError(err)
}
func ownerProjectHeader(h sdk.OwnerTextProjectMessageHeader) sdk.SharingProjectMessageHeader {
	return sdk.SharingProjectMessageHeader{Version: h.Version, ProjectID: h.ProjectID, NetworkID: h.NetworkID, PolicyHash: h.PolicyHash, DescriptorHash: h.DescriptorHash, ID: h.ID, ThreadID: h.ThreadID, CorrelationID: h.CorrelationID, Kind: h.Kind, SenderPrincipalID: h.SenderPrincipalID, RecipientPrincipalID: h.RecipientPrincipalID, CreatedAt: h.CreatedAt}
}
func (a *ownerProjectAdapter) OnSharingProjectMessage(handler func(context.Context, sdk.SharingProjectMessage) error) {
	a.raw.OnOwnerTextProjectMessage(func(ctx context.Context, message sdk.OwnerTextProjectMessage) error {
		_, peer, err := a.status(ctx, message.Header.ProjectID, true)
		if err != nil {
			return err
		}
		expected := "REPLY"
		if a.profile.ServiceRole() == "responder" {
			expected = "ASK"
		}
		h := message.Header
		if h.Domain != "pagnet/owner-text-project/message/v1" || h.Version != 1 || h.Kind != expected || h.SenderPrincipalID != peer || h.RecipientPrincipalID != a.profile.Service || len(message.Wire) == 0 {
			return errors.New("owner project callback direction mismatch")
		}
		if handler == nil {
			return errors.New("owner project message handler unavailable")
		}
		a.mu.Lock()
		a.ready[h.ProjectID] = false
		a.mu.Unlock()
		return handler(ctx, sdk.SharingProjectMessage{Header: ownerProjectHeader(h), Plaintext: message.Plaintext, Wire: message.Wire})
	})
}
func (a *ownerProjectAdapter) OnSharingProjectReady(handler func(string)) {
	a.raw.OnOwnerTextProjectReady(func(project string) {
		// This is a post-ACK wake hint from the owner SDK. Dispatch still
		// revalidates status/pins through the transport; avoid a fallible extra
		// status request here silently losing the only durable-outbox wake.
		if err := a.current(); err != nil {
			return
		}
		a.mu.Lock()
		a.ready[project] = true
		a.mu.Unlock()
		if handler != nil {
			handler(project)
		}
	})
}
func ownerProjectError(err error) error {
	if errors.Is(err, sdk.ErrOwnerTextProjectMessageAbandoned) {
		return errors.Join(err, sdk.ErrSharingProjectMessageAbandoned)
	}
	if errors.Is(err, sdk.ErrOwnerTextProjectMessageAdmitted) {
		return errors.Join(err, sdk.ErrSharingProjectMessageAdmitted)
	}
	var quota *sdk.OwnerTextProjectMessageQuotaError
	if errors.As(err, &quota) {
		return &sdk.SharingProjectMessageQuotaError{Limit: quota.Limit, Maximum: quota.Maximum, ResetAt: quota.ResetAt, RetryAfter: quota.RetryAfter, StatusCode: quota.StatusCode}
	}
	return err
}

func ownerIdentityMatches(p Profile, identity *sdk.Identity) bool {
	return identity != nil && identity.Kind == "service" && identity.PrincipalID == p.Service && (p.ProjectContract != OwnerTextProjectContract || (p.Registration != nil && identity.TenantID == p.Registration.TenantID))
}
