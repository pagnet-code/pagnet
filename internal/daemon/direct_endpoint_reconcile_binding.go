//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"time"

	"github.com/pagnet-code/pagnet/internal/directhttp"
	"github.com/pagnet-code/pagnet/transport"
)

var errDirectEndpointReconcileBinding = errors.New("direct endpoint enrollment binding rejected")

// directEndpointReconcileBinding is public evidence only, not a material-use
// lease. Descriptor fields absent from the retained issue (peer endpoint/key,
// key-evidence digests, limits and counting version) remain authenticated server
// evidence. Source V2 additionally has no retained epoch or authorization digest.
// Callers must authenticate both GET responses; wakes supply no binding facts.
type directEndpointReconcileBinding struct {
	Descriptor                                        transport.DirectChannelDescriptorV2
	Authority                                         directhttp.EnrollmentAuthority
	DescriptorBytes                                   []byte
	DescriptorHash, LocalFingerprint, PeerFingerprint [32]byte
	Protocol                                          directManagedSourceCredentialProtocolVariant
}

func validateDirectSourceReconcileBindingV2(s *DirectEndpointSubscription, captured ManagedEndpointPrepareScope, issue transport.DirectManagedSourceCredentialIssueV2, descriptor transport.DirectChannelDescriptorV2, enrollment directhttp.Enrollment, now time.Time) (directEndpointReconcileBinding, error) {
	return validateDirectSourceReconcileBindingV2Context(context.Background(), s, captured, issue, descriptor, enrollment, now)
}

func validateDirectSourceReconcileBindingV2Context(ctx context.Context, s *DirectEndpointSubscription, captured ManagedEndpointPrepareScope, issue transport.DirectManagedSourceCredentialIssueV2, descriptor transport.DirectChannelDescriptorV2, enrollment directhttp.Enrollment, now time.Time) (directEndpointReconcileBinding, error) {
	if err := directReconcileBindingContextError(ctx); err != nil {
		return directEndpointReconcileBinding{}, err
	}
	raw, err := issue.CanonicalBytes()
	subject := issue.PoP.Prepare.Subject
	native := nativeManagedSubjectFromSourceV2(subject)
	native.ExpiresAt = subject.AuthorizationExpiresAt
	out, err := validateDirectEndpointReconcileBindingContext(ctx, s, captured, raw, err, native, descriptor, enrollment, now, "S", issue.PoP.ACK.Reservation.X25519, issue.PoP.ACK.Reservation.ServerURL, string(issue.PoP.ACK.Reservation.InstallationID), directManagedSourceCredentialProtocolV2)
	if err != nil {
		return directEndpointReconcileBinding{}, err
	}
	d := out.Descriptor
	if now.Before(issue.IssuedAt) || enrollment.ObservedAt.Before(issue.IssuedAt) || !s.binding.metadata.Deadline.Equal(directEndpointDeadline(issue.CredentialExpiresAt, issue.BudgetExpiresAt, subject.AuthorizationExpiresAt)) || d.S.EndpointID != string(subject.EndpointID) || d.DirectIntentID != string(subject.DirectIntentID) || d.ParentGrantID != string(subject.GrantID) || d.GrantGeneration != strconv.FormatInt(subject.GrantGeneration, 10) || d.NetworkID != string(subject.NetworkID) || d.S.PrincipalID != string(subject.SourcePrincipalID) || d.P.PrincipalID != string(subject.TargetPrincipalID) || d.ChannelGeneration != issue.ChannelGeneration || d.Budget.AgreementID != string(subject.BudgetID) || d.Budget.AcceptedRevision != strconv.FormatInt(subject.BudgetAcceptedRevision, 10) || d.Budget.TermsDigest != subject.BudgetTermsDigest || d.Budget.ExpiresAt != issue.BudgetExpiresAt.UTC().Format(time.RFC3339Nano) || !reconcileDeadline(d, issue.IssuedAt, issue.CredentialExpiresAt, subject.AuthorizationExpiresAt, issue.BudgetExpiresAt) || d.S.CredentialID != string(issue.CredentialID) {
		return directEndpointReconcileBinding{}, errDirectEndpointReconcileBinding
	}
	if err := directReconcileBindingCurrentContext(ctx, s); err != nil {
		return directEndpointReconcileBinding{}, err
	}
	return out, nil
}

func validateDirectTargetReconcileBinding(s *DirectEndpointSubscription, captured ManagedEndpointPrepareScope, issue transport.ManagedDirectCredentialIssue, descriptor transport.DirectChannelDescriptorV2, enrollment directhttp.Enrollment, now time.Time) (directEndpointReconcileBinding, error) {
	return validateDirectTargetReconcileBindingContext(context.Background(), s, captured, issue, descriptor, enrollment, now)
}

func validateDirectTargetReconcileBindingContext(ctx context.Context, s *DirectEndpointSubscription, captured ManagedEndpointPrepareScope, issue transport.ManagedDirectCredentialIssue, descriptor transport.DirectChannelDescriptorV2, enrollment directhttp.Enrollment, now time.Time) (directEndpointReconcileBinding, error) {
	if err := directReconcileBindingContextError(ctx); err != nil {
		return directEndpointReconcileBinding{}, err
	}
	raw, err := issue.CanonicalBytes()
	native := nativeManagedSubjectFromEndpoint(issue.PoP.Prepare.Subject)
	native.ExpiresAt = issue.PoP.Authorization.ExpiresAt
	out, err := validateDirectEndpointReconcileBindingContext(ctx, s, captured, raw, err, native, descriptor, enrollment, now, "P", issue.PoP.ACK.Reservation.X25519, issue.PoP.ACK.Reservation.ServerURL, string(issue.PoP.ACK.Reservation.InstallationID), managedDirectCredentialProtocolV1)
	if err != nil {
		return directEndpointReconcileBinding{}, err
	}
	d, a := out.Descriptor, issue.PoP.Authorization
	if now.Before(issue.IssuedAt) || enrollment.ObservedAt.Before(issue.IssuedAt) || !s.binding.metadata.Deadline.Equal(directEndpointDeadline(issue.CredentialExpiresAt, issue.Budget.ExpiresAt, a.ExpiresAt)) || d.P.EndpointID != string(issue.PoP.Prepare.Subject.EndpointID) || d.ParentGrantID != string(a.GrantID) || d.GrantGeneration != strconv.FormatInt(a.GrantGeneration, 10) || d.NetworkID != string(a.NetworkID) || d.AuthorizationDigest != issue.PoP.AuthorizationDigest || d.DirectIntentID != string(a.DirectIntentID) || d.EpochID != string(a.EpochID) || d.S.PrincipalID != string(a.SourcePrincipalID) || d.P.PrincipalID != string(a.Target.PrincipalID) || d.S.TenantID != string(a.InviterTenantID) || d.P.TenantID != string(a.InviteeTenantID) || d.ChannelGeneration != strconv.FormatUint(issue.ChannelGeneration, 10) || d.Budget.AgreementID != string(issue.Budget.AgreementID) || d.Budget.AcceptedRevision != strconv.FormatUint(issue.Budget.AcceptedRevision, 10) || d.Budget.TermsDigest != issue.Budget.TermsDigest || d.Budget.ExpiresAt != issue.Budget.ExpiresAt.UTC().Format(time.RFC3339Nano) || d.P.CredentialID != string(issue.CredentialID) || !reconcileDeadline(d, issue.IssuedAt, issue.CredentialExpiresAt, a.ExpiresAt, a.GrantExpiresAt, issue.Budget.ExpiresAt) {
		return directEndpointReconcileBinding{}, errDirectEndpointReconcileBinding
	}
	if err := directReconcileBindingCurrentContext(ctx, s); err != nil {
		return directEndpointReconcileBinding{}, err
	}
	return out, nil
}

func reconcileDeadline(d transport.DirectChannelDescriptorV2, issued time.Time, deadlines ...time.Time) bool {
	expires, err := time.Parse(time.RFC3339Nano, d.ExpiresAt)
	if err != nil || !issued.Before(expires) {
		return false
	}
	for _, deadline := range deadlines {
		if expires.After(deadline) {
			return false
		}
	}
	return true
}

func validateDirectEndpointReconcileBinding(s *DirectEndpointSubscription, captured ManagedEndpointPrepareScope, issue []byte, issueErr error, subject nativeManagedSubject, d transport.DirectChannelDescriptorV2, e directhttp.Enrollment, now time.Time, role, key, server, installation string, protocol directManagedSourceCredentialProtocolVariant) (directEndpointReconcileBinding, error) {
	return validateDirectEndpointReconcileBindingContext(context.Background(), s, captured, issue, issueErr, subject, d, e, now, role, key, server, installation, protocol)
}

func validateDirectEndpointReconcileBindingContext(ctx context.Context, s *DirectEndpointSubscription, captured ManagedEndpointPrepareScope, issue []byte, issueErr error, subject nativeManagedSubject, d transport.DirectChannelDescriptorV2, e directhttp.Enrollment, now time.Time, role, key, server, installation string, protocol directManagedSourceCredentialProtocolVariant) (directEndpointReconcileBinding, error) {
	reject := func() (directEndpointReconcileBinding, error) {
		return directEndpointReconcileBinding{}, errDirectEndpointReconcileBinding
	}
	if err := directReconcileBindingContextError(ctx); err != nil {
		return directEndpointReconcileBinding{}, err
	}
	if issueErr != nil || now.IsZero() || s == nil || s.owner == nil {
		return reject()
	}
	// Membership is read without expiry removal: this validator remains pure.
	if err := directReconcileBindingCurrentContext(ctx, s); err != nil {
		return directEndpointReconcileBinding{}, err
	}
	b := s.binding
	session, err := json.Marshal(captured.Session)
	if !now.Before(b.metadata.Deadline) || err != nil || string(session) != b.sessionIdentity || captured.Socket != b.socket || captured.Connection != b.native || !reflect.DeepEqual(subject, b.subject) || sha256.Sum256(issue) != b.issueDigest || b.metadata.Role != role || b.metadata.ServerOrigin != server || string(b.metadata.InstallationID) != installation || b.metadata.OriginID != subject.OriginID || b.metadata.OwnershipGeneration != subject.OwnershipGeneration {
		return reject()
	}
	raw, err := d.CanonicalBytes()
	if err != nil || transport.ValidateDirectChannelDescriptorV2(d, now) != nil {
		return reject()
	}
	hash := sha256.Sum256(raw)
	channel, err := transport.DirectChannelIDV2(d)
	a := e.Authority
	expires, _ := time.Parse(time.RFC3339Nano, d.ExpiresAt)
	if err != nil || e.DescriptorHash != base64.RawURLEncoding.EncodeToString(hash[:]) || a.ParentGrantID != d.ParentGrantID || a.GrantGeneration != d.GrantGeneration || a.ChannelID != channel || a.ChannelGeneration != d.ChannelGeneration || a.EpochID != d.EpochID || !a.ExpiresAt.Equal(expires) || e.ObservedAt.IsZero() || e.ObservedAt.After(now) || !e.ObservedAt.Before(expires) {
		return reject()
	}
	local, peer := d.S, d.P
	if role == "P" {
		local, peer = d.P, d.S
	}
	m := b.metadata
	if local.TenantID != string(m.TenantID) || local.PrincipalID != string(m.PrincipalID) || local.EndpointID != string(m.EndpointID) || local.CredentialID != string(m.CredentialID) || d.DirectIntentID != string(m.IntentID) || local.TenantID != string(subject.TenantID) || local.PrincipalID != string(subject.PrincipalID) {
		return reject()
	}
	reserved, err := hex.DecodeString(key)
	public, errPublic := base64.RawURLEncoding.Strict().DecodeString(local.PublicKey)
	other, errPeer := base64.RawURLEncoding.Strict().DecodeString(peer.PublicKey)
	if err != nil || errPublic != nil || errPeer != nil || len(reserved) != 32 || hex.EncodeToString(reserved) != key || !bytes.Equal(reserved, public) {
		return reject()
	}
	if err := directReconcileBindingCurrentContext(ctx, s); err != nil {
		return directEndpointReconcileBinding{}, err
	}
	return directEndpointReconcileBinding{Descriptor: d, Authority: a, DescriptorBytes: bytes.Clone(raw), DescriptorHash: hash, LocalFingerprint: sha256.Sum256(public), PeerFingerprint: sha256.Sum256(other), Protocol: protocol}, nil
}

// publicationMatches rejects a publication from another descriptor, including a
// peer publication with otherwise valid public wire fields. It does no crypto.
func (b directEndpointReconcileBinding) publicationMatches(p transport.DirectChannelPublicationV2) bool {
	if _, err := p.CanonicalBytes(); err != nil {
		return false
	}
	raw, err := p.Descriptor.CanonicalBytes()
	return err == nil && b.DescriptorHash != ([32]byte{}) && bytes.Equal(raw, b.DescriptorBytes) && sha256.Sum256(raw) == b.DescriptorHash
}

func directReconcileBindingContextError(ctx context.Context) error {
	if ctx == nil {
		return errDirectEndpointReconcileBinding
	}
	return ctx.Err()
}

// This pure membership check never expires or replaces the admitted handle.
func directReconcileBindingCurrentContext(ctx context.Context, s *DirectEndpointSubscription) error {
	if err := directReconcileBindingContextError(ctx); err != nil {
		return err
	}
	if s == nil || s.owner == nil || s.aborted() {
		return errDirectEndpointReconcileBinding
	}
	unlock, err := directEndpointTryLock(ctx, &s.owner.mu)
	if err != nil {
		return err
	}
	defer unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, current := s.owner.entries[s]; !current || s.aborted() {
		return errDirectEndpointReconcileBinding
	}
	return nil
}
