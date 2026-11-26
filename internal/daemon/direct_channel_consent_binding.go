//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"strconv"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

// deriveDirectChannelConsentBinding derives public opt-in metadata from an exact
// live admission and previously validated reconcile evidence. captured must come
// from the authenticated connection; installation must come from the scoped
// consent store. This check neither enables consent nor leases later dispatch.
func deriveDirectChannelConsentBinding(s *DirectEndpointSubscription, captured ManagedEndpointPrepareScope, installation string, evidence directEndpointReconcileBinding, now time.Time) (directChannelConsentBinding, error) {
	reject := func() (directChannelConsentBinding, error) {
		return directChannelConsentBinding{}, errDirectChannelConsent
	}
	if now.IsZero() || !consentText(installation) || directReconcileBindingCurrentContext(context.Background(), s) != nil {
		return reject()
	}
	admitted := s.binding
	m, subject := admitted.metadata, admitted.subject
	session, err := json.Marshal(captured.Session)
	if err != nil || string(session) != admitted.sessionIdentity || captured.Socket == nil || captured.Connection == nil || captured.Socket != admitted.socket || captured.Connection != admitted.native || installation != string(m.InstallationID) || !now.Before(m.Deadline) || !now.Before(subject.ExpiresAt) {
		return reject()
	}
	host := captured.Session
	if host.TenantID != string(subject.TenantID) || host.AccountID != string(subject.AccountID) || host.HostID != string(subject.HostID) || host.HostCredentialID != string(subject.HostCredentialID) || host.NativeAdmissionID != string(subject.NativeAdmissionID) || host.RunnerID != string(subject.RunnerID) || !host.RunnerEpoch.Equal(subject.RunnerConnectedAt) || host.BootID != subject.BootID || m.TenantID != subject.TenantID || m.PrincipalID != subject.PrincipalID || m.OriginID != subject.OriginID || m.OwnershipGeneration != subject.OwnershipGeneration {
		return reject()
	}
	d := evidence.Descriptor
	raw, err := d.CanonicalBytes()
	channel, channelErr := transport.DirectChannelIDV2(d)
	expires, expiryErr := time.Parse(time.RFC3339Nano, d.ExpiresAt)
	generation, generationErr := strconv.ParseInt(d.GrantGeneration, 10, 64)
	a := evidence.Authority
	if err != nil || channelErr != nil || expiryErr != nil || generationErr != nil || transport.ValidateDirectChannelDescriptorV2(d, now) != nil || !bytes.Equal(raw, evidence.DescriptorBytes) || sha256.Sum256(raw) != evidence.DescriptorHash || a.ParentGrantID != d.ParentGrantID || a.GrantGeneration != d.GrantGeneration || a.ChannelID != channel || a.ChannelGeneration != d.ChannelGeneration || a.EpochID != d.EpochID || !a.ExpiresAt.Equal(expires) {
		return reject()
	}
	local, peer := d.S, d.P
	switch m.Role {
	case "S":
	case "P":
		local, peer = d.P, d.S
	default:
		return reject()
	}
	if local.TenantID != string(m.TenantID) || local.PrincipalID != string(m.PrincipalID) || local.EndpointID != string(m.EndpointID) || local.CredentialID != string(m.CredentialID) || d.DirectIntentID != string(m.IntentID) {
		return reject()
	}
	binding := directChannelConsentBinding{
		Key:      directChannelConsentKey{Server: m.ServerOrigin, Tenant: host.TenantID, Account: host.AccountID, Host: host.HostID, Intent: string(m.IntentID), Role: m.Role, Principal: string(m.PrincipalID)},
		Instance: string(subject.InstanceID), Origin: string(subject.OriginID), OwnershipGeneration: subject.OwnershipGeneration, NativeGeneration: subject.NativeGeneration,
		AuthorizationSnapshotDigest: d.AuthorizationDigest, PeerPrincipal: peer.PrincipalID, GrantID: d.ParentGrantID, GrantGeneration: generation, Epoch: d.EpochID, ExpiresAt: d.ExpiresAt,
	}
	if !consentKeyValid(binding.Key) || !binding.valid() || directReconcileBindingCurrentContext(context.Background(), s) != nil {
		return reject()
	}
	return binding, nil
}

// validateDirectChannelConsentEligibility compares one persisted snapshot with
// the caller's expected revision. It does not read storage or fence subsequent
// use: later dispatch still needs its own consent and authority synchronization.
func validateDirectChannelConsentEligibility(record directChannelConsentRecord, expectedRevision int64, s *DirectEndpointSubscription, captured ManagedEndpointPrepareScope, installation string, evidence directEndpointReconcileBinding, now time.Time) error {
	if expectedRevision <= 0 || record.Revision != expectedRevision || !record.Enabled || record.Binding == nil {
		return errDirectChannelConsent
	}
	binding, err := deriveDirectChannelConsentBinding(s, captured, installation, evidence, now)
	if err != nil || record.Key != binding.Key || *record.Binding != binding {
		return errDirectChannelConsent
	}
	return nil
}
