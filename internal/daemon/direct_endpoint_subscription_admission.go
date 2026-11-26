//go:build linux || darwin

package daemon

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"reflect"
	"time"

	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

// admitManagedTargetEndpoint is an explicit local admission. Credential install
// and ACK handling never call it. No HTTP, WSS or coordinator traffic is started.
func (d *Daemon) admitManagedTargetEndpoint(ctx context.Context, captured ManagedEndpointPrepareScope, issue transport.ManagedDirectCredentialIssue) (*DirectEndpointSubscription, error) {
	e, err := newLocalManagedDirectCredential(d)
	if err != nil {
		return nil, ErrManagedEndpointPrepareRetryable
	}
	raw, err := issue.CanonicalBytes()
	if err != nil {
		return nil, ErrManagedEndpointPrepareRejected
	}
	subject := nativeManagedSubjectFromEndpoint(issue.PoP.Prepare.Subject)
	subject.ExpiresAt = issue.PoP.Authorization.ExpiresAt
	metadata := DirectEndpointSubscriptionMetadata{InstallationID: e.keys.installation, TenantID: issue.PoP.Prepare.Subject.TenantID, PrincipalID: issue.PoP.Prepare.Subject.PrincipalID, EndpointID: issue.PoP.Prepare.Subject.EndpointID, OriginID: subject.OriginID, IntentID: issue.PoP.Prepare.Subject.DirectIntentID, CredentialID: issue.CredentialID, Role: "P", ServerOrigin: issue.PoP.ACK.Reservation.ServerURL, OwnershipGeneration: subject.OwnershipGeneration, Deadline: directEndpointDeadline(issue.CredentialExpiresAt, issue.Budget.ExpiresAt, subject.ExpiresAt)}
	scope := endpointMaterialScope{metadata.InstallationID, metadata.CredentialID, metadata.Role, endpointMaterialLiveUse}
	return d.admitDirectEndpoint(ctx, captured, metadata, raw, subject, managedDirectCredentialProtocolV1, issue.IssuedAt, func(verify func() error, fence endpointMaterialFence, use func(endpointMaterial) error) error {
		return e.keys.withManagedTargetEndpointMaterial(issue, metadata.ServerOrigin, captured.Session, scope, func(transport.ManagedDirectCredentialIssue, string, transport.HostSessionPayload) error {
			return verify()
		}, fence, use)
	}, d.verifyDirectEndpointToken)
}

func (d *Daemon) admitDirectManagedSourceEndpointV2(ctx context.Context, captured ManagedEndpointPrepareScope, issue transport.DirectManagedSourceCredentialIssueV2) (*DirectEndpointSubscription, error) {
	e, err := newLocalDirectManagedSourceCredentialV2(d)
	if err != nil {
		return nil, ErrManagedEndpointPrepareRetryable
	}
	raw, err := issue.CanonicalBytes()
	if err != nil {
		return nil, ErrManagedEndpointPrepareRejected
	}
	subject := nativeManagedSubjectFromSourceV2(issue.PoP.Prepare.Subject)
	subject.ExpiresAt = issue.PoP.Prepare.Subject.AuthorizationExpiresAt
	metadata := DirectEndpointSubscriptionMetadata{InstallationID: e.keys.installation, TenantID: issue.PoP.Prepare.Subject.TenantID, PrincipalID: issue.PoP.Prepare.Subject.PrincipalID, EndpointID: issue.PoP.Prepare.Subject.EndpointID, OriginID: subject.OriginID, IntentID: issue.PoP.Prepare.Subject.DirectIntentID, CredentialID: issue.CredentialID, Role: "S", ServerOrigin: issue.PoP.ACK.Reservation.ServerURL, OwnershipGeneration: subject.OwnershipGeneration, Deadline: directEndpointDeadline(issue.CredentialExpiresAt, issue.BudgetExpiresAt, subject.ExpiresAt)}
	scope := endpointMaterialScope{metadata.InstallationID, metadata.CredentialID, metadata.Role, endpointMaterialLiveUse}
	return d.admitDirectEndpoint(ctx, captured, metadata, raw, subject, directManagedSourceCredentialProtocolV2, issue.IssuedAt, func(verify func() error, fence endpointMaterialFence, use func(endpointMaterial) error) error {
		return e.keys.withDirectManagedSourceEndpointMaterialV2(issue, metadata.ServerOrigin, captured.Session, scope, func(transport.DirectManagedSourceCredentialIssueV2, string, transport.HostSessionPayload) error {
			return verify()
		}, fence, use)
	}, d.verifyDirectEndpointToken)
}

func directEndpointDeadline(values ...time.Time) time.Time {
	result := values[0]
	for _, value := range values[1:] {
		if value.Before(result) {
			result = value
		}
	}
	return result
}

func (d *Daemon) verifyDirectEndpointToken(ctx context.Context, captured ManagedEndpointPrepareScope, server string, subject nativeManagedSubject) (*nativeWorkerPublicationToken, error) {
	if ctx.Err() != nil || managedPrepareServerOrigin(d.nativeServerURL()) != server {
		return nil, ErrManagedEndpointPrepareRejected
	}
	return d.verifyNativeManagedSubjectToken(ctx, captured, server, subject, func(ctx context.Context, p *NativeWorkerProxy, ownership transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error) {
		response, err := p.call(ctx, sessionworker.Request{Type: "ownership_verify", OwnershipVerify: &sessionworker.NativeOwnershipVerifyRequest{Ownership: ownership}})
		return response.OwnershipVerify, err
	})
}

type directEndpointCustodyUse func(func() error, endpointMaterialFence, func(endpointMaterial) error) error

// Candidate publication is inside custody's authority fence. The handle stays
// private until transaction completion and the final verification succeed.
// Invalidation registration precedes releasing the fence, including on panic.
func (d *Daemon) admitDirectEndpoint(ctx context.Context, captured ManagedEndpointPrepareScope, metadata DirectEndpointSubscriptionMetadata, raw []byte, subject nativeManagedSubject, variant directManagedSourceCredentialProtocolVariant, issuedAt time.Time, custody directEndpointCustodyUse, verifyToken func(context.Context, ManagedEndpointPrepareScope, string, nativeManagedSubject) (*nativeWorkerPublicationToken, error)) (result *DirectEndpointSubscription, err error) {
	if d == nil || ctx == nil || custody == nil || verifyToken == nil || captured.Socket == nil || captured.Connection == nil || metadata.ServerOrigin == "" || managedPrepareServerOrigin(metadata.ServerOrigin) != metadata.ServerOrigin || managedPrepareServerOrigin(d.nativeServerURL()) != metadata.ServerOrigin {
		return nil, ErrManagedEndpointPrepareRejected
	}
	// Own the authenticated session copy: protocol feature slices must not alias a
	// caller's snapshot after admission.
	sessionRaw, err := json.Marshal(captured.Session)
	if err != nil {
		return nil, ErrManagedEndpointPrepareRejected
	}
	if err = json.Unmarshal(sessionRaw, &captured.Session); err != nil {
		return nil, ErrManagedEndpointPrepareRejected
	}
	var token *nativeWorkerPublicationToken
	var candidate *DirectEndpointSubscription
	complete := false
	defer func() {
		if !complete && candidate != nil {
			candidate.Remove()
		}
	}()
	lane := newDirectManagedSourceCredentialPublicationLane()
	stop := context.AfterFunc(ctx, lane.cancel)
	defer stop()
	verify := func() error {
		if ctx.Err() != nil {
			return ErrManagedEndpointPrepareRetryable
		}
		fresh, verifyErr := verifyToken(ctx, captured, metadata.ServerOrigin, subject)
		if verifyErr != nil {
			return verifyErr
		}
		if fresh == nil || fresh.link == nil || fresh.proxy == nil || !reflect.DeepEqual(fresh.subject, subject) {
			return ErrManagedEndpointPrepareRejected
		}
		if token != nil && (fresh.link != token.link || fresh.proxy != token.proxy || !sameManagedPrepareOwnership(fresh.ownership, token.ownership)) {
			return ErrManagedEndpointPrepareRetryable
		}
		epoch, current := fresh.proxy.directEndpointAuthority(subject)
		if !current || fresh.endpointEpoch != epoch {
			return ErrManagedEndpointPrepareRetryable
		}
		fresh.endpointUse = true
		token = fresh
		return nil
	}
	fence := func(conn *sql.Conn) (func(), func() error, error) {
		// The installation deadline is deliberately absent from live authority.
		release, fenceErr := d.credentialPublicationFence(token, captured, lane, subject, nativeManagedSessionMatches(subject, captured.Session), variant, issuedAt, metadata.Deadline, metadata.Deadline, metadata.Deadline)(conn, metadata.ServerOrigin, captured.Session)
		if fenceErr != nil {
			return release, nil, fenceErr
		}
		check := func() error {
			if ctx.Err() != nil || !time.Now().Before(metadata.Deadline) {
				return ErrManagedEndpointPrepareRetryable
			}
			return nil
		}
		return release, check, nil
	}
	err = custody(verify, fence, func(endpointMaterial) error {
		if ctx.Err() != nil || token == nil {
			return ErrManagedEndpointPrepareRetryable
		}
		// Registry, proxy and connection remain fenced here. Invalidation only
		// acquires its index followed by the owner leaf mutex.
		d.nativeRegistry.directInvalidations.register(&d.directSubscriptions)
		token.proxy.directInvalidations.register(&d.directSubscriptions)
		captured.Connection.directInvalidations.register(&d.directSubscriptions)
		candidate = d.directSubscriptions.add(directEndpointBinding{metadata: metadata, issueDigest: sha256.Sum256(raw), sessionIdentity: string(sessionRaw), socket: captured.Socket, native: captured.Connection, link: token.link, proxy: token.proxy, subject: subject})
		if candidate == nil {
			return ErrManagedEndpointPrepareRetryable
		}
		return nil
	})
	if err != nil || candidate == nil || ctx.Err() != nil || !d.directSubscriptions.activate(candidate) {
		return nil, ErrManagedEndpointPrepareRetryable
	}
	complete = true
	return candidate, nil
}
