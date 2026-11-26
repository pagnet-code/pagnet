//go:build linux || darwin

package daemon

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/directhttp"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func newReconcileObservationTargetFixture(t *testing.T) (*reconcileOperationFixture, directEndpointReconcileBinding, directhttp.Enrollment) {
	t.Helper()
	keys, pop, session, private := managedPoPStoreFixture(t, false)
	clear(private)
	pop.Authorization.EpochID = domain.ID("01900000-0000-7000-8000-000000000099")
	var err error
	pop.AuthorizationDigest, err = pop.Authorization.Digest()
	if err != nil {
		t.Fatal(err)
	}
	_, issue, session, _ := managedCredentialStoreIssue(t, keys, pop, session)
	endpointSubject := issue.PoP.Prepare.Subject
	session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol, transport.NativeWorkerOwnershipProtocol}
	scope := sessionworker.Scope{ServerURL: "https://example.test", TenantID: session.TenantID, AccountID: session.AccountID, HostID: session.HostID, InstanceID: endpointSubject.InstanceID.String(), Generation: endpointSubject.OwnershipGeneration}
	spec := sessionworker.NativeSpec{Runtime: domain.RuntimeQwenCode, Binary: "/bin/true", MCPExecutable: "/bin/true", Workspace: t.TempDir(), Kind: "worker", TenantID: scope.TenantID, NetworkTenantID: scope.TenantID, NetworkID: domain.NewID().String()}
	record, err := keys.registry.Reserve(scope, spec, "custom-qwen", "")
	if err != nil {
		t.Fatal(err)
	}
	ownership := transport.NativeWorkerOwnership{ID: endpointSubject.OwnershipID.String(), InstanceID: scope.InstanceID, OwnershipGeneration: scope.Generation, Runtime: string(spec.Runtime), Profile: record.Profile, ProfileFingerprint: record.ProfileFingerprint, OriginalAdmissionID: domain.NewID().String(), State: "active"}
	if err := keys.registry.BindOwnership(record, ownership); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.registry.db.Exec(`UPDATE native_workers SET launch_state='launched' WHERE instance_id=?`, scope.InstanceID); err != nil {
		t.Fatal(err)
	}
	state, err := OpenState(filepath.Join(t.TempDir(), "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.UpsertInstance(InstanceRow{InstanceID: scope.InstanceID, Runtime: string(spec.Runtime), Profile: record.Profile, AgentPrincipalID: endpointSubject.PrincipalID.String()}); err != nil {
		t.Fatal(err)
	}
	native := NewNativeObservationConnection(scope.ServerURL, scope.HostID, session.BootID, nil)
	if err := native.Admit(session); err != nil {
		t.Fatal(err)
	}
	socket := &websocket.Conn{}
	proxy := &NativeWorkerProxy{connection: native, scope: scope, profile: record.ProfileFingerprint, bootstrap: sessionworker.Bootstrap{Native: spec}, done: make(chan struct{}), abortDone: make(chan struct{})}
	link := &nativeWorkerLink{conn: socket, proxy: proxy, ownership: ownership}
	d := &Daemon{Config: Config{ServerURL: "https://example.test"}, state: state, nativeRegistry: keys.registry, nativeWorkers: map[string]*nativeWorkerLink{scope.InstanceID: link}, curConn: socket, nativeConn: native}
	token := &nativeWorkerPublicationToken{instanceID: scope.InstanceID, link: link, proxy: proxy, ownership: ownership, subject: nativeManagedSubjectFromEndpoint(endpointSubject)}
	captured := ManagedEndpointPrepareScope{Socket: socket, Connection: native, Session: session}
	if _, err := keys.InstallCredential(issue, d.ServerURL, captured.Session, managedCredentialScopeOK, managedCredentialFenceOK); err != nil {
		t.Fatal(err)
	}
	subject := nativeManagedSubjectFromEndpoint(issue.PoP.Prepare.Subject)
	subject.ExpiresAt = issue.PoP.Authorization.ExpiresAt
	token.subject = subject
	snapshot := reconcileOperationSnapshot(t, token)
	token.endpointEpoch = token.proxy.observeDirectEndpointSnapshot(snapshot, token.proxy.directEndpointObservationEpoch())
	metadata := DirectEndpointSubscriptionMetadata{InstallationID: keys.installation, TenantID: endpointSubject.TenantID, PrincipalID: endpointSubject.PrincipalID, EndpointID: endpointSubject.EndpointID, OriginID: subject.OriginID, IntentID: endpointSubject.DirectIntentID, CredentialID: issue.CredentialID, Role: "P", ServerOrigin: d.ServerURL, OwnershipGeneration: subject.OwnershipGeneration, Deadline: directEndpointDeadline(issue.CredentialExpiresAt, issue.Budget.ExpiresAt, subject.ExpiresAt)}
	raw, err := issue.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	materialScope := endpointMaterialScope{metadata.InstallationID, metadata.CredentialID, "P", endpointMaterialLiveUse}
	subscription, err := d.admitDirectEndpoint(context.Background(), captured, metadata, raw, subject, managedDirectCredentialProtocolV1, issue.IssuedAt, func(verify func() error, fence endpointMaterialFence, use func(endpointMaterial) error) error {
		return keys.withManagedTargetEndpointMaterial(issue, d.ServerURL, captured.Session, materialScope, func(transport.ManagedDirectCredentialIssue, string, transport.HostSessionPayload) error {
			return verify()
		}, fence, use)
	}, func(context.Context, ManagedEndpointPrepareScope, string, nativeManagedSubject) (*nativeWorkerPublicationToken, error) {
		return token, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.directSubscriptions.close)
	proxy.controller = endpointRPCController(t, proxy.scope, proxy.connection, func(server net.Conn, _ *NativeObservationConnection) {
		for endpointRPCRequest(t, server) {
			if swWriteFrame(server, sessionworker.Response{OwnershipVerify: &sessionworker.NativeOwnershipVerifyResult{Snapshot: snapshot}}) != nil {
				return
			}
		}
	})
	f := &reconcileOperationFixture{d: d, s: subscription, token: token, captured: captured, target: issue, role: "P"}
	raw, err = os.ReadFile("../directchannelcrypto/testdata/sdk-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct{ Descriptor []byte }
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	descriptor, err := transport.DecodeDirectChannelDescriptorV2(vector.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	v, a := issue.PoP.Prepare.Subject, issue.PoP.Authorization
	descriptor.ParentGrantID, descriptor.GrantGeneration, descriptor.NetworkID = string(a.GrantID), jsonDecimal(a.GrantGeneration), string(a.NetworkID)
	descriptor.AuthorizationDigest, descriptor.EpochID = issue.PoP.AuthorizationDigest, string(a.EpochID)
	descriptor.P.TenantID, descriptor.P.PrincipalID, descriptor.P.EndpointID, descriptor.P.CredentialID = string(v.TenantID), string(v.PrincipalID), string(v.EndpointID), string(issue.CredentialID)
	descriptor.S.TenantID, descriptor.S.PrincipalID = string(a.InviterTenantID), string(a.SourcePrincipalID)
	descriptor.DirectIntentID, descriptor.ChannelGeneration = string(v.DirectIntentID), "1"
	descriptor.Budget.AgreementID, descriptor.Budget.AcceptedRevision, descriptor.Budget.TermsDigest = string(issue.Budget.AgreementID), "2", issue.Budget.TermsDigest
	descriptor.Budget.ExpiresAt = issue.Budget.ExpiresAt.UTC().Format(time.RFC3339Nano)
	descriptor.ExpiresAt = issue.CredentialExpiresAt.UTC().Format(time.RFC3339Nano)
	public, err := hex.DecodeString(issue.PoP.ACK.Reservation.X25519)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.P.PublicKey = base64.RawURLEncoding.EncodeToString(public)
	now := time.Now()
	enrollment := reconcileEnrollment(t, descriptor, now)
	binding, err := validateDirectTargetReconcileBindingContext(t.Context(), subscription, captured, issue, descriptor, enrollment, now)
	if err != nil {
		t.Fatal(err)
	}
	return f, binding, enrollment
}
