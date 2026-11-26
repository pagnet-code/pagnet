//go:build linux || darwin

package daemon

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func consentBindingFixture(t *testing.T, role string) (*DirectEndpointSubscription, ManagedEndpointPrepareScope, string, directEndpointReconcileBinding, time.Time) {
	t.Helper()
	raw, err := os.ReadFile("../directchannelcrypto/testdata/sdk-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector enrollmentVector
	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	d, err := transport.DecodeDirectChannelDescriptorV2(vector.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	deadline := now.Add(time.Hour)
	d.ExpiresAt, d.Budget.ExpiresAt = deadline.Format(time.RFC3339Nano), deadline.Add(time.Hour).Format(time.RFC3339Nano)
	local := d.S
	if role == "P" {
		local = d.P
	}
	captured := ManagedEndpointPrepareScope{Socket: &websocket.Conn{}, Connection: &NativeObservationConnection{}, Session: transport.HostSessionPayload{TenantID: local.TenantID, AccountID: "account", HostID: "host", HostCredentialID: "host-credential", NativeAdmissionID: "admission", RunnerID: "runner", RunnerEpoch: now, BootID: "boot", ProtocolFeatures: []string{"feature"}}}
	subject := nativeManagedSubject{TenantID: domain.ID(local.TenantID), AccountID: "account", HostID: "host", HostCredentialID: "host-credential", NativeAdmissionID: "admission", RunnerID: "runner", RunnerConnectedAt: now, BootID: "boot", InstanceID: "instance", OwnershipGeneration: "1", NativeGeneration: "native-generation", PrincipalID: domain.ID(local.PrincipalID), OriginID: "origin", ExpiresAt: deadline}
	session, _ := json.Marshal(captured.Session)
	issue := []byte("retained issue")
	owner := &directEndpointSubscriptions{}
	s := owner.add(directEndpointBinding{metadata: DirectEndpointSubscriptionMetadata{InstallationID: "installation", TenantID: subject.TenantID, PrincipalID: subject.PrincipalID, EndpointID: domain.ID(local.EndpointID), OriginID: subject.OriginID, IntentID: domain.ID(d.DirectIntentID), CredentialID: domain.ID(local.CredentialID), Role: role, ServerOrigin: "https://server.example", OwnershipGeneration: subject.OwnershipGeneration, Deadline: deadline}, issueDigest: sha256.Sum256(issue), sessionIdentity: string(session), socket: captured.Socket, native: captured.Connection, subject: subject})
	t.Cleanup(owner.close)
	pub, _ := base64.RawURLEncoding.DecodeString(local.PublicKey)
	evidence, err := validateDirectEndpointReconcileBinding(s, captured, issue, nil, subject, d, reconcileEnrollment(t, d, now), now, role, hex.EncodeToString(pub), "https://server.example", "installation", directManagedSourceCredentialProtocolV2)
	if err != nil {
		t.Fatal(err)
	}
	return s, captured, "installation", evidence, now
}

func TestDirectChannelConsentBindingDerivation(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			s, captured, installation, evidence, now := consentBindingFixture(t, role)
			got, err := deriveDirectChannelConsentBinding(s, captured, installation, evidence, now)
			if err != nil {
				t.Fatal(err)
			}
			peer := evidence.Descriptor.P.PrincipalID
			if role == "P" {
				peer = evidence.Descriptor.S.PrincipalID
			}
			want := directChannelConsentBinding{Key: directChannelConsentKey{Server: "https://server.example", Tenant: captured.Session.TenantID, Account: "account", Host: "host", Intent: evidence.Descriptor.DirectIntentID, Role: role, Principal: string(s.binding.subject.PrincipalID)}, Instance: "instance", Origin: "origin", OwnershipGeneration: "1", NativeGeneration: "native-generation", AuthorizationSnapshotDigest: evidence.Descriptor.AuthorizationDigest, PeerPrincipal: peer, GrantID: evidence.Descriptor.ParentGrantID, GrantGeneration: 9007199254740993, Epoch: evidence.Descriptor.EpochID, ExpiresAt: evidence.Descriptor.ExpiresAt}
			if got != want {
				t.Fatalf("binding mismatch: got %+v want %+v", got, want)
			}
			record := directChannelConsentRecord{Key: got.Key, Revision: 7, Enabled: true, Binding: &got}
			if err := validateDirectChannelConsentEligibility(record, 7, s, captured, installation, evidence, now); err != nil {
				t.Fatal(err)
			}
			// Every persisted binding field participates, including every key field.
			for _, field := range []string{"Server", "Tenant", "Account", "Host", "Intent", "Role", "Principal", "Instance", "Origin", "OwnershipGeneration", "NativeGeneration", "AuthorizationSnapshotDigest", "PeerPrincipal", "GrantID", "GrantGeneration", "Epoch", "ExpiresAt"} {
				t.Run(field, func(t *testing.T) {
					changed := got
					value := reflect.ValueOf(&changed).Elem().FieldByName(field)
					if !value.IsValid() {
						value = reflect.ValueOf(&changed.Key).Elem().FieldByName(field)
					}
					if value.Kind() == reflect.Int64 {
						value.SetInt(value.Int() + 1)
					} else {
						value.SetString(value.String() + "-other")
					}
					r := record
					r.Binding = &changed
					if validateDirectChannelConsentEligibility(r, 7, s, captured, installation, evidence, now) == nil {
						t.Fatal("substituted binding accepted")
					}
				})
			}
			for _, kind := range []string{"disabled", "missing", "zero revision", "revision mismatch", "foreign record key", "foreign installation", "expired", "expired subscription", "expired subject", "session", "session features", "socket", "native", "foreign subject", "descriptor", "authority", "overflow", "stale subscription"} {
				t.Run(kind, func(t *testing.T) {
					r, scope, pin, e, at, revision := record, captured, installation, evidence, now, int64(7)
					old := s.binding
					defer func() { s.binding = old }()
					switch kind {
					case "disabled":
						r.Enabled = false
					case "missing":
						r.Binding = nil
					case "zero revision":
						revision, r.Revision = 0, 0
					case "revision mismatch":
						revision++
					case "foreign record key":
						r.Key.Account = "foreign"
					case "foreign installation":
						pin = "foreign"
					case "expired":
						at = now.Add(time.Hour)
					case "expired subscription":
						s.binding.metadata.Deadline = now
					case "expired subject":
						s.binding.subject.ExpiresAt = now
					case "session":
						scope.Session.HostID = "foreign"
					case "session features":
						scope.Session.ProtocolFeatures = []string{"changed"}
					case "socket":
						scope.Socket = &websocket.Conn{}
					case "native":
						scope.Connection = &NativeObservationConnection{}
					case "foreign subject":
						s.binding.subject.AccountID = "foreign"
					case "descriptor":
						e.Descriptor.AuthorizationDigest = strings.Repeat("ab", 32)
					case "authority":
						e.Authority.EpochID = "foreign"
					case "overflow":
						e.Descriptor.GrantGeneration = "9223372036854775808"
						e.DescriptorBytes, _ = e.Descriptor.CanonicalBytes()
						e.DescriptorHash = sha256.Sum256(e.DescriptorBytes)
						e.Authority = reconcileEnrollment(t, e.Descriptor, now).Authority
					case "stale subscription":
						s.Remove()
					}
					if validateDirectChannelConsentEligibility(r, revision, s, scope, pin, e, at) == nil {
						t.Fatal("ineligible snapshot accepted")
					}
					if kind == "expired subscription" {
						if _, exists := s.owner.entries[s]; !exists {
							t.Fatal("pure check removed expired subscription")
						}
					}
				})
			}
		})
	}
}
