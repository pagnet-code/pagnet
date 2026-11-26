//go:build linux || darwin

package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/directhttp"
	"github.com/pagnet-code/pagnet/transport"
)

func reconcileEnrollment(t *testing.T, d transport.DirectChannelDescriptorV2, now time.Time) directhttp.Enrollment {
	t.Helper()
	raw, err := d.CanonicalBytes()
	if err != nil {
		return directhttp.Enrollment{}
	}
	h := sha256.Sum256(raw)
	channel, _ := transport.DirectChannelIDV2(d)
	expires, _ := time.Parse(time.RFC3339Nano, d.ExpiresAt)
	return directhttp.Enrollment{DescriptorHash: base64.RawURLEncoding.EncodeToString(h[:]), ObservedAt: now, Authority: directhttp.EnrollmentAuthority{ParentGrantID: d.ParentGrantID, GrantGeneration: d.GrantGeneration, ChannelID: channel, ChannelGeneration: d.ChannelGeneration, EpochID: d.EpochID, ExpiresAt: expires}}
}

func TestDirectEndpointReconcileBinding(t *testing.T) {
	raw, err := os.ReadFile("../directchannelcrypto/testdata/sdk-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector enrollmentVector
	if json.Unmarshal(raw, &vector) != nil {
		t.Fatal("vector")
	}
	template, err := transport.DecodeDirectChannelDescriptorV2(vector.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			d := template
			captured := ManagedEndpointPrepareScope{}
			var issueRaw []byte
			var subject nativeManagedSubject
			var source transport.DirectManagedSourceCredentialIssueV2
			var target transport.ManagedDirectCredentialIssue
			var installation domain.ID
			var server, key string
			var issued, deadline time.Time
			if role == "S" {
				_, source, captured.Session = directSourceCredentialFixtureV2(t)
				issueRaw, err = source.CanonicalBytes()
				v := source.PoP.Prepare.Subject
				subject = nativeManagedSubjectFromSourceV2(v)
				subject.ExpiresAt = v.AuthorizationExpiresAt
				d.ParentGrantID, d.GrantGeneration, d.NetworkID = string(v.GrantID), "1", string(v.NetworkID)
				d.S.TenantID, d.S.PrincipalID, d.S.EndpointID, d.S.CredentialID = string(v.TenantID), string(v.PrincipalID), string(v.EndpointID), string(source.CredentialID)
				d.P.PrincipalID = string(v.TargetPrincipalID)
				d.DirectIntentID, d.ChannelGeneration = string(v.DirectIntentID), source.ChannelGeneration
				d.Budget.AgreementID, d.Budget.AcceptedRevision, d.Budget.TermsDigest = string(v.BudgetID), "2", v.BudgetTermsDigest
				d.GrantGeneration = jsonDecimal(v.GrantGeneration)
				d.Budget.AcceptedRevision = jsonDecimal(v.BudgetAcceptedRevision)
				d.Budget.ExpiresAt = source.BudgetExpiresAt.UTC().Format(time.RFC3339Nano)
				installation, server, key = source.PoP.ACK.Reservation.InstallationID, source.PoP.ACK.Reservation.ServerURL, source.PoP.ACK.Reservation.X25519
				issued, deadline = source.IssuedAt, source.CredentialExpiresAt
			} else {
				keys, pop, session, private := managedPoPStoreFixture(t, false)
				clear(private)
				pop.Authorization.EpochID = domain.ID("01900000-0000-7000-8000-000000000099")
				pop.AuthorizationDigest, err = pop.Authorization.Digest()
				if err != nil {
					t.Fatal("authorization")
				}
				_, target, captured.Session, _ = managedCredentialStoreIssue(t, keys, pop, session)
				issueRaw, err = target.CanonicalBytes()
				v, a := target.PoP.Prepare.Subject, target.PoP.Authorization
				subject = nativeManagedSubjectFromEndpoint(v)
				subject.ExpiresAt = a.ExpiresAt
				d.ParentGrantID, d.GrantGeneration, d.NetworkID = string(a.GrantID), jsonDecimal(a.GrantGeneration), string(a.NetworkID)
				d.AuthorizationDigest, d.EpochID = target.PoP.AuthorizationDigest, string(a.EpochID)
				d.P.TenantID, d.P.PrincipalID, d.P.EndpointID, d.P.CredentialID = string(v.TenantID), string(v.PrincipalID), string(v.EndpointID), string(target.CredentialID)
				d.S.TenantID, d.S.PrincipalID = string(a.InviterTenantID), string(a.SourcePrincipalID)
				d.DirectIntentID, d.ChannelGeneration = string(v.DirectIntentID), "1"
				d.Budget.AgreementID, d.Budget.AcceptedRevision, d.Budget.TermsDigest = string(target.Budget.AgreementID), "2", target.Budget.TermsDigest
				d.Budget.ExpiresAt = target.Budget.ExpiresAt.UTC().Format(time.RFC3339Nano)
				installation, server, key = target.PoP.ACK.Reservation.InstallationID, target.PoP.ACK.Reservation.ServerURL, target.PoP.ACK.Reservation.X25519
				issued, deadline = target.IssuedAt, target.CredentialExpiresAt
			}
			if err != nil {
				t.Fatal("issue")
			}
			now := issued.Add(time.Millisecond)
			d.ExpiresAt = deadline.UTC().Format(time.RFC3339Nano)
			pub, _ := hex.DecodeString(key)
			local := &d.S
			if role == "P" {
				local = &d.P
			}
			local.PublicKey = base64.RawURLEncoding.EncodeToString(pub)
			session, _ := json.Marshal(captured.Session)
			owner := &directEndpointSubscriptions{}
			s := owner.add(directEndpointBinding{metadata: DirectEndpointSubscriptionMetadata{InstallationID: installation, TenantID: domain.ID(local.TenantID), PrincipalID: domain.ID(local.PrincipalID), EndpointID: domain.ID(local.EndpointID), OriginID: subject.OriginID, IntentID: domain.ID(d.DirectIntentID), CredentialID: domain.ID(local.CredentialID), Role: role, ServerOrigin: server, OwnershipGeneration: subject.OwnershipGeneration, Deadline: deadline}, issueDigest: sha256.Sum256(issueRaw), sessionIdentity: string(session), subject: subject})
			t.Cleanup(owner.close)
			validate := func(desc transport.DirectChannelDescriptorV2, e directhttp.Enrollment, at time.Time) (directEndpointReconcileBinding, error) {
				if role == "S" {
					return validateDirectSourceReconcileBindingV2(s, captured, source, desc, e, at)
				}
				return validateDirectTargetReconcileBinding(s, captured, target, desc, e, at)
			}
			validateContext := func(ctx context.Context) (directEndpointReconcileBinding, error) {
				if role == "S" {
					return validateDirectSourceReconcileBindingV2Context(ctx, s, captured, source, d, reconcileEnrollment(t, d, now), now)
				}
				return validateDirectTargetReconcileBindingContext(ctx, s, captured, target, d, reconcileEnrollment(t, d, now), now)
			}
			for _, kind := range []string{"busy", "cancelled", "nil context", "aborted"} {
				t.Run("context "+kind, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
					defer cancel()
					var want error = errDirectEndpointLocalBusy
					if kind == "cancelled" {
						cancel()
						want = context.Canceled
					}
					var checkctx context.Context = ctx
					if kind == "nil context" {
						checkctx = nil
						want = errDirectEndpointReconcileBinding
					}
					if kind == "aborted" {
						done := make(chan struct{})
						close(done)
						s.binding.proxy = &NativeWorkerProxy{abortDone: done}
						defer func() { s.binding.proxy = nil }()
						want = errDirectEndpointReconcileBinding
					}
					s.owner.mu.Lock()
					start := time.Now()
					_, contextErr := validateContext(checkctx)
					s.owner.mu.Unlock()
					if !errors.Is(contextErr, want) {
						t.Fatalf("context validation: %v want %v", contextErr, want)
					}
					if time.Since(start) > time.Second {
						t.Fatal("binding validation waited for owner")
					}
				})
			}
			if _, err := validateContext(context.Background()); err != nil {
				t.Fatalf("context checks changed binding: %v", err)
			}
			e := reconcileEnrollment(t, d, now)
			out, err := validate(d, e, now)
			if err != nil {
				t.Fatal("valid binding rejected", err)
			}
			peer := d.P
			if role == "P" {
				peer = d.S
			}
			peerBytes, _ := base64.RawURLEncoding.DecodeString(peer.PublicKey)
			if out.LocalFingerprint != sha256.Sum256(pub) || out.PeerFingerprint != sha256.Sum256(peerBytes) {
				t.Fatal("fingerprints")
			}
			cases := map[string]func(*transport.DirectChannelDescriptorV2){
				"grant":              func(d *transport.DirectChannelDescriptorV2) { d.ParentGrantID = string(domain.NewID()) },
				"grant generation":   func(d *transport.DirectChannelDescriptorV2) { d.GrantGeneration = "99" },
				"channel generation": func(d *transport.DirectChannelDescriptorV2) { d.ChannelGeneration = "99" },
				"network":            func(d *transport.DirectChannelDescriptorV2) { d.NetworkID = string(domain.NewID()) },
				"intent":             func(d *transport.DirectChannelDescriptorV2) { d.DirectIntentID = string(domain.NewID()) },
				"source principal":   func(d *transport.DirectChannelDescriptorV2) { d.S.PrincipalID = string(domain.NewID()) },
				"target principal":   func(d *transport.DirectChannelDescriptorV2) { d.P.PrincipalID = string(domain.NewID()) },
				"budget ID":          func(d *transport.DirectChannelDescriptorV2) { d.Budget.AgreementID = string(domain.NewID()) },
				"budget revision":    func(d *transport.DirectChannelDescriptorV2) { d.Budget.AcceptedRevision = "99" },
				"budget digest":      func(d *transport.DirectChannelDescriptorV2) { d.Budget.TermsDigest = strings.Repeat("ab", 32) },
				"budget expiry": func(d *transport.DirectChannelDescriptorV2) {
					d.Budget.ExpiresAt = deadline.Add(time.Hour).UTC().Format(time.RFC3339Nano)
				},
				"deadline": func(d *transport.DirectChannelDescriptorV2) {
					d.ExpiresAt = deadline.Add(time.Second).UTC().Format(time.RFC3339Nano)
				},
				"expired":       func(d *transport.DirectChannelDescriptorV2) { d.ExpiresAt = now.UTC().Format(time.RFC3339Nano) },
				"swapped roles": func(d *transport.DirectChannelDescriptorV2) { d.S, d.P = d.P, d.S },
			}
			for _, field := range []string{"tenant", "endpoint", "credential", "key", "hex key", "padded key"} {
				field := field
				cases["local "+field] = func(d *transport.DirectChannelDescriptorV2) {
					p := &d.S
					if role == "P" {
						p = &d.P
					}
					switch field {
					case "tenant":
						p.TenantID = string(domain.NewID())
					case "endpoint":
						p.EndpointID = string(domain.NewID())
					case "credential":
						p.CredentialID = string(domain.NewID())
					case "key":
						p.PublicKey = peer.PublicKey
					case "hex key":
						p.PublicKey = key
					case "padded key":
						p.PublicKey += "="
					}
				}
			}
			if role == "P" {
				cases["authorization digest"] = func(d *transport.DirectChannelDescriptorV2) { d.AuthorizationDigest = strings.Repeat("ab", 32) }
				cases["epoch"] = func(d *transport.DirectChannelDescriptorV2) { d.EpochID = template.EpochID }
				cases["peer tenant"] = func(d *transport.DirectChannelDescriptorV2) { d.S.TenantID = string(domain.NewID()) }
			}
			for name, mutate := range cases {
				t.Run(name, func(t *testing.T) {
					bad := d
					mutate(&bad)
					if _, err := validate(bad, reconcileEnrollment(t, bad, now), now); err != errDirectEndpointReconcileBinding {
						t.Fatal("tamper accepted")
					}
				})
			}
			authorityCases := map[string]func(*directhttp.Enrollment){"hash": func(e *directhttp.Enrollment) { e.DescriptorHash += "=" }, "grant": func(e *directhttp.Enrollment) { e.Authority.ParentGrantID = string(domain.NewID()) }, "grant generation": func(e *directhttp.Enrollment) { e.Authority.GrantGeneration = "99" }, "channel": func(e *directhttp.Enrollment) { e.Authority.ChannelID = strings.Repeat("a", 43) }, "channel generation": func(e *directhttp.Enrollment) { e.Authority.ChannelGeneration = "99" }, "epoch": func(e *directhttp.Enrollment) { e.Authority.EpochID = "01900000-0000-7000-8000-000000000098" }, "expiry": func(e *directhttp.Enrollment) { e.Authority.ExpiresAt = e.Authority.ExpiresAt.Add(time.Second) }, "future observation": func(e *directhttp.Enrollment) { e.ObservedAt = now.Add(time.Second) }}
			for name, mutate := range authorityCases {
				t.Run("authority "+name, func(t *testing.T) {
					bad := e
					mutate(&bad)
					if _, err := validate(d, bad, now); err != errDirectEndpointReconcileBinding {
						t.Fatal("authority tamper accepted")
					}
				})
			}
			original := s.binding
			for _, field := range []string{"issue", "session", "role", "installation", "origin", "ownership", "deadline", "tenant", "principal", "endpoint", "credential", "intent", "server"} {
				t.Run("handle "+field, func(t *testing.T) {
					defer func() { s.binding = original }()
					switch field {
					case "issue":
						s.binding.issueDigest[0] ^= 1
					case "session":
						s.binding.sessionIdentity += " "
					case "role":
						s.binding.metadata.Role = "?"
					case "installation":
						s.binding.metadata.InstallationID = domain.NewID()
					case "origin":
						s.binding.metadata.OriginID = domain.NewID()
					case "ownership":
						s.binding.metadata.OwnershipGeneration = "other"
					case "deadline":
						s.binding.metadata.Deadline = now
					case "tenant":
						s.binding.metadata.TenantID = domain.NewID()
					case "principal":
						s.binding.metadata.PrincipalID = domain.NewID()
					case "endpoint":
						s.binding.metadata.EndpointID = domain.NewID()
					case "credential":
						s.binding.metadata.CredentialID = domain.NewID()
					case "intent":
						s.binding.metadata.IntentID = domain.NewID()
					case "server":
						s.binding.metadata.ServerOrigin = "https://other.test"
					}
					if _, err := validate(d, e, now); err != errDirectEndpointReconcileBinding {
						t.Fatal("handle tamper accepted")
					}
				})
			}
			publication, err := transport.DecodeDirectChannelPublicationV2(vector.Publication)
			if err != nil {
				t.Fatal(err)
			}
			publication.Descriptor = d
			if !out.publicationMatches(publication) {
				t.Fatal("matching publication rejected")
			}
			publication.Descriptor.P.EndpointID = string(domain.NewID())
			if out.publicationMatches(publication) {
				t.Fatal("wrong peer publication accepted")
			}
			t.Run("captured session", func(t *testing.T) {
				original := captured.Session
				defer func() { captured.Session = original }()
				captured.Session.ProtocolFeatures = append(append([]string(nil), captured.Session.ProtocolFeatures...), "other")
				if _, err := validate(d, e, now); err != errDirectEndpointReconcileBinding {
					t.Fatal("session tamper accepted")
				}
			})
			t.Run("retained issue", func(t *testing.T) {
				if role == "S" {
					original := source
					defer func() { source = original }()
					source.CredentialID = domain.NewID()
				} else {
					original := target
					defer func() { target = original }()
					target.CredentialID = domain.NewID()
				}
				if _, err := validate(d, e, now); err != errDirectEndpointReconcileBinding {
					t.Fatal("issue tamper accepted")
				}
			})
			t.Run("before issue", func(t *testing.T) {
				if _, err := validate(d, reconcileEnrollment(t, d, issued.Add(-time.Second)), issued.Add(-time.Second)); err != errDirectEndpointReconcileBinding {
					t.Fatal("premature evidence accepted")
				}
			})
			// Unavailable issue facts are intentionally preserved as server evidence.
			evidence := d
			evidence.S.KeyEvidenceDigest = strings.Repeat("ab", 32)
			evidence.P.KeyEvidenceDigest = strings.Repeat("ab", 32)
			if _, err := validate(evidence, reconcileEnrollment(t, evidence, now), now); err != nil {
				t.Fatal("server evidence rejected")
			}
			s.Remove()
			if _, err := validate(d, e, now); err != errDirectEndpointReconcileBinding {
				t.Fatal("removed handle accepted")
			}
		})
	}
}

func jsonDecimal(n int64) string { raw, _ := json.Marshal(n); return string(raw) }
