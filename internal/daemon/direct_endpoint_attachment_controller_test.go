//go:build linux || darwin

package daemon

import (
	"context"
	"encoding/json"
	"github.com/pagnet-code/pagnet/internal/directchannelcrypto"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func attachmentControllerFixture(t *testing.T, role string) (*directEndpointAttachmentController, *reconcilePassFixture, directChannelConsentBinding) {
	t.Helper()
	return attachmentControllerFixtureWithRoleAdmission(t, role, false)
}

func attachmentControllerFixtureWithRoleAdmission(t *testing.T, role string, realAdmission bool) (*directEndpointAttachmentController, *reconcilePassFixture, directChannelConsentBinding) {
	t.Helper()
	f := newReconcilePassFixture(t, role)
	if role == "P" {
		raw, err := os.ReadFile("../directchannelcrypto/testdata/sdk-v2.json")
		if err != nil {
			t.Fatal(err)
		}
		var vector struct{ SourcePrivate []byte }
		if json.Unmarshal(raw, &vector) != nil {
			t.Fatal("vector")
		}
		defer clear(vector.SourcePrivate)
		material, wire, err := directchannelcrypto.Prepare(f.binding.DescriptorBytes, f.binding.Descriptor, vector.SourcePrivate, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		material.Clear()
		f.client.publication, err = transport.DecodeDirectChannelPublicationV2(wire)
		if err != nil {
			t.Fatal(err)
		}
		f.client.enrollment = publishedEnrollment(f.client.enrollment, wire)
	}
	s := f.f.s
	subject := s.binding.subject
	s.binding.metadata.TenantID, s.binding.metadata.PrincipalID, s.binding.metadata.EndpointID = subject.TenantID, subject.PrincipalID, s.binding.metadata.EndpointID
	local := f.binding.Descriptor.S
	if role == "P" {
		local = f.binding.Descriptor.P
	}
	s.binding.metadata.EndpointID = domain.ID(local.EndpointID)
	features := append([]string(nil), f.f.captured.Session.ProtocolFeatures...)
	features = append(features, transport.DirectEndpointWakeFeatureV1)
	if role == "S" {
		features = append(features, directManagedSourceProtocolsV2[:]...)
	} else {
		features = append(features, transport.ManagedEndpointPrepareProtocol, transport.ManagedEndpointPoPProtocol, transport.ManagedDirectCredentialProtocol)
	}
	unique := make([]string, 0, len(features))
	seen := make(map[string]bool)
	for _, feature := range features {
		if !seen[feature] {
			unique = append(unique, feature)
			seen[feature] = true
		}
	}
	f.f.captured.Session.ProtocolFeatures = unique
	raw, err := json.Marshal(f.f.captured.Session)
	if err != nil {
		t.Fatal(err)
	}
	s.binding.sessionIdentity = string(raw)
	native := f.f.captured.Connection
	native.mu.Lock()
	session := f.f.captured.Session
	native.session, native.offeredDirectEndpointWake = &session, true
	native.mu.Unlock()
	wake := newDirectEndpointWakeConnection(f.f.d, f.f.captured.Socket, native)
	wake.write = func(time.Time, []byte) error { return nil }
	t.Cleanup(wake.close)
	store, err := newDirectChannelConsentStore(t.Context(), f.f.d.nativeRegistry, s.binding.metadata.ServerOrigin, session)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := deriveDirectChannelConsentBinding(s, f.f.captured, store.installation, f.binding, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var c *directEndpointAttachmentController
	if role == "S" {
		c, err = newDirectSourceEndpointAttachmentControllerWithClient(f.f.d, f.f.captured, wake, store, f.f.source, f.client)
	} else {
		c, err = newDirectTargetEndpointAttachmentControllerWithClient(f.f.d, f.f.captured, wake, store, f.f.target, f.client)
	}
	if err != nil {
		t.Fatal(err)
	}
	// The fixture already admitted through the real custody and authority fence.
	if !realAdmission {
		c.admit = func(context.Context) (*DirectEndpointSubscription, error) { return s, nil }
	}
	return c, f, binding
}

func assertAttachmentNoMutation(t *testing.T, f *reconcilePassFixture) {
	t.Helper()
	if len(f.client.publications)+len(f.client.challenges)+len(f.client.proofs)+len(f.client.activations) != 0 || passJournalTableCount(t, f.f.d.nativeRegistry) != 0 {
		t.Fatal("mutation or enrollment journal reached")
	}
}

func TestDirectAttachmentControllerRejects(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		for _, kind := range []string{"missing", "disabled", "revision", "binding", "session", "attach"} {
			t.Run(role+"/"+kind, func(t *testing.T) {
				c, f, binding := attachmentControllerFixture(t, role)
				if kind != "missing" {
					if kind == "binding" {
						binding.Epoch = "foreign"
					}
					if _, err := c.store.Enable(t.Context(), binding, 0, "enable"); err != nil {
						t.Fatal(err)
					}
				}
				revision := int64(1)
				switch kind {
				case "disabled":
					if _, err := c.store.Disable(t.Context(), binding.Key, 1, "disable"); err != nil {
						t.Fatal(err)
					}
				case "revision":
					revision = 2
				case "session":
					c.captured.Session.BootID = "foreign"
				case "attach":
					c.wake.close()
				}
				got, err := c.attach(t.Context(), revision)
				if got != nil || err != errDirectChannelConsent {
					t.Fatalf("accepted: %v %v", got, err)
				}
				assertAttachmentNoMutation(t, f)
				if kind == "missing" || kind == "disabled" || kind == "revision" {
					if len(f.client.calls) != 0 {
						t.Fatal("HTTP before enabled exact revision")
					}
				} else if f.f.s.Valid() {
					t.Fatal("failed admission remained live")
				}
			})
		}
	}
}

func TestDirectAttachmentControllerDisableDuringPreflight(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			c, f, binding := attachmentControllerFixture(t, role)
			if _, err := c.store.Enable(t.Context(), binding, 0, "enable"); err != nil {
				t.Fatal(err)
			}
			peer, err := newDirectChannelConsentStore(t.Context(), c.store.registry, c.store.server, c.captured.Session)
			if err != nil {
				t.Fatal(err)
			}
			f.client.hook = func(name string) {
				if name == "descriptor" {
					if _, err := peer.Disable(t.Context(), binding.Key, 1, "disable"); err != nil {
						t.Fatal(err)
					}
				}
			}
			if a, err := c.attach(t.Context(), 1); a != nil || err == nil {
				t.Fatal("disabled during GET attached")
			}
			assertAttachmentNoMutation(t, f)
			if f.f.s.Valid() {
				t.Fatal("failed admission remained live")
			}
		})
	}
}

func TestDirectAttachmentControllerDisableBeforeDispatch(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			c, f, binding := attachmentControllerFixture(t, role)
			if _, err := c.store.Enable(t.Context(), binding, 0, "enable"); err != nil {
				t.Fatal(err)
			}
			peer, err := newDirectChannelConsentStore(t.Context(), c.store.registry, c.store.server, c.captured.Session)
			if err != nil {
				t.Fatal(err)
			}
			entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			// Hold the attached pass before its authenticated read, after real preflight.
			original := c.pass
			c.pass = func(s *DirectEndpointSubscription, r directChannelConsentRecord, rev int64) (directEndpointReconcilePass, error) {
				pass, err := original(s, r, rev)
				return func(ctx context.Context) (directEndpointReconcilePassState, error) {
					defer close(finished)
					once.Do(func() { close(entered) })
					<-release
					return pass(ctx)
				}, err
			}
			a, err := c.attach(t.Context(), 1)
			if err != nil {
				t.Fatal(err)
			}
			<-entered
			duplicate, err := c.attach(t.Context(), 1)
			if err != nil || duplicate != a {
				t.Fatal("duplicate did not reuse attachment")
			}
			if _, err := peer.Disable(t.Context(), binding.Key, 1, "disable"); err != nil {
				t.Fatal(err)
			}
			close(release)
			<-finished
			select {
			case <-a.Done():
			case <-time.After(time.Second):
				t.Fatal("disable did not terminate attachment")
			}
			assertAttachmentNoMutation(t, f)
			if f.f.s.Valid() {
				t.Fatal("disable did not revoke admission")
			}
			if got, err := c.attach(t.Context(), 1); got != nil || err == nil {
				t.Fatal("disabled attachment revived")
			}
			if c.status() != errDirectChannelConsent {
				t.Fatal("terminal status not sanitized")
			}
		})
	}
}

func TestDirectAttachmentControllerStaleLocalConsent(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		for _, kind := range []string{"instance", "origin", "ownership generation", "native generation", "expired", "installation", "session"} {
			t.Run(role+"/"+kind, func(t *testing.T) {
				c, f, binding := attachmentControllerFixture(t, role)
				switch kind {
				case "instance":
					binding.Instance = "foreign"
				case "origin":
					binding.Origin = "foreign"
				case "ownership generation":
					binding.OwnershipGeneration = "foreign"
				case "native generation":
					binding.NativeGeneration = "foreign"
				case "expired":
					binding.ExpiresAt = time.Now().Add(100 * time.Millisecond).UTC().Format(time.RFC3339Nano)
				case "installation":
					f.f.s.binding.metadata.InstallationID = domain.NewID()
				case "session":
					c.captured.Session.BootID = "foreign"
				}
				if _, err := c.store.Enable(t.Context(), binding, 0, "enable"); err != nil {
					t.Fatal(err)
				}
				if kind == "expired" {
					expiry, err := time.Parse(time.RFC3339Nano, binding.ExpiresAt)
					if err != nil {
						t.Fatal(err)
					}
					time.Sleep(time.Until(expiry) + time.Millisecond)
				}
				if a, err := c.attach(t.Context(), 1); a != nil || err != errDirectChannelConsent {
					t.Fatal("stale local consent accepted")
				}
				if len(f.client.calls) != 0 {
					t.Fatal("stale local consent reached HTTP")
				}
				assertAttachmentNoMutation(t, f)
				if f.f.s.Valid() {
					t.Fatal("stale local consent admission remained live")
				}
			})
		}
	}
}

func TestDirectAttachmentControllerRoleAdmission(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			c, f, binding := attachmentControllerFixtureWithRoleAdmission(t, role, true)
			if _, err := c.store.Enable(t.Context(), binding, 0, "enable"); err != nil {
				t.Fatal(err)
			}
			entered, finished := make(chan struct{}), make(chan struct{})
			original := c.pass
			c.pass = func(s *DirectEndpointSubscription, record directChannelConsentRecord, revision int64) (directEndpointReconcilePass, error) {
				pass, err := original(s, record, revision)
				return func(ctx context.Context) (directEndpointReconcilePassState, error) {
					defer close(finished)
					close(entered)
					<-ctx.Done()
					return pass(ctx)
				}, err
			}
			a, err := c.attach(t.Context(), 1)
			if err != nil {
				t.Fatal(err)
			}
			if a.handle == f.f.s || a.handle.owner != &c.d.directSubscriptions || a.handle.binding.metadata.Role != role {
				t.Fatal("constructor did not admit a fresh exact-role handle")
			}
			<-entered
			c.wake.close()
			<-finished
		})
	}
}
