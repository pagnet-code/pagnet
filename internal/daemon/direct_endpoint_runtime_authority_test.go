//go:build linux || darwin

package daemon

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func runtimeAuthorityFixture(t *testing.T) (*reconcileOperationFixture, *directChannelConsentStore, *reconcileObservationReader, directRuntimeBinding) {
	t.Helper()
	f, evidence, enrollment := newReconcileObservationTargetFixture(t)
	reader := observationReader(t, f.s, evidence, enrollment)
	reader.publication = observationPublication(t, evidence)
	wire, _ := reader.publication.CanonicalBytes()
	reader.enrollment = publishedEnrollment(enrollment, wire)
	store, err := newDirectChannelConsentStore(t.Context(), f.d.nativeRegistry, f.d.ServerURL, f.captured.Session)
	if err != nil {
		t.Fatal(err)
	}
	consent, err := deriveDirectChannelConsentBinding(f.s, f.captured, store.installation, evidence, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Enable(t.Context(), consent, 0, "enable"); err != nil {
		t.Fatal(err)
	}
	binding, err := directRuntimeBindingFromObservation(f.s, directEndpointReconcileObservation{Binding: evidence, Enrollment: reader.enrollment, Publication: wire}, 1)
	if err != nil {
		t.Fatal(err)
	}
	return f, store, reader, binding
}

func TestDirectRuntimeAuthorityExactBinding(t *testing.T) {
	for _, change := range []string{"none", "session", "generation", "revision", "recipient", "context", "publication"} {
		t.Run(change, func(t *testing.T) {
			f, store, reader, binding := runtimeAuthorityFixture(t)
			authority, err := newDirectTargetRuntimeAuthorityWithReader(t.Context(), f.d, f.captured, f.s, f.target, store, 1, reader)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "session":
				binding.NativeSession = f.captured.Session.NativeAdmissionID
			case "generation":
				binding.NativeGeneration += "-replacement"
			case "revision":
				binding.ConsentRevision++
			case "recipient":
				binding.Recipient.PrincipalID = binding.Publication.Descriptor.S.PrincipalID
			case "context":
				binding.Context.PublicationHash = binding.Context.DescriptorHash
			case "publication":
				binding.Publication.Ciphertext = base64.RawURLEncoding.EncodeToString(make([]byte, 48))
			}
			called := false
			err = authority(t.Context(), binding, func(ctx context.Context, credential string) error {
				called = true
				id, encoded, ok := strings.Cut(credential, ":")
				secret, decodeErr := base64.RawURLEncoding.Strict().DecodeString(encoded)
				defer clear(secret)
				if ctx.Err() != nil || !ok || id != string(f.target.CredentialID) || decodeErr != nil || len(secret) != 32 {
					t.Error("invalid callback credential or context")
				}
				return nil
			})
			if change == "none" {
				if err != nil || !called {
					t.Fatal("valid authority rejected", err)
				}
			} else if err == nil || called {
				t.Fatal("substituted runtime binding dispatched")
			}
		})
	}
}

func TestDirectRuntimeAuthorityConsentRevocation(t *testing.T) {
	for _, during := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "during"}[during], func(t *testing.T) {
			f, store, reader, binding := runtimeAuthorityFixture(t)
			authority, err := newDirectTargetRuntimeAuthorityWithReader(t.Context(), f.d, f.captured, f.s, f.target, store, 1, reader)
			if err != nil {
				t.Fatal(err)
			}
			key := directChannelConsentKey{Server: store.server, Tenant: store.tenant, Account: store.account, Host: store.host, Intent: string(f.s.binding.metadata.IntentID), Role: "P", Principal: string(f.s.binding.metadata.PrincipalID)}
			revoke := func() {
				if _, err := store.Disable(t.Context(), key, 1, "disable"); err != nil {
					t.Fatal(err)
				}
			}
			if !during {
				revoke()
			}
			called := false
			err = authority(t.Context(), binding, func(ctx context.Context, _ string) error {
				called = true
				revoke()
				select {
				case <-ctx.Done():
				case <-time.After(time.Second):
					t.Fatal("revocation did not cancel callback")
				}
				return nil
			})
			if err == nil || called != during {
				t.Fatal("revoked authority accepted", err)
			}
			if _, err := newDirectTargetRuntimeAuthorityWithReader(t.Context(), f.d, f.captured, f.s, f.target, store, 1, reader); err == nil {
				t.Fatal("recovery admitted revoked consent")
			}
		})
	}
}

func TestDirectRuntimeAuthorityPublicationReplacement(t *testing.T) {
	f, store, reader, binding := runtimeAuthorityFixture(t)
	authority, err := newDirectTargetRuntimeAuthorityWithReader(t.Context(), f.d, f.captured, f.s, f.target, store, 1, reader)
	if err != nil {
		t.Fatal(err)
	}
	reader.publication.Ciphertext = base64.RawURLEncoding.EncodeToString(make([]byte, 48))
	wire, _ := reader.publication.CanonicalBytes()
	reader.enrollment = publishedEnrollment(reader.enrollment, wire)
	if err = authority(t.Context(), binding, func(context.Context, string) error {
		t.Fatal("replacement publication dispatched")
		return nil
	}); err == nil {
		t.Fatal("replacement publication accepted")
	}
}

func TestDirectRuntimeAuthorityNativeReplacement(t *testing.T) {
	f, store, reader, binding := runtimeAuthorityFixture(t)
	authority, err := newDirectTargetRuntimeAuthorityWithReader(t.Context(), f.d, f.captured, f.s, f.target, store, 1, reader)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := reconcileOperationSnapshot(t, f.token)
	snapshot.NativeStartIdentity = "replacement-generation"
	f.token.proxy.observeDirectEndpointSnapshot(snapshot, f.token.proxy.directEndpointObservationEpoch())
	if err := authority(t.Context(), binding, func(context.Context, string) error {
		t.Fatal("replacement native generation dispatched")
		return nil
	}); err == nil {
		t.Fatal("replacement native generation accepted")
	}
}

func TestDirectRuntimeAuthorityAdmissionConsent(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "wrong-revision", true: "disabled"}[disabled], func(t *testing.T) {
			f, store, reader, _ := runtimeAuthorityFixture(t)
			revision := int64(2)
			if disabled {
				records, err := store.List(t.Context())
				if err != nil || len(records) != 1 {
					t.Fatal("consent fixture unavailable", err)
				}
				if _, err := store.Disable(t.Context(), records[0].Key, 1, "disable-before-admission"); err != nil {
					t.Fatal(err)
				}
			}
			if !f.s.Valid() {
				t.Fatal("unleased admission unexpectedly removed")
			}
			if _, err := newDirectTargetRuntimeAuthorityWithReader(t.Context(), f.d, f.captured, f.s, f.target, store, revision, reader); err == nil {
				t.Fatal("ineligible persisted consent admitted")
			}
		})
	}
}
