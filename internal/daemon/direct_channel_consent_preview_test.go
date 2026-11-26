//go:build linux || darwin

package daemon

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

func consentPreviewFixture(t *testing.T, role string) (*directChannelConsentPreview, *reconcilePassFixture, directChannelConsentBinding, **DirectEndpointSubscription) {
	t.Helper()
	c, f, binding := attachmentControllerFixtureWithRoleAdmission(t, role, true)
	var p *directChannelConsentPreview
	var err error
	if role == "S" {
		p, err = newDirectSourceChannelConsentPreviewWithReader(c.d, c.captured, c.store, f.f.source, f.client)
	} else {
		p, err = newDirectTargetChannelConsentPreviewWithReader(c.d, c.captured, c.store, f.f.target, f.client)
	}
	if err != nil {
		t.Fatal(err)
	}
	var admitted *DirectEndpointSubscription
	admit := p.admit
	p.admit = func(ctx context.Context) (*DirectEndpointSubscription, error) {
		var err error
		admitted, err = admit(ctx)
		return admitted, err
	}
	return p, f, binding, &admitted
}

func assertConsentPreviewClean(t *testing.T, p *directChannelConsentPreview, f *reconcilePassFixture, admitted **DirectEndpointSubscription, revision int64, enabled bool) {
	t.Helper()
	if *admitted != nil && (*admitted).Valid() {
		t.Fatal("temporary admission remained live")
	}
	assertAttachmentNoMutation(t, f)
	for _, call := range f.client.calls {
		if call != "descriptor" && call != "enrollment" && call != "publication" {
			t.Fatal("mutating HTTP reached")
		}
	}
	record, err := p.store.Get(t.Context(), p.key)
	if err != nil || record.Revision != revision || record.Enabled != enabled {
		t.Fatal("preview changed consent")
	}
}

func TestDirectChannelConsentPreviewRoles(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		for _, state := range []string{"missing", "disabled", "enabled"} {
			t.Run(role+"/"+state, func(t *testing.T) {
				p, f, binding, admitted := consentPreviewFixture(t, role)
				revision, enabled := int64(0), false
				if state == "disabled" {
					if _, err := p.store.Disable(t.Context(), p.key, 0, "disable"); err != nil {
						t.Fatal(err)
					}
					revision = 1
				} else if state == "enabled" {
					if _, err := p.store.Enable(t.Context(), binding, 0, "enable"); err != nil {
						t.Fatal(err)
					}
					revision, enabled = 1, true
				}
				first, err := p.Preview(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if *admitted == nil || *admitted == f.f.s || (*admitted).binding.metadata.Role != role {
					t.Fatal("preview did not use fresh role admission")
				}
				if first.Selector != binding.Key || first.LocalPrincipal != binding.Key.Principal || first.PeerPrincipal != binding.PeerPrincipal || first.GrantID != binding.GrantID || first.GrantGeneration != binding.GrantGeneration || first.AuthorizationDigest != binding.AuthorizationSnapshotDigest || first.ExpiresAt != binding.ExpiresAt || first.Revision != revision || first.Enabled != enabled || len(first.Fingerprint) != 64 {
					t.Fatal("incorrect public summary")
				}
				if first.Budget != f.binding.Descriptor.Budget || first.Limits != f.binding.Descriptor.Limits {
					t.Fatal("summary omitted authenticated budget or effective limits")
				}
				if len(f.client.calls) < 2 || f.client.calls[0] != "descriptor" || f.client.calls[1] != "enrollment" {
					t.Fatal("missing authenticated observation")
				}
				assertConsentPreviewClean(t, p, f, admitted, revision, enabled)
				second, err := p.Preview(t.Context())
				if err != nil || first != second {
					t.Fatal("unchanged terms did not produce deterministic preview")
				}
				assertConsentPreviewClean(t, p, f, admitted, revision, enabled)
			})
		}
	}
}

func TestDirectChannelConsentPreviewRejects(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		for _, kind := range []string{"scope", "socket", "connection", "stale issue", "missing binding", "mismatched binding", "descriptor binding", "enrollment binding", "descriptor", "enrollment", "panic", "canceled"} {
			t.Run(role+"/"+kind, func(t *testing.T) {
				p, f, _, admitted := consentPreviewFixture(t, role)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				switch kind {
				case "scope":
					p.captured.Session.BootID = "foreign"
				case "socket":
					p.captured.Socket = nil
				case "connection":
					p.captured.Connection = &NativeObservationConnection{}
				case "stale issue":
					// A stale retained public issue cannot use installed custody.
					p.admit = func(ctx context.Context) (*DirectEndpointSubscription, error) {
						if role == "S" {
							issue := f.f.source
							issue.CredentialExpiresAt = time.Now().Add(-time.Second)
							return f.f.d.admitDirectManagedSourceEndpointV2(ctx, p.captured, issue)
						}
						issue := f.f.target
						issue.CredentialExpiresAt = time.Now().Add(-time.Second)
						return f.f.d.admitManagedTargetEndpoint(ctx, p.captured, issue)
					}
				case "missing binding", "mismatched binding":
					p.observe = func(*DirectEndpointSubscription) (directEndpointReconcileObserver, error) {
						return func(context.Context) (directEndpointReconcileObservation, error) {
							b := f.binding
							if kind == "missing binding" {
								b = directEndpointReconcileBinding{}
							} else {
								b.Authority.ParentGrantID = "foreign"
							}
							return directEndpointReconcileObservation{Binding: b}, nil
						}, nil
					}
				case "descriptor", "enrollment":
					f.client.fail, f.client.failure = kind, errors.New("private transport detail")
				case "descriptor binding":
					f.client.descriptor.DirectIntentID = "foreign"
				case "enrollment binding":
					f.client.enrollment.Authority.ParentGrantID = "foreign"
				case "panic":
					f.client.hook = func(string) { panic("private panic detail") }
				case "canceled":
					f.client.hook = func(string) { cancel() }
				}
				got, err := p.Preview(ctx)
				if err != errDirectChannelConsent || !reflect.DeepEqual(got, directChannelConsentPreviewSummary{}) {
					t.Fatal("unsafe preview accepted or leaked details")
				}
				assertConsentPreviewClean(t, p, f, admitted, 0, false)
				if (kind == "scope" || kind == "socket" || kind == "connection" || kind == "stale issue") && len(f.client.calls) != 0 {
					t.Fatal("invalid authenticated scope reached HTTP")
				}
			})
		}
	}
}

func TestDirectChannelConsentPreviewFingerprintTerms(t *testing.T) {
	p, f, binding, admitted := consentPreviewFixture(t, "S")
	first, err := p.Preview(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"grant", "authorization", "expiry", "generation", "scope", "issue", "installation"} {
		t.Run(kind, func(t *testing.T) {
			owned, b, store := *p, binding, *p.store
			owned.store = &store
			switch kind {
			case "grant":
				b.GrantID = "different"
			case "authorization":
				b.AuthorizationSnapshotDigest = "different"
			case "expiry":
				b.ExpiresAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
			case "generation":
				b.NativeGeneration = "different"
			case "scope":
				owned.captured.Session.BootID = "different"
			case "issue":
				owned.issue[0] ^= 1
			case "installation":
				store.installation = "different"
			}
			changed, err := owned.fingerprint(b, f.binding.DescriptorHash)
			if err != nil || changed == first.Fingerprint {
				t.Fatal("changed exact terms retained old fingerprint")
			}
		})
	}
	if _, err := p.store.Disable(t.Context(), p.key, 0, "disable"); err != nil {
		t.Fatal(err)
	}
	second, err := p.Preview(t.Context())
	if err != nil || first.Fingerprint != second.Fingerprint || second.Revision != 1 || second.Enabled {
		t.Fatal("stored revision changed terms fingerprint")
	}
	assertConsentPreviewClean(t, p, f, admitted, 1, false)
	// A fresh authenticated descriptor may carry changed terms under the same
	// local selector. A later enable must compare against this new fingerprint.
	f.client.descriptor.EpochID = string(domain.NewID())
	f.client.enrollment = reconcileEnrollment(t, f.client.descriptor, time.Now())
	changed, err := p.Preview(t.Context())
	if err != nil || changed.Selector != first.Selector || changed.Fingerprint == first.Fingerprint {
		t.Fatal("changed authenticated terms retained old fingerprint")
	}
	assertConsentPreviewClean(t, p, f, admitted, 1, false)
}

func TestDirectChannelConsentPreviewDescriptorTerms(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		for _, kind := range []string{"peer endpoint", "peer key", "key evidence", "limits", "budget limits"} {
			t.Run(role+"/"+kind, func(t *testing.T) {
				p, f, binding, admitted := consentPreviewFixture(t, role)
				if _, err := p.store.Enable(t.Context(), binding, 0, "enable"); err != nil {
					t.Fatal(err)
				}
				first, err := p.Preview(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				peer := &f.client.descriptor.P
				if role == "P" {
					peer = &f.client.descriptor.S
				}
				switch kind {
				case "peer endpoint":
					peer.EndpointID = string(domain.NewID())
				case "peer key":
					peer.PublicKey = base64.RawURLEncoding.EncodeToString(append([]byte{9}, make([]byte, 31)...))
				case "key evidence":
					peer.KeyEvidenceDigest = strings.Repeat("a", 64)
					if peer.KeyEvidenceDigest == f.binding.Descriptor.S.KeyEvidenceDigest || peer.KeyEvidenceDigest == f.binding.Descriptor.P.KeyEvidenceDigest {
						peer.KeyEvidenceDigest = strings.Repeat("b", 64)
					}
				case "limits":
					f.client.descriptor.Limits.MaxInFlight = 3 - f.client.descriptor.Limits.MaxInFlight
					f.client.descriptor.Budget.GrantLimits.MaxInFlight = 2
				case "budget limits":
					f.client.descriptor.Budget.GrantLimits.MaxInFlight = 3 - f.client.descriptor.Budget.GrantLimits.MaxInFlight
					f.client.descriptor.Limits.MaxInFlight = 1
				}
				enrollment := reconcileEnrollment(t, f.client.descriptor, time.Now())
				if f.client.enrollment.PublicationHash != nil {
					f.client.publication.Descriptor = f.client.descriptor
					wire, err := f.client.publication.CanonicalBytes()
					if err != nil {
						t.Fatal(err)
					}
					enrollment = publishedEnrollment(enrollment, wire)
				}
				f.client.enrollment = enrollment
				// Derive the new binding independently to prove this regression
				// changes only terms omitted from directChannelConsentBinding.
				sub, err := p.admit(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer sub.Remove()
				observe, err := p.observe(sub)
				if err != nil {
					t.Fatal(err)
				}
				observed, err := observe(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				derived, err := deriveDirectChannelConsentBinding(sub, p.captured, p.store.installation, observed.Binding, time.Now())
				sub.Remove()
				if err != nil || derived != binding {
					t.Fatal("descriptor-only terms changed consent binding")
				}
				changed, err := p.Preview(t.Context())
				if err != nil || changed.Fingerprint == first.Fingerprint {
					t.Fatal("descriptor-only terms retained old fingerprint")
				}
				if changed.Budget != f.client.descriptor.Budget || changed.Limits != f.client.descriptor.Limits || (kind == "limits" && changed.Limits == first.Limits) || (kind == "budget limits" && changed.Budget == first.Budget) {
					t.Fatal("summary did not reflect changed authenticated budget or limits")
				}
				changed.Fingerprint = first.Fingerprint
				changed.Budget, changed.Limits = first.Budget, first.Limits
				if changed != first || !changed.Enabled {
					t.Fatal("persisted selector state changed with observed terms")
				}
				assertConsentPreviewClean(t, p, f, admitted, 1, true)
			})
		}
	}
}
