//go:build linux || darwin

package daemon

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func nativeShareValidationFixture() (transport.NativeShareBindingPreparePayload, transport.HostSessionPayload, NativeWorkerRecord) {
	request := transport.NativeShareBindingPreparePayload{CommandID: "10000000-0000-4000-8000-000000000001", Binding: transport.NativeShareBinding{
		Version: 1, BindingID: "10000000-0000-4000-8000-000000000002", ProposalID: "10000000-0000-4000-8000-000000000003",
		GrantID: "10000000-0000-4000-8000-000000000004", NetworkID: "10000000-0000-4000-8000-000000000005", ProposalRevision: 1, GrantGeneration: 1,
		PrincipalID: "10000000-0000-4000-8000-000000000006", InstanceID: "10000000-0000-4000-8000-000000000007", NativeGeneration: "opaque-original-generation",
		ContextID: "10000000-0000-4000-8000-000000000008", ExpiresAt: "2027-01-02T03:04:05Z",
	}}
	session := transport.HostSessionPayload{
		TenantID: "10000000-0000-4000-8000-000000000009", AccountID: "10000000-0000-4000-8000-000000000010", OwnershipScope: "personal",
		NativeAdmissionID: "10000000-0000-4000-8000-000000000011", HostID: "10000000-0000-4000-8000-000000000012", RunnerID: "10000000-0000-4000-8000-000000000013",
		RunnerEpoch: time.Date(2026, 11, 2, 9, 10, 11, 123456789, time.UTC), BootID: "original-kernel-boot",
	}
	record := NativeWorkerRecord{
		Scope:       sessionworker.Scope{ServerURL: "https://example.test", TenantID: session.TenantID, AccountID: session.AccountID, HostID: session.HostID, InstanceID: string(request.Binding.InstanceID), Generation: request.Binding.NativeGeneration},
		Spec:        sessionworker.NativeSpec{TenantID: session.TenantID, Runtime: domain.RuntimeFakePersistent, Kind: "worker", Workspace: "/private/original-workspace", Binary: "/bin/true", MCPExecutable: "/bin/true"},
		LaunchState: "reserved",
	}
	record.ProfileFingerprint = sessionworker.NativeProfileFingerprint(record.Spec)
	return request, session, record
}

func TestNativeShareBindingValidatorCaptureAndTimestamp(t *testing.T) {
	request, session, record := nativeShareValidationFixture()
	// Equal instants from an authenticated session canonicalize to the same bytes.
	local := session
	local.RunnerEpoch = session.RunnerEpoch.In(time.FixedZone("local", 90*60))
	subject, err := ValidateNativeShareBinding(request, record.Scope.ServerURL, local, record)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := ValidateNativeShareBinding(request, record.Scope.ServerURL, session, record)
	if err != nil || subject != expected || subject.RunnerEpoch != "2026-11-02T09:10:11.123456789Z" {
		t.Fatal("session timestamp capture changed identity", err)
	}
	raw, err := subject.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip transport.NativeShareBindingSubject
	if err := json.Unmarshal(raw, &roundTrip); err != nil {
		t.Fatal(err)
	}
	again, err := roundTrip.CanonicalBytes()
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("canonical subject changed on round trip", err)
	}
	if bytes.Contains(raw, []byte("/private/")) || bytes.Contains(raw, []byte("/bin/")) {
		t.Fatal("local filesystem metadata entered evidence")
	}
}

func TestNativeShareBindingValidatorMismatches(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*transport.NativeShareBindingPreparePayload, *string, *transport.HostSessionPayload, *NativeWorkerRecord)
	}{
		{"endpoint", func(_ *transport.NativeShareBindingPreparePayload, endpoint *string, _ *transport.HostSessionPayload, _ *NativeWorkerRecord) {
			*endpoint = "https://other.example.test"
		}},
		{"missingEndpoint", func(_ *transport.NativeShareBindingPreparePayload, endpoint *string, _ *transport.HostSessionPayload, _ *NativeWorkerRecord) {
			*endpoint = ""
		}},
		{"instance", func(p *transport.NativeShareBindingPreparePayload, _ *string, _ *transport.HostSessionPayload, _ *NativeWorkerRecord) {
			p.Binding.InstanceID = "20000000-0000-4000-8000-000000000001"
		}},
		{"generation", func(p *transport.NativeShareBindingPreparePayload, _ *string, _ *transport.HostSessionPayload, _ *NativeWorkerRecord) {
			p.Binding.NativeGeneration = "other-generation"
		}},
		{"missingGeneration", func(p *transport.NativeShareBindingPreparePayload, _ *string, _ *transport.HostSessionPayload, _ *NativeWorkerRecord) {
			p.Binding.NativeGeneration = ""
		}},
		{"missingPrincipal", func(p *transport.NativeShareBindingPreparePayload, _ *string, _ *transport.HostSessionPayload, _ *NativeWorkerRecord) {
			p.Binding.PrincipalID = ""
		}},
		{"tenant", func(_ *transport.NativeShareBindingPreparePayload, _ *string, s *transport.HostSessionPayload, _ *NativeWorkerRecord) {
			s.TenantID = "20000000-0000-4000-8000-000000000001"
		}},
		{"account", func(_ *transport.NativeShareBindingPreparePayload, _ *string, s *transport.HostSessionPayload, _ *NativeWorkerRecord) {
			s.AccountID = "20000000-0000-4000-8000-000000000001"
		}},
		{"host", func(_ *transport.NativeShareBindingPreparePayload, _ *string, s *transport.HostSessionPayload, _ *NativeWorkerRecord) {
			s.HostID = "20000000-0000-4000-8000-000000000001"
		}},
		{"missingAccount", func(_ *transport.NativeShareBindingPreparePayload, _ *string, s *transport.HostSessionPayload, _ *NativeWorkerRecord) {
			s.AccountID = ""
		}},
		{"missingTenant", func(_ *transport.NativeShareBindingPreparePayload, _ *string, s *transport.HostSessionPayload, _ *NativeWorkerRecord) {
			s.TenantID = ""
		}},
		{"missingHost", func(_ *transport.NativeShareBindingPreparePayload, _ *string, s *transport.HostSessionPayload, _ *NativeWorkerRecord) {
			s.HostID = ""
		}},
		{"missingAdmission", func(_ *transport.NativeShareBindingPreparePayload, _ *string, s *transport.HostSessionPayload, _ *NativeWorkerRecord) {
			s.NativeAdmissionID = ""
		}},
		{"missingRunner", func(_ *transport.NativeShareBindingPreparePayload, _ *string, s *transport.HostSessionPayload, _ *NativeWorkerRecord) {
			s.RunnerID = ""
		}},
		{"missingRunnerEpoch", func(_ *transport.NativeShareBindingPreparePayload, _ *string, s *transport.HostSessionPayload, _ *NativeWorkerRecord) {
			s.RunnerEpoch = time.Time{}
		}},
		{"missingBoot", func(_ *transport.NativeShareBindingPreparePayload, _ *string, s *transport.HostSessionPayload, _ *NativeWorkerRecord) {
			s.BootID = ""
		}},
		{"ownershipScope", func(_ *transport.NativeShareBindingPreparePayload, _ *string, s *transport.HostSessionPayload, _ *NativeWorkerRecord) {
			s.OwnershipScope = ""
		}},
		{"organizationAccount", func(_ *transport.NativeShareBindingPreparePayload, _ *string, s *transport.HostSessionPayload, _ *NativeWorkerRecord) {
			s.OwnershipScope = "organization"
		}},
		{"specTenant", func(_ *transport.NativeShareBindingPreparePayload, _ *string, _ *transport.HostSessionPayload, r *NativeWorkerRecord) {
			r.Spec.TenantID = "20000000-0000-4000-8000-000000000001"
		}},
		{"specFingerprint", func(_ *transport.NativeShareBindingPreparePayload, _ *string, _ *transport.HostSessionPayload, r *NativeWorkerRecord) {
			r.Spec.Workspace = "/another/workspace"
		}},
		{"fingerprint", func(_ *transport.NativeShareBindingPreparePayload, _ *string, _ *transport.HostSessionPayload, r *NativeWorkerRecord) {
			r.ProfileFingerprint = strings.Repeat("ab", 32)
		}},
		{"launchState", func(_ *transport.NativeShareBindingPreparePayload, _ *string, _ *transport.HostSessionPayload, r *NativeWorkerRecord) {
			r.LaunchState = "unknown"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request, session, record := nativeShareValidationFixture()
			endpoint := record.Scope.ServerURL
			tt.mutate(&request, &endpoint, &session, &record)
			subject, err := ValidateNativeShareBinding(request, endpoint, session, record)
			if err == nil || subject != (transport.NativeShareBindingSubject{}) {
				t.Fatal("accepted mismatched or incomplete local authority")
			}
		})
	}
}

func TestNativeShareBindingValidatorTranscriptSubstitution(t *testing.T) {
	request, session, record := nativeShareValidationFixture()
	subject, err := ValidateNativeShareBinding(request, record.Scope.ServerURL, session, record)
	if err != nil {
		t.Fatal(err)
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	prepared := transport.NativeShareBindingPreparedPayload{Prepare: request, Subject: subject, HolderID: "10000000-0000-4000-8000-000000000014", HolderX25519: strings.Repeat("ab", 32)}
	prepared.BindingDigest, err = prepared.Digest()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := prepared.SignatureBytes()
	if err != nil {
		t.Fatal(err)
	}
	prepared.Signature = ed25519.Sign(private, raw)
	if err := prepared.Verify(request, subject, pub); err != nil {
		t.Fatal(err)
	}
	// A later authenticated session is distinct evidence, even on the same host.
	session.NativeAdmissionID = "20000000-0000-4000-8000-000000000001"
	later, err := ValidateNativeShareBinding(request, record.Scope.ServerURL, session, record)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Verify(request, later, pub) == nil {
		t.Fatal("receipt substituted across captured admission")
	}
	// Principal selection is server-authoritative and belongs to the new binding.
	changed := request
	changed.Binding.PrincipalID = "20000000-0000-4000-8000-000000000002"
	if _, err := ValidateNativeShareBinding(changed, record.Scope.ServerURL, session, record); err != nil {
		t.Fatal("inferred principal identity from local registry", err)
	}
	if prepared.Verify(changed, subject, pub) == nil {
		t.Fatal("receipt substituted across selected principal")
	}
}
