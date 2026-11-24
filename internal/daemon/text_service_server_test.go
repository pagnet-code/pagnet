//go:build linux || darwin

package daemon

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

func TestTextServiceServerEscapedPath(t *testing.T) {
	for _, item := range []struct{ input, want string }{
		{" https://EXAMPLE.TEST/a%2Fb/// ", "https://example.test/a%2Fb"},
		{"https://example.test/a%2F", "https://example.test/a%2F"},
		{"https://example.test/%61/", "https://example.test/%61"},
		{"https://example.test/a/b///", "https://example.test/a/b"},
		{"https://example.test/a%2fb///", "https://example.test/a%2fb"},
		{"https://example.test///", "https://example.test"},
		{"https://example.test?", "https://example.test?"},
		{"https://example.test#", "https://example.test"},
		{"https://[fe80::1%25ETH0]/", "https://[fe80::1%25eth0]"},
		{"https://example.test/%zz", ""},
	} {
		t.Run(item.input, func(t *testing.T) {
			got := textServiceServer(item.input)
			if got != item.want {
				t.Fatalf("normalized URL = %q, want %q", got, item.want)
			}
			if got != "" && textServiceServer(got) != got {
				t.Fatal("normalization is not idempotent")
			}
		})
	}
}

func textServiceCustodyCounts(t *testing.T, registry *NativeWorkerRegistry) [3]int {
	t.Helper()
	var result [3]int
	for i, table := range []string{"native_source_holder_enrollments", "native_managed_endpoint_keys", "native_managed_endpoint_prepare_commands"} {
		if err := registry.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&result[i]); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func TestTextServiceServerChangedCustodyScopesRejectBeforeWrites(t *testing.T) {
	for _, endpoint := range []string{"https://example.test/a%2Fb///", "https://example.test/a%2F", "https://example.test/%61/", "://invalid"} {
		for _, seeded := range []bool{false, true} {
			name := endpoint + "/fresh"
			if seeded {
				name = endpoint + "/legacy"
			}
			t.Run(name, func(t *testing.T) {
				journal, keys, command, session := managedPrepareJournalFixture(t)
				holder, err := NewNativeShareSourceHolderStore(keys.registry)
				if err != nil {
					t.Fatal(err)
				}
				scope := NativeShareSourceHolderScope{ServerURL: endpoint, TenantID: command.Subject.TenantID, AccountID: command.Subject.AccountID, HostID: command.Subject.HostID}
				legacy := legacyTextServiceServer(endpoint)
				if seeded && legacy != "" {
					oldScope := scope
					oldScope.ServerURL = legacy
					if _, err := holder.Ensure(oldScope); err != nil {
						t.Fatal(err)
					}
					if _, err := keys.Reserve(command.Subject, legacy, session); err != nil {
						t.Fatal(err)
					}
					if _, err := journal.Reserve(command, legacy, managedPrepareScopeOK); err != nil {
						t.Fatal(err)
					}
				}
				before := textServiceCustodyCounts(t, keys.registry)
				if _, err := holder.Ensure(scope); err == nil {
					t.Fatal("changed holder scope accepted")
				}
				if _, err := keys.Reserve(command.Subject, endpoint, session); err == nil {
					t.Fatal("changed key scope accepted")
				}
				if _, err := keys.RecoverReservation(command.Subject, endpoint, session); err == nil {
					t.Fatal("changed key recovery scope accepted")
				}
				called := false
				verify := func(transport.ManagedEndpointPrepareCommand, string) error { called = true; return nil }
				if _, err := journal.Reserve(command, endpoint, verify); err == nil {
					t.Fatal("changed journal scope accepted")
				}
				if _, err := journal.BeginKeyReservation(command, endpoint, verify); err == nil {
					t.Fatal("changed journal key reservation scope accepted")
				}
				if _, err := journal.Fail(command, endpoint, verify); err == nil {
					t.Fatal("changed journal terminal scope accepted")
				}
				if called {
					t.Fatal("changed scope reached journal verifier")
				}
				if after := textServiceCustodyCounts(t, keys.registry); after != before {
					t.Fatalf("rejected scope wrote rows: %v -> %v", before, after)
				}
				if !seeded || legacy == "" {
					for _, namespace := range []string{nativeShareSourceHolderNamespace, nativeManagedEndpointKeyNamespace, managedEndpointPrepareJournalNamespace} {
						if _, err := os.Stat(filepath.Join(keys.registry.root, namespace)); !os.IsNotExist(err) {
							t.Fatal("rejected scope created custody files", err)
						}
					}
				}
			})
		}
	}
}

func TestTextServiceServerUnchangedCustodyRetries(t *testing.T) {
	for _, endpoint := range []string{"https://example.test", "https://example.test/a%2Fb", "https://example.test/%61", "https://example.test/a%2fb", "https://example.test/a/b"} {
		t.Run(endpoint, func(t *testing.T) {
			journal, keys, command, session := managedPrepareJournalFixture(t)
			first, err := keys.Reserve(command.Subject, endpoint, session)
			if err != nil {
				t.Fatal(err)
			}
			retry, err := keys.Reserve(command.Subject, " "+endpoint+" ", session)
			if err != nil || first != retry {
				t.Fatal("canonical key retry changed", err)
			}
			holder, err := NewNativeShareSourceHolderStore(keys.registry)
			if err != nil {
				t.Fatal(err)
			}
			scope := NativeShareSourceHolderScope{ServerURL: endpoint, TenantID: command.Subject.TenantID, AccountID: command.Subject.AccountID, HostID: command.Subject.HostID}
			descriptor, err := holder.Ensure(scope)
			if err != nil {
				t.Fatal(err)
			}
			scope.ServerURL = " " + endpoint + " "
			retried, err := holder.Ensure(scope)
			if err != nil || retried != descriptor {
				t.Fatal("canonical holder retry changed", err)
			}
			initial, err := journal.Reserve(command, endpoint, managedPrepareScopeOK)
			if err != nil || !initial.Created {
				t.Fatal("journal reservation failed", err)
			}
			repeated, err := journal.Reserve(command, " "+endpoint+" ", managedPrepareScopeOK)
			if err != nil || repeated.Created || repeated.State != initial.State {
				t.Fatal("canonical journal retry changed", err)
			}
		})
	}
}

func TestTextServiceServerSourceSignedTranscripts(t *testing.T) {
	for _, endpoint := range []string{"https://example.test/a%2Fb", "https://example.test/a/b", "https://example.test/a%2fb", "https://example.test/%61"} {
		t.Run(endpoint, func(t *testing.T) {
			holder, session, request := sourcePrepareExecutorFixture(t)
			request.Enrollment.Subject.ServerURL = endpoint
			prepare, err := NewNativeShareSourcePrepareExecutor(holder.registry, sourcePrepareExecutorNow)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := prepare.Prepare(endpoint, session, request)
			if err != nil {
				t.Fatal(err)
			}
			signed := sourcePrepareBytes(t, prepared)
			retry, err := prepare.Prepare(endpoint, session, request)
			if err != nil || !bytes.Equal(signed, sourcePrepareBytes(t, retry)) {
				t.Fatal("signed prepare retry changed", err)
			}
			challenge := transport.NativeShareSourceProvePayload{NativeShareSourceChallengeContext: transport.NativeShareSourceChallengeContext{Version: transport.NativeShareSourceVersion, EnrollmentID: request.Enrollment.EnrollmentID, CommandID: domain.NewID(), EnrollmentDigest: prepared.EnrollmentDigest, DescriptorFingerprint: prepared.Descriptor.Fingerprint, ChallengeID: domain.NewID(), ExpiresAt: request.Enrollment.ExpiresAt}}
			plain := bytes.Repeat([]byte{0xa7}, 32)
			public, _ := hex.DecodeString(prepared.Descriptor.X25519)
			aad, err := challenge.ChallengeAAD()
			if err != nil {
				t.Fatal(err)
			}
			challenge.Challenge.Enc, challenge.Challenge.Ciphertext, err = crypto.WrapKey(public, []byte(transport.NativeShareSourceChallengeInfo), aad, plain)
			if err != nil {
				t.Fatal(err)
			}
			prove, err := NewNativeShareSourceProveExecutor(holder.registry, sourcePrepareExecutorNow)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := prove.Prove(endpoint, session, challenge)
			if err != nil || !bytes.Equal(proof.Challenge, plain) {
				t.Fatal("proof failed", err)
			}
			hash, err := proof.ChallengeHash()
			if err != nil {
				t.Fatal(err)
			}
			signer, _ := hex.DecodeString(prepared.Descriptor.Ed25519)
			if err := proof.Verify(challenge, hash, prepared.Descriptor.Fingerprint, signer, sourcePrepareExecutorNow()); err != nil {
				t.Fatal(err)
			}
			altered := prepared.Prepare
			altered.Enrollment.Subject.ServerURL = "https://example.test/a/b"
			if endpoint == altered.Enrollment.Subject.ServerURL {
				altered.Enrollment.Subject.ServerURL = "https://example.test/a%2Fb"
			}
			if prepared.Verify(altered, prepared.Descriptor, signer) == nil {
				t.Fatal("signed transcript accepted a different URL")
			}
		})
	}
}

func TestTextServiceServerSourceChangedScopeRejectsBeforeWrites(t *testing.T) {
	for _, endpoint := range []string{"https://example.test/a%2Fb///", "https://example.test/a%2F", "https://example.test/%61/"} {
		t.Run(endpoint, func(t *testing.T) {
			holder, session, request := sourcePrepareExecutorFixture(t)
			request.Enrollment.Subject.ServerURL = endpoint
			executor, err := NewNativeShareSourcePrepareExecutor(holder.registry, sourcePrepareExecutorNow)
			if err != nil {
				t.Fatal(err)
			}
			before := sourcePrepareExecutorCounts(t, holder.registry)
			if _, err := executor.Prepare(endpoint, session, request); err == nil {
				t.Fatal("changed source scope accepted")
			}
			if after := sourcePrepareExecutorCounts(t, holder.registry); after != before {
				t.Fatalf("rejected source scope wrote rows: %v -> %v", before, after)
			}
			if _, err := os.Stat(filepath.Join(holder.registry.root, nativeShareSourceHolderNamespace)); !os.IsNotExist(err) {
				t.Fatal("rejected source scope created holder files", err)
			}
		})
	}
}

func TestTextServiceServerEscapedCustodyScopesStayDistinct(t *testing.T) {
	holder, scope := sourceHolderFixture(t)
	seen := make(map[domain.ID]bool)
	for _, endpoint := range []string{"https://example.test/a%2Fb", "https://example.test/a/b", "https://example.test/a%2fb", "https://example.test/%61", "https://example.test/a"} {
		scope.ServerURL = endpoint
		descriptor, err := holder.Ensure(scope)
		if err != nil {
			t.Fatal(err)
		}
		if seen[descriptor.HolderID] {
			t.Fatal("distinct escaped scope reused holder identity")
		}
		seen[descriptor.HolderID] = true
	}
}
