//go:build linux || darwin

package daemon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func sourcePrepareRequest(scope NativeShareSourceHolderScope) transport.NativeShareSourcePreparePayload {
	return transport.NativeShareSourcePreparePayload{CommandID: domain.NewID(), Enrollment: transport.NativeShareSourceEnrollment{
		Version: transport.NativeShareSourceVersion, EnrollmentID: domain.NewID(), NetworkID: domain.NewID(), PreviousEpochID: domain.NewID(), ProposalID: domain.NewID(), ProposalRevision: 1, GrantID: domain.NewID(), GrantGeneration: 1, BindingID: domain.NewID(), BindingDigest: strings.Repeat("ab", 32), HostCredentialID: "host-credential", OwnershipScope: "host", ExpiresAt: time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC).Format(time.RFC3339Nano),
		Subject: transport.NativeShareSourceHostSubject{ServerURL: scope.ServerURL, TenantID: scope.TenantID, AccountID: scope.AccountID, HostID: scope.HostID, NativeAdmissionID: domain.NewID(), RunnerID: domain.NewID(), RunnerEpoch: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC).Format(time.RFC3339Nano), BootID: "boot"},
	}}
}

func sourcePrepareStore(t *testing.T) (*NativeShareSourcePrepareStore, *NativeShareSourceHolderStore, transport.NativeShareSourcePreparePayload) {
	t.Helper()
	holder, scope := sourceHolderFixture(t)
	store, err := NewNativeShareSourcePrepareStore(holder)
	if err != nil {
		t.Fatal(err)
	}
	return store, holder, sourcePrepareRequest(scope)
}

func sourcePrepareReopen(t *testing.T, holder *NativeShareSourceHolderStore) *NativeShareSourcePrepareStore {
	t.Helper()
	stateDir := filepath.Dir(holder.registry.root)
	if err := holder.registry.Close(); err != nil {
		t.Fatal(err)
	}
	registry, err := OpenNativeWorkerRegistry(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { registry.Close() })
	reopened, err := NewNativeShareSourceHolderStore(registry)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewNativeShareSourcePrepareStore(reopened)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func sourcePrepareBytes(t *testing.T, prepared transport.NativeShareSourcePreparedPayload) []byte {
	t.Helper()
	raw, err := prepared.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := hex.DecodeString(prepared.Descriptor.Ed25519)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepared.Verify(prepared.Prepare, prepared.Descriptor, signer); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestNativeShareSourcePrepareRestartRetry(t *testing.T) {
	store, holder, request := sourcePrepareStore(t)
	var before int
	if err := holder.registry.db.QueryRow(`SELECT COUNT(*) FROM native_workers`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	first, err := store.Prepare(request)
	if err != nil {
		t.Fatal(err)
	}
	raw := sourcePrepareBytes(t, first)
	var workers int
	if err := holder.registry.db.QueryRow(`SELECT COUNT(*) FROM native_workers`).Scan(&workers); err != nil || workers != before {
		t.Fatal("prepare created worker authority", workers, err)
	}
	retry, err := sourcePrepareReopen(t, holder).Prepare(request)
	if err != nil || !bytes.Equal(raw, sourcePrepareBytes(t, retry)) {
		t.Fatal("restart changed prepared response", err)
	}
}

func TestNativeShareSourcePrepareConflicts(t *testing.T) {
	for _, field := range []string{"command", "enrollment", "boot", "expiry", "binding", "runner", "credential", "scope"} {
		t.Run(field, func(t *testing.T) {
			store, _, request := sourcePrepareStore(t)
			first, err := store.Prepare(request)
			if err != nil {
				t.Fatal(err)
			}
			changed := request
			switch field {
			case "command":
				changed.CommandID = domain.NewID()
			case "enrollment":
				changed.Enrollment.EnrollmentID = domain.NewID()
			case "boot":
				changed.Enrollment.Subject.BootID = "other-boot"
			case "expiry":
				changed.Enrollment.ExpiresAt = "2027-01-03T03:04:05Z"
			case "binding":
				changed.Enrollment.BindingDigest = strings.Repeat("cd", 32)
			case "runner":
				changed.Enrollment.Subject.RunnerID = domain.NewID()
			case "credential":
				changed.Enrollment.HostCredentialID = "other-credential"
			case "scope":
				changed.Enrollment.Subject.HostID = domain.NewID()
			}
			if _, err := store.Prepare(changed); err == nil {
				t.Fatal("conflicting request accepted")
			}
			retry, err := store.Prepare(request)
			if err != nil || !bytes.Equal(sourcePrepareBytes(t, first), sourcePrepareBytes(t, retry)) {
				t.Fatal("conflict damaged original response", err)
			}
		})
	}
}

func TestNativeShareSourcePrepareConcurrent(t *testing.T) {
	for _, conflicting := range []bool{false, true} {
		t.Run(map[bool]string{false: "exact", true: "conflicting"}[conflicting], func(t *testing.T) {
			store, _, request := sourcePrepareStore(t)
			other := request
			if conflicting {
				other.Enrollment.Subject.BootID = "other-boot"
			}
			requests := []transport.NativeShareSourcePreparePayload{request, other}
			var replies [2]transport.NativeShareSourcePreparedPayload
			var errs [2]error
			var wg sync.WaitGroup
			start := make(chan struct{})
			for i := range requests {
				wg.Add(1)
				go func(i int) { defer wg.Done(); <-start; replies[i], errs[i] = store.Prepare(requests[i]) }(i)
			}
			close(start)
			wg.Wait()
			if conflicting {
				if (errs[0] == nil) == (errs[1] == nil) {
					t.Fatal("conflicting prepares did not have exactly one winner", errs)
				}
			} else if errs[0] != nil || errs[1] != nil || !bytes.Equal(sourcePrepareBytes(t, replies[0]), sourcePrepareBytes(t, replies[1])) {
				t.Fatal("exact concurrent retry diverged", errs)
			}
		})
	}
}

func TestNativeShareSourcePrepareConcurrentIndependent(t *testing.T) {
	store, _, request := sourcePrepareStore(t)
	other := request
	other.CommandID = domain.NewID()
	other.Enrollment.EnrollmentID = domain.NewID()
	requests := []transport.NativeShareSourcePreparePayload{request, other}
	var replies [2]transport.NativeShareSourcePreparedPayload
	var errs [2]error
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range requests {
		wg.Add(1)
		go func(i int) { defer wg.Done(); <-start; replies[i], errs[i] = store.Prepare(requests[i]) }(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
		sourcePrepareBytes(t, replies[i])
	}
	if replies[0].Descriptor != replies[1].Descriptor {
		t.Fatal("same scope selected different holders")
	}
}

func TestNativeShareSourcePrepareReservationRestart(t *testing.T) {
	for _, journalOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "existing-holder", true: "journal-only"}[journalOnly], func(t *testing.T) {
			store, holder, request := sourcePrepareStore(t)
			var first transport.NativeShareSourcePreparedPayload
			if journalOnly {
				subject := request.Enrollment.Subject
				_, name, err := nativeShareSourceHolderScope(NativeShareSourceHolderScope{ServerURL: subject.ServerURL, TenantID: subject.TenantID, AccountID: subject.AccountID, HostID: subject.HostID})
				if err != nil {
					t.Fatal(err)
				}
				raw, err := request.CanonicalBytes()
				if err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(append([]byte("pagnet/native-share-source/prepare-request/v1/"), raw...))
				if _, err := store.journal(request, name, digest[:], nil); err != nil {
					t.Fatal(err)
				}
			} else {
				var err error
				first, err = store.Prepare(request)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := holder.registry.db.Exec(`UPDATE native_source_prepare_journal SET prepared=NULL WHERE command_id=?`, request.CommandID); err != nil {
					t.Fatal(err)
				}
			}
			retry, err := sourcePrepareReopen(t, holder).Prepare(request)
			if err != nil {
				t.Fatal("matching reservation did not resume", err)
			}
			raw := sourcePrepareBytes(t, retry)
			if !journalOnly && !bytes.Equal(sourcePrepareBytes(t, first), raw) {
				t.Fatal("reservation retry changed holder or response")
			}
		})
	}
}

func TestNativeShareSourcePrepareCorruptCache(t *testing.T) {
	for _, corruption := range []string{"json", "signature", "request"} {
		t.Run(corruption, func(t *testing.T) {
			store, holder, request := sourcePrepareStore(t)
			reply, err := store.Prepare(request)
			if err != nil {
				t.Fatal(err)
			}
			raw := []byte(`{"corrupt":true}`)
			if corruption != "json" {
				if corruption == "signature" {
					reply.Signature[0] ^= 1
				} else {
					reply.Prepare.Enrollment.Subject.BootID = "corrupt"
				}
				if corruption == "request" {
					reply.EnrollmentDigest, err = reply.Digest()
					if err != nil {
						t.Fatal(err)
					}
				}
				raw, err = reply.CanonicalBytes()
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := holder.registry.db.Exec(`UPDATE native_source_prepare_journal SET prepared=? WHERE command_id=?`, raw, request.CommandID); err != nil {
				t.Fatal(err)
			}
			if _, err := sourcePrepareReopen(t, holder).Prepare(request); err == nil {
				t.Fatal("corrupt cached response accepted")
			}
		})
	}
}

func TestNativeShareSourcePrepareJournalInstallationEvidence(t *testing.T) {
	for _, missing := range []bool{true, false} {
		t.Run(map[bool]string{true: "missing", false: "changed"}[missing], func(t *testing.T) {
			store, holder, request := sourcePrepareStore(t)
			if _, err := store.Prepare(request); err != nil {
				t.Fatal(err)
			}
			if _, err := holder.registry.db.Exec(`DELETE FROM native_source_holder_enrollments`); err != nil {
				t.Fatal(err)
			}
			if err := os.RemoveAll(filepath.Join(holder.registry.root, nativeShareSourceHolderNamespace)); err != nil {
				t.Fatal(err)
			}
			query := `UPDATE native_registry_metadata SET value=? WHERE name='installation_id'`
			args := []any{domain.NewID()}
			if missing {
				query = `DELETE FROM native_registry_metadata WHERE name='installation_id'`
				args = nil
			}
			if _, err := holder.registry.db.Exec(query, args...); err != nil {
				t.Fatal(err)
			}
			stateDir := filepath.Dir(holder.registry.root)
			if err := holder.registry.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenNativeWorkerRegistry(stateDir)
			if err == nil {
				reopened.Close()
				t.Fatal("journal evidence allowed replacement installation")
			}
		})
	}
}

func TestNativeShareSourcePrepareSingleConnection(t *testing.T) {
	store, holder, request := sourcePrepareStore(t)
	holder.registry.db.SetMaxOpenConns(1)
	done := make(chan error, 1)
	go func() { _, err := store.Prepare(request); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("prepare deadlocked with one database connection")
	}
}

func TestNativeShareSourcePrepareRejectsNoncanonicalURLBeforeEnsure(t *testing.T) {
	for _, serverURL := range []string{"https://EXAMPLE.TEST", "https://example.test/", " https://example.test "} {
		t.Run(serverURL, func(t *testing.T) {
			store, holder, request := sourcePrepareStore(t)
			request.Enrollment.Subject.ServerURL = serverURL
			if _, err := store.Prepare(request); err == nil {
				t.Fatal("noncanonical URL accepted")
			}
			if _, err := os.Stat(filepath.Join(holder.registry.root, nativeShareSourceHolderNamespace)); !os.IsNotExist(err) {
				t.Fatal("invalid request enrolled source holder", err)
			}
			var count int
			if err := holder.registry.db.QueryRow(`SELECT COUNT(*) FROM native_source_prepare_journal`).Scan(&count); err != nil || count != 0 {
				t.Fatal("invalid request reserved journal", count, err)
			}
		})
	}
}
