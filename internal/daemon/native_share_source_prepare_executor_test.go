//go:build linux || darwin

package daemon

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func sourcePrepareExecutorFixture(t *testing.T) (*NativeShareSourceHolderStore, transport.HostSessionPayload, transport.NativeShareSourcePreparePayload) {
	t.Helper()
	_, holder, request := sourcePrepareStore(t)
	request.Enrollment.OwnershipScope = "personal"
	subject := request.Enrollment.Subject
	epoch, err := time.Parse(time.RFC3339Nano, subject.RunnerEpoch)
	if err != nil {
		t.Fatal(err)
	}
	session := transport.HostSessionPayload{
		TenantID: string(subject.TenantID), AccountID: string(subject.AccountID), HostID: string(subject.HostID),
		NativeAdmissionID: string(subject.NativeAdmissionID), RunnerID: string(subject.RunnerID), RunnerEpoch: epoch,
		BootID: subject.BootID, HostCredentialID: request.Enrollment.HostCredentialID, OwnershipScope: "personal",
	}
	return holder, session, request
}

func sourcePrepareExecutorNow() time.Time {
	return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
}

func sourcePrepareExecutorCounts(t *testing.T, registry *NativeWorkerRegistry) [3]int {
	t.Helper()
	var counts [3]int
	for i, table := range []string{"native_source_prepare_journal", "native_source_holder_enrollments", "native_workers"} {
		if err := registry.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&counts[i]); err != nil {
			t.Fatal(err)
		}
	}
	return counts
}

func TestNativeShareSourcePrepareExecutorRestartRetry(t *testing.T) {
	for _, scope := range []string{"personal", "organization"} {
		t.Run(scope, func(t *testing.T) {
			holder, session, request := sourcePrepareExecutorFixture(t)
			session.OwnershipScope, request.Enrollment.OwnershipScope = scope, scope
			if scope == "organization" {
				session.AccountID = session.TenantID
				request.Enrollment.Subject.AccountID = request.Enrollment.Subject.TenantID
			}
			executor, err := NewNativeShareSourcePrepareExecutor(holder.registry, sourcePrepareExecutorNow)
			if err != nil {
				t.Fatal(err)
			}
			before := sourcePrepareExecutorCounts(t, holder.registry)
			first, err := executor.Prepare(request.Enrollment.Subject.ServerURL, session, request)
			if err != nil {
				t.Fatal(err)
			}
			raw := sourcePrepareBytes(t, first)
			after := sourcePrepareExecutorCounts(t, holder.registry)
			if after[0] != before[0]+1 || after[1] != before[1]+1 || after[2] != before[2] {
				t.Fatalf("unexpected prepare side effects: before %v, after %v", before, after)
			}
			reopened := sourcePrepareReopen(t, holder)
			executor, err = NewNativeShareSourcePrepareExecutor(reopened.holder.registry, sourcePrepareExecutorNow)
			if err != nil {
				t.Fatal(err)
			}
			retry, err := executor.Prepare(request.Enrollment.Subject.ServerURL, session, request)
			if err != nil || !bytes.Equal(raw, sourcePrepareBytes(t, retry)) {
				t.Fatal("restart changed prepared response", err)
			}
		})
	}
}

func TestNativeShareSourcePrepareExecutorRejectsBeforePersistence(t *testing.T) {
	type input struct {
		endpoint string
		session  transport.HostSessionPayload
		request  transport.NativeShareSourcePreparePayload
		now      time.Time
	}
	cases := map[string]func(*input){
		"tenant mismatch":    func(i *input) { i.request.Enrollment.Subject.TenantID = domain.NewID() },
		"account mismatch":   func(i *input) { i.request.Enrollment.Subject.AccountID = domain.NewID() },
		"host mismatch":      func(i *input) { i.request.Enrollment.Subject.HostID = domain.NewID() },
		"admission mismatch": func(i *input) { i.request.Enrollment.Subject.NativeAdmissionID = domain.NewID() },
		"runner mismatch":    func(i *input) { i.request.Enrollment.Subject.RunnerID = domain.NewID() },
		"epoch mismatch": func(i *input) {
			i.request.Enrollment.Subject.RunnerEpoch = i.session.RunnerEpoch.Add(time.Second).Format(time.RFC3339Nano)
		},
		"boot mismatch":             func(i *input) { i.request.Enrollment.Subject.BootID = "other-boot" },
		"credential mismatch":       func(i *input) { i.request.Enrollment.HostCredentialID = "other-credential" },
		"scope mismatch":            func(i *input) { i.request.Enrollment.OwnershipScope = "organization" },
		"subject endpoint mismatch": func(i *input) { i.request.Enrollment.Subject.ServerURL = "https://other.test" },
		"missing session":           func(i *input) { i.session = transport.HostSessionPayload{} },
		"missing tenant":            func(i *input) { i.session.TenantID = "" },
		"invalid tenant":            func(i *input) { i.session.TenantID = "invalid" },
		"missing account":           func(i *input) { i.session.AccountID = "" },
		"missing host":              func(i *input) { i.session.HostID = "" },
		"missing admission":         func(i *input) { i.session.NativeAdmissionID = "" },
		"missing runner":            func(i *input) { i.session.RunnerID = "" },
		"missing epoch":             func(i *input) { i.session.RunnerEpoch = time.Time{} },
		"missing boot":              func(i *input) { i.session.BootID = "" },
		"missing credential":        func(i *input) { i.session.HostCredentialID = "" },
		"missing scope":             func(i *input) { i.session.OwnershipScope = "" },
		"invalid scope":             func(i *input) { i.session.OwnershipScope = "host"; i.request.Enrollment.OwnershipScope = "host" },
		"organization account mismatch": func(i *input) {
			i.session.OwnershipScope = "organization"
			i.request.Enrollment.OwnershipScope = "organization"
		},
		"missing endpoint":              func(i *input) { i.endpoint = "" },
		"invalid endpoint":              func(i *input) { i.endpoint = "://invalid" },
		"endpoint case":                 func(i *input) { i.endpoint = "https://EXAMPLE.TEST" },
		"endpoint slash":                func(i *input) { i.endpoint += "/" },
		"endpoint whitespace":           func(i *input) { i.endpoint = " " + i.endpoint + " " },
		"noncanonical subject endpoint": func(i *input) { i.request.Enrollment.Subject.ServerURL += "/" },
		"invalid schema":                func(i *input) { i.request.Enrollment.Version = 0 },
		"missing command":               func(i *input) { i.request.CommandID = "" },
		"expired":                       func(i *input) { i.request.Enrollment.ExpiresAt = i.now.Add(-time.Second).Format(time.RFC3339Nano) },
		"expiry equality":               func(i *input) { i.request.Enrollment.ExpiresAt = i.now.Format(time.RFC3339Nano) },
		"zero clock":                    func(i *input) { i.now = time.Time{} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			holder, session, request := sourcePrepareExecutorFixture(t)
			i := input{request.Enrollment.Subject.ServerURL, session, request, sourcePrepareExecutorNow()}
			change(&i)
			executor, err := NewNativeShareSourcePrepareExecutor(holder.registry, func() time.Time { return i.now })
			if err != nil {
				t.Fatal(err)
			}
			before := sourcePrepareExecutorCounts(t, holder.registry)
			if _, err := executor.Prepare(i.endpoint, i.session, i.request); err == nil {
				t.Fatal("invalid prepare accepted")
			}
			if after := sourcePrepareExecutorCounts(t, holder.registry); after != before {
				t.Fatalf("rejected prepare changed persistent state: before %v, after %v", before, after)
			}
			if _, err := os.Stat(filepath.Join(holder.registry.root, nativeShareSourceHolderNamespace)); !os.IsNotExist(err) {
				t.Fatal("rejected prepare created holder files", err)
			}
		})
	}
}

func TestNativeShareSourcePrepareExecutorExpiryAfterPersistence(t *testing.T) {
	holder, session, request := sourcePrepareExecutorFixture(t)
	expiry, err := time.Parse(time.RFC3339Nano, request.Enrollment.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	executor, err := NewNativeShareSourcePrepareExecutor(holder.registry, func() time.Time {
		calls++
		if calls == 1 {
			return expiry.Add(-time.Second)
		}
		return expiry
	})
	if err != nil {
		t.Fatal(err)
	}
	before := sourcePrepareExecutorCounts(t, holder.registry)
	reply, err := executor.Prepare(request.Enrollment.Subject.ServerURL, session, request)
	if err == nil || reply.Signature != nil {
		t.Fatal("expired reply escaped after persistence", err)
	}
	if calls < 2 {
		t.Fatal("clock was not checked after persistence")
	}
	after := sourcePrepareExecutorCounts(t, holder.registry)
	if after[0] != before[0]+1 || after[1] != before[1]+1 || after[2] != before[2] {
		t.Fatalf("prepare was not persisted before expiry recheck: before %v, after %v", before, after)
	}
	var prepared []byte
	if err := holder.registry.db.QueryRow(`SELECT prepared FROM native_source_prepare_journal WHERE command_id=?`, request.CommandID).Scan(&prepared); err != nil || len(prepared) == 0 {
		t.Fatal("expiry recheck did not retain completed journal", err)
	}
}

func TestNativeShareSourcePrepareExecutorBindingConflictPreservesOriginal(t *testing.T) {
	holder, session, request := sourcePrepareExecutorFixture(t)
	executor, err := NewNativeShareSourcePrepareExecutor(holder.registry, sourcePrepareExecutorNow)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := request.Enrollment.Subject.ServerURL
	first, err := executor.Prepare(endpoint, session, request)
	if err != nil {
		t.Fatal(err)
	}
	original := sourcePrepareBytes(t, first)
	before := sourcePrepareExecutorCounts(t, holder.registry)
	changed := request
	changed.Enrollment.BindingDigest = strings.Repeat("cd", 32)
	if _, err := executor.Prepare(endpoint, session, changed); err == nil {
		t.Fatal("changed binding retry accepted")
	}
	if after := sourcePrepareExecutorCounts(t, holder.registry); after != before {
		t.Fatalf("binding conflict changed persistent state: before %v, after %v", before, after)
	}
	retry, err := executor.Prepare(endpoint, session, request)
	if err != nil || !bytes.Equal(original, sourcePrepareBytes(t, retry)) {
		t.Fatal("binding conflict damaged original response", err)
	}
}

func TestNativeShareSourcePrepareExecutorScopeConflictPreservesOriginal(t *testing.T) {
	holder, session, request := sourcePrepareExecutorFixture(t)
	executor, err := NewNativeShareSourcePrepareExecutor(holder.registry, sourcePrepareExecutorNow)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := request.Enrollment.Subject.ServerURL
	first, err := executor.Prepare(endpoint, session, request)
	if err != nil {
		t.Fatal(err)
	}
	original := sourcePrepareBytes(t, first)
	before := sourcePrepareExecutorCounts(t, holder.registry)
	namespace := filepath.Join(holder.registry.root, nativeShareSourceHolderNamespace)
	entries, err := os.ReadDir(namespace)
	if err != nil {
		t.Fatal(err)
	}
	changed := request
	changed.Enrollment.Subject.HostID = domain.NewID()
	changedSession := session
	changedSession.HostID = string(changed.Enrollment.Subject.HostID)
	if _, err := executor.Prepare(endpoint, changedSession, changed); err == nil {
		t.Fatal("changed authenticated scope retry accepted")
	}
	if after := sourcePrepareExecutorCounts(t, holder.registry); after != before {
		t.Fatalf("scope conflict changed persistent state: before %v, after %v", before, after)
	}
	afterEntries, err := os.ReadDir(namespace)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterEntries) != len(entries) {
		t.Fatalf("scope conflict changed holder files: before %d, after %d", len(entries), len(afterEntries))
	}
	for i, entry := range entries {
		if entry.Name() != afterEntries[i].Name() {
			t.Fatal("scope conflict replaced holder file", entry.Name(), afterEntries[i].Name())
		}
	}
	retry, err := executor.Prepare(endpoint, session, request)
	if err != nil || !bytes.Equal(original, sourcePrepareBytes(t, retry)) {
		t.Fatal("scope conflict damaged original response", err)
	}
}
