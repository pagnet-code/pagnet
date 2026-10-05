package fabricagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

type hostedInvocationFixture struct {
	t          *testing.T
	inst       *localinstallation.Installation
	dir        string
	session    *fabricauth.Session
	known      map[string]bool
	probe      OriginalHostedProbe
	owner      fabric.ExecutionContext
	profiles   *HostedProfiles
	inv        *HostedInvocations
	root       registry.AuthorityIdentity
	ref        fabric.EndpointRef
	revision   fabric.Revision
	descriptor fabric.EndpointDescriptor
	scope      registry.DescriptorBatchScope
	profile    HostedProfile
	principal  fabric.Principal
	call       fabric.ExecutionContext
	invocation string
	original   []byte
	finalized  []byte
	frame      fabric.DispatchAdmissionFrame
	invoked    InvokedInput
	plan       [32]byte
}

func newHostedInvocationFixture(t *testing.T, limits HostedInvocationLimits, inputText, finalText string) *hostedInvocationFixture {
	t.Helper()
	ctx := t.Context()
	// kernel peer binding requires the socket directory to be owner-only.
	parent, e := os.MkdirTemp("", "pgn-hosted-invocation-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(parent) })
	socket := filepath.Join(parent, "hosted-invocation.sock")
	installation, e := localinstallation.Bootstrap(ctx, filepath.Join(parent, "local"), localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { installation.Close() })
	owner, e := installation.Operator(ctx)
	if e != nil {
		t.Fatal(e)
	}
	root := installation.Store.AuthorityIdentity()
	ref, e := fabric.NewEndpointRef(root.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	descriptor := fabric.EndpointDescriptor{
		Ref:         ref,
		Kind:        "actor.agent",
		Name:        "Public exact name",
		Description: "Exact hosted invocation target",
		Bindings: []fabric.BindingSummary{
			{ID: "original", Protocol: "pagnet.agent.hosted-native.v1", Version: "1"},
			{ID: "alternate", Protocol: "pagnet.agent.hosted-native.v1", Version: "1"},
		},
	}
	revision, e := installation.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: descriptor})
	if e != nil {
		t.Fatal(e)
	}
	profile := HostedProfile{
		DefinitionID:    domain.NewID().String(),
		PrincipalID:     domain.NewID().String(),
		NetworkID:       domain.NewID().String(),
		OwnershipID:     domain.NewID().String(),
		NativeProfile:   sha256.Sum256([]byte("actual-original-private-profile")),
		WorkerDirectory: filepath.Join(parent, "original-cloud-worker"),
		Scope: sessionworker.Scope{
			ServerURL:  "https://app.pagnet.dev",
			TenantID:   domain.NewID().String(),
			AccountID:  domain.NewID().String(),
			HostID:     domain.NewID().String(),
			InstanceID: domain.NewID().String(),
			Generation: "genuine-original-generation",
		},
	}
	scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: revision, BindingID: "original"}
	known := map[string]bool{profile.Scope.InstanceID: true}
	probe := func(_ context.Context, p HostedProfile) error {
		if !known[p.Scope.InstanceID] {
			return hostedProfileError()
		}
		return nil
	}
	profiles, e := NewHostedProfiles(ctx, installation.Store, func(context.Context) (fabric.ExecutionContext, error) { return owner, nil }, installation.Keys, probe)
	if e != nil {
		t.Fatal(e)
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { listener.Close() })
	listener.SetUnlinkOnClose(false)
	if e = os.Chmod(socket, 0600); e != nil {
		t.Fatal(e)
	}
	peer, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { peer.Close() })
	conn, e := listener.AcceptUnix()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { conn.Close() })
	auth, e := fabricauth.New(fabricauth.Config{Root: root, RootOwner: root.Owner, Audience: root.Namespace, SocketPath: socket, CurrentRoot: installation.Store.CurrentAuthorityIdentity})
	if e != nil {
		t.Fatal(e)
	}
	session, e := auth.BindOwner(ctx, conn)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { session.Close() })
	if e = session.WithOwnerAdministration(ctx, []byte(`{"operation":"agent.hosted.invocation.test"}`), func(ctx context.Context, access *fabricauth.OwnerAdministration) error {
		_, e := profiles.Install(ctx, access, scope, profile)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	inv, e := NewHostedInvocations(ctx, installation.Store, profiles, installation.Keys, limits)
	if e != nil {
		t.Fatal(e)
	}
	f := &hostedInvocationFixture{
		t: t, inst: installation, dir: filepath.Join(parent, "local"), session: session,
		known: known, probe: probe, owner: owner, profiles: profiles, inv: inv,
		root: root, ref: ref, revision: revision, descriptor: descriptor, scope: scope, profile: profile,
		principal: fabric.Principal{Ref: ref.String(), Kind: "actor.agent", Issuer: root.Namespace},
	}
	f.invocation = domain.NewID().String()
	f.call, f.original, f.finalized, f.frame, f.invoked = f.buildIdentity(f.invocation, inputText, finalText)
	f.plan[0], f.plan[31] = 0x01, 0x02
	return f
}

// buildIdentity produces a self-consistent original/finalized envelope pair,
// authenticated caller, admission frame and pre-computed encrypted input for
// one exact invocation.
func (f *hostedInvocationFixture) buildIdentity(invocation, inputText, finalText string) (fabric.ExecutionContext, []byte, []byte, fabric.DispatchAdmissionFrame, InvokedInput) {
	t := f.t
	env := fabric.Envelope{
		ProtocolVersion:  fabric.CurrentProtocolVersion,
		ID:               invocation,
		Operation:        fabric.OperationInvoke,
		Principal:        f.principal,
		Source:           f.principal.Ref,
		Target:           &f.ref,
		ExpectedRevision: f.revision,
		CreatedAt:        time.Now().UTC(),
		Payload:          json.RawMessage(`{"input":` + mustJSONString(t, inputText) + `}`),
		Context:          fabric.EnvelopeContext{Origin: f.principal.Ref},
	}
	original, e := json.Marshal(env)
	if e != nil {
		t.Fatal(e)
	}
	final := env
	final.Payload = json.RawMessage(`{"input":` + mustJSONString(t, finalText) + `}`)
	finalized, e := json.Marshal(final)
	if e != nil {
		t.Fatal(e)
	}
	caller, e := fabric.NewAuthenticatedContext(f.principal, f.root.Namespace, original)
	if e != nil {
		t.Fatal(e)
	}
	aad := e2ee.AAD{
		ProtocolVersion: transport.ProtocolVersion,
		TenantID:        f.profile.Scope.TenantID,
		NetworkID:       f.profile.NetworkID,
		ObjectType:      e2ee.ObjectTypeInvocationInput,
		ObjectID:        invocation,
		Sender:          f.profile.Scope.InstanceID,
		Recipient:       f.profile.Scope.InstanceID,
		CreatedAt:       "2026-10-05T00:00:00Z",
		KeyEpochID:      domain.NewID().String(),
	}
	cipher, e := e2ee.Encrypt([]byte(finalText), [32]byte{1}, aad)
	if e != nil {
		t.Fatal(e)
	}
	frame := fabric.DispatchAdmissionFrame{
		SourceDomain:            f.root.Namespace,
		AudienceDomain:          f.root.Namespace,
		CallerRef:               f.principal.Ref,
		InvocationID:            invocation,
		AttemptID:               "exact-hosted-attempt",
		ReplayID:                "exact-hosted-replay",
		FinalizedDispatchDigest: sha256.Sum256(finalized),
	}
	return caller, original, finalized, frame, InvokedInput{Ciphertext: cipher, AAD: aad, CommandID: domain.NewID().String()}
}

func (f *hostedInvocationFixture) reserve() (HostedInvocationReceipt, bool, error) {
	return f.inv.Reserve(context.Background(), f.scope, f.call, f.original, f.finalized, f.frame, f.invoked, f.plan)
}

func (f *hostedInvocationFixture) withOwner(next func(ctx context.Context, access *fabricauth.OwnerAdministration) error) error {
	return f.session.WithOwnerAdministration(context.Background(), []byte(`{"operation":"agent.hosted.invocation.reconfigure"}`), next)
}

func (f *hostedInvocationFixture) ownerTx(next func(tx *registry.AuthorityTx) error) error {
	return f.inst.Store.WithNativeAuthority(context.Background(), f.owner, registry.AuthorityScope{}, next)
}

func (f *hostedInvocationFixture) claimRow(principal fabric.Principal, invocation string) (registry.AuthorityRecord, error) {
	var row registry.AuthorityRecord
	e := f.ownerTx(func(tx *registry.AuthorityTx) error {
		var err error
		row, err = tx.Get(originalDispatchKeyFor(f.t, principal, invocation))
		return err
	})
	return row, e
}

func (f *hostedInvocationFixture) recordRow(principal fabric.Principal, invocation string) (registry.AuthorityRecord, error) {
	var row registry.AuthorityRecord
	e := f.ownerTx(func(tx *registry.AuthorityTx) error {
		var err error
		row, err = tx.Get(hostedInvocationKey(principal, invocation))
		return err
	})
	return row, e
}

func (f *hostedInvocationFixture) stateRow() (registry.AuthorityRecord, error) {
	var row registry.AuthorityRecord
	e := f.ownerTx(func(tx *registry.AuthorityTx) error {
		var err error
		row, err = tx.Get(hostedInvocationStateKey)
		return err
	})
	return row, e
}

// journalCount enumerates retained journal rows (marker + capacity state),
// never chunk payloads, so growth is observable at any sealed size.
func (f *hostedInvocationFixture) journalCount() int {
	page, e := f.inst.Store.ListGlobalAuthorityRecords(context.Background(), f.owner, registry.AuthorityNativeCheckpoint, "hosted/invocation/", "", 32)
	if e != nil {
		f.t.Fatal(e)
	}
	total := 0
	for _, record := range page.Records {
		if !strings.Contains(record.Key.ID, "/chunk/") {
			total++
		}
	}
	if page.NextCursor != "" {
		f.t.Fatal("journal exceeded one enumeration page")
	}
	return total
}

func originalDispatchKeyFor(t *testing.T, principal fabric.Principal, invocation string) registry.AuthorityKey {
	t.Helper()
	raw, e := json.Marshal(struct {
		Principal  fabric.Principal
		Invocation string
	}{principal, invocation})
	if e != nil {
		t.Fatal(e)
	}
	digest := sha256.Sum256(raw)
	return registry.AuthorityKey{Kind: registry.AuthorityNativeCheckpoint, ID: "original-dispatch/" + hex.EncodeToString(digest[:])}
}

func mustJSONString(t *testing.T, s string) string {
	t.Helper()
	raw, e := json.Marshal(s)
	if e != nil {
		t.Fatal(e)
	}
	return string(raw)
}

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	entries, e := os.ReadDir(src)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.MkdirAll(dst, 0700); e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatalf("unexpected directory %s in installation state", entry.Name())
		}
		raw, e := os.ReadFile(filepath.Join(src, entry.Name()))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dst, entry.Name()), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
}

func hostedInvocationCode(t *testing.T, e error, want fabric.ErrorCode) {
	t.Helper()
	if e == nil {
		t.Fatalf("expected %s, got success", want)
	}
	var typed *fabric.Error
	if !errors.As(e, &typed) || typed.Code != want {
		t.Fatalf("expected %s, got %v", want, e)
	}
}

func TestHostedInvocationExactRetryReturnsSameCiphertextCommandAndSource(t *testing.T) {
	f := newHostedInvocationFixture(t, HostedInvocationLimits{MaxInvocations: 16, MaxBytes: 768 << 10}, "original exact input", "finalized exact input")
	if _, e := f.claimRow(f.principal, f.invocation); e == nil {
		t.Fatal("claim existed before first reservation")
	}
	if got := f.journalCount(); got != 0 {
		t.Fatalf("journal rows existed before first reservation: %d", got)
	}
	first, fresh, e := f.reserve()
	if e != nil || !fresh {
		t.Fatalf("first reserve: %v fresh=%v", e, fresh)
	}
	if _, e := domain.ParseID(first.CommandID); e != nil {
		t.Fatalf("receipt command is not a valid ID: %v", e)
	}
	if first.Principal != f.principal || first.Original == nil || first.Finalized == nil || first.Ciphertext != f.invoked.Ciphertext || first.AAD != f.invoked.AAD {
		t.Fatal("receipt did not retain the exact source, envelopes, ciphertext and AAD")
	}
	claimAfter, e := f.claimRow(f.principal, f.invocation)
	if e != nil || claimAfter.Revision != 1 {
		t.Fatalf("first claim not committed at revision 1: %d %v", claimAfter.Revision, e)
	}
	recordAfter, e := f.recordRow(f.principal, f.invocation)
	if e != nil || recordAfter.Revision != 1 {
		t.Fatalf("first journal record not signed at revision 1: %d %v", recordAfter.Revision, e)
	}
	countAfter := f.journalCount()
	retry, fresh, e := f.reserve()
	if e != nil || fresh {
		t.Fatalf("exact retry: %v fresh=%v, want the retained receipt", e, fresh)
	}
	if !reflect.DeepEqual(first, retry) {
		t.Fatalf("exact retry receipt differs from retained: %+v vs %+v", first, retry)
	}
	claimRetry, e := f.claimRow(f.principal, f.invocation)
	if e != nil || !reflect.DeepEqual(claimRetry, claimAfter) {
		t.Fatalf("exact retry re-claimed the original dispatch: %v %v", claimRetry, e)
	}
	recordRetry, e := f.recordRow(f.principal, f.invocation)
	if e != nil || !reflect.DeepEqual(recordRetry, recordAfter) {
		t.Fatalf("exact retry re-signed the journal record: %v %v", recordRetry, e)
	}
	if got := f.journalCount(); got != countAfter {
		t.Fatalf("journal rows grew on exact retry: %d -> %d", countAfter, got)
	}
}

func TestHostedInvocationChangedInputCallerBindingRevisionEpochPlanConflict(t *testing.T) {
	f := newHostedInvocationFixture(t, HostedInvocationLimits{MaxInvocations: 16, MaxBytes: 768 << 10}, "original exact input", "finalized exact input")
	if _, fresh, e := f.reserve(); e != nil || !fresh {
		t.Fatalf("setup reserve: %v fresh=%v", e, fresh)
	}
	baseline := f.journalCount()
	recordBefore, e := f.recordRow(f.principal, f.invocation)
	if e != nil {
		t.Fatal(e)
	}
	changed := func(t *testing.T, scope registry.DescriptorBatchScope, caller fabric.ExecutionContext, original, finalized []byte, frame fabric.DispatchAdmissionFrame, invoked InvokedInput, plan [32]byte) {
		t.Helper()
		_, fresh, e := f.inv.Reserve(context.Background(), scope, caller, original, finalized, frame, invoked, plan)
		if fresh {
			t.Fatal("changed input must never report a fresh reservation")
		}
		hostedInvocationCode(t, e, fabric.CodeStaleReference)
		if got := f.journalCount(); got != baseline {
			t.Fatalf("journal grew: %d -> %d", baseline, got)
		}
		got, e := f.recordRow(f.principal, f.invocation)
		if e != nil || !reflect.DeepEqual(got, recordBefore) {
			t.Fatalf("retained record re-signed: %v %v", got, e)
		}
	}

	t.Run("input bytes", func(t *testing.T) {
		caller, original, finalized, frame, invoked := f.buildIdentity(f.invocation, "original exact input", "replacement exact input")
		changed(t, f.scope, caller, original, finalized, frame, invoked, f.plan)
	})
	t.Run("caller principal", func(t *testing.T) {
		external := fabric.Principal{Ref: "agent:" + domain.NewID().String(), Kind: "actor.agent", Issuer: f.root.Namespace}
		env := fabric.Envelope{
			ProtocolVersion:  fabric.CurrentProtocolVersion,
			ID:               f.invocation,
			Operation:        fabric.OperationInvoke,
			Principal:        external,
			Source:           external.Ref,
			Target:           &f.ref,
			ExpectedRevision: f.revision,
			CreatedAt:        time.Now().UTC(),
			Payload:          json.RawMessage(`{"input":"original exact input"}`),
			Context:          fabric.EnvelopeContext{Origin: external.Ref},
		}
		original, e := json.Marshal(env)
		if e != nil {
			t.Fatal(e)
		}
		final := env
		final.Payload = json.RawMessage(`{"input":"finalized exact input"}`)
		finalized, e := json.Marshal(final)
		if e != nil {
			t.Fatal(e)
		}
		caller, e := fabric.NewAuthenticatedContext(external, f.root.Namespace, original)
		if e != nil {
			t.Fatal(e)
		}
		frame := f.frame
		frame.CallerRef = external.Ref
		frame.FinalizedDispatchDigest = sha256.Sum256(finalized)
		changed(t, f.scope, caller, original, finalized, frame, f.invoked, f.plan)
	})
	t.Run("bindingID", func(t *testing.T) {
		scope := f.scope
		scope.BindingID = "alternate"
		changed(t, scope, f.call, f.original, f.finalized, f.frame, f.invoked, f.plan)
	})
	t.Run("AAD KeyEpochID", func(t *testing.T) {
		invoked := f.invoked
		invoked.AAD.KeyEpochID = domain.NewID().String()
		cipher, e := e2ee.Encrypt([]byte("finalized exact input"), [32]byte{2}, invoked.AAD)
		if e != nil {
			t.Fatal(e)
		}
		invoked.Ciphertext = cipher
		changed(t, f.scope, f.call, f.original, f.finalized, f.frame, invoked, f.plan)
	})
	t.Run("planFingerprint", func(t *testing.T) {
		plan := f.plan
		plan[0] ^= 1
		changed(t, f.scope, f.call, f.original, f.finalized, f.frame, f.invoked, plan)
	})
	t.Run("CommandID", func(t *testing.T) {
		invoked := f.invoked
		invoked.CommandID = domain.NewID().String()
		changed(t, f.scope, f.call, f.original, f.finalized, f.frame, invoked, f.plan)
	})
	t.Run("endpoint revision", func(t *testing.T) {
		f.descriptor.Name = "Public name changed"
		f.descriptor.Revision = ""
		if _, e := f.inst.Store.Update(context.Background(), f.owner, fabric.RegistryUpdate{Descriptor: f.descriptor, ExpectedRevision: f.revision}); e != nil {
			t.Fatal(e)
		}
		changed(t, f.scope, f.call, f.original, f.finalized, f.frame, f.invoked, f.plan)
	})
}

func TestHostedInvocationAdmissionFailureRollsBackClaimAndRecord(t *testing.T) {
	f := newHostedInvocationFixture(t, HostedInvocationLimits{MaxInvocations: 1, MaxBytes: 768 << 10}, "original exact input", "finalized exact input")
	first, fresh, e := f.reserve()
	if e != nil || !fresh {
		t.Fatalf("first reserve: %v fresh=%v", e, fresh)
	}
	second := domain.NewID().String()
	call, original, finalized, frame, invoked := f.buildIdentity(second, "original exact input", "finalized exact input")
	stateBefore, e := f.stateRow()
	if e != nil {
		t.Fatal(e)
	}
	_, fresh, e = f.inv.Reserve(context.Background(), f.scope, call, original, finalized, frame, invoked, f.plan)
	if fresh {
		t.Fatal("capacity exhaustion must not report a fresh reservation")
	}
	hostedInvocationCode(t, e, fabric.CodeTargetUnavailable)
	if _, e := f.claimRow(f.principal, second); e == nil {
		t.Fatal("dispatch claim survived the failed admission")
	}
	if _, e := f.recordRow(f.principal, second); e == nil {
		t.Fatal("journal record survived the failed admission")
	}
	stateAfter, e := f.stateRow()
	if e != nil || !reflect.DeepEqual(stateAfter, stateBefore) {
		t.Fatalf("capacity state row changed by failed admission: %v %v", stateAfter, e)
	}
	retry, fresh, e := f.reserve()
	if e != nil || fresh {
		t.Fatalf("first reservation lost after failed second: %v fresh=%v", e, fresh)
	}
	if !reflect.DeepEqual(first, retry) {
		t.Fatal("first reservation receipt changed after failed second admission")
	}
}

func TestHostedInvocationRootRestartRetainsSameCiphertextAndFailsClosedOnForeignRoot(t *testing.T) {
	ctx := context.Background()
	limits := HostedInvocationLimits{MaxInvocations: 16, MaxBytes: 768 << 10}
	f := newHostedInvocationFixture(t, limits, "original exact input", "finalized exact input")
	first, fresh, e := f.reserve()
	if e != nil || !fresh {
		t.Fatalf("first reserve: %v fresh=%v", e, fresh)
	}
	if e = f.inst.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := localinstallation.Load(ctx, f.dir, registry.DefaultOptions())
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	owner, e := reopened.Operator(ctx)
	if e != nil {
		t.Fatal(e)
	}
	profiles, e := NewHostedProfiles(ctx, reopened.Store, func(context.Context) (fabric.ExecutionContext, error) { return owner, nil }, reopened.Keys, f.probe)
	if e != nil {
		t.Fatal(e)
	}
	inv, e := NewHostedInvocations(ctx, reopened.Store, profiles, reopened.Keys, limits)
	if e != nil {
		t.Fatal(e)
	}
	retry, fresh, e := inv.Reserve(ctx, f.scope, f.call, f.original, f.finalized, f.frame, f.invoked, f.plan)
	if e != nil || fresh {
		t.Fatalf("restart replay: %v fresh=%v", e, fresh)
	}
	if !bytes.Equal(retry.Original, first.Original) || !bytes.Equal(retry.Finalized, first.Finalized) || retry.Ciphertext != first.Ciphertext || retry.AAD != first.AAD || retry.CommandID != first.CommandID || retry.Principal != first.Principal {
		t.Fatal("restart changed the retained exact ciphertext, command or source")
	}

	// A foreign root over the same data directory must fail closed, never sign.
	foreignParent := t.TempDir()
	foreignDir := filepath.Join(foreignParent, "foreign")
	foreign, e := localinstallation.Bootstrap(ctx, foreignDir, localinstallation.Options{Settings: localinstallation.DefaultSettings(filepath.Join(foreignParent, "foreign.sock"))})
	if e != nil {
		t.Fatal(e)
	}
	defer foreign.Close()
	mixed := filepath.Join(foreignParent, "mixed")
	copyDir(t, f.dir, mixed)
	for _, name := range []string{"installation.json", "installation.key"} {
		raw, e := os.ReadFile(filepath.Join(foreignDir, name))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(mixed, name), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = localinstallation.Load(ctx, mixed, registry.DefaultOptions()); e == nil {
		t.Fatal("installation loaded under a foreign root instead of failing closed")
	}
}

func TestHostedInvocationNonHostedCallerAndRetiredAssociationDenied(t *testing.T) {
	ctx := context.Background()
	f := newHostedInvocationFixture(t, HostedInvocationLimits{MaxInvocations: 16, MaxBytes: 768 << 10}, "original exact input", "finalized exact input")
	if _, fresh, e := f.reserve(); e != nil || !fresh {
		t.Fatalf("setup reserve: %v fresh=%v", e, fresh)
	}
	baseline := f.journalCount()

	t.Run("owner principal as caller", func(t *testing.T) {
		ownerPrincipal := f.root.Owner
		env := fabric.Envelope{
			ProtocolVersion:  fabric.CurrentProtocolVersion,
			ID:               f.invocation,
			Operation:        fabric.OperationInvoke,
			Principal:        ownerPrincipal,
			Source:           ownerPrincipal.Ref,
			Target:           &f.ref,
			ExpectedRevision: f.revision,
			CreatedAt:        time.Now().UTC(),
			Payload:          json.RawMessage(`{"input":"original exact input"}`),
			Context:          fabric.EnvelopeContext{Origin: ownerPrincipal.Ref},
		}
		original, e := json.Marshal(env)
		if e != nil {
			t.Fatal(e)
		}
		final := env
		final.Payload = json.RawMessage(`{"input":"finalized exact input"}`)
		finalized, e := json.Marshal(final)
		if e != nil {
			t.Fatal(e)
		}
		caller, e := fabric.NewAuthenticatedContext(ownerPrincipal, f.root.Namespace, original)
		if e != nil {
			t.Fatal(e)
		}
		frame := f.frame
		frame.CallerRef = ownerPrincipal.Ref
		frame.FinalizedDispatchDigest = sha256.Sum256(finalized)
		_, fresh, e := f.inv.Reserve(ctx, f.scope, caller, original, finalized, frame, f.invoked, f.plan)
		if fresh {
			t.Fatal("owner principal must never reserve as a hosted caller")
		}
		hostedInvocationCode(t, e, fabric.CodeStaleReference)
		if got := f.journalCount(); got != baseline {
			t.Fatalf("journal grew: %d -> %d", baseline, got)
		}
	})

	t.Run("retired association", func(t *testing.T) {
		witness, e := f.profiles.CallerAuthority(ctx, f.scope, f.principal)
		if e != nil {
			t.Fatal(e)
		}
		if e := f.ownerTx(func(tx *registry.AuthorityTx) error {
			row, e := tx.Get(hostedProfileKey(f.scope))
			if e != nil {
				return e
			}
			_, e = tx.CAS(row.Key, row.Revision, row.Value, true)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if e := f.ownerTx(witness.VerifyTx); e == nil {
			t.Fatal("in-transaction witness accepted a retired association")
		}
		_, fresh, e := f.reserve()
		if fresh {
			t.Fatal("retired association must not reserve")
		}
		hostedInvocationCode(t, e, fabric.CodeStaleReference)
		if got := f.journalCount(); got != baseline {
			t.Fatalf("journal grew: %d -> %d", baseline, got)
		}
	})

	t.Run("replaced association", func(t *testing.T) {
		f.descriptor.Name = "Public name replaced"
		f.descriptor.Revision = ""
		next, e := f.inst.Store.Update(ctx, f.owner, fabric.RegistryUpdate{Descriptor: f.descriptor, ExpectedRevision: f.revision})
		if e != nil {
			t.Fatal(e)
		}
		replacement := f.profile
		replacement.Scope.Generation = "replacement-generation"
		replacement.OwnershipID = domain.NewID().String()
		replacement.Scope.InstanceID = domain.NewID().String()
		f.known[replacement.Scope.InstanceID] = true
		replacementScope := registry.DescriptorBatchScope{Endpoint: f.ref, ExpectedEndpointRevision: next, BindingID: "original"}
		if e := f.withOwner(func(ctx context.Context, access *fabricauth.OwnerAdministration) error {
			_, e := f.profiles.Install(ctx, access, replacementScope, replacement)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		_, fresh, e := f.inv.Reserve(ctx, replacementScope, f.call, f.original, f.finalized, f.frame, f.invoked, f.plan)
		if fresh {
			t.Fatal("replaced association must not re-reserve the retained original")
		}
		hostedInvocationCode(t, e, fabric.CodeStaleReference)
	})
}

func TestHostedInvocationExactUnicodeNewlinesAndLargeIntegerInputFidelity(t *testing.T) {
	prefix := "Sales questions\n<literal> & café\norder 9007199254740993 "
	text := prefix + strings.Repeat("é", (128<<10-len(prefix))/2)
	if len(text) < 128<<10 {
		text += "x"
	}
	if len(text) != 128<<10 {
		t.Fatalf("fixture input must hit the exact 128 KiB prompt limit, got %d bytes", len(text))
	}
	f := newHostedInvocationFixture(t, HostedInvocationLimits{MaxInvocations: 16, MaxBytes: 768 << 10}, text, text)
	first, fresh, e := f.reserve()
	if e != nil || !fresh {
		t.Fatalf("reserve: %v fresh=%v", e, fresh)
	}
	var env fabric.Envelope
	if e = fabric.DecodeJSON(first.Finalized, &env); e != nil {
		t.Fatal(e)
	}
	bound, e := BindHostedPrompt(env, f.profile)
	if e != nil {
		t.Fatal(e)
	}
	if bound != text {
		t.Fatalf("retained finalized prompt lost exact bytes: %d vs %d bytes", len(bound), len(text))
	}
	retry, fresh, e := f.reserve()
	if e != nil || fresh || !bytes.Equal(retry.Original, first.Original) || !bytes.Equal(retry.Finalized, first.Finalized) {
		t.Fatalf("retry changed the exact unicode input: %v fresh=%v", e, fresh)
	}
}

func TestHostedInvocationCapacityExhausted(t *testing.T) {
	t.Run("count", func(t *testing.T) {
		f := newHostedInvocationFixture(t, HostedInvocationLimits{MaxInvocations: 2, MaxBytes: 768 << 10}, "one", "one")
		for i := 0; i < 2; i++ {
			second := domain.NewID().String()
			call, original, finalized, frame, invoked := f.buildIdentity(second, "one", "one")
			plan := f.plan
			plan[0] = byte(i)
			if _, fresh, e := f.inv.Reserve(context.Background(), f.scope, call, original, finalized, frame, invoked, plan); e != nil || !fresh {
				t.Fatalf("reservation %d: %v fresh=%v", i, e, fresh)
			}
		}
		stateBefore, e := f.stateRow()
		if e != nil {
			t.Fatal(e)
		}
		third := domain.NewID().String()
		call, original, finalized, frame, invoked := f.buildIdentity(third, "one", "one")
		plan := f.plan
		plan[0] = 0x0f
		_, fresh, e := f.inv.Reserve(context.Background(), f.scope, call, original, finalized, frame, invoked, plan)
		if fresh {
			t.Fatal("count exhaustion must not report fresh")
		}
		hostedInvocationCode(t, e, fabric.CodeTargetUnavailable)
		if _, e := f.claimRow(f.principal, third); e == nil {
			t.Error("claim survived count exhaustion")
		}
		if _, e := f.recordRow(f.principal, third); e == nil {
			t.Error("record survived count exhaustion")
		}
		stateAfter, e := f.stateRow()
		if e != nil || !reflect.DeepEqual(stateAfter, stateBefore) {
			t.Fatalf("capacity state row changed on exhaustion: %v %v", stateAfter, e)
		}
	})
	t.Run("bytes", func(t *testing.T) {
		f := newHostedInvocationFixture(t, HostedInvocationLimits{MaxInvocations: 8, MaxBytes: 64 << 10}, "small", "small")
		if _, fresh, e := f.reserve(); e != nil || !fresh {
			t.Fatalf("small reserve: %v fresh=%v", e, fresh)
		}
		large := strings.Repeat("genuine large original input ", 2000)
		second := domain.NewID().String()
		call, original, finalized, frame, invoked := f.buildIdentity(second, large, "large finalized")
		_, fresh, e := f.inv.Reserve(context.Background(), f.scope, call, original, finalized, frame, invoked, f.plan)
		if fresh {
			t.Fatal("byte exhaustion must not report fresh")
		}
		hostedInvocationCode(t, e, fabric.CodeTargetUnavailable)
		if _, e := f.claimRow(f.principal, second); e == nil {
			t.Error("claim survived byte exhaustion")
		}
		if _, e := f.recordRow(f.principal, second); e == nil {
			t.Error("record survived byte exhaustion")
		}
	})
}

func TestHostedInvocationValidateDeliveredAcceptMutateAbsent(t *testing.T) {
	ctx := context.Background()
	f := newHostedInvocationFixture(t, HostedInvocationLimits{MaxInvocations: 16, MaxBytes: 768 << 10}, "original exact input", "finalized exact input")
	first, fresh, e := f.reserve()
	if e != nil || !fresh {
		t.Fatalf("reserve: %v fresh=%v", e, fresh)
	}
	base := transport.FabricHostedInvocation{
		RequestID:           domain.NewID().String(),
		CommandID:           first.CommandID,
		Ref:                 first.Target,
		Revision:            first.TargetRevision,
		InvocationID:        first.InvocationID,
		NetworkID:           first.AAD.NetworkID,
		InstanceID:          first.AAD.Recipient,
		OwnershipID:         f.profile.OwnershipID,
		OwnershipGeneration: f.profile.Scope.Generation,
		Envelope:            first.Ciphertext,
		AAD:                 first.AAD,
	}
	if e := base.Validate(); e != nil {
		t.Fatalf("fixture delivery frame invalid: %v", e)
	}
	receipt, e := f.inv.ValidateDelivered(ctx, f.scope, f.call, base)
	if e != nil {
		t.Fatalf("valid delivery rejected: %v", e)
	}
	if !reflect.DeepEqual(receipt, first) {
		t.Fatal("delivery receipt differs from the retained original")
	}
	mutated := func(change func(*transport.FabricHostedInvocation)) {
		inv := base
		change(&inv)
		if e := inv.Validate(); e != nil {
			t.Fatalf("mutation produced an invalid frame: %v", e)
		}
		_, e := f.inv.ValidateDelivered(ctx, f.scope, f.call, inv)
		hostedInvocationCode(t, e, fabric.CodeStaleReference)
	}
	mutated(func(inv *transport.FabricHostedInvocation) { inv.CommandID = domain.NewID().String() })
	mutated(func(inv *transport.FabricHostedInvocation) {
		inv.Envelope.Nonce = base64.StdEncoding.EncodeToString(make([]byte, 12))
	})
	mutated(func(inv *transport.FabricHostedInvocation) { inv.AAD.Sender = domain.NewID().String() })
	mutated(func(inv *transport.FabricHostedInvocation) {
		ref, e := fabric.NewEndpointRef(f.root.PublicKey)
		if e != nil {
			t.Fatal(e)
		}
		inv.Ref = ref
	})
	mutated(func(inv *transport.FabricHostedInvocation) { inv.Revision = fabric.Revision(strings.Repeat("0", 64)) })
	mutated(func(inv *transport.FabricHostedInvocation) { inv.OwnershipID = domain.NewID().String() })
	mutated(func(inv *transport.FabricHostedInvocation) { inv.OwnershipGeneration = "replaced-generation" })
	missing := base
	missing.InvocationID = domain.NewID().String()
	missing.AAD.ObjectID = missing.InvocationID
	_, e = f.inv.ValidateDelivered(ctx, f.scope, f.call, missing)
	hostedInvocationCode(t, e, fabric.CodeNotFound)
}
