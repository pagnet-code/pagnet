//go:build linux || darwin

package fabricnode

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/internal/fabricadmin"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
)

// TestInstalledFederationCurrentRoundTripCAS proves the G1 read: Current
// returns the exact declared configuration + retained revision, follows FULL
// CAS (create at 0, update at the current base, stale bases conflict), and
// treats a missing record as the not-configured state (empty, revision 0,
// NO error) while Reload still denies a missing record. The owner fence
// denies a non-owner context, and the declared-configuration bounds
// (own-namespace grant, non-local target, duplicate, count) still hold.
func TestInstalledFederationCurrentRoundTripCAS(t *testing.T) {
	ctx := t.Context()
	private, e := os.MkdirTemp("", "pagnet-fedexposure-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(private)
	dir := filepath.Join(private, "domain")
	socket := filepath.Join(private, "fabric.sock")
	installed, e := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if e != nil {
		t.Fatal(e)
	}
	defer installed.Close()
	owner, e := installed.Operator(ctx)
	if e != nil {
		t.Fatal(e)
	}
	s, e := NewFederationExposures(ctx, installed.Store, installed.Operator, installed, installed.Keys)
	if e != nil {
		t.Fatal(e)
	}
	// Not configured yet: an empty configuration at revision 0, not an error.
	cfg, revision, e := s.Current(ctx)
	if e != nil || revision != 0 || cfg.Exposures != nil {
		t.Fatalf("fresh Current = %+v (revision %d) err %v; want empty at 0 with no error", cfg, revision, e)
	}
	// Reload still denies a missing record (no behavior change).
	if e = s.Reload(ctx); e == nil {
		t.Fatal("missing exposure auto initialized by Reload")
	}
	root := installed.Store.AuthorityIdentity()
	ref, e := fabric.NewEndpointRef(root.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	rev, e := installed.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Name: "published", Kind: "tool.local", Bindings: []fabric.BindingSummary{{ID: "native", Protocol: "local.native", Version: "1"}}}})
	if e != nil {
		t.Fatal(e)
	}
	remoteRef, e := fabric.NewEndpointRef(make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	remote := remoteRef.Domain()
	if remote == root.Namespace {
		t.Fatal("fixture foreign domain collided with the local domain")
	}
	cfgA := FederationExposureConfiguration{Exposures: []FederationExposure{{remote, ref, rev, "native"}}}
	cfgB := FederationExposureConfiguration{Exposures: []FederationExposure{{remote, ref, rev, "native-v2"}}}
	create, e := s.Put(ctx, 0, cfgA)
	if e != nil || create != 1 {
		t.Fatalf("Put(0) = %d, %v; want revision 1", create, e)
	}
	got, revSeen, e := s.Current(ctx)
	if e != nil || revSeen != 1 || !reflect.DeepEqual(got, cfgA) {
		t.Fatalf("Current after Put(0) = %+v (revision %d) err %v; want %+v at 1", got, revSeen, e, cfgA)
	}
	// The exact (base, content) retry is a signed no-op: the same committed
	// revision, no duplicate record.
	retry, e := s.Put(ctx, 0, cfgA)
	if e != nil || retry != 1 {
		t.Fatalf("exact retry Put(0) = %d, %v; want the committed revision 1", retry, e)
	}
	update, e := s.Put(ctx, 1, cfgB)
	if e != nil || update != 2 {
		t.Fatalf("Put(1) = %d, %v; want revision 2", update, e)
	}
	got, revSeen, e = s.Current(ctx)
	if e != nil || revSeen != 2 || !reflect.DeepEqual(got, cfgB) {
		t.Fatalf("Current after Put(1) = %+v (revision %d) err %v; want %+v at 2", got, revSeen, e, cfgB)
	}
	// Stale CAS bases conflict: re-create and a stale update.
	if _, e = s.Put(ctx, 0, cfgA); e == nil {
		t.Fatal("stale create base accepted")
	} else if !isFabricCode(e, fabric.CodeStaleReference) {
		t.Fatalf("stale create base = %v; want CodeStaleReference", e)
	}
	if _, e = s.Put(ctx, 1, cfgA); e == nil {
		t.Fatal("stale update base accepted")
	} else if !isFabricCode(e, fabric.CodeStaleReference) {
		t.Fatalf("stale update base = %v; want CodeStaleReference", e)
	}
	// Owner fence: a non-owner context is denied with the typed failure.
	static, e := fabric.NewAuthenticatedContext(fabric.Principal{Ref: "local:foreign", Kind: "local.owner", Issuer: "federation-fixture"}, installed.Store.Namespace(), []byte("static foreign owner"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = NewFederationExposures(ctx, installed.Store, func(context.Context) (fabric.ExecutionContext, error) { return static, nil }, installed, installed.Keys); e == nil {
		t.Fatal("non-owner construction accepted")
	} else if !isFabricCode(e, fabric.CodeUnauthenticated) {
		t.Fatalf("non-owner construction = %v; want CodeUnauthenticated", e)
	}
	// Declared-configuration bounds are still enforced through Put.
	if _, e = s.Put(ctx, 2, FederationExposureConfiguration{Exposures: []FederationExposure{{root.Namespace, ref, rev, "native"}}}); e == nil {
		t.Fatal("grant to own namespace accepted")
	}
	if _, e = s.Put(ctx, 2, FederationExposureConfiguration{Exposures: []FederationExposure{{remote, remoteRef, rev, "native"}}}); e == nil {
		t.Fatal("non-local target accepted")
	}
	if _, e = s.Put(ctx, 2, FederationExposureConfiguration{Exposures: []FederationExposure{{remote, ref, rev, "native"}, {remote, ref, rev, "native"}}}); e == nil {
		t.Fatal("duplicate exposure entry accepted")
	}
	overflow := make([]FederationExposure, 65)
	for i := range overflow {
		overflow[i] = FederationExposure{remote, ref, rev, fmt.Sprintf("native-%d", i)}
	}
	if _, e = s.Put(ctx, 2, FederationExposureConfiguration{Exposures: overflow}); e == nil {
		t.Fatal("65-entry exposure configuration accepted")
	}
}

func isFabricCode(err error, code fabric.ErrorCode) bool {
	var typed *fabric.Error
	return errors.As(err, &typed) && typed != nil && typed.Code == code
}

// TestInstalledFederationOpenInstalledCompositionWithoutExposureRecord proves
// OpenInstalled with an explicit Federation config composes the exposure
// surface over a FRESH installation: NewFederationExposures must not require a
// pre-existing exposure record (the first declaration creates it), and the
// fail-closed composition is joined cleanly.
func TestInstalledFederationOpenInstalledCompositionWithoutExposureRecord(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	private := t.TempDir()
	dir, socket := filepath.Join(private, "domain"), filepath.Join(private, "run", "node.sock")
	if err := os.Mkdir(filepath.Join(private, "run"), 0o700); err != nil {
		t.Fatal(err)
	}
	installed, err := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if err != nil {
		t.Fatal(err)
	}
	if err = installed.Close(); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	n, err := OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary, Federation: &InstalledFederationConfig{}})
	if err != nil {
		t.Fatalf("OpenInstalled with Federation on a fresh installation: %v", err)
	}
	defer func() { _ = n.Close() }()
	if n.Federation == nil || n.Federation.Exposures == nil {
		t.Fatal("the federation exposure surface was not composed")
	}
}

// TestInstalledFederationAdminExposurePutGetActualSocket proves the two
// administration operations over the REAL private admin socket of an
// OpenInstalled node with Federation enabled: get mirrors a put (including
// the canonical pagnet:// endpoint-ref string), the FULL CAS receipt is
// truthful, a stale base conflicts, and a non-owner (managed) session is
// denied by the genuine kernel classification gate before any operation.
func TestInstalledFederationAdminExposurePutGetActualSocket(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	parent := t.TempDir()
	socketDir := filepath.Join(parent, "run")
	if err := os.Mkdir(socketDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "authority")
	socket := filepath.Join(socketDir, "node.sock")
	installed, err := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := installed.Operator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	root := installed.Store.AuthorityIdentity()
	ref, err := fabric.NewEndpointRef(root.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rev, err := installed.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Name: "published", Kind: "tool.local", Bindings: []fabric.BindingSummary{{ID: "native", Protocol: "local.native", Version: "1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	remoteRef, err := fabric.NewEndpointRef(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	remote := remoteRef.Domain()
	if remote == root.Namespace {
		t.Fatal("fixture foreign domain collided with the local domain")
	}
	if err = installed.Close(); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	n, err := OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary, Federation: &InstalledFederationConfig{}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = n.Close() }()
	if n.Federation == nil {
		t.Fatal("the federation surface was not composed")
	}
	admin, err := fabricadmin.Dial(ctx, socket)
	if err != nil {
		t.Fatalf("dial the real private admin socket: %v", err)
	}
	defer func() { _ = admin.Close() }()
	call := func(id, operation string, input []byte) (json.RawMessage, *fabric.Error) {
		t.Helper()
		response, err := admin.Call(ctx, fabricadmin.Request{Version: fabricadmin.Version, ID: id, Operation: operation, Input: input})
		if err != nil {
			t.Fatalf("%s transport: %v", operation, err)
		}
		if response.Error != nil {
			return nil, response.Error
		}
		return response.Result, nil
	}
	type exposureView struct {
		Revision  uint64               `json:"revision"`
		Exposures []FederationExposure `json:"exposures"`
	}
	get := func() exposureView {
		t.Helper()
		result, failure := call("federation-exposure-get", "federation.exposure.get", []byte(`{}`))
		if failure != nil {
			t.Fatalf("federation.exposure.get: %v", failure)
		}
		var view exposureView
		if err := json.Unmarshal(result, &view); err != nil {
			t.Fatalf("decode get result: %v (%s)", err, result)
		}
		return view
	}
	// Not configured yet: revision 0, an empty (not null) list.
	view := get()
	if view.Revision != 0 || len(view.Exposures) != 0 {
		t.Fatalf("fresh get = %+v; want revision 0 with no exposures", view)
	}
	// Declare one exposure at the create base.
	putInput, err := json.Marshal(struct {
		ExpectedRevision uint64               `json:"expectedRevision"`
		Exposures        []FederationExposure `json:"exposures"`
	}{0, []FederationExposure{{remote, ref, rev, "native"}}})
	if err != nil {
		t.Fatal(err)
	}
	putResult, failure := call("federation-exposure-put", "federation.exposure.put", putInput)
	if failure != nil {
		t.Fatalf("federation.exposure.put: %v", failure)
	}
	var receipt struct {
		Revision uint64 `json:"revision"`
	}
	if err := json.Unmarshal(putResult, &receipt); err != nil || receipt.Revision != 1 {
		t.Fatalf("put receipt = %s; want revision 1", putResult)
	}
	// Get mirrors the put: the exact declared entry, canonical pagnet:// target.
	view = get()
	if view.Revision != 1 || len(view.Exposures) != 1 || view.Exposures[0] != (FederationExposure{remote, ref, rev, "native"}) {
		t.Fatalf("get after put = %+v; want the declared exposure at revision 1", view)
	}
	if !strings.HasPrefix(view.Exposures[0].Target.String(), "pagnet://"+root.Namespace+"/e/") {
		t.Fatalf("target is not the canonical local pagnet:// endpoint-ref string: %s", view.Exposures[0].Target)
	}
	// A stale CAS base conflicts with the typed stale-reference failure
	// (different content, so the exact-retry no-op path cannot apply).
	staleInput, err := json.Marshal(struct {
		ExpectedRevision uint64               `json:"expectedRevision"`
		Exposures        []FederationExposure `json:"exposures"`
	}{0, []FederationExposure{{remote, ref, rev, "native-stale"}}})
	if err != nil {
		t.Fatal(err)
	}
	stale, failure := call("federation-exposure-put-stale", "federation.exposure.put", staleInput)
	if failure == nil {
		t.Fatalf("stale put base accepted: %s", stale)
	}
	if failure.Code != fabric.CodeStaleReference {
		t.Fatalf("stale put base = %v; want CodeStaleReference", failure)
	}
	// An unknown field is refused before any effect.
	extra, failure := call("federation-exposure-put-extra", "federation.exposure.put", []byte(`{"expectedRevision":1,"exposures":[],"unknown":true}`))
	if failure == nil {
		t.Fatalf("unsupported put input accepted: %s", extra)
	}
	if failure.Code != fabric.CodeInvalidInput {
		t.Fatalf("unsupported put input = %v; want CodeInvalidInput", failure)
	}
	// A non-owner (managed) session cannot establish an administration
	// session on the owner-only surface: the genuine kernel classification
	// gate denies with the typed unauthenticated failure before any
	// operation runs.
	managed, _, err := fabrichost.DialProtocol(ctx, socket, fabrichost.Authentication{Type: "fabric.auth", Mode: "managed", Endpoint: ref, WorkerID: "federation-probe", Generation: "gen", Nonce: "nonce"}, fabrichost.AdminProtocol)
	if err == nil {
		if managed != nil {
			managed.Close()
		}
		t.Fatal("non-owner session established on the administration surface")
	}
	var typed *fabric.Error
	if !errors.As(err, &typed) || typed.Code != fabric.CodeUnauthenticated {
		t.Fatalf("non-owner denial = %v; want typed CodeUnauthenticated", err)
	}
}
