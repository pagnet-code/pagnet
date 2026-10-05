//go:build linux || darwin

package fabricnode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension/continuation"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/mcpbridge"
	"github.com/pagnet-code/pagnet/fabric/node/continuations"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
)

func TestExtensionPrivateProfilesNotificationRootPublicationRotation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	private := t.TempDir()
	if e := os.Chmod(private, 0700); e != nil {
		t.Fatal(e)
	}
	socket := filepath.Join(private, "fabric.sock")
	i, e := localinstallation.Bootstrap(ctx, filepath.Join(private, "root"), localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if e != nil {
		t.Fatal(e)
	}
	defer i.Close()
	if _, e = OpenExtensionProfiles(ctx, i, 2); e == nil {
		t.Fatal("startup silently initialized profiles")
	}
	if e = initializeExtensionProfiles(ctx, i, 2); e != nil {
		t.Fatal(e)
	}
	p, e := OpenExtensionProfiles(ctx, i, 2)
	if e != nil {
		t.Fatal(e)
	}
	profile := ExtensionProfile{Protocol: extensionHTTPProtocol, URL: "http://127.0.0.1:12345/intercept", CredentialSelector: "operator.extension.credentials", MaxConcurrency: 2}
	digest, e := p.Put(ctx, profile)
	if e != nil {
		t.Fatal(e)
	}
	owner, e := i.Operator(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var generation registry.AuthorityRecord
	readGeneration := func() registry.AuthorityRecord {
		var r registry.AuthorityRecord
		e := i.Store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{HistoryOnly: true, MaxOperations: 1}, func(tx *registry.AuthorityTx) error { var x error; r, x = tx.ExtensionPurposeGeneration(); return x })
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	generation = readGeneration()
	if got, e := p.Put(ctx, profile); e != nil || got != digest || readGeneration().Sequence != generation.Sequence {
		t.Fatal("immutable profile retry advanced plan", e)
	}
	p, e = OpenExtensionProfiles(ctx, i, 2)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := p.Get(ctx, digest); e != nil || got != profile {
		t.Fatal("profile readback", e)
	}
	bad := profile
	bad.Protocol = "arbitrary.provider"
	if _, e = p.Put(ctx, bad); e == nil {
		t.Fatal("uninstalled provider fallback")
	}
	bad = profile
	bad.URL = "http://example.com/intercept"
	if _, e = p.Put(ctx, bad); e == nil {
		t.Fatal("implicit remote plaintext disclosure")
	}

	root := i.Store.AuthorityIdentity()
	a, e := fabricauth.New(fabricauth.Config{Root: root, RootOwner: root.Owner, Audience: root.Namespace, SocketPath: socket, CurrentRoot: i.Store.CurrentAuthorityIdentity})
	if e != nil {
		t.Fatal(e)
	}
	session, closeSession := runtimeOwnerSession(t, ctx, &NativeRuntime{Authenticator: a}, socket)
	defer closeSession()
	raw, proof, e := session.Build(ctx, mcpbridge.Call{Operation: fabric.OperationDiscover, Discover: &fabric.DiscoverRequest{Query: "exact private source", Limit: 1}})
	if e != nil {
		t.Fatal(e)
	}
	caller, e := a.Authenticate(ctx, fabric.AuthenticationRequest{Audience: root.Namespace, ExactEnvelope: raw, PeerEvidence: proof})
	if e != nil {
		t.Fatal(e)
	}
	store, e := continuation.Bootstrap(ctx, filepath.Join(private, "continuations"), continuation.Scope{Audience: root.Namespace}, continuation.DefaultOptions(), i.Keys)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	id := sha256.Sum256([]byte("notification-source"))
	pipeline := []byte(`{"stage":1}`)
	pd := sha256.Sum256(pipeline)
	snapshot := continuation.Snapshot{Format: 1, DeferralID: hex.EncodeToString(id[:]), OriginalEnvelope: raw, OriginalPrincipal: caller.PrincipalView(), AllowedResumePrincipals: []fabric.Principal{root.Owner}, PlanRevision: "plan:fixture", PlanVersion: "1", PlanDigest: hex.EncodeToString(pd[:]), Pipeline: pipeline, State: []byte(`{}`)}
	expiry := time.Now().UTC().Add(time.Minute)
	issued, e := store.Create(ctx, caller, snapshot, expiry)
	if e != nil {
		t.Fatal(e)
	}
	boundary, e := newLocalBoundary(ctx, i.Store, owner, i, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	boundary.sessions = a
	n, e := newExtensionNotifications(ctx, i, store, boundary)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = n.Delivery(ctx, owner, issued.ID); e == nil {
		t.Fatal("static/operator context promoted to recipient")
	}
	notice := continuations.PrivateNotification{ID: issued.ID, Capability: issued.Capability, Revision: issued.CapabilityRevision, ExpiresAt: expiry, Recipients: []fabric.Principal{root.Owner}}
	// A crash/outage before Root publication leaves the exact SQLite secret.
	var resumer fabric.ExecutionContext
	e = session.WithOwnerAdministration(ctx, []byte(`{"operation":"continuation.inspect"}`), func(c context.Context, admin *fabricauth.OwnerAdministration) error {
		return admin.WithResumerContext(c, func(c context.Context, r fabric.ExecutionContext) error {
			resumer = r
			if _, x := n.Delivery(c, r, issued.ID); x == nil {
				t.Fatal("unpublished Root receipt delivered")
			}
			if x := n.Publish(c, notice); x != nil {
				return x
			}
			if x := n.Publish(c, notice); x != nil {
				return x
			}
			d, x := n.Delivery(c, r, issued.ID)
			if x != nil {
				return x
			}
			if d.Capability().Token() != notice.Capability.Token() {
				t.Fatal("publication changed original secret")
			}
			if _, x = json.Marshal(d); x == nil {
				t.Fatal("secret wire serialization")
			}
			rotated, x := store.RotatePendingCapability(c, r, issued.ID, 1)
			if x != nil {
				return x
			}
			if _, x = n.Delivery(c, r, issued.ID); x == nil {
				t.Fatal("old signed publication authorized new revision")
			}
			if x = n.Publish(c, notice); x == nil {
				t.Fatal("old capability republished after rotation")
			}
			notice.Capability = rotated.Capability
			notice.Revision = rotated.CapabilityRevision
			if x = n.Publish(c, notice); x != nil {
				return x
			}
			_, x = n.Delivery(c, r, issued.ID)
			return x
		})
	})
	if e != nil {
		t.Fatal(e)
	}
	if a.AssociationOpen(resumer) {
		t.Fatal("inspection callback became retained authority")
	}
	if readGeneration().Sequence != generation.Sequence {
		t.Fatal("notification publication changed extension plan")
	}
	e = i.Store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{HistoryOnly: true, MaxOperations: 1}, func(tx *registry.AuthorityTx) error {
		r, x := tx.Get(notificationPinKey(issued.ID, root.Owner))
		if x != nil {
			return x
		}
		if bytes.Contains(r.Value, []byte(notice.Capability.Token())) {
			t.Fatal("plaintext capability in Root record")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}
