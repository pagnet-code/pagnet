//go:build linux || darwin

package fabricauth

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

func TestControlAuthenticatesActualCurrentKernelSession(t *testing.T) {
	a, store, path := ownerFixture(t)
	conn, _ := ownerSocket(t, path)
	session, err := a.BindOwner(t.Context(), conn)
	if err != nil {
		t.Fatal(err)
	}
	remote, _, _ := ownerFixture(t)
	root := store.AuthorityIdentity()
	dest := remote.config.Root
	payload := []byte(`{"credit":1}`)
	digest := sha256.Sum256(payload)
	now := time.Now().UTC()
	f := fabric.ControlFrame{ProtocolVersion: "1", SourceDomain: root.Namespace, SourceStoreID: root.StoreID, SourceKeyRevision: root.KeyRevision, DestinationDomain: dest.Namespace, DestinationStoreID: dest.StoreID, SourcePeerBindingDigest: digest, DestinationPeerBindingDigest: digest, Principal: root.Owner, OriginalPrincipal: root.Owner, InvocationID: "original", ReceiptDigest: digest, AttemptID: "original-attempt", Action: "pull", PayloadDigest: digest, ReplayID: "fresh-control", IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(30 * time.Second).Format(time.RFC3339Nano), BindingProfile: fabric.ForwardBindingProfile}
	called := 0
	callback := func(ctx context.Context, c fabric.ExecutionContext) error {
		called++
		raw, _ := f.SigningBytes()
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded current authentication")
		}
		return c.VerifyAuthenticatedData(raw, root.Namespace)
	}
	if err = session.WithAuthenticatedControl(t.Context(), f, payload, callback); err != nil || called != 1 {
		t.Fatal(err, called)
	}
	wrong := f
	wrong.Principal.Kind = "actor.other"
	if err = session.WithAuthenticatedControl(t.Context(), wrong, payload, callback); err == nil || called != 1 {
		t.Fatal("wire principal manufactured current identity")
	}
	if err = session.WithAuthenticatedControl(t.Context(), f, []byte(`{}`), callback); err == nil {
		t.Fatal("changed payload accepted")
	}
	session.Close()
	if err = session.WithAuthenticatedControl(t.Context(), f, payload, callback); err == nil {
		t.Fatal("closed peer authorized fresh control")
	}
}
