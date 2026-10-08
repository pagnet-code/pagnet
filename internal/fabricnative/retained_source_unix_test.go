//go:build linux || darwin

package fabricnative

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

func TestActualRetainedNativeSourceDeliveryDetachReopenExactACKWithoutResend(t *testing.T) {
	r := actualAdapterRig(t)
	result, _, err := r.execute(t, "retained-original-source", "let retained once")
	if err != nil {
		t.Fatal(err)
	}
	// The original node stream is deliberately not closed: Close is a genuine
	// stop operation. This test exercises the separate delivery-only API.
	source, err := r.adapter.RetainOriginal(r.ctx, r.owner, r.owner.PrincipalView(), "retained-original-source")
	if err != nil {
		t.Fatal(err)
	}
	reference := source.Reference()
	for _, change := range []func(*SourceReference){func(v *SourceReference) { v.AdmissionSHA[0] ^= 1 }, func(v *SourceReference) { v.BindingSHA[0] ^= 1 }, func(v *SourceReference) { v.ReservationSHA[0] ^= 1 }, func(v *SourceReference) { v.Principal.Issuer = "foreign" }} {
		wrong := reference
		change(&wrong)
		if s, e := r.adapter.OpenRetainedSource(r.ctx, r.owner, wrong); e == nil {
			s.Close()
			t.Fatal("altered original source reference accepted")
		}
	}
	if err = source.PollActivation(r.ctx, r.owner); err != nil {
		t.Fatal(err)
	}
	source.Close()
	if _, err = source.Page(r.ctx, r.owner, -1); err == nil {
		t.Fatal("closed delivery handle remained usable")
	}
	// A new controller and authentic IPC lease must retain original A source.
	old := r.resolver.handle
	d := r.endpoint
	d.Name = "Renamed retained original"
	d.Revision = ""
	rev, e := r.store.Update(r.ctx, r.owner, fabric.RegistryUpdate{Descriptor: d, ExpectedRevision: r.endpoint.Revision})
	if e != nil {
		t.Fatal(e)
	}
	scope := old.Binding.Scope
	scope.DescriptorRevision = rev
	current, e := r.authority.AcquireController(r.ctx, r.owner, scope, old.Current.Epoch(), "retained-current-B", "retained-B")
	if e != nil {
		t.Fatal(e)
	}
	binding, e := r.authority.RenewWorkerBinding(r.ctx, r.owner, current, old.Binding)
	if e != nil {
		t.Fatal(e)
	}
	client, e := sessionworker.DialLocal(r.ctx, old.Directory, old.Ownership, old.ControlKey, "retained-B")
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	r.resolver.handle = WorkerHandle{Current: current, Binding: binding, Ownership: old.Ownership, Directory: old.Directory, ControlKey: old.ControlKey, Client: client}
	// New adapter object consumes retained authority/journal, never invokes again.
	reopenedAdapter, err := NewAdapter(r.adapter.config)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := reopenedAdapter.OpenRetainedSource(r.ctx, r.owner, reference)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	cursor := int64(-1)
	var output bytes.Buffer
	for {
		if err = reopened.PollActivation(r.ctx, r.owner); err != nil {
			t.Fatal(err)
		}
		page, e := reopened.Page(r.ctx, r.owner, cursor)
		if e != nil {
			t.Fatal(e)
		}
		if page.Frame == nil {
			if page.Readiness == nil {
				t.Fatal("genuine readiness absent")
			}
			if e = reopened.Wait(r.ctx, r.owner, *page.Readiness); e != nil {
				t.Fatal(e)
			}
			continue
		}
		frame := page.Frame
		if frame.InvocationID != reference.InvocationID || frame.Sequence != uint64(cursor+1) {
			t.Fatal("original frame relabeled")
		}
		again, e := reopened.Page(r.ctx, r.owner, cursor)
		if e != nil || again.Frame == nil || sourceSHA(*again.Frame) != sourceSHA(*frame) || again.CipherDigest != page.CipherDigest {
			t.Fatal("unacknowledged original frame changed", e)
		}
		if _, e = reopened.Ack(r.ctx, r.owner, page.Cursor, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); e == nil {
			t.Fatal("substituted ciphertext ACK accepted")
		}
		if acked, e := reopened.Ack(r.ctx, r.owner, page.Cursor, page.CipherDigest); e != nil {
			t.Fatal(e)
		} else if acked != page.CipherDigest {
			t.Fatal("journal-verified ACK digest differs from the retained cipher digest")
		}
		cursor = page.Cursor
		if frame.Kind == fabric.FrameChunk {
			output.Write(frame.Data)
		}
		if frame.Kind == fabric.FrameError {
			t.Fatal(frame.Error)
		}
		if frame.Kind == fabric.FrameComplete {
			break
		}
	}
	if output.String() != "[fake-persist local-native] let retained = once" {
		t.Fatal("original content changed", output.Len())
	}
	response, err := r.resolver.handle.Client.Call(r.ctx, sessionworker.LocalRequest{Type: "snapshot"})
	if err != nil || response.Snapshot == nil || response.Snapshot.PID <= 0 || response.Snapshot.NativeSessionID == "" {
		t.Fatal("detach stopped original native endpoint", err)
	}
	raw, err := os.ReadFile(filepath.Join(r.resolver.handle.Directory, "native-state", "sessions", r.resolver.handle.Ownership.WorkerID(), "session.json"))
	if err != nil {
		t.Fatal(err)
	}
	var native struct {
		Turns int `json:"turns"`
	}
	if json.Unmarshal(raw, &native) != nil || native.Turns != 1 {
		t.Fatal("reopened source repeated native work", native.Turns)
	}
	// Only now explicit original-stream cleanup may stop its already completed
	// endpoint; the retained source itself owns neither process nor connection.
	_ = result.Stream.Close()
}
