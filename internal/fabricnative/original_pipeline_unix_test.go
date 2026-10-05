//go:build linux || darwin

package fabricnative

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

type captureAdapterResolver struct {
	base      *adapterResolver
	authority *identity.Authority
	owner     fabric.ExecutionContext
}

func (r *captureAdapterResolver) Resolve(c context.Context, p fabric.ExecutionContext, d fabric.EndpointDescriptor) (WorkerHandle, error) {
	return r.base.Resolve(c, p, d)
}
func (r *captureAdapterResolver) Refresh(c context.Context, p fabric.ExecutionContext, s nativeauthority.Scope) (WorkerHandle, error) {
	return r.base.Refresh(c, p, s)
}
func (r *captureAdapterResolver) RefreshOriginalOutput(c context.Context, p *identity.OriginalOutputCapture, d identity.NativeDispatchReservation, s nativeauthority.Scope) (WorkerHandle, error) {
	if err := r.authority.ValidateOriginalOutput(c, r.owner, p, d); err != nil {
		return WorkerHandle{}, err
	}
	h, err := r.base.Refresh(c, r.owner, s)
	h.ControlKey = append([]byte(nil), h.ControlKey...)
	return h, err
}
func TestActualOriginalNativePipelineCaptureUsesAcceptedSourceAndDeliveryCloseNeverStops(t *testing.T) {
	r := actualAdapterRig(t)
	r.adapter.config.Workers = &captureAdapterResolver{r.resolver, r.authority, r.owner}
	result, _, err := r.execute(t, "accepted-original-capture", "let captured once")
	if err != nil {
		t.Fatal(err)
	}
	ownership, err := fabric.OriginalStreamOwnership(r.ctx, result.Stream)
	if err != nil {
		t.Fatal(err)
	}
	native, ok := ownership.(*OriginalCaptureOwnership)
	if !ok {
		t.Fatal("no genuine native source")
	}
	ref, err := native.Reference()
	if err != nil {
		t.Fatal(err)
	}
	var escaped context.Context
	frames := 0
	err = fabric.WithOriginalSourceCapture(r.ctx, result.Stream, func(c context.Context) error {
		escaped = c
		for {
			frame, err := result.Stream.Next(c)
			if err != nil {
				return err
			}
			if frame.InvocationID != ref.InvocationID || frame.Sequence != uint64(frames) {
				t.Fatal("original native frame relabeled")
			}
			frames++
			if frame.Kind == fabric.FrameError {
				t.Fatal(frame.Error)
			}
			if frame.Kind == fabric.FrameComplete {
				return nil
			}
		}
	})
	if err != nil || frames < 3 {
		t.Fatal("actual native original capture", frames, err)
	}
	if native.stream.outputCapture.Active(escaped) {
		t.Fatal("escaped capture retained authority")
	}
	if err = ownership.Close(); err != nil {
		t.Fatal(err)
	}
	if err = result.Stream.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = result.Stream.Next(r.ctx); !errors.Is(err, io.EOF) {
		t.Fatal("genuine completion lost", err)
	}
	if _, err = r.adapter.RetainOriginal(r.ctx, r.owner, ref.Principal, ref.InvocationID); err != nil {
		t.Fatal("delivery close erased original source", err)
	}
}

func TestActualOriginalNativeProjectionFailureDetachesWithoutCancellingPaidSource(t *testing.T) {
	r := actualAdapterRig(t, false, true)
	r.adapter.config.Workers = &captureAdapterResolver{r.resolver, r.authority, r.owner}
	result, _, err := r.execute(t, "native-projection-quota", "actual held native source")
	if err != nil {
		t.Fatal(err)
	}
	ownership, err := fabric.OriginalStreamOwnership(r.ctx, result.Stream)
	if err != nil {
		t.Fatal(err)
	}
	quota := fabric.NewError(fabric.CodeTargetUnavailable, "finite final projection exhausted")
	var before *sessionworker.LocalNativeSnapshot
	err = fabric.WithOriginalSourceCapture(r.ctx, result.Stream, func(c context.Context) error {
		frame, err := result.Stream.Next(c)
		if err != nil || frame.Kind != fabric.FrameStart {
			t.Fatal("no genuine native start", err)
		}
		response, err := r.resolver.handle.Client.Call(c, sessionworker.LocalRequest{Type: "snapshot"})
		if err != nil || response.Snapshot == nil || response.Snapshot.PID <= 1 || response.Snapshot.NativeSessionID == "" {
			t.Fatal("no original live PID/session", err)
		}
		before = response.Snapshot
		return quota
	})
	if !errors.Is(err, quota) {
		t.Fatal("projection failure changed", err)
	}
	if err = ownership.Close(); err != nil {
		t.Fatal(err)
	}
	if err = result.Stream.Close(); err != nil {
		t.Fatal(err)
	}
	response, err := r.resolver.handle.Client.Call(r.ctx, sessionworker.LocalRequest{Type: "snapshot"})
	if err != nil || response.Snapshot == nil || response.Snapshot.PID != before.PID || response.Snapshot.NativeSessionID != before.NativeSessionID || response.Snapshot.NativeGeneration != before.NativeGeneration {
		t.Fatal("delivery failure stopped/replaced original accepted runtime", err, response.Snapshot)
	}
}
