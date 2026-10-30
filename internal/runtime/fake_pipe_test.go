//go:build linux

package runtime

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/pagnet-code/pagnet/internal/proc"
)

type refusingFakeLifecycle struct {
	proc.Lifecycle
	err     error
	streams []*os.File
}

func (l *refusingFakeLifecycle) Launch(_ context.Context, req proc.LaunchRequest) (*proc.Handle, error) {
	l.streams = []*os.File{req.Cmd.Stdin.(*os.File), req.Cmd.Stdout.(*os.File), req.Cmd.Stderr.(*os.File)}
	return nil, l.err
}

func TestFakeLaunchRefusalClosesPipes(t *testing.T) {
	refused := errors.New("launch refused before Start")
	life := &refusingFakeLifecycle{err: refused}
	adapter := NewFake(p0FakeBinary(t))
	adapter.SetLifecycle(life)
	spec := TurnSpec{InstanceID: "refused", TurnID: "refused", Workspace: t.TempDir(), SessionDir: t.TempDir()}
	baseline := countFDs()
	for i := 0; i < 25; i++ {
		events := make(chan TurnEvent)
		if err := adapter.StartTurn(context.Background(), spec, events); !errors.Is(err, refused) {
			t.Fatalf("StartTurn: got %v, want launch refusal", err)
		}
		for _, stream := range life.streams {
			if _, err := stream.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("child pipe end left open after refusal: %v", err)
			}
		}
		if _, ok := <-events; ok {
			t.Fatal("events left open after refusal")
		}
	}
	if final := countFDs(); final > baseline {
		t.Fatalf("fd leak after launch refusals: baseline %d final %d", baseline, final)
	}
}
