package daemon

import (
	"context"
	"errors"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

func (p *NativeWorkerProxy) OpenNativeTerminalStream(ctx context.Context, dir, generation string) (*sessionworker.TerminalStream, error) {
	snap, err := p.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if !snap.HasTerminal || snap.NativeGeneration != generation || snap.PID <= 0 || snap.NativeSessionID == "" {
		return nil, errors.New("original runtime has no live terminal")
	}
	b, key, err := sessionworker.LoadControllerBootstrap(dir, p.scope)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	if sessionworker.NativeProfileFingerprint(b.Native) != p.profile {
		return nil, ErrNativeObservationConflict
	}
	stream, err := p.controller.OpenTerminalStream(ctx, dir, p.scope, key, generation)
	if err != nil {
		return nil, err
	}
	after, err := p.Snapshot(ctx)
	if err != nil || after.NativeGeneration != generation || after.NativeStartIdentity != snap.NativeStartIdentity || after.NativeSessionID != snap.NativeSessionID || !after.HasTerminal {
		stream.Close()
		return nil, ErrNativeObservationConflict
	}
	go func() {
		select {
		case <-p.done:
			_ = stream.Close()
		case <-stream.Done():
		}
	}()
	return stream, nil
}
func (p *NativeWorkerProxy) NativeTerminalOutput(ctx context.Context, replay string, cursor int64) (sessionworker.OutputPage, error) {
	response, err := p.call(ctx, sessionworker.Request{Type: "output", ReplayGeneration: replay, Cursor: cursor, Limit: 64})
	if err != nil {
		return sessionworker.OutputPage{}, err
	}
	page := response.Output
	if page == nil || page.ReplayGeneration == "" || len(page.ReplayGeneration) > 256 || len(page.Records) > 64 || page.NextSequence <= 0 || page.RetiredThrough < 0 || page.RetiredThrough >= page.NextSequence {
		return sessionworker.OutputPage{}, ErrNativeObservationConflict
	}
	previous := cursor
	if page.Gap {
		previous = page.RetiredThrough
	}
	for _, record := range page.Records {
		if record.Sequence <= previous || record.Sequence >= page.NextSequence || len(record.Data) > 32<<10 || len(record.Origin) > 8192 || len(record.NativeGeneration) > 256 {
			return sessionworker.OutputPage{}, ErrNativeObservationConflict
		}
		previous = record.Sequence
	}
	return *page, nil
}
