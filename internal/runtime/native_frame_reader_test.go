package runtime

import (
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func TestNativeFrameReadAheadBoundedOrderedAndJoined(t *testing.T) {
	input, output := io.Pipe()
	reader := newNativeFrameReader(input, 4<<20)
	defer reader.close()
	written := make(chan struct{})
	go func() {
		defer close(written)
		defer output.Close()
		for i := 0; i < 100; i++ {
			if _, err := fmt.Fprintf(output, "%03d%s\n", i, strings.Repeat("x", 4093)); err != nil {
				return
			}
		}
	}()
	for i := 0; i < 100; i++ {
		frame, ok := reader.next()
		if !ok || string(frame[:3]) != fmt.Sprintf("%03d", i) {
			t.Fatal("original frame order lost", i)
		}
		reader.mu.Lock()
		if reader.queuedBytes > nativeReadyBytes || reader.queuedFrames > nativeReadyFrames {
			t.Fatal("unbounded ready queue")
		}
		reader.mu.Unlock()
	}
	if _, ok := reader.next(); ok {
		t.Fatal("invented extra frame")
	}
	reader.close()
	select {
	case <-written:
	case <-time.After(time.Second):
		t.Fatal("original writer not joined")
	}
}

func TestNativeFrameReadAheadCloseUnblocksIdleInputAndFullQueue(t *testing.T) {
	for _, full := range []bool{false, true} {
		t.Run(fmt.Sprint(full), func(t *testing.T) {
			input, output := io.Pipe()
			reader := newNativeFrameReader(input, 4<<20)
			written := make(chan struct{})
			go func() {
				defer close(written)
				defer output.Close()
				if full {
					for i := 0; i < 100; i++ {
						if _, err := fmt.Fprintln(output, strings.Repeat("x", 4096)); err != nil {
							return
						}
					}
				} else {
					_, _ = io.Copy(output, strings.NewReader("partial-no-newline"))
				}
			}()
			closed := make(chan struct{})
			go func() { reader.close(); close(closed) }()
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("read-ahead leaked during close")
			}
			select {
			case <-written:
			case <-time.After(time.Second):
				t.Fatal("native writer blocked after reader close")
			}
		})
	}
}
