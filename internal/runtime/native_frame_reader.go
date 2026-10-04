package runtime

import (
	"bufio"
	"io"
	"sync"
)

// Read-ahead retains original frames, never source receipts. Parsing and source
// observation remain on the endpoint's single consumer. Bounds include one
// scanner/pending vendor frame plus the fixed ready-queue budget.
type nativeFrameReader struct {
	frames       chan []byte
	stop         chan struct{}
	done         chan struct{}
	input        io.ReadCloser
	once         sync.Once
	mu           sync.Mutex
	changed      *sync.Cond
	queuedBytes  int
	queuedFrames int
	err          error
}

const nativeReadyFrames = 32
const nativeReadyBytes = 64 << 10

func newNativeFrameReader(input io.ReadCloser, maxFrameBytes int) *nativeFrameReader {
	r := &nativeFrameReader{frames: make(chan []byte, nativeReadyFrames), stop: make(chan struct{}), done: make(chan struct{}), input: input}
	r.changed = sync.NewCond(&r.mu)
	go func() {
		defer close(r.done)
		defer close(r.frames)
		scanner := bufio.NewScanner(input)
		scanner.Buffer(make([]byte, 0, 64<<10), maxFrameBytes)
		for scanner.Scan() {
			frame := append([]byte(nil), scanner.Bytes()...)
			r.mu.Lock()
			for r.queuedFrames >= nativeReadyFrames || (r.queuedFrames > 0 && len(frame) > nativeReadyBytes-r.queuedBytes) {
				select {
				case <-r.stop:
					r.mu.Unlock()
					return
				default:
				}
				r.changed.Wait()
			}
			select {
			case <-r.stop:
				r.mu.Unlock()
				return
			default:
			}
			r.queuedBytes += len(frame)
			r.queuedFrames++
			r.mu.Unlock()
			select {
			case r.frames <- frame:
			case <-r.stop:
				return
			}
		}
		r.mu.Lock()
		r.err = scanner.Err()
		r.mu.Unlock()
	}()
	return r
}

func (r *nativeFrameReader) release(frame []byte) {
	r.mu.Lock()
	r.queuedBytes -= len(frame)
	r.queuedFrames--
	r.changed.Broadcast()
	r.mu.Unlock()
}
func (r *nativeFrameReader) next() ([]byte, bool) {
	frame, ok := <-r.frames
	if ok {
		r.release(frame)
	}
	return frame, ok
}
func (r *nativeFrameReader) ready() ([]byte, bool) {
	select {
	case frame, ok := <-r.frames:
		if ok {
			r.release(frame)
		}
		return frame, ok
	default:
		return nil, false
	}
}
func (r *nativeFrameReader) close() {
	r.once.Do(func() { close(r.stop); r.mu.Lock(); r.changed.Broadcast(); r.mu.Unlock(); _ = r.input.Close() })
	<-r.done
}
