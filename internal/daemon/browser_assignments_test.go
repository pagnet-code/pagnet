package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

const browserTestHost = "3a6a2efc-46fb-43e8-b7a2-3b0cc852ff9f"
const browserTestID = "a8c3ee28-fd54-4f43-8863-fcefa441c11f"

func browserTestSnapshot(revision int64, assigned bool) browserAssignmentsSnapshot {
	s := browserAssignmentsSnapshot{Revision: revision}
	if assigned {
		s.Items = []browserAssignment{{ID: browserTestID, HostID: browserTestHost, RuntimeMode: "managed", DesiredRevision: revision}}
	}
	return s
}
func browserTestSupervisor(t *testing.T) (*browserAssignmentSupervisor, context.CancelFunc, <-chan struct{}) {
	t.Helper()
	s := newBrowserAssignmentSupervisor(&Daemon{Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	s.runBinding = func(ctx context.Context, _ browserAssignment) { <-ctx.Done() }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("supervisor did not join")
		}
	})
	return s, cancel, done
}
func browserWait(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatal("condition timed out")
		}
		time.Sleep(time.Millisecond)
	}
}
func browserApplied(s *browserAssignmentSupervisor, revision int64, count int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applied == revision && len(s.running) == count
}
func browserNotice(s *browserAssignmentSupervisor, revision int64) {
	s.notice(transport.BrowserConnectionsRevisionPayload{HostID: browserTestHost, BrowserAssignmentsRevision: revision})
}

func TestBrowserAssignmentsReconnectAndEmptySnapshot(t *testing.T) {
	s, _, _ := browserTestSupervisor(t)
	var requests atomic.Int32
	s.fetch = func(context.Context) (browserAssignmentsSnapshot, error) {
		n := requests.Add(1)
		return browserTestSnapshot(int64(n), n == 1), nil
	}
	s.admit(browserTestHost)
	browserWait(t, func() bool { return browserApplied(s, 1, 1) })
	s.mu.Lock()
	old := s.running[browserTestID]
	s.mu.Unlock()
	s.disconnect()
	browserWait(t, func() bool {
		select {
		case <-old.done:
			return true
		default:
			return false
		}
	})
	s.admit(browserTestHost)
	browserWait(t, func() bool { return browserApplied(s, 2, 0) })
	if requests.Load() != 2 {
		t.Fatal("reconnect did not fetch exactly once")
	}
}
func TestBrowserAssignmentsEmptySnapshotStopsChildren(t *testing.T) {
	s, _, _ := browserTestSupervisor(t)
	var requests atomic.Int32
	s.fetch = func(context.Context) (browserAssignmentsSnapshot, error) {
		n := requests.Add(1)
		return browserTestSnapshot(int64(n), n == 1), nil
	}
	s.admit(browserTestHost)
	browserWait(t, func() bool { return browserApplied(s, 1, 1) })
	s.mu.Lock()
	child := s.running[browserTestID]
	s.mu.Unlock()
	browserNotice(s, 2)
	browserWait(t, func() bool { return browserApplied(s, 2, 0) })
	select {
	case <-child.done:
	default:
		t.Fatal("complete empty snapshot did not join child")
	}
}
func TestBrowserAssignmentsNoticeOrderingAndNoPolling(t *testing.T) {
	s, _, _ := browserTestSupervisor(t)
	var requests atomic.Int32
	s.fetch = func(context.Context) (browserAssignmentsSnapshot, error) {
		requests.Add(1)
		return browserTestSnapshot(7, true), nil
	}
	s.admit(browserTestHost)
	browserWait(t, func() bool { return browserApplied(s, 7, 1) })
	for _, revision := range []int64{7, 6, 0, -1} {
		browserNotice(s, revision)
	}
	s.notice(transport.BrowserConnectionsRevisionPayload{HostID: "wrong", BrowserAssignmentsRevision: 99})
	// No timer should start another snapshot request while the socket is idle.
	time.Sleep(40 * time.Millisecond)
	if requests.Load() != 1 {
		t.Fatal("duplicate, old, wrong-host notice or polling caused a fetch")
	}
}
func TestBrowserAssignmentsNoticeDuringFetch(t *testing.T) {
	s, _, _ := browserTestSupervisor(t)
	entered := make(chan int, 3)
	release := make(chan struct{})
	var requests atomic.Int32
	s.fetch = func(context.Context) (browserAssignmentsSnapshot, error) {
		n := int(requests.Add(1))
		entered <- n
		if n == 1 {
			<-release
		}
		return browserTestSnapshot(int64(n), n == 1), nil
	}
	s.admit(browserTestHost)
	<-entered
	browserNotice(s, 2)
	browserNotice(s, 2)
	close(release)
	browserWait(t, func() bool { return browserApplied(s, 2, 0) })
	if requests.Load() != 2 {
		t.Fatal("notice during fetch was lost or not coalesced")
	}
}
func TestBrowserAssignmentsStaleConnectionResponse(t *testing.T) {
	s, _, _ := browserTestSupervisor(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var requests atomic.Int32
	s.fetch = func(context.Context) (browserAssignmentsSnapshot, error) {
		if requests.Add(1) == 1 {
			close(entered)
			<-release
			return browserTestSnapshot(100, true), nil
		}
		return browserTestSnapshot(2, false), nil
	}
	s.admit(browserTestHost)
	<-entered
	s.disconnect()
	s.admit(browserTestHost)
	close(release)
	browserWait(t, func() bool { return browserApplied(s, 2, 0) })
}
func TestBrowserAssignmentsShutdownJoinsFetchAndChildren(t *testing.T) {
	s, cancel, done := browserTestSupervisor(t)
	entered := make(chan struct{})
	var requests atomic.Int32
	s.fetch = func(ctx context.Context) (browserAssignmentsSnapshot, error) {
		if requests.Add(1) == 1 {
			return browserTestSnapshot(1, true), nil
		}
		close(entered)
		<-ctx.Done()
		return browserAssignmentsSnapshot{}, ctx.Err()
	}
	s.admit(browserTestHost)
	browserWait(t, func() bool { return browserApplied(s, 1, 1) })
	s.mu.Lock()
	child := s.running[browserTestID]
	s.mu.Unlock()
	browserNotice(s, 2)
	<-entered
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not join fetch")
	}
	select {
	case <-child.done:
	default:
		t.Fatal("shutdown did not join child")
	}
}
func TestBrowserAssignmentsDormant404AndNoticeRepair(t *testing.T) {
	s, _, _ := browserTestSupervisor(t)
	s.retryDelay = func(int) time.Duration { return time.Millisecond }
	var requests atomic.Int32
	s.fetch = func(context.Context) (browserAssignmentsSnapshot, error) {
		if requests.Add(1) == 1 {
			return browserAssignmentsSnapshot{}, browserAssignmentsHTTPError(http.StatusNotFound)
		}
		return browserTestSnapshot(2, false), nil
	}
	s.admit(browserTestHost)
	browserWait(t, func() bool { return requests.Load() == 1 })
	time.Sleep(40 * time.Millisecond)
	if requests.Load() != 1 {
		t.Fatal("404 retried without a notice")
	}
	browserNotice(s, 2)
	browserWait(t, func() bool { return browserApplied(s, 2, 0) })
}
func TestBrowserAssignmentsHTTP(t *testing.T) {
	for i, body := range []string{`{"browserAssignmentsRevision":3,"items":[]}`, `{}`, `{"browserAssignmentsRevision":3}`, `{"browserAssignmentsRevision":3,"items":null}`, `{"browserAssignmentsRevision":3,"items":[]} {}`, `{"browserAssignmentsRevision":3,"items":[]}junk`, `{"browserAssignmentsRevision":3,"items":[]}` + strings.Repeat(" ", 1<<20)} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/api/v1/hosts/self/browser-connections" || r.Header.Get("Authorization") != "Bearer test" {
					t.Error("incorrect authenticated assignment request")
				}
				io.WriteString(w, body)
			}))
			defer server.Close()
			s := newBrowserAssignmentSupervisor(&Daemon{Config: Config{ServerURL: server.URL, Credential: "test", InsecureRemoteHTTP: true}})
			snapshot, err := s.fetch(context.Background())
			if body == `{"browserAssignmentsRevision":3,"items":[]}` {
				if err != nil || snapshot.Revision != 3 || len(snapshot.Items) != 0 {
					t.Fatal("valid empty snapshot rejected", err)
				}
			} else if err == nil {
				t.Fatal("incomplete snapshot accepted")
			}
		})
	}
}

func TestBrowserAssignmentsTransientRetry(t *testing.T) {
	for _, validationFailure := range []bool{false, true} {
		t.Run(fmt.Sprint(validationFailure), func(t *testing.T) {
			s, _, _ := browserTestSupervisor(t)
			s.retryDelay = func(int) time.Duration { return time.Millisecond }
			var requests atomic.Int32
			s.fetch = func(context.Context) (browserAssignmentsSnapshot, error) {
				if requests.Add(1) == 1 {
					if validationFailure {
						return browserTestSnapshot(-1, false), nil
					}
					return browserAssignmentsSnapshot{}, errors.New("transient")
				}
				return browserTestSnapshot(1, true), nil
			}
			s.admit(browserTestHost)
			browserWait(t, func() bool { return browserApplied(s, 1, 1) })
			if requests.Load() != 2 {
				t.Fatal("transient failure did not retry once")
			}
		})
	}
}
func TestBrowserAssignmentsDisconnectCancelsRetry(t *testing.T) {
	s, _, _ := browserTestSupervisor(t)
	scheduled := make(chan struct{}, 1)
	s.retryDelay = func(int) time.Duration { scheduled <- struct{}{}; return 20 * time.Millisecond }
	var requests atomic.Int32
	s.fetch = func(context.Context) (browserAssignmentsSnapshot, error) {
		requests.Add(1)
		return browserAssignmentsSnapshot{}, errors.New("transient")
	}
	s.admit(browserTestHost)
	<-scheduled
	s.disconnect()
	time.Sleep(50 * time.Millisecond)
	if requests.Load() != 1 {
		t.Fatal("disconnected generation retried")
	}
}
func TestBrowserAssignmentRetryDelayBounded(t *testing.T) {
	for attempt := 1; attempt < 20; attempt++ {
		d := browserAssignmentRetryDelay(attempt)
		if d < 750*time.Millisecond || d > 30*time.Second {
			t.Fatalf("retry out of bounds: %v", d)
		}
	}
}

func TestBrowserAssignmentsSnapshotBehindKnownRevisionRetries(t *testing.T) {
	s, _, _ := browserTestSupervisor(t)
	s.retryDelay = func(int) time.Duration { return time.Millisecond }
	// A reconnect retains the revision already advertised by the previous socket.
	s.mu.Lock()
	s.wanted = 2
	s.mu.Unlock()
	var requests atomic.Int32
	s.fetch = func(context.Context) (browserAssignmentsSnapshot, error) {
		n := requests.Add(1)
		return browserTestSnapshot(int64(n), false), nil
	}
	s.admit(browserTestHost)
	browserWait(t, func() bool { return browserApplied(s, 2, 0) })
	if requests.Load() != 2 {
		t.Fatal("snapshot behind advertised revision did not retry")
	}
}

func TestBrowserAssignmentsUnchangedSnapshotKeepsSingleChild(t *testing.T) {
	s, _, _ := browserTestSupervisor(t)
	var starts atomic.Int32
	s.runBinding = func(ctx context.Context, _ browserAssignment) {
		starts.Add(1)
		<-ctx.Done()
	}
	s.fetch = func(context.Context) (browserAssignmentsSnapshot, error) {
		return browserTestSnapshot(1, true), nil
	}
	s.admit(browserTestHost)
	browserWait(t, func() bool { return browserApplied(s, 1, 1) && starts.Load() == 1 })
	s.mu.Lock()
	original := s.running[browserTestID]
	s.dirty = true
	s.mu.Unlock()
	s.signal()
	browserWait(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return !s.dirty && s.cancelFetch == nil
	})
	s.mu.Lock()
	same := original == s.running[browserTestID]
	s.mu.Unlock()
	if !same || starts.Load() != 1 {
		t.Fatal("unchanged assignment started a duplicate child")
	}
}

func TestBrowserAssignmentsJoinLeavesSocketCallbacksResponsive(t *testing.T) {
	s, _, _ := browserTestSupervisor(t)
	releasing := make(chan struct{})
	released := make(chan struct{})
	s.runBinding = func(ctx context.Context, _ browserAssignment) {
		<-ctx.Done()
		close(releasing)
		<-released
	}
	var requests atomic.Int32
	s.fetch = func(context.Context) (browserAssignmentsSnapshot, error) {
		n := requests.Add(1)
		return browserTestSnapshot(int64(n), n == 1), nil
	}
	s.admit(browserTestHost)
	browserWait(t, func() bool { return browserApplied(s, 1, 1) })
	browserNotice(s, 2)
	<-releasing
	callbackDone := make(chan struct{})
	go func() { s.disconnect(); close(callbackDone) }()
	select {
	case <-callbackDone:
	case <-time.After(time.Second):
		close(released)
		t.Fatal("child release blocked socket disconnect callback")
	}
	close(released)
	browserWait(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return len(s.running) == 0
	})
}

func TestBrowserAssignmentsRejectAmbiguousPolicy(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*browserAssignment)
	}{
		{"zero desired revision", func(a *browserAssignment) { a.DesiredRevision = 0 }},
		{"duplicate network", func(a *browserAssignment) {
			a.Networks = []browserAssignmentNetwork{{NetworkID: browserTestID}, {NetworkID: browserTestID}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := browserTestSnapshot(1, true)
			test.edit(&snapshot.Items[0])
			if validateBrowserAssignments(snapshot, browserTestHost) == nil {
				t.Fatal("ambiguous assignment accepted")
			}
		})
	}
}

func TestBrowserAssignmentsFreshSnapshotRestartsStoppedChild(t *testing.T) {
	s, _, _ := browserTestSupervisor(t)
	var starts atomic.Int32
	s.runBinding = func(ctx context.Context, _ browserAssignment) {
		if starts.Add(1) > 1 {
			<-ctx.Done()
		}
	}
	var requests atomic.Int32
	s.fetch = func(context.Context) (browserAssignmentsSnapshot, error) {
		snapshot := browserTestSnapshot(1, true)
		snapshot.Revision = int64(requests.Add(1))
		return snapshot, nil
	}
	s.admit(browserTestHost)
	browserWait(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		c := s.running[browserTestID]
		if c == nil {
			return false
		}
		select {
		case <-c.done:
			return true
		default:
			return false
		}
	})
	browserNotice(s, 2)
	browserWait(t, func() bool { return browserApplied(s, 2, 1) && starts.Load() == 2 })
}
