//go:build linux || darwin

package runtime

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
)

func TestPersistentFakePreHandshakeEOFSettlesAfterGenuineReap(t *testing.T) {
	sup, manager, driver, _ := newPersistentFixture(t)
	driver.Binary = "/bin/true"
	sess := manager.Session(domain.NewID().String(), domain.RuntimeFakePersistent, t.TempDir())
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	events := make(chan session.SessionEvent, 64)
	endpoint, err := manager.EnsureActive(ctx, sess, events)
	if !errors.Is(err, session.ErrSessionLost) || endpoint != nil {
		t.Fatalf("genuine pre-handshake exit must settle without the activation deadline: endpoint=%v err=%v", endpoint, err)
	}
	if sup.EndpointPID(sess.InstanceID) != nil || driver.Live(sess.InstanceID) {
		t.Fatal("failed startup retained a live endpoint after its original reader reaped it")
	}
	if len(events) != 0 || sess.NativeID != "" {
		t.Fatal("startup EOF fabricated a native session or runtime event")
	}
	if err := manager.Stop(sess.InstanceID); err != nil {
		t.Fatal("stop after failed startup", err)
	}
}
