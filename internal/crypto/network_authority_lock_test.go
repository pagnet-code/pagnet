//go:build linux || darwin

package crypto

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNetworkAuthorityPinsActionAgainstConcurrentRevocation(t *testing.T) {
	state := t.TempDir()
	ring := NewKeyring("01900000-0000-7000-8000-0000000000a9")
	epoch, err := ring.Activate(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err = SaveKeyring(state, ring); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	readDone := make(chan error, 1)
	go func() {
		readDone <- WithNetworkKeyring(context.Background(), state, ring.NetworkID, func(actual *Keyring) error {
			if loaded, ok := actual.EpochByID(epoch.ID); !ok || loaded.State == EpochRevoked {
				return errors.New("original authority missing")
			}
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	if err = ring.Revoke(epoch.ID); err != nil {
		t.Fatal(err)
	}
	written := make(chan error, 1)
	go func() { written <- SaveKeyring(state, ring) }()
	select {
	case err = <-written:
		t.Fatal("revocation crossed active native authority", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err = <-readDone; err != nil {
		t.Fatal(err)
	}
	if err = <-written; err != nil {
		t.Fatal(err)
	}
	if err = WithNetworkKeyring(context.Background(), state, ring.NetworkID, func(actual *Keyring) error {
		loaded, ok := actual.EpochByID(epoch.ID)
		if !ok || loaded.State != EpochRevoked {
			return errors.New("revocation not durable")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
