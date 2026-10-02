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

func TestNetworkStaleSaveCannotReviveOrForgetPersistedEpochAuthority(t *testing.T) {
	state := t.TempDir()
	ring := NewKeyring("01900000-0000-7000-8000-0000000000aa")
	original, err := ring.Activate(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err = SaveKeyring(state, ring); err != nil {
		t.Fatal(err)
	}
	stale, err := LoadKeyring(state, ring.NetworkID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ring.Rotate(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err = SaveKeyring(state, ring); err != nil {
		t.Fatal("explicit rotation rejected", err)
	}
	if err = SaveKeyring(state, stale); err == nil {
		t.Fatal("stale active epoch revived after rotation")
	}
	if err = ring.Revoke(original.ID); err != nil {
		t.Fatal(err)
	}
	if err = SaveKeyring(state, ring); err != nil {
		t.Fatal(err)
	}
	stale.Epochs[0].State = EpochRotated
	if err = SaveKeyring(state, stale); err == nil {
		t.Fatal("stale rotated epoch revived after revocation")
	}
	changed, err := LoadKeyring(state, ring.NetworkID)
	if err != nil {
		t.Fatal(err)
	}
	changed.Epochs[0].Key = append([]byte(nil), changed.Epochs[0].Key...)
	changed.Epochs[0].Key[0] ^= 1
	if err = SaveKeyring(state, changed); err == nil {
		t.Fatal("same epoch key material replaced")
	}
	changed, err = LoadKeyring(state, ring.NetworkID)
	if err != nil {
		t.Fatal(err)
	}
	changed.Epochs = changed.Epochs[1:]
	if err = SaveKeyring(state, changed); err == nil {
		t.Fatal("persisted authority history forgotten")
	}
	latest, err := LoadKeyring(state, ring.NetworkID)
	if err != nil {
		t.Fatal(err)
	}
	if epoch, ok := latest.EpochByID(original.ID); !ok || epoch.State != EpochRevoked {
		t.Fatal("failed stale writes changed durable revocation")
	}
	if _, err = latest.Rotate(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err = SaveKeyring(state, latest); err != nil {
		t.Fatal("fresh explicit rotation rejected", err)
	}
}
