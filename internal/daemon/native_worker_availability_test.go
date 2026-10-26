//go:build linux || darwin

package daemon

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func TestNativeWorkerAvailabilityStaleSocketNeverRelaunches(t *testing.T) {
	r, scope, spec := nativeRegistryFixture(t)
	record, err := r.Reserve(scope, spec, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.prepare(record); err != nil {
		t.Fatal(err)
	}
	if _, err := r.db.Exec(`UPDATE native_workers SET launch_state='launched' WHERE instance_id=?`, scope.InstanceID); err != nil {
		t.Fatal(err)
	}
	path, err := sessionworker.SocketPath(record.Dir)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "launched")
	binary := filepath.Join(t.TempDir(), "unexpected-launch")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	boot := domain.NewID().String()
	var sent transport.NativeWorkerAvailabilityPayload
	c := NewNativeObservationConnection(scope.ServerURL, scope.HostID, boot, func(_ context.Context, _ string, payload any) error {
		sent = payload.(transport.NativeWorkerAvailabilityPayload)
		return nil
	})
	if err := c.Admit(transport.HostSessionPayload{TenantID: scope.TenantID, AccountID: scope.AccountID, OwnershipScope: "personal", NativeAdmissionID: domain.NewID().String(), HostID: scope.HostID, BootID: boot, RunnerID: domain.NewID().String(), RunnerEpoch: time.Now(), ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol, transport.NativeWorkerAvailabilityProtocol}}); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{nativeRegistry: r}
	for range 3 {
		if err := EnsureNativeWorker(t.Context(), r, record, binary, nil, ""); err != nil {
			t.Fatal(err)
		}
		if p, err := AttachNativeWorker(t.Context(), c, record.Dir, scope, boot); err == nil {
			_ = p.Close()
			t.Fatal("stale socket authenticated")
		}
		c.recordNativeWorkerAttachFailure(scope)
		if err := d.sendNativeWorkerAvailability(t.Context(), nil, c); err != nil {
			t.Fatal(err)
		}
		if sent.State != "unavailable" {
			t.Fatal(sent)
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("availability retry relaunched consumed owner")
	}
	current, err := r.Lookup(scope.InstanceID)
	if err != nil || current.LaunchState != "launched" {
		t.Fatal("availability mutated launch claim", err)
	}
}

func TestNativeWorkerAvailabilityCurrentProxyOnly(t *testing.T) {
	r, scope, spec := nativeRegistryFixture(t)
	record, err := r.Reserve(scope, spec, "", "")
	if err != nil {
		t.Fatal(err)
	}
	c := NewNativeObservationConnection(scope.ServerURL, scope.HostID, "boot", nil)
	conn := &websocket.Conn{}
	now := time.Now()
	old := &NativeWorkerProxy{connection: c, scope: scope, done: make(chan struct{}), snapshotAt: now}
	d := &Daemon{nativeRegistry: r, nativeWorkers: map[string]*nativeWorkerLink{scope.InstanceID: {conn: conn, proxy: old}}}
	check := func(want string, at time.Time) {
		t.Helper()
		if got := d.nativeWorkerAvailability(conn, c, record, at); got != want {
			t.Fatalf("got %s, want %s", got, want)
		}
	}
	check("connected", now)
	check("connected", now.Add(10*time.Second))
	check("unknown", now.Add(10*time.Second+time.Nanosecond))
	close(old.done)
	check("unavailable", now)
	replacement := &NativeWorkerProxy{connection: c, scope: scope, done: make(chan struct{})}
	d.nativeWorkers[scope.InstanceID] = &nativeWorkerLink{conn: conn, proxy: replacement}
	check("unknown", now)
	// A late observation from the replaced proxy cannot refresh its successor.
	old.snapshotAt = now.Add(time.Second)
	c.recordNativeWorkerAttachFailure(scope)
	check("unknown", now)
	replacement.snapshotAt = now
	check("connected", now)
	other := NewNativeObservationConnection(scope.ServerURL, scope.HostID, "new-boot", nil)
	if got := d.nativeWorkerAvailability(conn, other, record, now); got != "unknown" {
		t.Fatal("replayed previous connection observation", got)
	}
	other.recordNativeWorkerAttachFailure(scope)
	if got := d.nativeWorkerAvailability(conn, other, record, now); got != "unavailable" {
		t.Fatal("attach failure lost", got)
	}
}

func TestNativeWorkerAvailabilityNegotiationSequenceAndNoReplay(t *testing.T) {
	r, scope, spec := nativeRegistryFixture(t)
	if _, err := r.Reserve(scope, spec, "", ""); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{nativeRegistry: r}
	conn := &websocket.Conn{}
	var sent []transport.NativeWorkerAvailabilityPayload
	newConnection := func(feature bool) *NativeObservationConnection {
		boot := domain.NewID().String()
		c := NewNativeObservationConnection(scope.ServerURL, scope.HostID, boot, func(_ context.Context, typ string, payload any) error {
			if typ != transport.MsgNativeWorkerAvailability {
				t.Fatal(typ)
			}
			sent = append(sent, payload.(transport.NativeWorkerAvailabilityPayload))
			return nil
		})
		features := []string{transport.NativeObservationReceiptProtocol}
		if feature {
			features = append(features, transport.NativeWorkerAvailabilityProtocol)
		}
		if err := c.Admit(transport.HostSessionPayload{TenantID: scope.TenantID, AccountID: scope.AccountID, OwnershipScope: "personal", NativeAdmissionID: domain.NewID().String(), HostID: scope.HostID, BootID: boot, RunnerID: domain.NewID().String(), RunnerEpoch: time.Now(), ProtocolFeatures: features}); err != nil {
			t.Fatal(err)
		}
		return c
	}
	legacy := newConnection(false)
	if err := d.sendNativeWorkerAvailability(t.Context(), conn, legacy); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 0 {
		t.Fatal("event sent to legacy server")
	}
	c := newConnection(true)
	c.recordNativeWorkerAttachFailure(scope)
	for range 2 {
		if err := d.sendNativeWorkerAvailability(t.Context(), conn, c); err != nil {
			t.Fatal(err)
		}
	}
	if len(sent) != 2 || sent[0].Sequence != 1 || sent[1].Sequence != 2 || sent[1].State != "unavailable" {
		t.Fatal(sent)
	}
	c.Close()
	if err := d.sendNativeWorkerAvailability(t.Context(), conn, c); err == nil {
		t.Fatal("closed connection published")
	}
	next := newConnection(true)
	if err := d.sendNativeWorkerAvailability(t.Context(), conn, next); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 3 || sent[2].Sequence != 1 || sent[2].State != "unknown" {
		t.Fatal("old connection state replayed", sent)
	}
	record, err := r.Lookup(scope.InstanceID)
	if err != nil || record.LaunchState != "reserved" {
		t.Fatal("publisher changed launch state", record.LaunchState, err)
	}
}
