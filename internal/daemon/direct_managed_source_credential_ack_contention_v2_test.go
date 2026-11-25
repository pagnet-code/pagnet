//go:build linux || darwin

package daemon

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestSourceCredentialACKReservationContentionV2(t *testing.T) {
	for _, held := range []string{"registry", "namespace", "pool", "writer", "canceled"} {
		t.Run(held, func(t *testing.T) {
			keys, issue, d, token, captured := sourceCredentialAuthorityFixtureV2(t)
			lane := newDirectManagedSourceCredentialPublicationLane()
			ack, err := keys.InstallCredential(issue, "https://example.test", captured.Session, directSourceCredentialScopeOKV2, d.directManagedSourceCredentialPublicationFenceV2(token, captured, lane))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch held {
			case "registry":
				keys.registry.mu.Lock()
				defer keys.registry.mu.Unlock()
			case "namespace":
				root, err := nativeShareHolderDirectory(keys.registry.root)
				if err != nil {
					t.Fatal(err)
				}
				defer root.Close()
				dir, err := nativeShareHolderExistingChild(root, nativeDirectManagedSourceKeyNamespaceV2)
				if err != nil {
					t.Fatal(err)
				}
				defer dir.Close()
				lock, err := nativeShareHolderLockMode(dir, false)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
			case "pool":
				conn, err := keys.registry.db.Conn(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
			case "writer":
				var databasePath string
				if err := keys.registry.db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&databasePath); err != nil {
					t.Fatal(err)
				}
				db, err := sql.Open("sqlite", filepath.Clean(databasePath))
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				if _, err := db.Exec(`BEGIN IMMEDIATE`); err != nil {
					t.Fatal(err)
				}
				defer db.Exec(`ROLLBACK`)
			case "canceled":
				cancel()
			}
			e := &localDirectManagedSourceCredentialV2{&localDirectManagedSourcePoPV2{&localDirectManagedSourcePrepareV2{d: d, keys: keys}}}
			reserved, finished := make(chan struct{}), make(chan error, 1)
			go func() {
				d.writeMu.Lock()
				close(reserved)
				defer d.writeMu.Unlock()
				finished <- e.publishCredentialACKWithToken(ctx, token, captured.Socket, captured.Connection, captured.Session, "https://example.test", issue, lane, ack, func() error { t.Error("contention reached write"); return nil })
			}()
			<-reserved
			unrelatedSocket, peer := nativeBindingSocketPair(t)
			d.writeTimeout = time.Second
			writerDone := make(chan error, 1)
			go func() { writerDone <- d.write(unrelatedSocket, []byte("unrelated frame")) }()
			select {
			case err := <-writerDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("ACK reservation blocked unrelated writer")
			}
			_ = peer.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			if _, raw, err := peer.ReadMessage(); err != nil || string(raw) != "unrelated frame" {
				t.Fatalf("unrelated socket write failed: %v", err)
			}
			select {
			case err := <-finished:
				if err == nil {
					t.Fatal("contention succeeded")
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("ACK reservation did not finish")
			}
		})
	}
}
