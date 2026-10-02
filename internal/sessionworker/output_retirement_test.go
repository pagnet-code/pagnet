//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/transport"
)

func TestOriginalStoppedDeletionOnlyReclaimsAuthenticatedEmptySettledStream(t *testing.T) {
	for _, mode := range []string{"empty", "tail", "ready", "uncertain", "wrong-key", "foreign-marker", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			j, _ := testJournal(t)
			defer j.Close()
			ctx := context.Background()
			p, _ := retiredFixture(t, j, "origin-A", "generation-A")
			a := lease(t, j)
			if _, _, err := j.Admit(ctx, a, 1, "original-A", "prompt", json.RawMessage(`{}`)); err != nil {
				t.Fatal(err)
			}
			source := NativeTurnSource{Sequence: 1, LogicalTurnID: logicalWorkerTurn(1), NativeGeneration: p.generation, NativeSessionID: "session-A", SourceCommandID: "command-A", SourceAdmissionID: "admission-A", InputKind: "task"}
			if err := j.BindNativeTurn(ctx, source); err != nil {
				t.Fatal(err)
			}
			if _, err := j.db.Exec(`UPDATE worker_intent SET state='completed' WHERE sequence=1`); err != nil {
				t.Fatal(err)
			}
			if mode == "uncertain" {
				j.db.Exec(`UPDATE worker_intent SET state='executing' WHERE sequence=1`)
			}
			key := bytes.Repeat([]byte{23}, 32)
			tail := nativeOutputSpool{Source: source, Origin: p.origin, StreamID: "stream-A", BatchID: "batch-A", NativeBytes: 1, DeltaCount: 1, RollingDigest: strings.Repeat("a", 64), ByteOffset: 1}
			if mode == "tail" {
				tail.Text = "x"
			}
			if mode == "ready" {
				tail.Ready = &nativeOutputReady{}
			}
			cipher, err := sealOutputSpool(key, j.scope, j.dir, tail)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = j.db.Exec(`INSERT INTO worker_output_spools VALUES(?,?,?,?)`, 1, p.generation, cipher, len(cipher)); err != nil {
				t.Fatal(err)
			}
			marker := transport.NativeResourceInterruption{Cause: transport.NativeResourceOutputLimit, Source: transport.NativeAgentSource{OriginID: p.originID, NativeGeneration: p.generation, SessionID: source.NativeSessionID, LogicalTurnID: source.LogicalTurnID, NativeTurnSequence: 1, SourceCommandID: source.SourceCommandID, SourceAdmissionID: source.SourceAdmissionID, InputKind: source.InputKind}}
			if mode == "foreign-marker" {
				marker.Source.SourceAdmissionID = "foreign"
			}
			raw, _ := json.Marshal(marker)
			if _, err = j.db.Exec(`INSERT INTO worker_resource_interruptions VALUES(?,?,?)`, 1, p.generation, raw); err != nil {
				t.Fatal(err)
			}
			if _, err = j.db.Exec(`INSERT INTO worker_terminal_reservations VALUES(1,'',1,1,1)`); err != nil {
				t.Fatal(err)
			}
			if err = j.retireNativeSource(ctx, p); err != nil {
				t.Fatal(err)
			}
			if mode == "wrong-key" {
				key = bytes.Repeat([]byte{24}, 32)
			}
			tx, err := j.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = j.collectStoppedNativeReservationsTx(ctx, tx, key, p.generation, source.NativeSessionID, p.originID)
			allowed := mode == "empty" || mode == "rollback"
			if (err == nil) != allowed {
				tx.Rollback()
				t.Fatal("deletion did not preserve original uncommitted/uncertain evidence", mode, err)
			}
			if mode == "empty" {
				if err = tx.Commit(); err != nil {
					t.Fatal(err)
				}
			} else {
				tx.Rollback()
			}
			expected := 1
			if mode == "empty" {
				expected = 0
			}
			for _, table := range []string{"worker_output_spools", "worker_resource_interruptions", "worker_terminal_reservations"} {
				if sourceCount(t, j, table) != expected {
					t.Fatal("deletion transaction lost evidence", table, mode)
				}
			}
		})
	}
}
