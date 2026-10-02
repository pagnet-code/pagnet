//go:build linux || darwin

package sessionworker

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func originalDeleteFixture(t *testing.T, quarantined bool, private ...string) (resourceFixture, *transport.NativeOwnershipDeletionProof) {
	t.Helper()
	f := acceptedInterruptionFixture(t, false, private...)
	j := f.journal
	if err := j.Settle(t.Context(), 1, "uncertain", json.RawMessage(`{"error":"native operation failed"}`)); err != nil {
		t.Fatal(err)
	}
	var ownershipRaw string
	if err := j.db.QueryRow(`SELECT ownership FROM worker_dispatch_meta`).Scan(&ownershipRaw); err != nil {
		t.Fatal(err)
	}
	var own transport.NativeWorkerOwnership
	if json.Unmarshal([]byte(ownershipRaw), &own) != nil {
		t.Fatal("bad ownership")
	}
	stop := dispatchProof(own, 2)
	current := &Admission{Scope: j.scope, NativeAdmissionID: stop.SourceAdmissionID, RunnerID: stop.SourceRunnerID, RunnerEpoch: stop.SourceRunnerEpoch, BootID: stop.SourceBootID}
	out, run, err := j.admitDispatch(t.Context(), f.lease, 0, stop.SourceCommandID, "stop", json.RawMessage(`{}`), func() (*Admission, error) { return current, nil }, &stop)
	if err != nil || !run {
		t.Fatal(out, run, err)
	}
	if err = j.Settle(t.Context(), out.Sequence, "completed", nil); err != nil {
		t.Fatal(err)
	}
	if err = j.retireNativeSource(t.Context(), f.producer); err != nil {
		t.Fatal(err)
	}
	if quarantined {
		f.receipt.Disposition = "expired"
		if err = j.RecordNativeSourceDisposition(t.Context(), f.lease, f.observation.ID, f.observation.SourceDigest, f.receipt); err != nil {
			t.Fatal(err)
		}
	} else if err = f.ack(t); err != nil {
		t.Fatal(err)
	}
	wire, err := NativeBackendObservation(f.observation)
	if err != nil {
		t.Fatal(err)
	}
	proof := &transport.NativeOwnershipDeletionProof{DeleteRequestID: domain.NewID().String(), StopProof: stop, OriginID: wire.OriginID, NativeGeneration: f.observation.NativeGeneration, NativeSessionID: f.observation.NativeSessionID, StoppedObservationID: f.observation.ID, StoppedDigest: wire.Digest, StoppedSourceSequence: f.observation.SourceSequence, StoppedDisposition: f.receipt.Disposition, StoppedObservedAt: wire.ObservedAt, StoppedExpiresAt: wire.ExpiresAt}
	return f, proof
}
func TestOwnerStoppedRequiresOriginalDeleteStopAndActualAcceptedEOF(t *testing.T) {
	for _, negative := range []string{"foreign-job-scope", "foreign-stop", "wrong-session", "missing-eof", "unaccepted-native", "uncompleted-stop", "different-digest", "unknown-other-effect"} {
		t.Run(negative, func(t *testing.T) {
			f, p := originalDeleteFixture(t, false)
			j := f.journal
			switch negative {
			case "foreign-job-scope":
				p.StopProof.OwnershipGeneration = "foreign"
			case "foreign-stop":
				p.StopProof.SourceCommandID = domain.NewID().String()
			case "wrong-session":
				p.NativeSessionID = "foreign"
			case "missing-eof":
				j.db.Exec(`DELETE FROM worker_stopped_receipts`)
			case "unaccepted-native":
				j.db.Exec(`UPDATE worker_turn_sources SET started=0`)
			case "uncompleted-stop":
				j.db.Exec(`UPDATE worker_intent SET state='uncertain' WHERE kind='stop'`)
			case "different-digest":
				p.StoppedDigest = f.observation.SourceDigest
			case "unknown-other-effect":
				// A separately admitted original resolution remains non-replayable.
				other := f.proof
				other.DispatchSequence = 3
				other.SourceCommandID = domain.NewID().String()
				admission := &Admission{Scope: j.scope, NativeAdmissionID: other.SourceAdmissionID, RunnerID: other.SourceRunnerID, RunnerEpoch: other.SourceRunnerEpoch, BootID: other.SourceBootID}
				out, run, err := j.admitDispatch(t.Context(), f.lease, 0, other.SourceCommandID, "resolve", json.RawMessage(`{}`), func() (*Admission, error) { return admission, nil }, &other)
				if err != nil || !run {
					t.Fatal(out, run, err)
				}
				if err = j.Settle(t.Context(), out.Sequence, "uncertain", nil); err != nil {
					t.Fatal(err)
				}
			}
			if err := j.collectDeletionQuarantines(t.Context(), f.lease, p, f.key); err == nil {
				t.Fatal("unproven owner stop settled", negative)
			}
			out, err := j.Outcome(t.Context(), 1)
			if err != nil || out.State != "uncertain" {
				t.Fatal("unknown prior effects changed", out, err)
			}
			if sourceCount(t, j, "worker_owner_stop_settlements") != 0 {
				t.Fatal("rollback leaked abandonment")
			}
		})
	}
}
func TestOwnerStoppedDeleteProofLostReplyReopenAndQuarantine(t *testing.T) {
	for _, quarantined := range []bool{false, true} {
		t.Run(map[bool]string{false: "committed", true: "expired-original"}[quarantined], func(t *testing.T) {
			f, p := originalDeleteFixture(t, quarantined)
			j := f.journal
			if _, err := j.db.Exec(`CREATE TRIGGER fail_owner_stop BEFORE DELETE ON worker_terminal_reservations BEGIN SELECT RAISE(ABORT,'rollback owner stop'); END`); err != nil {
				t.Fatal(err)
			}
			if err := j.collectDeletionQuarantines(t.Context(), f.lease, p, f.key); err == nil {
				t.Fatal("failed closure acknowledged")
			}
			out, _ := j.Outcome(t.Context(), 1)
			if out.State != "uncertain" || sourceCount(t, j, "worker_owner_stop_settlements") != 0 {
				t.Fatal("failed closure settled original", out)
			}
			j.db.Exec(`DROP TRIGGER fail_owner_stop`)
			if err := j.collectDeletionQuarantines(t.Context(), f.lease, p, f.key); err != nil {
				t.Fatal(err)
			}
			out, err := j.Outcome(t.Context(), 1)
			if err != nil || out.State != OwnerStopped {
				t.Fatal(out, err)
			}
			if err = j.Close(); err != nil {
				t.Fatal(err)
			}
			j, err = OpenJournal(filepath.Clean(f.dir), testScope())
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			f.journal = j
			f.lease = lease(t, j)
			if err = j.collectDeletionQuarantines(t.Context(), f.lease, p, f.key); err != nil {
				t.Fatal("lost delete reply not replayed", err)
			}
			if _, run, err := j.admitDispatch(t.Context(), f.lease, 0, f.proof.SourceCommandID, "prompt", f.payload, nil, &f.proof); err != nil || run {
				t.Fatal("owner-abandoned turn replayed", run, err)
			}
			if err = j.Acknowledge(t.Context(), f.lease, 1); err != nil {
				t.Fatal(err)
			}
			if err = j.Acknowledge(t.Context(), f.lease, 2); err != nil {
				t.Fatal(err)
			}
			if err = j.RetireDispatches(t.Context(), f.lease, 2); err != nil {
				t.Fatal(err)
			}
			if sourceCount(t, j, "worker_owner_stop_settlements") != 0 || sourceCount(t, j, "worker_stopped_receipts") != 0 {
				t.Fatal("settled deletion retained lifetime evidence")
			}
		})
	}
}

func TestOwnerStoppedPurgesOnlyOriginalUnpublishedPrivatePermission(t *testing.T) {
	for _, kind := range []string{"permission", "permission-no-id", "output", "plan", "fragment", "wrong-turn"} {
		t.Run(kind, func(t *testing.T) {
			f, p := originalDeleteFixture(t, false, kind)
			err := f.journal.collectDeletionQuarantines(t.Context(), f.lease, p, f.key)
			if kind == "permission" || kind == "permission-no-id" {
				if err != nil {
					t.Fatal(err)
				}
				if sourceCount(t, f.journal, "worker_observations") != 0 || sourceCount(t, f.journal, "worker_source_captures") != 0 {
					t.Fatal("original dead permission capture retained")
				}
			} else {
				if err == nil {
					t.Fatal("uncommitted source erased", kind)
				}
				if sourceCount(t, f.journal, "worker_observations") != 1 || sourceCount(t, f.journal, "worker_source_captures") != 1 || sourceCount(t, f.journal, "worker_owner_stop_settlements") != 0 {
					t.Fatal("failed deletion lost original evidence", kind)
				}
			}
		})
	}
}

func TestOwnerStoppedAcceptsOnlyExactSQLTimestampInstants(t *testing.T) {
	for _, change := range []string{"representation", "changed-epoch", "changed-stopped-time"} {
		t.Run(change, func(t *testing.T) {
			f, p := originalDeleteFixture(t, false, "permission-no-id")
			defer f.journal.Close()
			p.StopProof.SourceRunnerEpoch = p.StopProof.SourceRunnerEpoch.In(time.FixedZone("Europe/Lisbon", 3600))
			p.StoppedObservedAt = p.StoppedObservedAt.In(time.FixedZone("Europe/Lisbon", 3600))
			p.StoppedExpiresAt = p.StoppedExpiresAt.In(time.FixedZone("Europe/Lisbon", 3600))
			if change == "changed-epoch" {
				p.StopProof.SourceRunnerEpoch = p.StopProof.SourceRunnerEpoch.Add(time.Nanosecond)
			}
			if change == "changed-stopped-time" {
				p.StoppedObservedAt = p.StoppedObservedAt.Add(time.Nanosecond)
			}
			err := f.journal.collectDeletionQuarantines(t.Context(), f.lease, p, f.key)
			if change == "representation" {
				if err != nil {
					t.Fatal(err)
				}
				if sourceCount(t, f.journal, "worker_owner_stop_settlements") != 1 || sourceCount(t, f.journal, "worker_observations") != 0 {
					t.Fatal("exact original interruption not reclaimed")
				}
			} else if err == nil || sourceCount(t, f.journal, "worker_owner_stop_settlements") != 0 || sourceCount(t, f.journal, "worker_observations") != 1 {
				t.Fatal("changed original timestamp accepted or evidence lost", err)
			}
		})
	}
}
