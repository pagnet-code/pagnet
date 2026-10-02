//go:build linux || darwin

package sessionworker

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

func TestExplicitDeletionCollectsOnlyAuthenticQuiescedQuarantine(t *testing.T) {
	for _, variant := range []string{"expired", "stale_origin", "missing-proof", "missing-disposition", "invalid-disposition", "foreign-ownership", "foreign-generation", "unaccepted-stop", "live-reader", "uncertain-effect", "uncommitted-source", "corrupt-receipt"} {
		t.Run(variant, func(t *testing.T) {
			j, _ := testJournal(t)
			defer j.Close()
			l := lease(t, j)
			owned := dispatchOwnership(t, j, l)
			stop := dispatchProof(owned, 1)
			out, _, err := j.admitDispatch(t.Context(), l, 0, stop.SourceCommandID, "stop", json.RawMessage(`{}`), func() (*Admission, error) { return &Admission{Scope: j.scope}, nil }, &stop)
			if err != nil {
				t.Fatal(err)
			}
			state := "completed"
			if variant == "uncertain-effect" {
				state = "uncertain"
			}
			if err = j.Settle(t.Context(), out.Sequence, state, nil); err != nil {
				t.Fatal(err)
			}
			// This is an older activation of the same original worker lifetime.
			origin := transport.NativeObservationOrigin{ID: domain.NewID().String(), HostID: j.scope.HostID, InstanceID: j.scope.InstanceID, Runtime: owned.Runtime, NativeGeneration: "old-activation"}
			raw, _ := json.Marshal(origin)
			producer, err := j.registerNativeSource(t.Context(), origin.NativeGeneration, raw)
			if err != nil {
				t.Fatal(err)
			}
			observation := NativeObservation{ID: domain.NewID().String(), Origin: raw, NativeGeneration: origin.NativeGeneration, NativeSessionID: "original-session", ObservedAt: time.Now().UTC(), Event: session.SessionEvent{Type: session.EventBusy}}
			observation.SourceDigest, _ = observationDigest(observation)
			if err = j.journalCapturedObservation(t.Context(), producer, observation, nil); err != nil {
				t.Fatal(err)
			}
			pending, err := j.PendingObservationsForLease(t.Context(), l, 32)
			if err != nil || len(pending) != 1 {
				t.Fatal(err, len(pending))
			}
			wire, err := NativeBackendObservation(pending[0])
			if err != nil {
				t.Fatal(err)
			}
			disposition := "expired"
			if variant == "stale_origin" {
				disposition = variant
			}
			receipt := transport.NativeObservationReceiptPayload{ObservationID: wire.ObservationID, OriginID: wire.OriginID, Digest: wire.Digest, Disposition: disposition}
			if variant != "uncommitted-source" {
				if err = j.RecordNativeSourceDisposition(t.Context(), l, observation.ID, observation.SourceDigest, receipt); err != nil {
					t.Fatal(err)
				}
			}
			if variant != "live-reader" {
				if err = j.retireNativeSource(t.Context(), producer); err != nil {
					t.Fatal(err)
				}
			}
			now := time.Now().UTC()
			proof := &transport.NativeOwnershipDeletionProof{DeleteRequestID: domain.NewID().String(), StopProof: stop, OriginID: "latest-original-stop-origin", NativeGeneration: "latest-activation", NativeSessionID: "latest-session", StoppedObservationID: domain.NewID().String(), StoppedDigest: strings.Repeat("a", 64), StoppedSourceSequence: 3, StoppedDisposition: "committed", StoppedObservedAt: now, StoppedExpiresAt: now.Add(time.Hour)}
			switch variant {
			case "missing-proof":
				proof = nil
			case "missing-disposition":
				proof.StoppedDisposition = ""
			case "invalid-disposition":
				proof.StoppedDisposition = "unsupported"
			case "foreign-ownership":
				proof.StopProof.OwnershipID = domain.NewID().String()
			case "foreign-generation":
				proof.StopProof.OwnershipGeneration = "foreign"
			case "unaccepted-stop":
				proof.StopProof.DispatchSequence = 2
			case "corrupt-receipt":
				receipt.Digest = strings.Repeat("b", 64)
				bad, _ := json.Marshal(receipt)
				if _, err = j.db.Exec(`UPDATE worker_source_dispositions SET receipt=?,size=?`, bad, len(bad)); err != nil {
					t.Fatal(err)
				}
			}
			err = j.CollectDeletionQuarantines(t.Context(), l, proof)
			retained := sourceCount(t, j, "worker_observations")
			if variant == "expired" || variant == "stale_origin" {
				if err != nil || retained != 0 || sourceCount(t, j, "worker_source_dispositions") != 0 {
					t.Fatal("exact terminal quarantine blocks deletion", err, retained)
				}
			} else if variant == "uncommitted-source" {
				if err != nil || retained != 1 {
					t.Fatal("uncommitted evidence erased", err, retained)
				}
			} else if !errors.Is(err, ErrConflict) || retained != 1 {
				t.Fatal("unproven evidence reclaimed", err, retained)
			}
		})
	}
}
