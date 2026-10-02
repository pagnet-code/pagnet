//go:build linux || darwin

package sessionworker

import (
	"encoding/json"
	"errors"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
	"testing"
	"time"
)

func TestRetirementCollectsOnlyQuiescedPrivateUnboundCapture(t *testing.T) {
	for _, variant := range []string{"private", "live-reader", "supported", "accepted-turn"} {
		t.Run(variant, func(t *testing.T) {
			j, _ := testJournal(t)
			defer j.Close()
			l := lease(t, j)
			owned := dispatchOwnership(t, j, l)
			origin := transport.NativeObservationOrigin{ID: domain.NewID().String(), HostID: j.scope.HostID, InstanceID: j.scope.InstanceID, NativeGeneration: "original-native", Runtime: owned.Runtime}
			raw, _ := json.Marshal(origin)
			producer, err := j.registerNativeSource(t.Context(), origin.NativeGeneration, raw)
			if err != nil {
				t.Fatal(err)
			}
			event := session.SessionEvent{Type: session.EventTurnStarted, SessionID: "native-session", TurnID: "unmanaged-native-turn"}
			if variant == "supported" {
				event.Type = session.EventBusy
			}
			observation := NativeObservation{ID: domain.NewID().String(), NativeGeneration: origin.NativeGeneration, NativeSessionID: event.SessionID, Origin: raw, ObservedAt: time.Now().UTC(), Event: event}
			if variant == "accepted-turn" {
				proof := dispatchProof(owned, 1)
				out, _, admitErr := j.admitDispatch(t.Context(), l, 0, proof.SourceCommandID, "prompt", json.RawMessage(`{}`), func() (*Admission, error) { return &Admission{Scope: j.scope}, nil }, &proof)
				if admitErr != nil {
					t.Fatal(admitErr)
				}
				source := NativeTurnSource{Sequence: out.Sequence, LogicalTurnID: logicalWorkerTurn(out.Sequence), NativeGeneration: origin.NativeGeneration, NativeSessionID: event.SessionID, SourceCommandID: proof.SourceCommandID, SourceAdmissionID: proof.SourceAdmissionID, InputKind: "task"}
				if err = j.BindNativeTurn(t.Context(), source); err != nil {
					t.Fatal(err)
				}
				observation.Event.TurnID = source.LogicalTurnID
				observation.TurnSource = &source
				observation.SourceContentUnavailable = true
			}
			observation.SourceDigest, _ = observationDigest(observation)
			if err = j.journalCapturedObservation(t.Context(), producer, observation, nil); err != nil {
				t.Fatal(err)
			}
			if variant != "live-reader" {
				if err = j.retireNativeSource(t.Context(), producer); err != nil {
					t.Fatal(err)
				}
			}
			owned.State = "retired"
			err = j.CommitOwnershipRetirement(t.Context(), l, owned)
			if variant == "private" {
				if err != nil {
					t.Fatal("closed private native capture blocks retirement", err)
				}
				if n := sourceCount(t, j, "worker_observations"); n != 0 {
					t.Fatal("private capture leaks", n)
				}
			} else {
				if !errors.Is(err, ErrConflict) {
					t.Fatal("unproven live/supported/accepted evidence erased", err)
				}
				if n := sourceCount(t, j, "worker_observations"); n != 1 {
					t.Fatal("failed retirement deleted evidence", n)
				}
			}
		})
	}
}
