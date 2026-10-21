//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

func TestDeletionCollectsOnlyAcknowledgedPrivateAskOutput(t *testing.T) {
	for _, variant := range []string{"private", "older-generation", "missing-key", "wrong-key", "live-reader", "unacknowledged", "failed-prompt", "task", "invocation", "unavailable", "content-unavailable", "published", "source-sequence", "fragment", "disposition", "corrupt-capture", "corrupt-digest", "wrong-stream", "wrong-turn", "wrong-admission", "wrong-stop", "nonfinal-stop"} {
		t.Run(variant, func(t *testing.T) {
			j, _ := testJournal(t)
			defer j.Close()
			l := lease(t, j)
			owned := dispatchOwnership(t, j, l)
			prompt := dispatchProof(owned, 1)
			out, _, err := j.admitDispatch(t.Context(), l, 0, prompt.SourceCommandID, "prompt", json.RawMessage(`{}`), func() (*Admission, error) { return &Admission{Scope: j.scope}, nil }, &prompt)
			if err != nil {
				t.Fatal(err)
			}
			generation := "original"
			origin := transport.NativeObservationOrigin{ID: domain.NewID().String(), TenantID: j.scope.TenantID, HostID: j.scope.HostID, InstanceID: j.scope.InstanceID, Runtime: owned.Runtime, NativeGeneration: generation}
			raw, _ := json.Marshal(origin)
			producer, err := j.registerNativeSource(t.Context(), generation, raw)
			if err != nil {
				t.Fatal(err)
			}
			source := NativeTurnSource{Sequence: out.Sequence, LogicalTurnID: logicalWorkerTurn(out.Sequence), NativeGeneration: generation, NativeSessionID: "native-session", SourceCommandID: prompt.SourceCommandID, SourceAdmissionID: prompt.SourceAdmissionID, InputKind: "ask"}
			if variant == "task" {
				source.InputKind = "task"
			}
			if variant == "invocation" {
				source.InputKind = "invocation"
				source.SourceInvocation = &transport.NativeInvocationSource{InvocationID: "original-invocation", InputAAD: e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: j.scope.TenantID, NetworkID: domain.NewID().String(), ObjectType: e2ee.ObjectTypeInvocationInput, ObjectID: "original-invocation", KeyEpochID: "original-key"}}
			}
			if err = j.BindNativeTurn(t.Context(), source); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			stream := &NativeOutputStreamProof{Format: NativeOutputStreamCaptureFormat, StreamID: domain.NewID().String(), BatchID: domain.NewID().String(), DeltaCount: 1, RollingDigest: strings.Repeat("a", 64), ByteLength: 7, FirstObservedAt: now, LastObservedAt: now}
			o := NativeObservation{ID: stream.BatchID, NativeGeneration: generation, NativeSessionID: source.NativeSessionID, Origin: raw, ObservedAt: now, TurnSource: &source, OutputStream: stream, Event: session.SessionEvent{Type: session.EventTurnOutput, NativeOutput: true, TurnID: source.LogicalTurnID, SessionID: source.NativeSessionID}}
			if variant == "unavailable" {
				o.SourceUnavailable = true
			}
			if variant == "content-unavailable" {
				o.SourceContentUnavailable = true
			}
			if variant == "published" {
				o.OutputContent = &transport.NativeContentReference{}
			}
			if variant == "wrong-stream" {
				stream.ByteLength++
			}
			private := NativeSourceCapture{Format: NativeSourceCaptureFormat, OutputStream: stream, Event: o.Event, OriginalTurnOutputContent: o.OutputContent}
			private.Event.Output = "private"
			key := bytes.Repeat([]byte{71}, 32)
			var encrypted []byte
			o.Capture, encrypted, err = sealNativeCapture(key, j.scope, j.dir, o, private)
			if err != nil {
				t.Fatal(err)
			}
			o.SourceDigest, _ = observationDigest(o)
			if err = j.journalCapturedObservation(t.Context(), producer, o, encrypted); err != nil {
				t.Fatal(err)
			}
			if variant != "live-reader" {
				if err = j.retireNativeSource(t.Context(), producer); err != nil {
					t.Fatal(err)
				}
			}
			state := "completed"
			if variant == "failed-prompt" {
				state = "failed"
			}
			if err = j.Settle(t.Context(), out.Sequence, state, nil); err != nil {
				t.Fatal(err)
			}
			if variant != "unacknowledged" {
				if err = j.Acknowledge(t.Context(), l, out.Sequence); err != nil {
					t.Fatal(err)
				}
			}
			stop := dispatchProof(owned, 2)
			stopped, _, err := j.admitDispatch(t.Context(), l, 0, stop.SourceCommandID, "stop", json.RawMessage(`{}`), func() (*Admission, error) { return &Admission{Scope: j.scope}, nil }, &stop)
			if err != nil {
				t.Fatal(err)
			}
			if err = j.Settle(t.Context(), stopped.Sequence, "completed", nil); err != nil {
				t.Fatal(err)
			}
			proof := &transport.NativeOwnershipDeletionProof{DeleteRequestID: domain.NewID().String(), StopProof: stop, OriginID: origin.ID, NativeGeneration: generation, NativeSessionID: source.NativeSessionID, StoppedObservationID: domain.NewID().String(), StoppedDigest: strings.Repeat("b", 64), StoppedSourceSequence: 1, StoppedDisposition: "committed", StoppedObservedAt: now, StoppedExpiresAt: now.Add(time.Hour)}
			switch variant {
			case "older-generation":
				_, err = j.db.Exec(`DELETE FROM worker_terminal_reservations WHERE sequence=?`, source.Sequence)
				proof.NativeGeneration = "latest"
				proof.OriginID = "latest-origin"
				proof.NativeSessionID = "latest-session"
			case "missing-key":
				key = nil
			case "wrong-key":
				key = bytes.Repeat([]byte{72}, 32)
			case "corrupt-capture":
				_, err = j.db.Exec(`UPDATE worker_source_captures SET ciphertext=zeroblob(size)`)
			case "corrupt-digest":
				_, err = j.db.Exec(`UPDATE worker_observations SET digest=?`, strings.Repeat("f", 64))
			case "wrong-turn":
				_, err = j.db.Exec(`UPDATE worker_turn_sources SET native_session='other'`)
			case "wrong-admission":
				_, err = j.db.Exec(`UPDATE worker_turn_sources SET source_admission='other'`)
			case "wrong-stop":
				proof.StopProof.SourceCommandID = "other"
			case "source-sequence":
				_, err = j.db.Exec(`INSERT INTO worker_observation_sequence(observation_id,origin_id,source_sequence) VALUES(?,'origin',1)`, o.ID)
			case "fragment":
				_, err = j.db.Exec(`INSERT INTO worker_content_fragments(observation_id,content_id,ordinal,payload,size) VALUES(?,'content',0,'{}',2)`, o.ID)
			case "disposition":
				_, err = j.db.Exec(`INSERT INTO worker_source_dispositions(observation_id,source_digest,receipt,size) VALUES(?,'digest','{}',2)`, o.ID)
			case "nonfinal-stop":
				extra := dispatchProof(owned, 3)
				next, _, e := j.admitDispatch(t.Context(), l, 0, extra.SourceCommandID, "stop", json.RawMessage(`{}`), func() (*Admission, error) { return &Admission{Scope: j.scope}, nil }, &extra)
				if e != nil {
					t.Fatal(e)
				}
				err = j.Settle(t.Context(), next.Sequence, "completed", nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			err = j.collectDeletionQuarantines(t.Context(), l, proof, key)
			eligible := variant == "private" || variant == "older-generation"
			if eligible {
				if err != nil {
					t.Fatal(err)
				}
				if sourceCount(t, j, "worker_observations") != 0 || sourceCount(t, j, "worker_source_captures") != 0 || sourceCount(t, j, "worker_turn_sources") != 0 {
					t.Fatal("private output or turn retained")
				}
				if err = j.Acknowledge(t.Context(), l, stopped.Sequence); err != nil {
					t.Fatal(err)
				}
				if err = j.CheckDispatchRetirement(t.Context(), l, 2); err != nil {
					t.Fatal("private output blocks retirement", err)
				}
				if err = j.collectDeletionQuarantines(t.Context(), l, proof, key); err != nil {
					t.Fatal("cleanup retry", err)
				}
			} else if sourceCount(t, j, "worker_observations") != 1 || sourceCount(t, j, "worker_source_captures") != 1 || sourceCount(t, j, "worker_turn_sources") != 1 {
				t.Fatal("unproven output erased", err)
			}
		})
	}
}
