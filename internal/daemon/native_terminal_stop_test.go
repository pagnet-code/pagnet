package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func TestNativeTerminalStopFollowsExactOriginalOperationDespiteInterleavedInput(t *testing.T) {
	proof := transport.NativeDispatchProof{OwnershipID: domain.NewID().String(), OwnershipGeneration: "original-worker", DispatchSequence: 9, SourceCommandID: domain.NewID().String(), SourceAdmissionID: domain.NewID().String(), SourceRunnerID: domain.NewID().String(), SourceRunnerEpoch: time.Now().UTC(), SourceBootID: domain.NewID().String()}
	original := sessionworker.Outcome{Sequence: 42, Kind: "stop", CommandID: proof.SourceCommandID, State: "completed", SourceAdmission: &sessionworker.Admission{NativeAdmissionID: proof.SourceAdmissionID, RunnerID: proof.SourceRunnerID, RunnerEpoch: proof.SourceRunnerEpoch, BootID: proof.SourceBootID}}
	for _, mode := range []string{"complete", "admitted", "failed", "uncertain", "mapping_missing", "foreign_mapping", "foreign_command", "foreign_admission", "foreign_runner", "foreign_boot", "foreign_epoch", "wrong_kind", "missing_outcome", "pruned_completed", "pruned_admitted", "pruned_uncertain", "pruned_failed", "pruned_activate", "pruned_unknown", "disconnected"} {
		t.Run(mode, func(t *testing.T) {
			outcome := original
			admission := *original.SourceAdmission
			outcome.SourceAdmission = &admission
			record := sessionworker.NativeDispatchRecord{Proof: proof, OperationSequence: 42, Kind: "stop", State: "admitted"}
			if mode == "pruned_completed" {
				record.State = "completed"
			}
			if mode == "pruned_uncertain" {
				record.State = "uncertain"
			}
			if mode == "pruned_failed" {
				record.State = "failed"
			}
			if mode == "pruned_activate" {
				record.State = "completed"
				record.Kind = "activate"
			}
			if mode == "pruned_unknown" {
				record.State = "completed"
				record.Kind = ""
			}
			switch mode {
			case "admitted", "failed", "uncertain":
				outcome.State = mode
			case "foreign_mapping":
				record.Proof.SourceCommandID = domain.NewID().String()
			case "foreign_command":
				outcome.CommandID = domain.NewID().String()
			case "foreign_admission":
				admission.NativeAdmissionID = domain.NewID().String()
			case "foreign_runner":
				admission.RunnerID = domain.NewID().String()
			case "foreign_boot":
				admission.BootID = domain.NewID().String()
			case "foreign_epoch":
				admission.RunnerEpoch = admission.RunnerEpoch.Add(time.Nanosecond)
			case "wrong_kind":
				outcome.Kind = "hibernate"
			}
			calls := 0
			err := awaitNativeTerminalStop(context.Background(), proof, func(ctx context.Context, request sessionworker.Request) (sessionworker.Response, error) {
				calls++
				if mode == "disconnected" {
					return sessionworker.Response{}, context.Canceled
				}
				if request.Type == "dispatches" {
					if mode == "mapping_missing" {
						return sessionworker.Response{}, nil
					}
					// Server ordinal 9 belongs to a different earlier local resize operation;
					// observing its completion must not close the explicit stop's view.
					return sessionworker.Response{Dispatches: []sessionworker.NativeDispatchRecord{record}}, nil
				}
				if request.Type != "outcome" || request.Sequence != 42 {
					t.Fatalf("read unrelated local input/resize outcome: type=%s sequence=%d", request.Type, request.Sequence)
				}
				if mode == "missing_outcome" || mode == "pruned_completed" || mode == "pruned_admitted" || mode == "pruned_uncertain" || mode == "pruned_failed" {
					return sessionworker.Response{}, nil
				}
				return sessionworker.Response{Outcome: &outcome}, nil
			})
			if mode == "complete" || mode == "pruned_completed" {
				if err != nil || (mode == "complete" && calls != 2) || (mode == "pruned_completed" && calls != 1) {
					t.Fatal("exact completed original stop refused", err)
				}
			} else if err == nil {
				t.Fatal("unproven stop closed terminal view")
			}
			if mode == "admitted" || mode == "mapping_missing" || mode == "foreign_mapping" || mode == "missing_outcome" || mode == "pruned_admitted" || mode == "pruned_uncertain" || mode == "pruned_failed" || mode == "disconnected" {
				if !errors.Is(err, ErrDeferred) {
					t.Fatal("incomplete authority was not deferred", err)
				}
			}
		})
	}
}
