package transport

import (
	"reflect"
	"testing"
	"time"
)

func TestNativeProofIdentityPreservesExactInstantsAndEverySourceField(t *testing.T) {
	epoch := time.Date(2026, 10, 2, 12, 0, 0, 123456789, time.UTC)
	original := NativeDispatchProof{OwnershipID: "own", OwnershipGeneration: "lifetime", DispatchSequence: 5, SourceCommandID: "command", SourceAdmissionID: "admission", SourceRunnerID: "runner", SourceBootID: "boot", SourceRunnerEpoch: epoch, TaskSource: &NativeTaskSource{TaskID: "task"}}
	alternate := original
	alternate.SourceRunnerEpoch = epoch.In(time.FixedZone("Europe/Lisbon", 3600))
	if reflect.DeepEqual(original, alternate) || !SameNativeDispatchProof(original, alternate) {
		t.Fatal("SQL timestamp representation changed exact proof identity")
	}
	if alternate.SourceRunnerEpoch.Location() == time.UTC {
		t.Fatal("comparison rewrote source")
	}
	typ := reflect.TypeOf(original)
	for i := 0; i < typ.NumField(); i++ {
		mutated := original
		field := reflect.ValueOf(&mutated).Elem().Field(i)
		switch field.Kind() {
		case reflect.String:
			field.SetString(field.String() + "-foreign")
		case reflect.Int64:
			field.SetInt(field.Int() + 1)
		case reflect.Pointer:
			field.SetZero()
		case reflect.Struct:
			mutated.SourceRunnerEpoch = epoch.Add(time.Nanosecond)
		default:
			t.Fatal("uncovered immutable proof field", typ.Field(i).Name)
		}
		if SameNativeDispatchProof(original, mutated) {
			t.Fatal("foreign proof field accepted", typ.Field(i).Name)
		}
	}
	deletion := NativeOwnershipDeletionProof{DeleteRequestID: "job", StopProof: original, StoppedObservedAt: epoch, StoppedExpiresAt: epoch.Add(time.Hour)}
	other := deletion
	other.StopProof = alternate
	other.StoppedObservedAt = epoch.In(time.FixedZone("Europe/Lisbon", 3600))
	other.StoppedExpiresAt = other.StoppedExpiresAt.In(time.FixedZone("Europe/Lisbon", 3600))
	if !SameNativeOwnershipDeletionProof(deletion, other) {
		t.Fatal("original deletion instants differ only in representation")
	}
	other.StoppedObservedAt = other.StoppedObservedAt.Add(time.Nanosecond)
	if SameNativeOwnershipDeletionProof(deletion, other) {
		t.Fatal("changed stopped instant accepted")
	}
	other = deletion
	other.StoppedExpiresAt = other.StoppedExpiresAt.Add(time.Nanosecond)
	if SameNativeOwnershipDeletionProof(deletion, other) {
		t.Fatal("changed expiry accepted")
	}
}
