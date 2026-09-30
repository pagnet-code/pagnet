package daemon

import "testing"

func TestRestartReconcilesAllDeadLiveStatuses(t *testing.T) {
	d := newTestDaemon(t)
	for _, status := range []string{"idle", "working", "waking", "hibernated", "blocked", "failed", "stopped", "interrupted", "rate_limited", "auth_required"} {
		if err := d.state.UpsertInstance(InstanceRow{InstanceID: status, DefinitionID: "def", Runtime: "fake", Status: status, SessionID: "native-session"}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := d.state.ReconcileRestart()
	if err != nil || n != 3 {
		t.Fatalf("reconciled %d: %v", n, err)
	}
	for _, status := range []string{"idle", "working", "waking", "hibernated", "blocked", "failed", "stopped", "interrupted", "rate_limited", "auth_required"} {
		row, ok, err := d.state.GetInstance(status)
		want := status
		if status == "idle" || status == "working" || status == "waking" {
			want = "hibernated"
		}
		if err != nil || !ok || row.Status != want || row.SessionID != "native-session" {
			t.Fatalf("%s => %+v, %v", status, row, err)
		}
	}
	n, err = d.state.ReconcileRestart()
	if err != nil || n != 0 {
		t.Fatalf("reconciliation is not idempotent: %d %v", n, err)
	}
}
