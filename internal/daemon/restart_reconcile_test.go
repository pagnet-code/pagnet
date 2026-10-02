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

func TestRestartReconciliationPreservesIndependentWorkerNamespaces(t *testing.T) {
	d := newTestDaemon(t)
	for _, row := range []InstanceRow{{InstanceID: "independent-working", DefinitionID: "definition", Runtime: "qwen-code", Status: "working", SessionID: "original-session"}, {InstanceID: "legacy-working", DefinitionID: "definition", Runtime: "qwen-code", Status: "working", SessionID: "legacy-session"}} {
		if err := d.state.UpsertInstance(row); err != nil {
			t.Fatal(err)
		}
	}
	count, err := d.state.ReconcileRestartExcept([]string{"independent-working"})
	if err != nil || count != 1 {
		t.Fatal(count, err)
	}
	owned, ok, err := d.state.GetInstance("independent-working")
	if err != nil || !ok || owned.Status != "working" || owned.SessionID != "original-session" {
		t.Fatal("controller restart rewrote surviving owner", owned, err)
	}
	old, ok, err := d.state.GetInstance("legacy-working")
	if err != nil || !ok || old.Status != "hibernated" || old.SessionID != "legacy-session" {
		t.Fatal("legacy reconciliation changed", old, err)
	}
}
