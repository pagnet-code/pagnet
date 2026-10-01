package daemon

// observedInstanceStatus supplements the persisted lifecycle row with positive
// native activity (e.g. a human turn in the endpoint's own terminal). Merely
// having a live endpoint never means working, and task state is not inferred.
func (d *Daemon) observedInstanceStatus(row InstanceRow) string {
	if row.Status == "idle" && d.sessions != nil && d.sessions.ActiveWork(row.InstanceID) {
		return "working"
	}
	return row.Status
}
