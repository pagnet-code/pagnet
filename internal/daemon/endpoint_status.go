package daemon

import (
	"github.com/gorilla/websocket"

	"github.com/pagnet-code/pagnet/transport"
)

// endpointOnline maps a local instance status to the endpoint liveness the
// control plane derives from host.endpoint_status.
//
// online  = the instance is live and can accept network work (a delivery or
//
//	invocation routed to its endpoint will be acted on): a turn is in
//	flight ("working"), it is idle and reachable ("idle"), or it is coming
//	up ("starting").
//
// offline = the instance will not accept work until explicitly re-activated:
//
//	hibernated (endpoint stopped, session preserved — a wake is required),
//	stopped, blocked (needs explicit restart), failed, rate_limited.
func endpointOnline(status string) bool {
	switch status {
	case "working", "idle", "starting":
		return true
	default:
		return false
	}
}

// reportEndpointStatus reports the instance's endpoint liveness
// (host.endpoint_status, live / at-most-once) carrying the agent principal,
// the instance id, the derived online state, and the instance's
// self-declared capability set. The control plane derives the managed_agent
// PrincipalEndpoint row from these reports + the instance state.
//
// It reads the CURRENT row (status + principal + capabilities) so the report
// always reflects the latest state, and routes through d.send so it goes out
// on the live host connection even when the caller's captured conn is stale.
// A missing/unknown instance is a no-op (nothing to report).
func (d *Daemon) reportEndpointStatus(conn *websocket.Conn, instanceID string) {
	row, ok, err := d.state.GetInstance(instanceID)
	if err != nil || !ok {
		return
	}
	_ = d.send(conn, transport.MsgEndpointStatus, transport.EndpointStatusPayload{
		AgentPrincipalID: row.AgentPrincipalID,
		InstanceID:       row.InstanceID,
		Online:           endpointOnline(row.Status),
		Capabilities:     row.Capabilities,
	})
}

// reportAllEndpointStatuses re-syncs endpoint liveness for every tracked
// instance. Called after (re)connect so the control plane's derived
// PrincipalEndpoint rows converge with the daemon's actual state (a daemon
// restart loses the at-most-once reports it sent on the prior connection).
func (d *Daemon) reportAllEndpointStatuses(conn *websocket.Conn) {
	rows, err := d.state.ListInstances()
	if err != nil {
		return
	}
	for _, r := range rows {
		d.reportEndpointStatus(conn, r.InstanceID)
	}
}
