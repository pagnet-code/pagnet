package transport

const MsgBrowserConnectionsRevision = "host.browser_connections_revision"

// BrowserConnectionsRevisionPayload invalidates the host's complete assignment
// snapshot. Desired configuration and credentials are fetched separately.
type BrowserConnectionsRevisionPayload struct {
	HostID                     string `json:"hostId"`
	BrowserAssignmentsRevision int64  `json:"browserAssignmentsRevision"`
}
