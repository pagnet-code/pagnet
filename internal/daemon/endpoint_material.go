//go:build linux || darwin

package daemon

import (
	"database/sql"
	"fmt"
	"io"

	"github.com/pagnet-code/pagnet/domain"
)

const endpointMaterialLiveUse = "live"

// endpointMaterialScope is captured by the authenticated daemon coordinator.
// Historical outgoing reconciliation needs separate journal-bound authority and
// is deliberately unavailable through this live-use scope.
type endpointMaterialScope struct {
	installation domain.ID
	credential   domain.ID
	role         string
	use          string
}

// endpointMaterialFence acquires live session/ownership/cancellation authority
// with the existing registry reservation held. It must fail fast and never take
// registry or key locks, call remote services or worker IPC. release stays held
// through transaction completion; check validates cancellation before and after
// use without acquiring further locks. It must use credential use deadlines,
// not the short installation deadline. Both functions are mandatory on success.
type endpointMaterialFence func(*sql.Conn) (release func(), check func() error, err error)

// endpointMaterial exists only during a synchronous daemon callback. Both slices
// are cleared when the callback returns, including panic unwinding. Never retain
// or export either slice. Formatting deliberately reveals no bytes.
type endpointMaterial struct {
	secret  []byte
	private []byte
}

func (endpointMaterial) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, "endpointMaterial{closed}")
}
