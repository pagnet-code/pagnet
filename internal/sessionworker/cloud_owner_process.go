package sessionworker

import (
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"strconv"
)

// OwnerProcess is the exact mutually authenticated original controller socket's
// kernel peer. It classifies descendants before any native vendor subprocess
// starts, not a SID/PID adoption or native invocation source receipt.
func (c *Controller) OwnerProcess() (localpeer.ProcessSnapshot, error) {
	if c == nil {
		return localpeer.ProcessSnapshot{}, ErrFenced
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	pid, uid, e := localpeer.Owner(c.conn)
	if e != nil {
		return localpeer.ProcessSnapshot{}, e
	}
	process, e := localpeer.ReadProcess(pid)
	if e != nil || process.UID != uid || localpeer.VerifyOwned(c.conn, pid, strconv.FormatInt(process.Start, 10)) != nil {
		return localpeer.ProcessSnapshot{}, ErrFenced
	}
	return process, nil
}
