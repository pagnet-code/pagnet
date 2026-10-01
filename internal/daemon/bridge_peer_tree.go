package daemon

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/pagnet-code/pagnet/internal/localpeer"
)

func (d *Daemon) verifyOwnedBridgePeer(c net.Conn, rootPID int) error {
	if d.sup == nil {
		return errors.New("instance supervisor unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	identity, err := d.sup.OwnedStartIdentity(ctx, rootPID)
	if err != nil {
		return err
	}
	return localpeer.VerifyOwned(c, rootPID, identity)
}
