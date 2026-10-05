//go:build !linux && !darwin

package fabricauth

import (
	"context"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"net"
)

func peer(context.Context, *net.UnixConn, string) (localpeer.ProcessSnapshot, error) {
	return localpeer.ProcessSnapshot{}, denied()
}
