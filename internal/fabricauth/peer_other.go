//go:build !linux && !darwin

package fabricauth

import (
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"net"
)

func peer(*net.UnixConn, string) (localpeer.ProcessSnapshot, error) {
	return localpeer.ProcessSnapshot{}, denied()
}
