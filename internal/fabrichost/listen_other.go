//go:build !linux && !darwin

package fabrichost

import (
	"github.com/pagnet-code/pagnet/fabric"
	"net"
)

func listenPrivate(string) (*net.UnixListener, func(), error) {
	return nil, nil, fabric.NewError(fabric.CodeUnsupported, "Local Fabric requires supported kernel Unix peer authentication")
}
func sameOwner(uint32) bool { return false }
func checkSocket(string) error {
	return fabric.NewError(fabric.CodeUnsupported, "Local Fabric requires supported kernel Unix peer authentication")
}
