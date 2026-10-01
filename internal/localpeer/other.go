//go:build !linux && !darwin

package localpeer

import (
	"errors"
	"net"
)

func Owner(net.Conn) (int, uint32, error) { return 0, 0, errors.New("kernel peer binding unsupported") }
func ReadProcess(int) (ProcessSnapshot, error) {
	return ProcessSnapshot{}, errors.New("kernel process binding unsupported")
}
func Verify(net.Conn, int) error { return errors.New("kernel peer binding unsupported") }
