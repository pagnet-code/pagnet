//go:build !linux && !darwin

package fabrichost

import "github.com/pagnet-code/pagnet/fabric"

func ValidateSocketPath(string) error {
	return fabric.NewError(fabric.CodeUnsupported, "Local Fabric requires supported kernel Unix peer authentication")
}
