//go:build !linux && !darwin

package main

import (
	"os"

	"github.com/pagnet-code/pagnet/fabric"
)

func openLocalA2ACard(string) (*os.File, error) {
	return nil, fabric.NewError(fabric.CodeUnsupported, "Local Fabric requires a supported private host socket; use Linux, macOS or WSL")
}
