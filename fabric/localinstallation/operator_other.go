//go:build !linux && !darwin && !windows

package localinstallation

import "github.com/pagnet-code/pagnet/fabric"

func currentOperator() (fabric.Principal, error) {
	return fabric.Principal{}, fabric.NewError(fabric.CodeUnsupported, "Private local operator installation is unsupported on this platform")
}

func currentOperatorProcess() (int, string, error) { return 0, "", denied() }
