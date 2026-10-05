//go:build windows

package localinstallation

import (
	"github.com/pagnet-code/pagnet/fabric"
	"golang.org/x/sys/windows"
	"os"
	"strconv"
)

func currentOperator() (fabric.Principal, error) {
	owner, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil || owner.User.Sid == nil {
		return fabric.Principal{}, denied()
	}
	return fabric.Principal{Ref: "local:sid:" + owner.User.Sid.String(), Kind: "actor.human", Issuer: "local:kernel:sid"}, nil
}

func currentOperatorProcess() (int, string, error) {
	if _, err := currentOperator(); err != nil {
		return 0, "", err
	}
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &creation, &exit, &kernel, &user); err != nil {
		return 0, "", denied()
	}
	birth := uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime)
	if birth == 0 {
		return 0, "", denied()
	}
	return os.Getpid(), strconv.FormatUint(birth, 10), nil
}
