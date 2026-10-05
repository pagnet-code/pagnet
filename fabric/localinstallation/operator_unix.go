//go:build linux || darwin

package localinstallation

import (
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"os"
	"strconv"
)

func currentOperator() (fabric.Principal, error) {
	if os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return fabric.Principal{}, denied()
	}
	return fabric.Principal{Ref: "local:uid:" + strconv.Itoa(os.Getuid()), Kind: "actor.human", Issuer: "local:kernel:uid"}, nil
}

func currentOperatorProcess() (int, string, error) {
	if _, err := currentOperator(); err != nil {
		return 0, "", err
	}
	actual, err := localpeer.ReadProcess(os.Getpid())
	if err != nil || actual.PID != os.Getpid() || actual.UID != uint32(os.Getuid()) || actual.Start <= 0 {
		return 0, "", denied()
	}
	return actual.PID, strconv.FormatInt(actual.Start, 10), nil
}
