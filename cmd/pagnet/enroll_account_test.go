package main

import (
	"testing"

	"github.com/pagnet-code/pagnet/internal/accounts"
)

func TestOneTimeEnrollmentSelectsFirstAccountWithoutLogin(t *testing.T) {
	idp := newStubIdP(t, []string{"success"})
	ts := newStubPagnetServer(t, idp, "oidc", testDeviceCredential)
	previousServer, previousAccount := serverURL, accountFlag
	serverURL, accountFlag = ts.URL, ""
	t.Cleanup(func() { serverURL, accountFlag = previousServer, previousAccount })
	t.Setenv("PAGNET_SERVER", "")
	root := t.TempDir()
	cmd := enrollCmd()
	cmd.SetArgs([]string{"--token", ts.mintedEnrollToken, "--state-dir", root, "--name", "test-host"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	cfg, account, err := loadAccountConfig(root)
	if err != nil || account != accounts.DefaultAccount || cfg.Credential != "hostcred123" || cfg.HostID != "h1" {
		t.Fatalf("enroll did not produce usable daemon config: account=%s host=%s error=%v", account, cfg.HostID, err)
	}
	if ts.enrollCallCount() != 0 {
		t.Fatal("one-time enrollment unexpectedly requested an account-authorized token")
	}
	global, err := accounts.LoadGlobal(root)
	if err != nil || global.CurrentAccount != accounts.DefaultAccount {
		t.Fatal("missing first-account selection", err)
	}
	// An explicit enrollment for another account must preserve the operator's
	// existing selected identity, rather than silently switching it.
	accountFlag = "secondary"
	cmd = enrollCmd()
	cmd.SetArgs([]string{"--token", ts.mintedEnrollToken, "--state-dir", root, "--name", "secondary-host"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	global, err = accounts.LoadGlobal(root)
	if err != nil || global.CurrentAccount != accounts.DefaultAccount {
		t.Fatal("enrollment switched an existing selected account", err)
	}
}
