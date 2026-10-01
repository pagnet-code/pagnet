package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// The parent verifies and saves the principal-bound profile before launching.
// The provider key is inherited only in the child's process environment, never
// in arguments, the profile, the PID file, or logs.
func serviceDetachedCommand(executable string, saved serviceRunnerProfile, stateDir string, providerEnv []string) *exec.Cmd {
	child := exec.Command(executable, "service", saved.Adapter, "--service", saved.Service, "--state-dir", stateDir)
	child.SysProcAttr = detachedProcessAttrs()
	for _, entry := range os.Environ() {
		overridden := false
		for _, override := range providerEnv {
			name, _, _ := strings.Cut(override, "=")
			if strings.HasPrefix(entry, name+"=") {
				overridden = true
				break
			}
		}
		if !overridden {
			child.Env = append(child.Env, entry)
		}
	}
	child.Env = append(child.Env, providerEnv...)
	return child
}

func launchServiceDetached(out io.Writer, saved serviceRunnerProfile, stateDir string, providerEnv []string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	dir := filepath.Join(stateDir, "services", saved.Adapter)
	logPath := filepath.Join(dir, saved.Service+".log")
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	stat, err := log.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		return fmt.Errorf("service log must be a private regular file")
	}
	if err := validateServiceProfileOwner(stat); err != nil {
		return err
	}
	child := serviceDetachedCommand(executable, saved, stateDir, providerEnv)
	child.Stdout, child.Stderr = log, log
	if err := child.Start(); err != nil {
		return err
	}
	pid := child.Process.Pid
	pidPath := filepath.Join(dir, saved.Service+".pid")
	// Advisory PID only: it must never authorize killing a reused process.
	if err := writeServicePID(pidPath, pid); err != nil {
		_ = child.Process.Kill()
		_ = child.Wait()
		return err
	}
	_ = child.Process.Release()
	fmt.Fprintf(out, "Service background process started (PID %d). Connection and encryption readiness are reported in %s and the Services page. Startup is not a readiness confirmation.\n", pid, logPath)
	return nil
}

func writeServicePID(path string, pid int) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".service-pid-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.WriteString(strconv.Itoa(pid) + "\n")
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}
