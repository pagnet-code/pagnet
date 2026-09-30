//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestApplyKeepsRestrictionsThroughSchedulingAndExec(t *testing.T) {
	if mode := os.Getenv("PAGNET_TEST_SANDBOX_THREAD"); mode != "" {
		root := os.Getenv("PAGNET_TEST_SANDBOX_ROOT")
		runtime.GOMAXPROCS(8)
		stop := make(chan struct{})
		for i := 0; i < 24; i++ {
			go func() {
				for {
					select {
					case <-stop:
						return
					default:
						runtime.Gosched()
					}
				}
			}()
		}
		fail := func(err error) {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(20)
		}
		// Force scheduler opportunities between privilege setup and Landlock,
		// then between Landlock and exec. A test-only hook cannot weaken policy.
		apply := applyLandlockFunc
		applyLandlockFunc = func(spec *Spec) error {
			tid := unix.Gettid()
			for i := 0; i < 100; i++ {
				runtime.Gosched()
				if unix.Gettid() != tid {
					return errors.New("sandbox setup migrated to an unrestricted OS thread")
				}
			}
			return apply(spec)
		}
		result := make(chan error, 1)
		go func() {
			if err := Apply(&Spec{RW: []string{filepath.Join(root, "rw")}, RO: []string{"/bin", "/usr", "/lib", "/lib64"}, Dev: []string{"/dev"}}); err != nil {
				fail(err)
			}
			tid := unix.Gettid()
			for i := 0; i < 100; i++ {
				runtime.Gosched()
				if unix.Gettid() != tid {
					fail(errors.New("sandbox execution migrated to an unrestricted OS thread"))
				}
				if _, err := os.ReadFile(filepath.Join(root, "secret")); !errors.Is(err, syscall.EACCES) {
					fail(fmt.Errorf("restricted thread read outside allowlist: %v", err))
				}
			}
			if mode == "retire" {
				result <- nil
				return // The restricted OS thread must retire, never rejoin Go's pool.
			}
			fail(syscall.Exec("/bin/sh", []string{"sh", "-c", `if cat "$1" >/dev/null 2>&1; then exit 21; fi; printf ok > "$2"`, "sh", filepath.Join(root, "secret"), filepath.Join(root, "rw", "marker")}, os.Environ()))
		}()
		if mode == "retire" {
			<-result
			for i := 0; i < 100; i++ {
				runtime.Gosched()
				if _, err := os.ReadFile(filepath.Join(root, "secret")); err != nil {
					fail(fmt.Errorf("unrelated goroutine inherited retired thread restrictions: %w", err))
				}
			}
			close(stop)
			return
		}
		select {} // successful exec replaces the entire helper process
	}
	skipNoLandlock(t)
	for _, mode := range []string{"exec", "retire"} {
		t.Run(mode, func(t *testing.T) {
			for i := 0; i < 3; i++ {
				root := t.TempDir()
				if err := os.Mkdir(filepath.Join(root, "rw"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "secret"), []byte("secret"), 0o600); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(os.Args[0], "-test.run=^TestApplyKeepsRestrictionsThroughSchedulingAndExec$")
				cmd.Env = append(os.Environ(), "PAGNET_TEST_SANDBOX_THREAD="+mode, "PAGNET_TEST_SANDBOX_ROOT="+root)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("isolated thread/restriction helper: %v: %s", err, strings.TrimSpace(string(out)))
				}
				if mode == "exec" {
					if data, err := os.ReadFile(filepath.Join(root, "rw", "marker")); err != nil || string(data) != "ok" {
						t.Fatalf("exec did not retain allowed write: %q %v", data, err)
					}
				}
			}
		})
	}
}
