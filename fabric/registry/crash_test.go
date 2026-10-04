package registry

import (
	"context"
	"github.com/pagnet-code/pagnet/fabric"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestBootstrapCrashBoundaryActualProcess(t *testing.T) {
	if stage := os.Getenv("PAGNET_REGISTRY_CRASH_STAGE"); stage != "" {
		dir := os.Getenv("PAGNET_REGISTRY_CRASH_DIR")
		_, e := bootstrap(context.Background(), dir, testOwner, func(at string) {
			if at == stage {
				os.Exit(37)
			}
		})
		if e != nil {
			os.Exit(38)
		}
		os.Exit(39)
	}
	for _, stage := range []string{"key-installed", "ledger-committed"} {
		t.Run(stage, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "domain")
			command := exec.Command(os.Args[0], "-test.run=^TestBootstrapCrashBoundaryActualProcess$")
			command.Env = append(os.Environ(), "PAGNET_REGISTRY_CRASH_STAGE="+stage, "PAGNET_REGISTRY_CRASH_DIR="+dir)
			e := command.Run()
			exit, ok := e.(*exec.ExitError)
			if !ok || exit.ExitCode() != 37 {
				t.Fatalf("child checkpoint not reached: %v", e)
			}
			s, e := Open(context.Background(), dir)
			if stage == "key-installed" {
				if e == nil {
					s.Close()
					t.Fatal("partial bootstrap published")
				}
				if _, e = Bootstrap(context.Background(), dir, testOwner); e == nil {
					t.Fatal("crashed bootstrap replaced identity")
				}
			} else {
				if e != nil {
					t.Fatal("durable bootstrap not recoverable", e)
				}
				s.Close()
			}
		})
	}
}
func TestWriteCommitCrashActualProcessAndExactRetry(t *testing.T) {
	if dir := os.Getenv("PAGNET_REGISTRY_WRITE_CRASH_DIR"); dir != "" {
		s, e := Open(context.Background(), dir)
		if e != nil {
			os.Exit(38)
		}
		ref, e := fabric.ParseEndpointRef(os.Getenv("PAGNET_REGISTRY_WRITE_REF"))
		if e != nil {
			os.Exit(38)
		}
		c, e := fabric.NewAuthenticatedContext(testOwner, s.Namespace(), []byte("trusted request"))
		if e != nil {
			os.Exit(38)
		}
		if _, e = s.Register(context.Background(), c, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "agent.local", Name: "Crash"}}); e != nil {
			os.Exit(38)
		}
		os.Exit(37)
	}
	s, c, dir := fixture(t)
	d := endpoint(t, s)
	d.Bindings = nil
	d.Description = ""
	d.Name = "Crash"
	s.Close()
	command := exec.Command(os.Args[0], "-test.run=^TestWriteCommitCrashActualProcessAndExactRetry$")
	command.Env = append(os.Environ(), "PAGNET_REGISTRY_WRITE_CRASH_DIR="+dir, "PAGNET_REGISTRY_WRITE_REF="+d.Ref.String())
	e := command.Run()
	exit, ok := e.(*exec.ExitError)
	if !ok || exit.ExitCode() != 37 {
		t.Fatalf("child commit not reached: %v", e)
	}
	s, e = Open(context.Background(), dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	existing, e := s.GetEndpoint(context.Background(), d.Ref, "")
	if e != nil {
		t.Fatal(e)
	}
	rev, e := s.Register(context.Background(), c, fabric.RegistryUpdate{Descriptor: d})
	if e != nil || rev != existing.Revision {
		t.Fatal("committed retry not exact", e)
	}
	records, e := s.Records(context.Background(), s.Namespace(), 0, 100)
	if e != nil || len(records) != 1 {
		t.Fatal("duplicate crash-recovered update", e)
	}
}
