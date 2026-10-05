//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/internal/fabricnode"
)

func TestLocalAgentCLIRealOwnerCreationAndExactRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	private, e := os.MkdirTemp("", "pgn-agent-cli-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(private)
	socket, dir := filepath.Join(private, "node.sock"), filepath.Join(private, "domain")
	initial, e := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if e != nil {
		t.Fatal(e)
	}
	if e = initial.Close(); e != nil {
		t.Fatal(e)
	}
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	n, e := fabricnode.OpenInstalled(ctx, fabricnode.InstalledConfig{Directory: dir, Binary: binary})
	if e != nil {
		t.Fatal(e)
	}
	defer n.CloseContext(ctx)
	savedJSON, savedSilent, savedNonInteractive := jsonOut, silent, nonInteractive
	jsonOut, silent, nonInteractive = true, false, true
	defer func() { jsonOut, silent, nonInteractive = savedJSON, savedSilent, savedNonInteractive }()
	create := func(description string) (string, error) {
		command := localAgentCreateCmd()
		command.SetContext(ctx)
		var output bytes.Buffer
		command.SetOut(&output)
		command.SetArgs([]string{"Maria", "--description", description, "--socket", socket, "--request-id", "cli-maria"})
		e := command.Execute()
		return output.String(), e
	}
	first, e := create("Maria supports sales and customers")
	if e != nil || !json.Valid([]byte(first)) {
		t.Fatal(e, first)
	}
	second, e := create("Maria supports sales and customers")
	if e != nil || second != first {
		t.Fatal("exact retry changed identity", e, first, second)
	}
	if _, e = create("Another description"); e == nil {
		t.Fatal("same request modified another identity")
	}
	missing := localAgentCreateCmd()
	missing.SetContext(ctx)
	missing.SetArgs([]string{"Maria", "--socket", socket})
	if e = missing.Execute(); e == nil {
		t.Fatal("required description absent")
	}
}
