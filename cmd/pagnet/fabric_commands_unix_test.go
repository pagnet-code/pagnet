//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/internal/fabricnode"
	"github.com/spf13/cobra"
)

func TestLocalCLIActualSocketDiscoverDescribeAndExactInvokeFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	parent, err := os.MkdirTemp("", "pgn-cli-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(parent)
	dir := filepath.Join(parent, "authority")
	run := filepath.Join(parent, "run")
	if err = os.Mkdir(run, 0700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(run, "node.sock")
	installation, err := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := installation.Operator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := fabric.NewEndpointRef(installation.Store.AuthorityIdentity().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := installation.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "actor.agent", Name: "Maria", Description: "Sales and customer enquiries"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = installation.Close(); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	n, err := fabricnode.OpenInstalled(ctx, fabricnode.InstalledConfig{Directory: dir, Binary: binary})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if _, err = n.Node.Synchronize(ctx, 2); err != nil {
		t.Fatal(err)
	}
	for _, factory := range []func() *cobra.Command{discoverCmd, describeCmd} {
		cmd := factory()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetContext(ctx)
		if cmd.Name() == "discover" {
			cmd.SetArgs([]string{"sales", "--socket", socket})
		} else {
			cmd.SetArgs([]string{ref.String(), "--socket", socket, "--revision", string(revision)})
		}
		if err = cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(out.Bytes(), []byte("Maria")) || !json.Valid(out.Bytes()) {
			t.Fatal("real CLI lost selected descriptor", out.String())
		}
	}
	cmd := invokeCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{ref.String(), "--revision", string(revision), "--socket", socket})
	if err = cmd.Execute(); err == nil {
		t.Fatal("unbound agent silently executed a fallback")
	}
	// A stale selected revision remains an explicit failure; CLI never describes
	// again, refreshes it or selects another endpoint.
	cmd = describeCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{ref.String(), "--revision", "stale", "--socket", socket})
	if err = cmd.Execute(); err == nil {
		t.Fatal("stale reference silently refreshed")
	}
}
func TestLocalResultRawNumbersAndStructuredErrors(t *testing.T) {
	raw := `{"result":9007199254740993123456789}`
	result := &sdkmcp.CallToolResult{Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: raw}}}
	value, err := localOperationResult(result)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = printLocalResult(&out, value); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "9007199254740993123456789") {
		t.Fatal("rounded exact result", out.String())
	}
	result.IsError = true
	result.Content = []sdkmcp.Content{&sdkmcp.TextContent{Text: `{"error":{"code":"TARGET_UNAVAILABLE","message":"selected target offline"}}`}}
	if _, err = localOperationResult(result); err == nil {
		t.Fatal("tool failure treated as success")
	}
	result.Content = append(result.Content, &sdkmcp.TextContent{Text: raw})
	if _, err = localOperationResult(result); err == nil {
		t.Fatal("ambiguous result accepted")
	}
}
func TestLocalInputBoundedAndDuplicateKeysRefusedBeforeConnection(t *testing.T) {
	cmd := &cobra.Command{}
	for _, input := range []string{`{"a":1,"a":2}`, strings.Repeat(" ", fabric.DefaultWireLimits.MaxBytes+1) + "{}"} {
		cmd.SetIn(strings.NewReader(input))
		if _, err := readLocalInput(cmd, "-"); err == nil {
			t.Fatal("invalid/unbounded input accepted")
		}
	}
	raw := `{"n":9007199254740993}`
	cmd.SetIn(strings.NewReader(raw))
	actual, err := readLocalInput(cmd, "-")
	if err != nil || string(actual) != raw {
		t.Fatal("input numeric bytes changed", err, string(actual))
	}
}
