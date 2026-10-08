//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/internal/fabricnode"
	"github.com/spf13/cobra"
)

// TestFederationExposureAdminCLIFlagWiring asserts, for each subcommand, the
// exact fabricadmin.Request{Operation, Input} bytes the CLI emits from its
// flags (same recorder precedent as the extension/continuation surface).
func TestFederationExposureAdminCLIFlagWiring(t *testing.T) {
	temp := t.TempDir()
	target, err := fabric.NewEndpointRef(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	remoteKey := make([]byte, 32)
	remoteKey[0] = 0xff
	remote, err := fabric.NewEndpointRef(remoteKey)
	if err != nil {
		t.Fatal(err)
	}
	config := fabricnode.FederationExposureConfiguration{Exposures: []fabricnode.FederationExposure{{RemoteDomain: remote.Domain(), Target: target, Revision: "1", BindingID: "native"}}}
	configBytes, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(temp, "exposure.json")
	if err := os.WriteFile(configPath, configBytes, 0600); err != nil {
		t.Fatal(err)
	}
	putExpected := func(expectedRevision uint64) []byte {
		raw, err := json.Marshal(federationExposurePutRequest{ExpectedRevision: expectedRevision, Exposures: config.Exposures})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	rec := newExtensionAdminRecorder(t, json.RawMessage(`{"ok":true}`))
	socket := rec.path

	tests := []struct {
		name      string
		args      []string
		wantOp    string
		wantInput []byte
		wantID    string
	}{
		{
			name:      "federation.exposure.put",
			args:      []string{"exposure", "put", "--config", configPath, "--expected-revision", "3", "--socket", socket, "--request-id", "federation-exposure-put-1"},
			wantOp:    "federation.exposure.put",
			wantInput: putExpected(3),
			wantID:    "federation-exposure-put-1",
		},
		{
			name:      "federation.exposure.put.default-base",
			args:      []string{"exposure", "put", "--config", configPath, "--socket", socket},
			wantOp:    "federation.exposure.put",
			wantInput: putExpected(0),
		},
		{
			name:      "federation.exposure.get",
			args:      []string{"exposure", "get", "--socket", socket},
			wantOp:    "federation.exposure.get",
			wantInput: []byte(`{}`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := localFederationCmd()
			cmd.SetArgs(append([]string{}, test.args...))
			out := &bytes.Buffer{}
			cmd.SetOut(out)
			cmd.SetErr(out)
			if err := cmd.Execute(); err != nil {
				t.Fatalf("CLI %v failed: %v\noutput: %s", test.args, err, out.String())
			}
			got := rec.lastRequest(t)
			if got.Operation != test.wantOp {
				t.Fatalf("operation = %q, want %q", got.Operation, test.wantOp)
			}
			if !bytes.Equal(got.Input, test.wantInput) {
				t.Fatalf("input = %s, want %s", got.Input, test.wantInput)
			}
			if test.wantID != "" && got.ID != test.wantID {
				t.Fatalf("request id = %q, want %q", got.ID, test.wantID)
			}
		})
	}
}

// TestFederationExposureAdminCLIGetHasNoRequestID asserts get is a read: it
// never offers the mutating --request-id retry pin (put alone does).
func TestFederationExposureAdminCLIGetHasNoRequestID(t *testing.T) {
	cmd := localFederationCmd()
	var exposure *cobra.Command
	for _, c := range cmd.Commands() {
		if c.Name() == "exposure" {
			exposure = c
		}
	}
	if exposure == nil {
		t.Fatal("exposure subcommand not found")
	}
	var get *cobra.Command
	for _, c := range exposure.Commands() {
		if c.Name() == "get" {
			get = c
		}
	}
	if get == nil {
		t.Fatal("get subcommand not found")
	}
	if get.Flags().Lookup("request-id") != nil {
		t.Fatal("get must not expose --request-id")
	}
}

// runCLISubcommandHuman drives the real command constructor + RunE with the
// human output policy and returns the printed one-liner.
func runCLISubcommandHuman(t *testing.T, build func() *cobra.Command, args ...string) string {
	t.Helper()
	oldJSON, oldSilent := jsonOut, silent
	jsonOut, silent = false, false
	defer func() { jsonOut, silent = oldJSON, oldSilent }()
	cmd := build()
	cmd.SetArgs(args)
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("CLI %v failed: %v\noutput: %s", args, err, out.String())
	}
	return out.String()
}

// TestFederationExposureAdminCLIInstalledNode starts a genuine installed node
// with Federation enabled and drives the real put/get CLI end-to-end against
// its private admin socket: the put receipt is the committed revision, the get
// mirrors the declaration (canonical pagnet:// target), and the human
// one-liners print the exact counts.
func TestFederationExposureAdminCLIInstalledNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
	defer cancel()
	private := t.TempDir()
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	socketDir := filepath.Join(private, "run")
	if err := os.Mkdir(socketDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dir, socket := filepath.Join(private, "domain"), filepath.Join(socketDir, "node.sock")
	initial, err := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if err != nil {
		t.Fatal(err)
	}
	rootOwnerRef := initial.Store.AuthorityIdentity()
	owner, err := initial.Operator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	target, err := fabric.NewEndpointRef(rootOwnerRef.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := initial.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: target, Name: "published", Kind: "tool.local", Bindings: []fabric.BindingSummary{{ID: "native", Protocol: "local.native", Version: "1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	remote, err := fabric.NewEndpointRef(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if remote.Domain() == rootOwnerRef.Namespace {
		t.Fatal("fixture foreign domain collided with the local domain")
	}
	if err = initial.Close(); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(private, "pagnet")
	// The test binary's cwd is this package's source dir (cmd/pagnet); the
	// module root (go.mod) is two levels up.
	source, _ := filepath.Abs("../..")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/pagnet")
	build.Dir = source
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatal("actual CLI build", err, string(output))
	}

	product, err := fabricnode.OpenInstalled(ctx, fabricnode.InstalledConfig{Directory: dir, Binary: binary, Federation: &fabricnode.InstalledFederationConfig{}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = product.CloseContext(context.WithoutCancel(ctx)) }()
	if product.Federation == nil {
		t.Fatal("the federation surface was not composed")
	}

	configPath := filepath.Join(private, "exposure.json")
	config := fabricnode.FederationExposureConfiguration{Exposures: []fabricnode.FederationExposure{{RemoteDomain: remote.Domain(), Target: target, Revision: revision, BindingID: "native"}}}
	configBytes, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configBytes, 0600); err != nil {
		t.Fatal(err)
	}

	// 1) put (CLI) -> the server-side CAS receipt.
	var receipt struct {
		Revision uint64 `json:"revision"`
	}
	if err := json.Unmarshal(runCLISubcommandJSON(t, localFederationCmd, "exposure", "put", "--config", configPath, "--socket", socket), &receipt); err != nil {
		t.Fatal("put", err)
	}
	if receipt.Revision != 1 {
		t.Fatalf("put receipt = %+v; want revision 1", receipt)
	}

	// 2) get (CLI) -> mirrors the declaration, canonical pagnet:// target.
	var view struct {
		Revision  uint64 `json:"revision"`
		Exposures []struct {
			RemoteDomain string `json:"remoteDomain"`
			Target       string `json:"target"`
			Revision     string `json:"revision"`
			BindingID    string `json:"bindingId"`
		} `json:"exposures"`
	}
	if err := json.Unmarshal(runCLISubcommandJSON(t, localFederationCmd, "exposure", "get", "--socket", socket), &view); err != nil {
		t.Fatal("get", err)
	}
	if view.Revision != 1 || len(view.Exposures) != 1 {
		t.Fatalf("get view = %+v; want the declared exposure at revision 1", view)
	}
	if view.Exposures[0].RemoteDomain != remote.Domain() || view.Exposures[0].Target != target.String() || view.Exposures[0].Revision != string(revision) || view.Exposures[0].BindingID != "native" {
		t.Fatalf("get view = %+v; want the exact declaration", view)
	}
	if !strings.HasPrefix(view.Exposures[0].Target, "pagnet://"+rootOwnerRef.Namespace+"/e/") {
		t.Fatalf("target is not the canonical local pagnet:// endpoint-ref string: %s", view.Exposures[0].Target)
	}

	// 3) The human one-liners print the exact counts.
	if out := runCLISubcommandHuman(t, localFederationCmd, "exposure", "get", "--socket", socket); out != "exposures: 1 (revision 1)\n" {
		t.Fatalf("human get output = %q", out)
	}
	// An identical put at the current base is a truthful update: the CAS
	// commits the next revision (FULL CAS, no content diffing at the base).
	if out := runCLISubcommandHuman(t, localFederationCmd, "exposure", "put", "--config", configPath, "--expected-revision", "1", "--socket", socket); out != "exposures: 1 (revision 2)\n" {
		t.Fatalf("human update put output = %q", out)
	}
	// Repeating that exact (base, content) pair is the signed exact retry:
	// the same committed revision is returned, no duplicate record.
	if out := runCLISubcommandHuman(t, localFederationCmd, "exposure", "put", "--config", configPath, "--expected-revision", "1", "--socket", socket); out != "exposures: 1 (revision 2)\n" {
		t.Fatalf("human retry put output = %q", out)
	}
	if out := runCLISubcommandHuman(t, localFederationCmd, "exposure", "get", "--socket", socket); out != "exposures: 1 (revision 2)\n" {
		t.Fatalf("human get after retry = %q", out)
	}
}

// TestFederationPeerLinkAdminCLIInstalledNode starts a genuine installed node
// with Federation enabled and drives the peer certify + link put/get CLI
// end-to-end against its private admin socket: the certify receipt carries the
// exchange key, and the link put/get round-trips the declared channel.
func TestFederationPeerLinkAdminCLIInstalledNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 240*time.Second)
	defer cancel()
	private := t.TempDir()
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	socketDir := filepath.Join(private, "run")
	if err := os.Mkdir(socketDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dir, socket := filepath.Join(private, "domain"), filepath.Join(socketDir, "node.sock")
	initial, err := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if err != nil {
		t.Fatal(err)
	}
	root := initial.Store.AuthorityIdentity()
	if err = initial.Close(); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(private, "pagnet")
	// The test binary's cwd is this package's source dir (cmd/pagnet); the
	// module root (go.mod) is two levels up.
	source, _ := filepath.Abs("../..")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/pagnet")
	build.Dir = source
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatal("actual CLI build", err, string(output))
	}

	product, err := fabricnode.OpenInstalled(ctx, fabricnode.InstalledConfig{Directory: dir, Binary: binary, Federation: &fabricnode.InstalledFederationConfig{}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = product.CloseContext(context.WithoutCancel(ctx)) }()
	if product.Federation == nil {
		t.Fatal("the federation surface was not composed")
	}

	// 1) certify (CLI) -> the receipt carries the exchange key + certificate.
	var certify struct {
		PublicKey   [32]byte `json:"publicKey"`
		KeyRevision string   `json:"keyRevision"`
	}
	if err := json.Unmarshal(runCLISubcommandJSON(t, localFederationCmd, "peer", "certify", "--socket", socket), &certify); err != nil {
		t.Fatal("certify", err)
	}
	if certify.KeyRevision != "1" || certify.PublicKey == ([32]byte{}) {
		t.Fatalf("certify receipt = %+v; want a non-zero exchange key at revision 1", certify)
	}

	// 2) link put (CLI) -> the per-channel link at revision 1.
	remoteKey := make([]byte, 32)
	remoteKey[0] = 0x22
	remoteRef, err := fabric.NewEndpointRef(remoteKey)
	if err != nil {
		t.Fatal(err)
	}
	if remoteRef.Domain() == root.Namespace {
		t.Fatal("fixture foreign domain collided with the local domain")
	}
	remoteNamespace := remoteRef.Domain()
	remoteStoreID := strings.Repeat("0", 64)
	channelID := strings.Repeat("1", 64)
	sourceRoute := strings.Repeat("2", 64)
	destinationRoute := strings.Repeat("3", 64)
	var put struct {
		Revision string `json:"revision"`
	}
	if err := json.Unmarshal(runCLISubcommandJSON(t, localFederationCmd, "link", "put",
		"--socket", socket,
		"--remote-namespace", remoteNamespace, "--remote-store-id", remoteStoreID,
		"--channel-id", channelID, "--source-route", sourceRoute, "--destination-route", destinationRoute,
		"--source-role"), &put); err != nil {
		t.Fatal("link put", err)
	}
	if put.Revision != "1" {
		t.Fatalf("link put receipt = %+v; want revision 1", put)
	}

	// 3) link get (CLI) -> mirrors the declaration.
	var get struct {
		Revision string `json:"revision"`
		Link     struct {
			RemoteNamespace string `json:"remoteNamespace"`
			RemoteStoreID   string `json:"remoteStoreId"`
			SourceRole      bool   `json:"sourceRole"`
		} `json:"link"`
	}
	if err := json.Unmarshal(runCLISubcommandJSON(t, localFederationCmd, "link", "get", "--socket", socket, "--channel-id", channelID), &get); err != nil {
		t.Fatal("link get", err)
	}
	if get.Revision != "1" || get.Link.RemoteNamespace != remoteNamespace || get.Link.RemoteStoreID != remoteStoreID || !get.Link.SourceRole {
		t.Fatalf("link get = %+v; want the declared link at revision 1", get)
	}
}
