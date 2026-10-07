//go:build linux || darwin

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension"
	extregistry "github.com/pagnet-code/pagnet/fabric/extension/registry"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/internal/fabricadmin"
	"github.com/pagnet-code/pagnet/internal/fabricclient"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
	"github.com/pagnet-code/pagnet/internal/fabricnode"
	"github.com/spf13/cobra"
)

// ===== Fake private-admin server (unit tests) =====
//
// It speaks just enough of the genuine private socket handshake
// (auth line -> "fabric.ready" -> newline-delimited admin frames) for the real
// fabricadmin.Client to dial it, and records the exact request bytes the CLI
// sends. It performs no authority binding: these tests assert the CLI's request
// construction, not authentication.

type extensionAdminRecorder struct {
	path     string
	listener net.Listener
	mu       sync.Mutex
	requests []fabricadmin.Request
	response json.RawMessage
	failure  *fabric.Error
	joined   chan struct{}
}

func newExtensionAdminRecorder(t *testing.T, response json.RawMessage) *extensionAdminRecorder {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "admin.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	rec := &extensionAdminRecorder{path: path, listener: listener, response: response, joined: make(chan struct{})}
	go rec.serve()
	t.Cleanup(func() {
		_ = listener.Close()
		<-rec.joined
	})
	return rec
}

func (r *extensionAdminRecorder) serve() {
	defer close(r.joined)
	for {
		conn, err := r.listener.Accept()
		if err != nil {
			return
		}
		go r.handle(conn)
	}
}

func (r *extensionAdminRecorder) handle(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	// Consume the client's authentication line, then answer with the exact
	// ready frame the genuine host sends for the administration protocol.
	if _, err := reader.ReadString('\n'); err != nil {
		return
	}
	if _, err := fmt.Fprintf(conn, "{\"type\":\"fabric.ready\",\"protocol\":\"%s\"}\n", fabrichost.AdminProtocol); err != nil {
		return
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		var req fabricadmin.Request
		if err := json.Unmarshal([]byte(strings.TrimRight(line, "\n")), &req); err != nil {
			return
		}
		r.mu.Lock()
		r.requests = append(r.requests, req)
		response, failure := r.response, r.failure
		r.mu.Unlock()
		resp := struct {
			Version int             `json:"version"`
			ID      string          `json:"id"`
			Result  json.RawMessage `json:"result,omitempty"`
			Error   *fabric.Error   `json:"error,omitempty"`
		}{Version: fabricadmin.Version, ID: req.ID}
		if failure != nil {
			resp.Error = failure
		} else {
			resp.Result = response
		}
		out, _ := json.Marshal(resp)
		if _, err := fmt.Fprintf(conn, "%s\n", out); err != nil {
			return
		}
	}
}

func (r *extensionAdminRecorder) lastRequest(t *testing.T) fabricadmin.Request {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.requests) == 0 {
		t.Fatal("no private administration request recorded")
	}
	return r.requests[len(r.requests)-1]
}

// runCLISubcommand drives the real command constructor + RunE (not a re-implementation)
// with --json and captures the emitted JSON receipt.
func runCLISubcommandJSON(t *testing.T, build func() *cobra.Command, args ...string) []byte {
	t.Helper()
	oldJSON, oldSilent := jsonOut, silent
	jsonOut, silent = true, false
	defer func() { jsonOut, silent = oldJSON, oldSilent }()
	cmd := build()
	cmd.SetArgs(args)
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("CLI %v failed: %v\noutput: %s", args, err, out.String())
	}
	return bytes.TrimSpace(out.Bytes())
}

// TestExtensionAdminCLIFlagWiring asserts, for every subcommand, the exact
// fabricadmin.Request{Operation, Input} bytes the CLI emits from its flags.
func TestExtensionAdminCLIFlagWiring(t *testing.T) {
	temp := t.TempDir()
	writeFile := func(name, content string) string {
		t.Helper()
		path := filepath.Join(temp, name)
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	installation := extregistry.Installation{
		Manifest: extension.ExtensionManifest{ManifestVersion: "1.0", ID: "test.ext", Version: "1", MinProtocol: "1.0", MaxProtocol: "1.0"},
		Bindings: []extregistry.Binding{{ID: "test.ext.b", Protocol: "pagnet.interceptor.http.v1", Selector: "credentials.none", ProfileDigest: "digest0"}},
	}
	installationJSON, err := json.Marshal(installation)
	if err != nil {
		t.Fatal(err)
	}
	installationPath := writeFile("installation.json", string(installationJSON))

	profilePath := writeFile("profile.json", `{"protocol":"pagnet.interceptor.http.v1","url":"https://example.test/hook","credentialSelector":"credentials.none","maxConcurrency":2}`)
	profileExpected := `{"protocol":"pagnet.interceptor.http.v1","url":"https://example.test/hook","credentialSelector":"credentials.none","maxConcurrency":2}`

	mutationExpected := func(generation, revision uint64) []byte {
		raw, err := json.Marshal(extensionMutationRequest{Generation: generation, Revision: revision, Installation: installation})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	rec := newExtensionAdminRecorder(t, json.RawMessage(`{"ok":true}`))
	socket := rec.path

	tests := []struct {
		name      string
		build     func() *cobra.Command
		args      []string
		wantOp    string
		wantInput []byte
	}{
		{
			name:      "extension.profile.put",
			build:     localExtensionCmd,
			args:      []string{"profile", "put", "--profile", profilePath, "--socket", socket, "--request-id", "put-1"},
			wantOp:    "extension.profile.put",
			wantInput: []byte(profileExpected),
		},
		{
			name:      "extension.install",
			build:     localExtensionCmd,
			args:      []string{"install", "--generation", "7", "--installation", installationPath, "--socket", socket},
			wantOp:    "extension.install",
			wantInput: mutationExpected(7, 0),
		},
		{
			name:      "extension.update",
			build:     localExtensionCmd,
			args:      []string{"update", "--generation", "3", "--revision", "5", "--installation", installationPath, "--socket", socket},
			wantOp:    "extension.update",
			wantInput: mutationExpected(3, 5),
		},
		{
			name:      "extension.inspect",
			build:     localExtensionCmd,
			args:      []string{"inspect", "some.id", "--socket", socket},
			wantOp:    "extension.inspect",
			wantInput: []byte(`{"id":"some.id"}`),
		},
		{
			name:      "extension.list",
			build:     localExtensionCmd,
			args:      []string{"list", "--limit", "9", "--socket", socket},
			wantOp:    "extension.list",
			wantInput: []byte(`{"limit":9}`),
		},
		{
			name:      "extension.list.after",
			build:     localExtensionCmd,
			args:      []string{"list", "--after", "cursor123", "--limit", "9", "--socket", socket},
			wantOp:    "extension.list",
			wantInput: []byte(`{"after":"cursor123","limit":9}`),
		},
		{
			name:      "extension.remove",
			build:     localExtensionCmd,
			args:      []string{"remove", "some.id", "--generation", "4", "--revision", "2", "--socket", socket},
			wantOp:    "extension.remove",
			wantInput: []byte(`{"id":"some.id","generation":"4","revision":"2"}`),
		},
		{
			name:      "continuation.inspect",
			build:     localContinuationCmd,
			args:      []string{"inspect", "id1", "--claim", "claim1", "--socket", socket},
			wantOp:    "continuation.inspect",
			wantInput: []byte(`{"id":"id1","claimId":"claim1"}`),
		},
		{
			name:      "continuation.stop",
			build:     localContinuationCmd,
			args:      []string{"stop", "id1", "--claim", "claim1", "--socket", socket},
			wantOp:    "continuation.stop",
			wantInput: []byte(`{"id":"id1","claimId":"claim1"}`),
		},
		{
			name:      "continuation.resume",
			build:     localContinuationCmd,
			args:      []string{"resume", "id1", "--claim", "claim1", "--socket", socket},
			wantOp:    "continuation.resume",
			wantInput: []byte(`{"id":"id1","claimId":"claim1"}`),
		},
		{
			name:      "continuation.recover",
			build:     localContinuationCmd,
			args:      []string{"recover", "id1", "--socket", socket},
			wantOp:    "continuation.recover",
			wantInput: []byte(`{"id":"id1"}`),
		},
		{
			name:      "continuation.rotate",
			build:     localContinuationCmd,
			args:      []string{"rotate", "id1", "--revision", "6", "--socket", socket},
			wantOp:    "continuation.rotate",
			wantInput: []byte(`{"id":"id1","revision":"6"}`),
		},
		{
			name:      "continuation.stream.page",
			build:     localContinuationCmd,
			args:      []string{"stream", "page", "--handle", "H", "--ack", "A", "--wait-ms", "100", "--socket", socket},
			wantOp:    "continuation.stream.page",
			wantInput: []byte(`{"handle":"H","ack":"A","waitMillis":100}`),
		},
		{
			name:      "continuation.stream.page.bare",
			build:     localContinuationCmd,
			args:      []string{"stream", "page", "--handle", "H", "--socket", socket},
			wantOp:    "continuation.stream.page",
			wantInput: []byte(`{"handle":"H"}`),
		},
		{
			name:      "continuation.stream.close",
			build:     localContinuationCmd,
			args:      []string{"stream", "close", "--handle", "H", "--socket", socket},
			wantOp:    "continuation.stream.close",
			wantInput: []byte(`{"handle":"H"}`),
		},
		{
			name:      "continuation.stream.close.ack",
			build:     localContinuationCmd,
			args:      []string{"stream", "close", "--handle", "H", "--ack", "A", "--socket", socket},
			wantOp:    "continuation.stream.close",
			wantInput: []byte(`{"handle":"H","ack":"A"}`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := test.build()
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
		})
	}
}

// TestExtensionAdminCLIRejectsInstallRevision asserts install cannot send a
// revision at all (the server denies a nonzero revision on install).
func TestExtensionAdminCLIRejectsInstallRevision(t *testing.T) {
	cmd := localExtensionCmd()
	// locate the install leaf by name.
	var found *cobra.Command
	for _, c := range cmd.Commands() {
		if c.Name() == "install" {
			found = c
		}
	}
	if found == nil {
		t.Fatal("install subcommand not found")
	}
	if found.Flags().Lookup("revision") != nil {
		t.Fatal("install must not expose --revision")
	}
}

// TestExtensionAdminCLIAbsentSocket asserts a mutating operation against an
// absent socket returns a clean error (non-zero, no panic).
func TestExtensionAdminCLIAbsentSocket(t *testing.T) {
	private := t.TempDir()
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(private, "absent.sock") // never created
	cmd := localExtensionCmd()
	cmd.SetArgs([]string{"remove", "some.id", "--generation", "1", "--revision", "1", "--socket", socket})
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected a clean error for an absent socket, got success")
	}
}

// TestExtensionAdminCLIInstalledNode starts a genuine installed node with the
// admin socket and drives the real CLI commands end-to-end against it.
func TestExtensionAdminCLIInstalledNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	private := t.TempDir()
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	dir, socket := filepath.Join(private, "domain"), filepath.Join(private, "node.sock")
	initial, err := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if err != nil {
		t.Fatal(err)
	}
	rootOwnerRef := initial.Store.AuthorityIdentity().Owner.Ref
	if err = fabricnode.InitializeDefaultServices(ctx, initial); err != nil {
		t.Fatal(err)
	}
	if err = fabricnode.InitializeExtensionInfrastructure(ctx, initial, fabricnode.DefaultExtensionSettings()); err != nil {
		t.Fatal(err)
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

	// SDK source (the paid effect) and a deferring source interceptor.
	var effects atomic.Int32
	official := sdk.NewServer(&sdk.Implementation{Name: "cli extension source", Version: "1"}, nil)
	official.AddTool(&sdk.Tool{
		Name:         "echo",
		Description:  "Exact approved source",
		InputSchema:  json.RawMessage(`{"type":"object","properties":{"input":{"type":"string"}},"required":["input"]}`),
	}, func(_ context.Context, _ *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		effects.Add(1)
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: strings.Repeat("approved output\n", 2000)}}}, nil
	})
	server := httptest.NewServer(sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return official }, &sdk.StreamableHTTPOptions{Stateless: false}))
	defer server.Close()
	var action atomic.Value
	action.Store(extension.Defer)
	interceptor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request extension.InterceptRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			w.WriteHeader(400)
			return
		}
		decision := extension.Decision{Action: extension.Continue}
		if request.Phase == extension.PhaseRequest && request.Stage == "invoke.dispatch" && action.Load().(extension.Action) == extension.Defer {
			decision.Action = extension.Defer
			decision.Deferral = &extension.Deferral{Durable: true, ExpiresAt: time.Now().UTC().Add(time.Minute), ResumePrincipals: []string{rootOwnerRef}}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(decision)
	}))
	defer interceptor.Close()

	product, err := fabricnode.OpenInstalled(ctx, fabricnode.InstalledConfig{Directory: dir, Binary: binary})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = product.CloseContext(context.WithoutCancel(ctx)) }()
	admin, err := fabricadmin.Dial(ctx, socket)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()

	// Connect the SDK source directly over the admin socket (the CLI has no
	// service.add surface; this is fixture setup, not a re-implemented command).
	var added fabricnode.ServiceAddResult
	addedInput, _ := json.Marshal(fabricnode.ServiceAddInput{URL: server.URL, Name: "cli source", Description: "clitest", AllowHTTP: true})
	addedResp, err := admin.Call(ctx, fabricadmin.Request{Version: fabricadmin.Version, ID: "service.add", Operation: "service.add", Input: addedInput})
	if err != nil || addedResp.Error != nil {
		t.Fatal("service.add", err, addedResp.Error)
	}
	if err := json.Unmarshal(addedResp.Result, &added); err != nil || added.State != "connected" {
		t.Fatal("source not connected", err, added)
	}
	offers, _, err := product.Node.Store.ListOffers(ctx, added.Ref, added.Revision, "", 2)
	if err != nil || len(offers) != 1 {
		t.Fatal(err, len(offers))
	}

	// 1) extension profile put (CLI) -> server-side digest receipt.
	profile := fabricnode.ExtensionProfile{Protocol: "pagnet.interceptor.http.v1", URL: interceptor.URL, CredentialSelector: "credentials.none", MaxConcurrency: 2}
	profilePath := filepath.Join(private, "profile.json")
	if err := os.WriteFile(profilePath, extensionMustJSONBytes(t, profile), 0600); err != nil {
		t.Fatal(err)
	}
	var profileReceipt struct {
		Digest string `json:"digest"`
	}
	if err := json.Unmarshal(runCLISubcommandJSON(t, localExtensionCmd, "profile", "put", "--profile", profilePath, "--socket", socket), &profileReceipt); err != nil {
		t.Fatal("profile put", err)
	}
	if len(profileReceipt.Digest) != 64 {
		t.Fatalf("profile digest receipt = %q", profileReceipt.Digest)
	}

	// 2) extension install (CLI) -> server-side signed reference receipt.
	installation := extregistry.Installation{
		Manifest: extension.ExtensionManifest{ManifestVersion: "1.0", ID: "cli.guard", Version: "1", MinProtocol: "1.0", MaxProtocol: "1.0", Interceptors: []extension.Registration{{
			ID: "cli.guard.invoke",
			Match:     extension.Match{Operation: fabric.OperationInvoke, Stage: "invoke.dispatch"},
			Placement: extension.PlacementSource, NeedsPlaintext: true,
			Phases:        []extension.Phase{extension.PhaseRequest, extension.PhaseChunk, extension.PhaseResponse, extension.PhaseCompletion},
			TimeoutMillis: 1000,
			Binding:       "cli.guard.binding",
		}}},
		Bindings: []extregistry.Binding{{ID: "cli.guard.binding", Protocol: "pagnet.interceptor.http.v1", Selector: "credentials.none", ProfileDigest: profileReceipt.Digest}},
	}
	installationPath := filepath.Join(private, "installation.json")
	if err := os.WriteFile(installationPath, extensionMustJSONBytes(t, installation), 0600); err != nil {
		t.Fatal(err)
	}
	var installed extregistry.Reference
	if err := json.Unmarshal(runCLISubcommandJSON(t, localExtensionCmd, "install", "--generation", "1", "--installation", installationPath, "--socket", socket), &installed); err != nil {
		t.Fatal("install", err)
	}
	if installed.ID == "" || installed.Revision != 1 {
		t.Fatalf("install reference = %+v", installed)
	}

	// 3) extension list (CLI) -> server-side registry page contains the install.
	var page extregistry.Page
	if err := json.Unmarshal(runCLISubcommandJSON(t, localExtensionCmd, "list", "--limit", "10", "--socket", socket), &page); err != nil {
		t.Fatal("list", err)
	}
	if len(page.Entries) != 1 || page.Entries[0] != installed {
		t.Fatalf("list page = %+v, want %+v", page, installed)
	}

	// 4) Defer one invocation through the installed source (fabricclient, the
	// same owner client the CLI uses) to create a retained continuation.
	client, err := fabricclient.Dial(ctx, socket, fabrichost.Authentication{Type: "fabric.auth", Mode: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	deadline := time.Now().UTC().Add(45 * time.Second)
	invokeArgs, _ := json.Marshal(struct {
		Target   fabric.EndpointRef `json:"target"`
		Input    json.RawMessage    `json:"input"`
		Revision string             `json:"revision"`
		Deadline time.Time          `json:"deadline"`
	}{offers[0].Ref, json.RawMessage(`{"input":"defer me"}`), string(offers[0].Revision), deadline})
	invokeResult, err := client.Call(ctx, fabric.OperationInvoke, invokeArgs)
	if err != nil {
		t.Fatal("invoke", err)
	}
	invokeContent, err := localOperationResult(invokeResult)
	if err != nil {
		t.Fatal("invoke content", err)
	}
	var deferred struct {
		DeferredID string `json:"deferredId"`
	}
	if err := json.Unmarshal(invokeContent, &deferred); err != nil || deferred.DeferredID == "" || effects.Load() != 0 {
		t.Fatalf("paid effect before approval / not deferred: %v %s effects=%d", err, invokeContent, effects.Load())
	}

	// 5) continuation recover (CLI) -> server-side republished notification.
	var recovered struct {
		Published bool `json:"published"`
	}
	if err := json.Unmarshal(runCLISubcommandJSON(t, localContinuationCmd, "recover", deferred.DeferredID, "--socket", socket), &recovered); err != nil {
		t.Fatal("recover", err)
	}
	if !recovered.Published {
		t.Fatal("recover did not publish")
	}

	// 6) continuation rotate (CLI) -> server-side capability revision advance.
	var rotated struct {
		ID       string `json:"id"`
		Revision uint64 `json:"capabilityRevision,string"`
	}
	if err := json.Unmarshal(runCLISubcommandJSON(t, localContinuationCmd, "rotate", deferred.DeferredID, "--revision", "1", "--socket", socket), &rotated); err != nil {
		t.Fatal("rotate", err)
	}
	if rotated.ID != deferred.DeferredID || rotated.Revision != 2 || effects.Load() != 0 {
		t.Fatalf("rotate = %+v effects=%d", rotated, effects.Load())
	}
}

func extensionMustJSONBytes(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
