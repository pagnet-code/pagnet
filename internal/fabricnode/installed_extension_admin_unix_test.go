//go:build linux || darwin

package fabricnode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension"
	"github.com/pagnet-code/pagnet/fabric/extension/continuation"
	extregistry "github.com/pagnet-code/pagnet/fabric/extension/registry"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/internal/fabricadmin"
	"github.com/pagnet-code/pagnet/internal/fabricclient"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
)

func extensionSocketRequest(t *testing.T, ctx context.Context, c *fabricadmin.Client, operation string, input any) fabricadmin.Response {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	response, err := c.Call(ctx, fabricadmin.Request{Version: 1, ID: operation, Operation: operation, Input: raw})
	if err != nil {
		t.Fatal("actual private admin transport", err)
	}
	return response
}
func extensionSocketSuccess(t *testing.T, ctx context.Context, c *fabricadmin.Client, operation string, input, target any) {
	t.Helper()
	response := extensionSocketRequest(t, ctx, c, operation, input)
	if response.Error != nil {
		t.Fatal("actual private admin operation", operation, response.Error)
	}
	if target != nil {
		if err := json.Unmarshal(response.Result, target); err != nil {
			t.Fatal(err)
		}
	}
	if bytes.Contains(response.Result, []byte("capability\"")) || bytes.Contains(response.Result, []byte("originalEnvelope")) {
		t.Fatal("private admin DTO exposed source or capability")
	}
}
func TestActualInstalledExtensionAdminSocketResumeACKIsolationRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
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
	owner, err := initial.Operator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := newLocalBoundary(ctx, initial.Store, owner, initial, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err = InitializeConfiguredServices(ctx, initial, boundary, DefaultInstalledServiceSettings()); err != nil {
		t.Fatal(err)
	}
	if err = InitializeExtensionInfrastructure(ctx, initial, DefaultExtensionSettings()); err != nil {
		t.Fatal(err)
	}
	root := initial.Store.AuthorityIdentity()
	if err = initial.Close(); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(private, "pagnet")
	source, _ := filepath.Abs("../..")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/pagnet")
	build.Dir = source
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatal("actual CLI build", err, string(output))
	}
	var effects atomic.Int32
	official := sdk.NewServer(&sdk.Implementation{Name: "installed extension source", Version: "1"}, nil)
	official.AddTool(&sdk.Tool{Name: "echo", Description: "Exact approved source", InputSchema: json.RawMessage(`{"type":"object","properties":{"input":{"type":"string"}},"required":["input"]}`)}, func(_ context.Context, request *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		effects.Add(1)
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: strings.Repeat("real approved output\n", 5000)}}}, nil
	})
	server := httptest.NewServer(sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return official }, &sdk.StreamableHTTPOptions{Stateless: false}))
	defer server.Close()
	var interceptorCalls atomic.Int32
	var action atomic.Value
	action.Store(extension.Defer)
	interceptor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("credential-free configured profile received secret")
		}
		var request extension.InterceptRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			w.WriteHeader(400)
			return
		}
		interceptorCalls.Add(1)
		decision := extension.Decision{Action: extension.Continue}
		if request.Phase == extension.PhaseRequest && request.Stage == "invoke.dispatch" && action.Load().(extension.Action) == extension.Defer {
			decision.Action = extension.Defer
			decision.Deferral = &extension.Deferral{Durable: true, ExpiresAt: time.Now().UTC().Add(time.Minute), ResumePrincipals: []string{root.Owner.Ref}}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(decision)
	}))
	defer interceptor.Close()
	paging := DefaultExtensionPagerOptions()
	paging.MaxHandles = 1
	paging.MaxBytes = extensionPageReservation
	product, err := OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary, ExtensionPaging: &paging})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { product.CloseContext(context.WithoutCancel(ctx)) }()
	admin, err := fabricadmin.Dial(ctx, socket)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	other, err := fabricadmin.Dial(ctx, socket)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	var added ServiceAddResult
	extensionSocketSuccess(t, ctx, admin, "service.add", ServiceAddInput{URL: server.URL, Name: "Approved service", Description: "extensionadminsource", AllowHTTP: true}, &added)
	if added.State != "connected" {
		t.Fatal("actual SDK source not connected", added)
	}
	offers, _, err := product.Node.Store.ListOffers(ctx, added.Ref, added.Revision, "", 2)
	if err != nil || len(offers) != 1 {
		t.Fatal(err, len(offers))
	}
	var profile struct {
		Digest string `json:"digest"`
	}
	extensionSocketSuccess(t, ctx, admin, "extension.profile.put", ExtensionProfile{Protocol: extensionHTTPProtocol, URL: interceptor.URL, CredentialSelector: "credentials.none", MaxConcurrency: 2}, &profile)
	installation := extregistry.Installation{Manifest: extension.ExtensionManifest{ManifestVersion: "1.0", ID: "installed.guard", Version: "1", MinProtocol: "1.0", MaxProtocol: "1.0", Interceptors: []extension.Registration{{ID: "installed.guard.invoke", Match: extension.Match{Operation: fabric.OperationInvoke, Stage: "invoke.dispatch"}, Placement: extension.PlacementSource, NeedsPlaintext: true, Phases: []extension.Phase{extension.PhaseRequest, extension.PhaseChunk, extension.PhaseResponse, extension.PhaseCompletion}, TimeoutMillis: 1000, Binding: "installed.guard.binding"}}}, Bindings: []extregistry.Binding{{ID: "installed.guard.binding", Protocol: extensionHTTPProtocol, Selector: "credentials.none", ProfileDigest: profile.Digest}}}
	var installed extregistry.Reference
	extensionSocketSuccess(t, ctx, admin, "extension.install", extensionMutationInput{Generation: 1, Installation: installation}, &installed)
	var inspected struct {
		Reference    extregistry.Reference    `json:"reference"`
		Installation extregistry.Installation `json:"installation"`
	}
	extensionSocketSuccess(t, ctx, admin, "extension.inspect", extensionReferenceInput{ID: installed.ID}, &inspected)
	if inspected.Reference != installed {
		t.Fatal("inspection changed signed reference")
	}
	inspected.Installation.Manifest.Version = "2"
	extensionSocketSuccess(t, ctx, admin, "extension.update", extensionMutationInput{Generation: 2, Revision: installed.Revision, Installation: inspected.Installation}, &installed)
	var listed extregistry.Page
	extensionSocketSuccess(t, ctx, admin, "extension.list", extensionListInput{Limit: 1}, &listed)
	if len(listed.Entries) != 1 || listed.Entries[0] != installed {
		t.Fatal("paginated current registry metadata")
	}
	client, err := fabricclient.Dial(ctx, socket, fabrichost.Authentication{Type: "fabric.auth", Mode: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var deferred struct {
		DeferredID string `json:"deferredId"`
	}
	deadline := time.Now().UTC().Add(45 * time.Second)
	raw := installedServiceCall(t, ctx, client, fabric.OperationInvoke, map[string]any{"deadline": deadline, "target": offers[0].Ref, "revision": offers[0].Revision, "input": map[string]string{"input": "approved exact data"}})
	if err = json.Unmarshal(raw, &deferred); err != nil || deferred.DeferredID == "" || effects.Load() != 0 {
		t.Fatal("paid effect before approval", err, string(raw), effects.Load())
	}
	claim := sha256.Sum256([]byte("installed actual claim"))
	input := extensionResumeInput{ID: deferred.DeferredID, ClaimID: hex.EncodeToString(claim[:])}
	extensionSocketSuccess(t, ctx, admin, "continuation.recover", extensionReferenceInput{ID: input.ID}, nil)
	var resumed ExtensionResumeReceipt
	extensionSocketSuccess(t, ctx, admin, "continuation.resume", input, &resumed)
	if !resumed.Fresh || resumed.Handle == "" || effects.Load() != 1 {
		t.Fatal("actual fresh private resume", resumed, effects.Load())
	}
	var repeated ExtensionResumeReceipt
	extensionSocketSuccess(t, ctx, admin, "continuation.resume", input, &repeated)
	if repeated.Fresh || repeated.Handle != resumed.Handle || effects.Load() != 1 {
		t.Fatal("duplicate dispatched", repeated, effects.Load())
	}

	raw = installedServiceCall(t, ctx, client, fabric.OperationInvoke, map[string]any{"target": offers[0].Ref, "revision": offers[0].Revision, "deadline": deadline, "input": map[string]string{"input": "second independently approved source"}})
	var abandoned struct {
		DeferredID string `json:"deferredId"`
	}
	if err = json.Unmarshal(raw, &abandoned); err != nil || abandoned.DeferredID == "" {
		t.Fatal(err)
	}
	secondClaim := sha256.Sum256([]byte("second installed claim"))
	secondInput := extensionResumeInput{ID: abandoned.DeferredID, ClaimID: hex.EncodeToString(secondClaim[:])}
	if response := extensionSocketRequest(t, ctx, admin, "continuation.resume", secondInput); response.Error == nil || response.Error.Code != fabric.CodeTargetUnavailable {
		t.Fatal("source accepted without reserved page capacity", response.Error)
	}
	var beforeApproval ExtensionResumeReceipt
	extensionSocketSuccess(t, ctx, admin, "continuation.inspect", secondInput, &beforeApproval)
	if beforeApproval.State != continuation.Pending || effects.Load() != 1 {
		t.Fatal("capacity refusal claimed or executed source", beforeApproval, effects.Load())
	}
	if response := extensionSocketRequest(t, ctx, other, "continuation.stream.page", extensionPageInput{Handle: resumed.Handle}); response.Error == nil {
		t.Fatal("second genuine owner connection adopted original page")
	}
	var assembled []byte
	ack := ""
	var pages int
	for {
		var page ExtensionStreamPage
		extensionSocketSuccess(t, ctx, admin, "continuation.stream.page", extensionPageInput{Handle: resumed.Handle, ACK: ack}, &page)
		if page.Pending {
			timer := time.NewTimer(5 * time.Millisecond)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				t.Fatal(ctx.Err())
			}
			continue
		}
		if len(page.Frames) == 0 {
			if !page.Terminal {
				t.Fatal("empty source page")
			}
			break
		}
		pages++
		var duplicate ExtensionStreamPage
		extensionSocketSuccess(t, ctx, admin, "continuation.stream.page", extensionPageInput{Handle: resumed.Handle}, &duplicate)
		first, _ := json.Marshal(page)
		second, _ := json.Marshal(duplicate)
		if !bytes.Equal(first, second) {
			t.Fatal("cached original page changed")
		}
		if response := extensionSocketRequest(t, ctx, admin, "continuation.stream.page", extensionPageInput{Handle: resumed.Handle, ACK: strings.Repeat("0", 64)}); response.Error == nil {
			t.Fatal("wrong page ACK advanced source")
		}
		for _, frame := range page.Frames {
			assembled = append(assembled, frame.Data...)
		}
		ack = page.Digest
	}
	if interceptorCalls.Load() < 3 {
		t.Fatal("configured callback phases not exercised")
	}
	if pages < 3 || !bytes.Contains(assembled, []byte("real approved output")) || effects.Load() != 1 {
		t.Fatal("actual paged source missing", pages, len(assembled), effects.Load())
	}

	// A later connection may inspect/explicitly stop an exact durable claim,
	// while the old connection's original output window never transfers.
	var rotated struct {
		Revision uint64 `json:"capabilityRevision,string"`
	}
	extensionSocketSuccess(t, ctx, admin, "continuation.rotate", extensionReferenceInput{ID: secondInput.ID, Revision: 1}, &rotated)
	if rotated.Revision != 2 || effects.Load() != 1 {
		t.Fatal("rotation executed source", rotated, effects.Load())
	}
	var second ExtensionResumeReceipt
	extensionSocketSuccess(t, ctx, admin, "continuation.resume", secondInput, &second)
	if second.Handle == "" || second.Receipt.CapabilityRevision != 2 || effects.Load() != 2 {
		t.Fatal("current rotated claim", second, effects.Load())
	}
	admin.Close()
	if response := extensionSocketRequest(t, ctx, other, "continuation.stream.page", extensionPageInput{Handle: second.Handle}); response.Error == nil {
		t.Fatal("disconnected page transferred to new owner")
	}
	var inspectedClaim ExtensionResumeReceipt
	extensionSocketSuccess(t, ctx, other, "continuation.inspect", secondInput, &inspectedClaim)
	if inspectedClaim.Receipt != second.Receipt || inspectedClaim.Handle != "" {
		t.Fatal("current owner receipt promoted old delivery")
	}
	wrong := secondInput
	wrong.ClaimID = strings.Repeat("0", 64)
	if response := extensionSocketRequest(t, ctx, other, "continuation.stop", wrong); response.Error == nil {
		t.Fatal("wrong claim stopped original source")
	}
	extensionSocketSuccess(t, ctx, other, "continuation.stop", secondInput, &inspectedClaim)
	product.extensionAdmin.pager.mu.Lock()
	remaining := len(product.extensionAdmin.pager.entries)
	product.extensionAdmin.pager.mu.Unlock()
	if remaining != 0 || effects.Load() != 2 {
		t.Fatal("exact cleanup did not reclaim original slot", remaining, effects.Load())
	}
	client.Close()
	admin.Close()
	other.Close()
	if err = product.CloseContext(ctx); err != nil {
		t.Fatal("original resources did not join", err)
	}
	product, err = OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary})
	if err != nil {
		t.Fatal("retained installed extension restart", err)
	}
	admin, err = fabricadmin.Dial(ctx, socket)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	var historical ExtensionResumeReceipt
	extensionSocketSuccess(t, ctx, admin, "continuation.resume", input, &historical)
	if historical.Fresh || historical.Handle != "" || historical.Receipt.ClaimID != input.ClaimID || effects.Load() != 2 {
		t.Fatal("restart recreated source or dispatch", fmt.Sprint(historical), effects.Load())
	}
}
