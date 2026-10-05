//go:build linux || darwin

package fabricnode

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/internal/fabricadmin"
	"github.com/pagnet-code/pagnet/internal/fabricclient"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
)

func TestActualServiceAddCLIStableOwnerSetupNegotiationCatalogAndRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	private, e := os.MkdirTemp("", "pgn-service-add-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(private)
	dir, socket := filepath.Join(private, "domain"), filepath.Join(private, "node.sock")
	i, e := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if e != nil {
		t.Fatal(e)
	}
	root := i.Store.AuthorityIdentity()
	if e = InitializeDefaultServices(ctx, i); e != nil {
		t.Fatal(e)
	}
	if e = i.Close(); e != nil {
		t.Fatal(e)
	}
	binary := filepath.Join(private, "pagnet")
	cmd := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/pagnet")
	cmd.Dir = "../.."
	if raw, e := cmd.CombinedOutput(); e != nil {
		t.Fatal(e, string(raw))
	}
	published := make(chan error, 64)
	observe := func(more bool, e error) {
		if !more || e != nil {
			select {
			case published <- e:
			default:
			}
		}
	}
	n, e := OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary, ObserveIndexPublication: observe})
	if e != nil {
		t.Fatal(e)
	}
	defer func() { n.CloseContext(ctx) }()
	var effects atomic.Int32
	payload := strings.Repeat("large-json-output-", 4096) + "9007199254740993"
	official := sdk.NewServer(&sdk.Implementation{Name: "actual-installed-2025", Version: "1"}, &sdk.ServerOptions{SupportedProtocolVersions: []string{"2025-11-25"}})
	official.AddTool(&sdk.Tool{Name: "echo", Description: "serviceaddtoolmarker", InputSchema: json.RawMessage(`{"type":"object","properties":{"n":{"const":9007199254740993}},"required":["n"]}`)}, func(_ context.Context, r *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		effects.Add(1)
		if !bytes.Equal(r.Params.Arguments, []byte(`{"n":9007199254740993}`)) {
			t.Error("input numeric precision lost")
		}
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: payload}}}, nil
	})
	handler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return official }, &sdk.StreamableHTTPOptions{Stateless: false})
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("unselected credential leaked")
		}
		handler.ServeHTTP(w, r)
	}))
	defer func() { n.CloseContext(ctx); remote.Close() }()
	add := func(description string) (ServiceAddResult, error) {
		c := exec.CommandContext(ctx, binary, "--json", "service", "add", remote.URL, "--name", "Customer support", "--description", description, "--socket", socket, "--request-id", "stable-service-setup")
		c.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + private, "MCP_TOKEN=unselected-secret"}
		raw, e := c.CombinedOutput()
		if e != nil {
			return ServiceAddResult{}, e
		}
		if bytes.Contains(raw, []byte(remote.URL)) || bytes.Contains(raw, []byte("unselected-secret")) {
			t.Fatal("private setup leaked into output", string(raw))
		}
		var v ServiceAddResult
		e = json.Unmarshal(raw, &v)
		return v, e
	}
	first, e := add("serviceaddmarker customer operations")
	if e != nil || first.State != "connected" || first.ProtocolVersion != "2025-11-25" {
		t.Fatal("genuine selected CLI setup", e, first)
	}
	second, e := add("serviceaddmarker customer operations")
	if e != nil || second != first || effects.Load() != 0 {
		t.Fatal("setup retry changed identity or invoked a tool", e, second)
	}
	if _, e = add("changed setup"); e == nil {
		t.Fatal("same request changed private setup")
	}
	d, e := n.Node.Store.GetEndpoint(ctx, first.Ref, first.Revision)
	if e != nil {
		t.Fatal(e)
	}
	descriptorJSON, _ := json.Marshal(d)
	if bytes.Contains(descriptorJSON, []byte(remote.URL)) || bytes.Contains(descriptorJSON, []byte("unselected-secret")) {
		t.Fatal("private transport leaked into descriptor")
	}
	client, e := fabricclient.Dial(ctx, socket, fabrichost.Authentication{Type: "fabric.auth", Mode: "owner"})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	// Event-driven indexed discovery can be awaited via actual publisher notice;
	// metadata read is bounded and no explicit Synchronize/reconnect is used.
	for {
		select {
		case err := <-published:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("actual committed service catalog not discoverable")
		}
		raw := installedServiceCall(t, ctx, client, fabric.OperationDiscover, map[string]any{"query": "serviceaddtoolmarker", "limit": 10})
		var result fabric.DiscoverResult
		if json.Unmarshal(raw, &result) != nil {
			t.Fatal(string(raw))
		}
		if len(result.Candidates) > 0 {
			break
		}
	}
	offers, _, e := n.Node.Store.ListOffers(ctx, first.Ref, first.Revision, "", 1)
	if e != nil || len(offers) != 1 {
		t.Fatal("real tool offer missing", e)
	}
	described := installedServiceCall(t, ctx, client, fabric.OperationDescribe, map[string]any{"selections": []map[string]any{{"ref": offers[0].Ref.String(), "expectedRevision": offers[0].Revision}}})
	if !bytes.Contains(described, []byte("9007199254740993")) {
		t.Fatal("schema precision lost", string(described))
	}
	page := installedNativePage(t, ctx, client, map[string]any{"target": offers[0].Ref.String(), "revision": offers[0].Revision, "input": json.RawMessage(`{"n":9007199254740993}`)})
	var output bytes.Buffer
	complete := false
	for {
		for _, f := range page.Frames {
			if f.Kind == fabric.FrameError {
				t.Fatal(f.Error)
			}
			output.Write(f.Data)
			complete = complete || f.Kind == fabric.FrameComplete
		}
		if complete {
			break
		}
		if !page.More || len(page.Frames) == 0 || page.Handle == "" {
			t.Fatal("genuine large output incomplete")
		}
		page = installedNativePage(t, ctx, client, map[string]any{"stream": map[string]any{"handle": page.Handle, "afterSequence": strconv.FormatUint(page.Frames[len(page.Frames)-1].Sequence, 10)}})
	}
	if !bytes.Contains(output.Bytes(), []byte(payload)) || effects.Load() != 1 {
		t.Fatal("original exact output/effect changed", output.Len(), effects.Load())
	}
	client.Close()
	if e = n.CloseContext(ctx); e != nil {
		t.Fatal(e)
	}
	n, e = OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary})
	if e != nil {
		t.Fatal(e)
	}
	if n.Installation.Store.AuthorityIdentity().StoreID != root.StoreID {
		t.Fatal("setup restart replaced root")
	}
	third, e := add("serviceaddmarker customer operations")
	if e != nil || third.Ref != first.Ref || third.Revision != first.Revision || effects.Load() != 1 {
		t.Fatal("restart replay changed setup or paid effect", e, third)
	}
	admin, err := fabricadmin.Dial(ctx, socket)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	var available atomic.Bool
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !available.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer func() { n.CloseContext(ctx); flaky.Close() }()
	incompleteInput, _ := json.Marshal(ServiceAddInput{URL: flaky.URL, Name: "Pending integration", Description: "recovers without a new identity"})
	request := fabricadmin.Request{Version: 1, ID: "incomplete-exact-setup", Operation: "service.add", Input: incompleteInput}
	response, err := admin.Call(ctx, request)
	if err != nil || response.Error != nil {
		t.Fatal(err, response.Error)
	}
	var incomplete ServiceAddResult
	if json.Unmarshal(response.Result, &incomplete) != nil || incomplete.State != "incomplete" || incomplete.Revision != "" {
		t.Fatal("unnegotiated endpoint falsely published", string(response.Result))
	}
	if _, err = n.Installation.Store.GetEndpoint(ctx, incomplete.Ref, ""); err == nil {
		t.Fatal("incomplete probe published endpoint")
	}
	available.Store(true)
	response, err = admin.Call(ctx, request)
	if err != nil || response.Error != nil {
		t.Fatal(err, response.Error)
	}
	var recovered ServiceAddResult
	if json.Unmarshal(response.Result, &recovered) != nil || recovered.Ref != incomplete.Ref || recovered.State != "connected" || effects.Load() != 1 {
		t.Fatal("same exact setup did not recover cleanly", string(response.Result), effects.Load())
	}
	// Explicit offline preparation publishes only the selected supported
	// protocol; a later exact retry opens its already-created catalog.
	var readyOffline atomic.Bool
	offlineRemote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !readyOffline.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer func() { n.CloseContext(ctx); offlineRemote.Close() }()
	offlineInput, _ := json.Marshal(ServiceAddInput{URL: offlineRemote.URL, Name: "Explicit offline selection", Description: "offlinefixturemarker", ProtocolVersion: "2025-11-25"})
	offlineRequest := fabricadmin.Request{Version: 1, ID: "explicit-offline-version", Operation: "service.add", Input: offlineInput}
	offlineResponse, err := admin.Call(ctx, offlineRequest)
	if err != nil || offlineResponse.Error != nil {
		t.Fatal(err, offlineResponse.Error)
	}
	var offlineSetup ServiceAddResult
	if json.Unmarshal(offlineResponse.Result, &offlineSetup) != nil || offlineSetup.State != "offline" || offlineSetup.Revision == "" {
		t.Fatal("explicit offline setup falsely connected", string(offlineResponse.Result))
	}
	readyOffline.Store(true)
	offlineResponse, err = admin.Call(ctx, offlineRequest)
	if err != nil || offlineResponse.Error != nil {
		t.Fatal(err, offlineResponse.Error)
	}
	var later ServiceAddResult
	if json.Unmarshal(offlineResponse.Result, &later) != nil || later.Ref != offlineSetup.Ref || later.Revision != offlineSetup.Revision || later.State != "connected" || effects.Load() != 1 {
		t.Fatal("offline retry reset catalog/ref or invoked tool", string(offlineResponse.Result))
	}

	for _, bad := range []ServiceAddInput{{URL: "https://user:secret@example.com/mcp", Description: "hidden URL credential"}, {URL: "https://example.com/mcp?token=secret", Description: "hidden query token"}, {URL: "http://example.com/mcp", Description: "unselected plaintext transport"}, {URL: remote.URL, Description: "unknown provider", CredentialSelector: "api-token"}, {URL: remote.URL, Description: "unknown protocol", ProtocolVersion: "not-a-supported-version"}} {
		raw, _ := json.Marshal(bad)
		result, err := admin.Call(ctx, fabricadmin.Request{Version: 1, ID: "reject-private-input", Operation: "service.add", Input: raw})
		if err != nil || result.Error == nil {
			t.Fatal("invalid/private input accepted", err, string(result.Result))
		}
	}
	if effects.Load() != 1 {
		t.Fatal("metadata retry/rejection called tools")
	}

}
