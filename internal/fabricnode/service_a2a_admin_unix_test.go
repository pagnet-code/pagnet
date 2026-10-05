//go:build linux || darwin

package fabricnode

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/internal/fabricclient"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
)

func TestActualA2AServiceAddCLIExactInterfaceNoSetupEffectAndRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	private, e := os.MkdirTemp("", "pgn-a2a-add-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(private)
	dir, socket := filepath.Join(private, "domain"), filepath.Join(private, "node.sock")
	installation, e := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if e != nil {
		t.Fatal(e)
	}
	if e = InitializeDefaultServices(ctx, installation); e != nil {
		t.Fatal(e)
	}
	root := installation.Store.AuthorityIdentity()
	if e = installation.Close(); e != nil {
		t.Fatal(e)
	}
	binary := filepath.Join(private, "pagnet")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/pagnet")
	build.Dir = "../.."
	if output, e := build.CombinedOutput(); e != nil {
		t.Fatal(e, string(output))
	}
	var effects atomic.Int32
	server := httptest.NewServer(a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(a2asrv.AgentExecutorFunc(func(_ context.Context, c *a2asrv.ExecutorContext) iter.Seq2[sdk.Event, error] {
		return func(yield func(sdk.Event, error) bool) {
			effects.Add(1)
			task := sdk.NewSubmittedTask(c, c.Message)
			if !yield(task, nil) {
				return
			}
			if !yield(sdk.NewArtifactEvent(task, sdk.NewDataPart(map[string]any{"large": uint64(9007199254740993)})), nil) {
				return
			}
			yield(sdk.NewStatusUpdateEvent(task, sdk.TaskStateCompleted, nil), nil)
		}
	}))))
	defer server.Close()
	selected := sdk.NewAgentInterface(server.URL, sdk.TransportProtocolJSONRPC)
	card := sdk.AgentCard{Name: "private-provider-card-name", Version: "1", Capabilities: sdk.AgentCapabilities{Streaming: true}, SupportedInterfaces: []*sdk.AgentInterface{selected}}
	cardRaw, _ := json.Marshal(card)
	cardPath := filepath.Join(private, "card.json")
	if e = os.WriteFile(cardPath, cardRaw, 0600); e != nil {
		t.Fatal(e)
	}
	notices := make(chan struct{}, 64)
	n, e := OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary, ObserveIndexPublication: func(more bool, e error) {
		if !more && e == nil {
			select {
			case notices <- struct{}{}:
			default:
			}
		}
	}})
	if e != nil {
		t.Fatal(e)
	}
	defer func() { n.CloseContext(ctx) }()
	add := func(description string) (ServiceAddResult, error) {
		command := exec.CommandContext(ctx, binary, "--json", "service", "add", server.URL, "--a2a-card", cardPath, "--name", "Invoice expert", "--description", description, "--socket", socket, "--request-id", "exact-a2a-setup")
		command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + private, "MCP_TOKEN=unselected-secret"}
		raw, e := command.CombinedOutput()
		if e != nil {
			return ServiceAddResult{}, fmt.Errorf("%w: %s", e, raw)
		}
		if bytes.Contains(raw, []byte(server.URL)) || bytes.Contains(raw, []byte(card.Name)) || bytes.Contains(raw, []byte("unselected-secret")) {
			t.Fatal("private setup leaked", string(raw))
		}
		var result ServiceAddResult
		e = fabric.DecodeJSON(raw, &result)
		return result, e
	}
	first, e := add("a2aaddmarker invoice retrieval")
	if e != nil || first.State != "configured" || first.ProtocolVersion != string(sdk.Version) || effects.Load() != 0 {
		t.Fatal("setup must not claim remote health or execute", e, first, effects.Load())
	}
	second, e := add("a2aaddmarker invoice retrieval")
	if e != nil || second != first || effects.Load() != 0 {
		t.Fatal("setup retry changed identity/effect", e, second)
	}
	if _, e = add("changed setup"); e == nil {
		t.Fatal("setup id accepted conflicting input")
	}
	d, e := n.Node.Store.GetEndpoint(ctx, first.Ref, first.Revision)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(d)
	if bytes.Contains(raw, []byte(server.URL)) || bytes.Contains(raw, []byte(card.Name)) {
		t.Fatal("private card leaked in descriptor")
	}
	client, e := fabricclient.Dial(ctx, socket, fabrichost.Authentication{Type: "fabric.auth", Mode: "owner"})
	if e != nil {
		t.Fatal(e)
	}
	for {
		select {
		case <-notices:
		case <-ctx.Done():
			t.Fatal("catalog publication missing")
		}
		var result fabric.DiscoverResult
		raw := installedServiceCall(t, ctx, client, fabric.OperationDiscover, map[string]any{"query": "a2aaddmarker", "limit": 10})
		if e := fabric.DecodeJSON(raw, &result); e != nil {
			t.Fatal(e)
		}
		if len(result.Candidates) > 0 {
			break
		}
	}
	described := installedServiceCall(t, ctx, client, fabric.OperationDescribe, map[string]any{"selections": []map[string]any{{"ref": first.Ref.String(), "expectedRevision": first.Revision}}})
	if !bytes.Contains(described, []byte("extensions.pagnet.agent.input_schema")) || !bytes.Contains(described, []byte("associationInvocation")) || bytes.Contains(described, []byte(server.URL)) || bytes.Contains(described, []byte(card.Name)) || effects.Load() != 0 {
		t.Fatal("describe omitted adapter grammar, disclosed private card or executed target", string(described))
	}
	page := installedNativePage(t, ctx, client, map[string]any{"target": first.Ref.String(), "revision": first.Revision, "input": json.RawMessage(`{"operation":"send","mode":"stream","parts":[{"text":"Retrieve invoice"}]}`)})
	var output bytes.Buffer
	for {
		terminal := false
		for _, frame := range page.Frames {
			if frame.Kind == fabric.FrameError {
				t.Fatal(frame.Error)
			}
			output.Write(frame.Data)
			terminal = terminal || frame.Kind == fabric.FrameComplete
		}
		if terminal {
			break
		}
		if !page.More || len(page.Frames) == 0 || page.Handle == "" {
			t.Fatal("actual A2A stream incomplete")
		}
		page = installedNativePage(t, ctx, client, map[string]any{"stream": map[string]any{"handle": page.Handle, "afterSequence": strconv.FormatUint(page.Frames[len(page.Frames)-1].Sequence, 10)}})
	}
	if effects.Load() != 1 || !bytes.Contains(output.Bytes(), []byte("9007199254740993")) {
		t.Fatal("original SDK effect/precision lost", effects.Load(), output.String())
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
		t.Fatal("restart replaced original root")
	}
	third, e := add("a2aaddmarker invoice retrieval")
	if e != nil || third != first || effects.Load() != 1 {
		t.Fatal("restart setup repeated paid effect/identity", e, third, effects.Load())
	}
}

func TestA2AServiceAddRejectsUnselectedInterfacesAndPrivateURLs(t *testing.T) {
	endpoint := sdk.NewAgentInterface("https://example.com/agent", sdk.TransportProtocolJSONRPC)
	card, _ := json.Marshal(sdk.AgentCard{Name: "private card", Version: "1", SupportedInterfaces: []*sdk.AgentInterface{endpoint}})
	for _, url := range []string{"https://other.example/agent", "https://user:secret@example.com/agent", "https://example.com/agent?token=secret", "http://example.com/agent"} {
		input := A2AServiceAddInput{URL: url, Description: "invoice expert", Card: card}
		if _, _, e := validateA2AServiceAdd(&input); e == nil {
			t.Fatal("unselected/private transport accepted", url)
		}
	}
}
