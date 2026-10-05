//go:build linux || darwin

package fabricnode

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/internal/fabricagent"
	"github.com/pagnet-code/pagnet/internal/fabricclient"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

// The selected executable speaks the documented Claude machine interface. The
// actual ClaudePersistent driver, Supervisor, source journal and managed kernel
// boundary run unchanged; this performs no model/provider request.
const selectedClaudeFixture = `package main
import("bufio";"encoding/json";"fmt";"os";"strings")
func main(){ sid:=""; config:=""; standing:=""; for i,a:=range os.Args { if strings.HasPrefix(a,"--session-id="){sid=strings.TrimPrefix(a,"--session-id=")};if strings.HasPrefix(a,"--resume="){sid=strings.TrimPrefix(a,"--resume=")};if a=="--mcp-config"&&i+1<len(os.Args){config=os.Args[i+1]};if a=="--append-system-prompt-file"&&i+1<len(os.Args){standing=os.Args[i+1]} }; if sid==""||config==""||standing==""{os.Exit(12)}; var cfg struct{Servers map[string]any ` + "`json:\"mcpServers\"`" + `}; if json.Unmarshal([]byte(config),&cfg)!=nil||len(cfg.Servers)!=1||cfg.Servers["pagnet-fabric"]==nil{os.Exit(13)}; role,e:=os.ReadFile(standing);if e!=nil||string(role)!="private-role-DO-NOT-PUBLISH"{os.Exit(14)}; emit:=func(v any){b,_:=json.Marshal(v);fmt.Println(string(b))}; s:=bufio.NewScanner(os.Stdin);for s.Scan(){var m struct{Type string; RequestID string ` + "`json:\"request_id\"`" + `; Message struct{Content string}};if json.Unmarshal(s.Bytes(),&m)!=nil{os.Exit(15)};switch m.Type{case "control_request":emit(map[string]any{"type":"control_response","response":map[string]any{"subtype":"success","request_id":m.RequestID,"response":map[string]any{}}});case "user":f,_:=os.OpenFile("effects",os.O_CREATE|os.O_APPEND|os.O_WRONLY,0600);fmt.Fprintln(f,m.Message.Content);f.Close();emit(map[string]any{"type":"system","subtype":"init","session_id":sid});emit(map[string]any{"type":"user","session_id":sid});emit(map[string]any{"type":"assistant","session_id":sid,"message":map[string]any{"content":[]map[string]string{{"type":"text","text":m.Message.Content}}}});emit(map[string]any{"type":"result","session_id":sid,"result":m.Message.Content,"usage":map[string]int{"input_tokens":1,"output_tokens":1}})}}}
`

func TestAgentCreateProvisionsActualClaudeWithoutPaidLaunchAndRetainsWorker(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	private, e := os.MkdirTemp("", "pgn-agent-runtime-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(private)
	bin, workspace := filepath.Join(private, "bin"), filepath.Join(private, "workspace")
	for _, p := range []string{bin, workspace} {
		if e = os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	goBinary, e := exec.LookPath("go")
	if e != nil {
		t.Fatal(e)
	}
	rootDir, _ := filepath.Abs("../..")
	binary := filepath.Join(bin, "pagnet")
	build := exec.CommandContext(ctx, goBinary, "build", "-o", binary, "./cmd/pagnet")
	build.Dir = rootDir
	if out, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build product %v %s", e, out)
	}
	fixture := filepath.Join(bin, "claude.go")
	if e = os.WriteFile(fixture, []byte(selectedClaudeFixture), 0600); e != nil {
		t.Fatal(e)
	}
	build = exec.CommandContext(ctx, goBinary, "build", "-o", filepath.Join(bin, "claude"), fixture)
	if out, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build selected native protocol %v %s", e, out)
	}
	t.Setenv("HOME", workspace)
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	dir, socket := filepath.Join(private, "authority"), filepath.Join(private, "node.sock")
	initial, e := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if e != nil {
		t.Fatal(e)
	}
	root := initial.Store.AuthorityIdentity()
	if e = initial.Close(); e != nil {
		t.Fatal(e)
	}
	published := make(chan error, 16)
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
	select {
	case e := <-published:
		if e != nil {
			t.Fatal(e)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	create := func(extra ...string) AgentSetupResult {
		args := []string{"--json", "agent", "create", "Actual Claude", "--description", "Published assistant", "--runtime", "claude-code", "--role", "private-role-DO-NOT-PUBLISH", "--workspace", workspace, "--socket", socket, "--request-id", "real-agent"}
		args = append(args, extra...)
		cmd := exec.CommandContext(ctx, binary, args...)
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("actual CLI creation %v %s", e, out)
		}
		var result AgentSetupResult
		if e = fabric.DecodeJSON(out, &result); e != nil {
			t.Fatalf("creation JSON %v %s", e, out)
		}
		return result
	}
	setup := create()
	if setup.State != "configured" || setup.Runtime != domain.RuntimeClaudeCode {
		t.Fatal("not configured", setup.State)
	}
	owner, e := n.Installation.Operator(ctx)
	if e != nil {
		t.Fatal(e)
	}
	agents, e := fabricagent.NewRetainedAgentStore(ctx, n.Installation.Store, owner, n.Installation.Keys)
	if e != nil {
		t.Fatal(e)
	}
	retained, e := agents.Get(ctx, setup.Ref)
	if e != nil {
		t.Fatal(e)
	}
	if retained.Instance.PID != nil || retained.Instance.RuntimeSessionID != nil || retained.Instance.Status != "" || retained.Instance.NetworkID != "" || retained.Instance.HostID != "" {
		t.Fatal("configured record fabricated native/cloud state")
	}
	if _, e = os.Stat(retained.Profile.Directory); !os.IsNotExist(e) {
		t.Fatal("creation launched or materialized worker", e)
	}
	if _, e = os.Stat(filepath.Join(workspace, "effects")); !os.IsNotExist(e) {
		t.Fatal("creation submitted paid/native turn", e)
	}
	retry := create()
	if retry.Ref != setup.Ref || retry.Revision != setup.Revision {
		t.Fatal("exact setup retry replaced identity")
	}
	changed := exec.CommandContext(ctx, binary, "--json", "agent", "create", "Actual Claude", "--description", "Published assistant", "--runtime", "claude-code", "--role", "changed-role", "--workspace", workspace, "--socket", socket, "--request-id", "real-agent")
	if _, e = changed.CombinedOutput(); e == nil {
		t.Fatal("changed setup reused original identity")
	}
	changedSpec := retained.Profile.Native
	changedSpec.StandingInstructions = "changed-role"
	if _, e = agents.Reserve(ctx, setup.Ref, retained.InputSHA, changedSpec, filepath.Dir(retained.Profile.Directory)); e == nil {
		t.Fatal("changed execution selection reused pinned setup commitment")
	}
	unchanged, e := agents.Get(ctx, setup.Ref)
	if e != nil || unchanged.Instance.ID != retained.Instance.ID || unchanged.Definition.ID != retained.Definition.ID || unchanged.Profile.Worker != retained.Profile.Worker {
		t.Fatal("rejected retry mutated original private instance", e)
	}
	desc, e := n.Node.Store.GetEndpoint(ctx, setup.Ref, setup.Revision)
	if e != nil {
		t.Fatal(e)
	}
	publishedJSON, _ := json.Marshal(desc)
	for _, secret := range []string{workspace, binary, "private-role-DO-NOT-PUBLISH", string(retained.Definition.ID)} {
		if strings.Contains(string(publishedJSON), secret) {
			t.Fatal("private agent configuration leaked")
		}
	}
	client, e := fabricclient.Dial(ctx, socket, fabrichost.Authentication{Type: "fabric.auth", Mode: "owner"})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	select {
	case e := <-published:
		if e != nil {
			t.Fatal(e)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	discoverArgs, _ := json.Marshal(map[string]any{"query": "Published assistant", "limit": 10})
	discovered, e := client.Call(ctx, fabric.OperationDiscover, discoverArgs)
	if e != nil || discovered.IsError || !strings.Contains(discovered.Content[0].(*sdk.TextContent).Text, setup.Ref.String()) {
		t.Fatal("event-published agent missing before invocation", e)
	}
	describeArgs, _ := json.Marshal(fabric.DescribeRequest{Selections: []fabric.DescribeSelection{{Ref: setup.Ref, ExpectedRevision: setup.Revision}}})
	described, e := client.Call(ctx, fabric.OperationDescribe, describeArgs)
	if e != nil || described.IsError || !strings.Contains(described.Content[0].(*sdk.TextContent).Text, "local.native") {
		t.Fatal("actual bound description unavailable", e)
	}
	if out := installedNativeOutput(t, ctx, client, setup.Ref, setup.Revision, "exact user prompt"); out != "exact user prompt" {
		t.Fatal("direct native input changed", out)
	}
	handle, e := n.Runtime.Resolver.Resolve(ctx, owner, desc)
	if e != nil {
		t.Fatal(e)
	}
	before, e := handle.Client.Call(ctx, sessionworker.LocalRequest{Type: "snapshot"})
	if e != nil || before.Snapshot == nil || before.Snapshot.PID == 0 || before.Snapshot.NativeSessionID == "" {
		t.Fatal("missing genuine kernel/native source", e)
	}
	process, e := handle.Client.OwnerProcess()
	if e != nil {
		t.Fatal(e)
	}
	child, _ := os.FindProcess(process.PID)
	defer child.Signal(os.Interrupt)
	client.Close()
	if e = n.CloseContext(ctx); e != nil {
		t.Fatal(e)
	}
	n, e = OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary})
	if e != nil {
		t.Fatal(e)
	}
	owner, e = n.Installation.Operator(ctx)
	if e != nil {
		t.Fatal(e)
	}
	agents, e = fabricagent.NewRetainedAgentStore(ctx, n.Installation.Store, owner, n.Installation.Keys)
	if e != nil {
		t.Fatal(e)
	}
	reopened, e := agents.Get(ctx, setup.Ref)
	if e != nil || reopened.Instance.ID != retained.Instance.ID || reopened.Definition.ID != retained.Definition.ID || reopened.Profile.Worker != retained.Profile.Worker {
		t.Fatal("restart changed private lifecycle IDs", e)
	}
	client, e = fabricclient.Dial(ctx, socket, fabrichost.Authentication{Type: "fabric.auth", Mode: "owner"})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	if out := installedNativeOutput(t, ctx, client, setup.Ref, setup.Revision, "second exact prompt"); out != "second exact prompt" {
		t.Fatal(out)
	}
	handle, e = n.Runtime.Resolver.Resolve(ctx, owner, desc)
	if e != nil {
		t.Fatal(e)
	}
	after, e := handle.Client.Call(ctx, sessionworker.LocalRequest{Type: "snapshot"})
	if e != nil || after.Snapshot.PID != before.Snapshot.PID || after.Snapshot.NativeSessionID != before.Snapshot.NativeSessionID || n.Installation.Store.AuthorityIdentity().StoreID != root.StoreID {
		t.Fatal("restart forked original worker", e)
	}
	effects, e := os.ReadFile(filepath.Join(workspace, "effects"))
	if e != nil || string(effects) != "exact user prompt\nsecond exact prompt\n" {
		t.Fatal("duplicate/changed native effect", e, string(effects))
	}
	// The actual maintained SDK discovers the new runtime-bound identity without
	// manual registry/index synchronization in the product path.
	raw, _ := json.Marshal(map[string]any{"query": "Published assistant", "limit": 10})
	result, e := client.Call(ctx, fabric.OperationDiscover, raw)
	if e != nil || result.IsError {
		t.Fatal("actual discovery", e)
	}
	if !strings.Contains(result.Content[0].(*sdk.TextContent).Text, setup.Ref.String()) {
		t.Fatal("agent not discoverable")
	}
}
