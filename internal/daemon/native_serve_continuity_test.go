//go:build linux || darwin

package daemon

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/accounts"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"github.com/pagnet-code/pagnet/internal/proc"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

type serveProofStatus struct {
	HolderReady bool                 `json:"holderReady"`
	OK          bool                 `json:"ok"`
	RunnerID    string               `json:"runnerId"`
	RunnerEpoch time.Time            `json:"runnerEpoch"`
	BootID      string               `json:"bootId"`
	Instance    domain.AgentInstance `json:"instance"`
	Commands    []struct {
		ID, Type, Status string
		Error            *string `json:"error"`
	} `json:"commands"`
}

func TestActualPagnetServeControllerReplacementPrivateTerminal(t *testing.T) {
	if os.Getenv("PAGNET_NATIVE_SERVE_PROOF") != "1" {
		t.Skip("requires explicit isolated PostgreSQL production serve proof")
	}
	t.Setenv("PAGNET_NATIVE_SERVE_HELPER", "1")
	t.Setenv("PAGNET_NATIVE_SOURCE_HELPER_RUNTIME", string(domain.RuntimeFakePersistent))
	helper, fixture := startNativeBackendHelper(t)
	root := privateDaemonStateDir(t)
	fixtureRoot := t.TempDir()
	workspace := filepath.Join(fixtureRoot, "workspace")
	bin := filepath.Join(fixtureRoot, "bin")
	for _, dir := range []string{workspace, bin} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	git := exec.Command("git", "init", "-q", workspace)
	if err := git.Run(); err != nil {
		t.Fatal("synthetic workspace initialization failed")
	}
	build := func(name, pkg, version string) string {
		target := filepath.Join(bin, name)
		args := []string{"build", "-o", target}
		if version != "" {
			args = append(args, "-ldflags=-X main.version="+version)
		}
		args = append(args, pkg)
		command := exec.Command("go", args...)
		command.Dir = "../.."
		command.Env = append(os.Environ(), "GOWORK=off")
		if err := command.Run(); err != nil {
			t.Fatal("actual proof binary build failed", err)
		}
		return target
	}
	aBinary := build("pagnet-a", "./cmd/pagnet", "proof-controller-a")
	bBinary := build("pagnet-b", "./cmd/pagnet", "proof-controller-b")
	build("pagnet-fake-runtime", "./cmd/pagnet-fake-runtime", "")
	if err := accounts.SaveGlobal(root, accounts.Global{CurrentAccount: "isolated"}); err != nil {
		t.Fatal(err)
	}
	accountDir := accounts.ConfigDir(root, "isolated")
	if err := os.MkdirAll(accountDir, 0700); err != nil {
		t.Fatal(err)
	}
	endpoint := strings.Replace(fixture.URL, "ws://", "http://", 1)
	endpoint = strings.TrimSuffix(endpoint, "/api/v1/hosts/ws")
	configuration := map[string]any{"serverUrl": endpoint, "credential": fixture.Credential, "hostId": fixture.HostID, "allowedRoots": []string{workspace}, "rootsMode": "allow_list", "debug": true, "autoUpdate": false}
	configRaw, _ := json.Marshal(configuration)
	if err := os.WriteFile(filepath.Join(accountDir, "config.yaml"), configRaw, 0600); err != nil {
		t.Fatal(err)
	}
	clear(configRaw)
	epochKey := [32]byte{}
	for i := range epochKey {
		epochKey[i] = 23
	}
	defer clear(epochKey[:])
	ring := &hostcrypto.Keyring{NetworkID: fixture.NetworkID, Epochs: []hostcrypto.KeyEpoch{{ID: fixture.EpochID, State: hostcrypto.EpochActive, Key: append([]byte(nil), epochKey[:]...), CreatedAt: time.Now().UTC()}}}
	defer clearNativeTerminalEpochKeys(ring.Epochs)
	if err := hostcrypto.SaveKeyring(root, ring); err != nil {
		t.Fatal(err)
	}

	manifest := func() *transport.NetworkEpochManifest {
		identity, err := hostcrypto.EnsureHostIdentity(root)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(identity.X25519Priv)
		defer clear(identity.Ed25519Priv)
		ring, err := hostcrypto.LoadKeyring(root, fixture.NetworkID)
		if err != nil {
			t.Fatal(err)
		}
		defer clearNativeTerminalEpochKeys(ring.Epochs)
		signer, err := hostcrypto.EpochPossessionSigner(ring, fixture.EpochID)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(signer)
		m := &transport.NetworkEpochManifest{Protocol: transport.NetworkEpochPossessionProtocol, TenantID: fixture.TenantID, NetworkID: fixture.NetworkID, EpochID: fixture.EpochID, VerifierPub: base64.StdEncoding.EncodeToString(signer.Public().(ed25519.PublicKey)), AuthorityHostID: fixture.HostID, AuthorityX25519: base64.StdEncoding.EncodeToString(identity.X25519Pub), AuthorityEd25519: base64.StdEncoding.EncodeToString(identity.Ed25519Pub)}
		m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(identity.Ed25519Signer(), m.SignatureBytes()))
		return m
	}
	manifest() // original valid local identity exists before real inventory publication
	start := func(binary string) (*exec.Cmd, <-chan error) {
		command := exec.Command(binary, "serve", "--state-dir", root, "--debug", "--no-auto-update")
		command.Dir = workspace
		command.Env = append(os.Environ(), "PATH="+bin+":/usr/local/bin:/usr/bin:/bin", "HOME="+root, "PAGNET_RUNTIME_ENV=PAGNET_FAKE_TUI_TICK_MS=50,PAGNET_FAKE_TUI_BOOT_BYTES=65536")
		// Credentials, encrypted keys and PTY bytes never enter test logs.
		if err := command.Start(); err != nil {
			t.Fatal("actual serve failed to start", err)
		}
		done := make(chan error, 1)
		go func() { defer close(done); done <- command.Wait() }()
		t.Cleanup(func() {
			_ = command.Process.Kill()
			<-done
		})
		return command, done
	}
	status := func() serveProofStatus {
		var value serveProofStatus
		helper.call(t, map[string]any{"action": "serve_status"}, &value)
		return value
	}
	wait := func(label string, predicate func(serveProofStatus) bool) serveProofStatus {
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			value := status()
			if predicate(value) {
				return value
			}
			time.Sleep(50 * time.Millisecond)
		}
		last := status()
		for _, command := range last.Commands {
			t.Log("bounded command diagnostic", command.Type, command.Status)
		}
		registry, err := OpenNativeWorkerRegistry(root)
		if err == nil {
			records, err := registry.List()
			if err == nil {
				for _, record := range records {
					t.Log("bounded worker diagnostic", record.LaunchState)
				}
			}
			registry.Close()
		}
		t.Fatal("actual serve proof timed out waiting for " + label)
		return serveProofStatus{}
	}
	t.Log("phase: start controller A and await production admission")
	a, aDone := start(aBinary)
	current := wait("controller A backend admission", func(s serveProofStatus) bool { return s.RunnerID != "" && s.HolderReady })
	t.Log("phase: prepare current holder crypto metadata")
	var prepared map[string]any
	helper.call(t, map[string]any{"action": "prepare_serve", "runnerId": current.RunnerID, "runnerEpoch": current.RunnerEpoch, "bootId": current.BootID, "manifest": manifest()}, &prepared)
	if prepared["ok"] != true {
		t.Fatal("actual holder preparation rejected", prepared["errorCode"])
	}
	var launch struct {
		OK         bool   `json:"ok"`
		InstanceID string `json:"instanceId"`
		CommandID  string `json:"commandId"`
	}
	t.Log("phase: production launch route")
	helper.call(t, map[string]any{"action": "real_launch", "workspace": workspace}, &launch)
	if !launch.OK || launch.InstanceID == "" || launch.CommandID == "" {
		t.Fatal("production launch lacked immutable command/instance identity")
	}
	wait("original native launch", func(s serveProofStatus) bool {
		for _, c := range s.Commands {
			if c.ID == launch.CommandID && c.Status == "acked" {
				return true
			}
		}
		return false
	})
	registry, err := OpenNativeWorkerRegistry(root)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	record, err := registry.Lookup(launch.InstanceID)
	if err != nil {
		t.Fatal("actual serve did not reserve original worker", err)
	}
	socket, err := sessionworker.SocketPath(record.Dir)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	workerPID, _, err := localpeer.Owner(peer)
	peer.Close()
	if err != nil {
		t.Fatal(err)
	}
	workerBirth, err := proc.StartIdentity(workerPID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if birth, err := proc.StartIdentity(workerPID); err == nil && birth == workerBirth {
			_ = syscall.Kill(workerPID, syscall.SIGTERM)
		}
	})
	type attached struct {
		SessionID      string `json:"attachSessionId"`
		WSURL          string `json:"wsUrl"`
		Ticket         string `json:"wsTicket"`
		TerminalCrypto struct {
			Required            bool `json:"required"`
			TenantID, NetworkID string
		} `json:"terminalCrypto"`
	}
	attach := func() (*websocket.Conn, transport.TerminalSessionKeyPayload, terminalSessionSecret, []byte) {
		var result struct {
			Attach attached `json:"attach"`
		}
		helper.call(t, map[string]any{"action": "attach_terminal"}, &result)
		if !result.Attach.TerminalCrypto.Required {
			t.Fatal("production terminal descriptor permitted plaintext")
		}
		address := result.Attach.WSURL
		if address == "" {
			address = "ws" + strings.TrimPrefix(endpoint, "http") + "/api/v1/attach/" + result.Attach.SessionID + "/ws?ticket=" + url.QueryEscape(result.Attach.Ticket) + "&instance=" + launch.InstanceID
		}
		conn, _, err := websocket.DefaultDialer.Dial(address, nil)
		if err != nil {
			t.Fatal("production terminal websocket failed", err)
		}
		t.Cleanup(func() { conn.Close() })
		conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		// Decode frame maps separately because output/bootstrap share metadata fields.
		for {
			var raw json.RawMessage
			if err := conn.ReadJSON(&raw); err != nil {
				t.Fatal("private terminal bootstrap missing", err)
			}
			var typ struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
				Error  string `json:"error"`
			}
			json.Unmarshal(raw, &typ)
			if typ.Type == "terminal_key" {
				var meta transport.TerminalSessionKeyPayload
				if json.Unmarshal(raw, &meta) != nil || meta.Envelope == nil || meta.AAD == nil {
					t.Fatal("malformed bootstrap")
				}
				objectID, err := e2ee.TerminalKeyObjectID(meta.InstanceID, meta.SessionID, meta.NativeGeneration, meta.SessionKeyID)
				if err != nil || meta.InstanceID != launch.InstanceID || meta.SessionID != result.Attach.SessionID || meta.AAD.ObjectID != objectID || meta.AAD.ObjectType != e2ee.ObjectTypeRuntimeTerminalSession || meta.AAD.TenantID != fixture.TenantID || meta.AAD.NetworkID != fixture.NetworkID || meta.AAD.KeyEpochID != fixture.EpochID {
					t.Fatal("bootstrap changed original authorized scope")
				}
				plain, err := e2ee.Decrypt(*meta.Envelope, epochKey, *meta.AAD)
				if err != nil {
					t.Fatal("bootstrap did not decrypt with original authorized epoch", err)
				}
				var secret terminalSessionSecret
				if json.Unmarshal(plain, &secret) != nil {
					t.Fatal("bootstrap secret invalid")
				}
				clear(plain)
				if secret.Format != e2ee.TerminalSessionFormat || secret.InstanceID != meta.InstanceID || secret.SessionID != meta.SessionID || secret.NativeGeneration != meta.NativeGeneration || secret.SessionKeyID != meta.SessionKeyID || secret.RealEpochID != fixture.EpochID || secret.OutputKey == secret.InputKey {
					t.Fatal("private bootstrap secret changed original scope")
				}
				output, err := base64.StdEncoding.DecodeString(secret.OutputKey)
				if err != nil || len(output) != 32 {
					t.Fatal("direction key invalid")
				}
				return conn, meta, secret, output
			}
			if typ.Type == "closed" || typ.Type == "error" {
				for _, command := range status().Commands {
					if command.Type == transport.MsgAttachTerminal && command.Error != nil {
						for _, class := range []string{"retired", "crypto", "ready", "scope", "unavailable", "permission", "deadline", "activation", "conflict", "invalid", "terminal", "epoch", "generation", "native", "canceled", "fenced", "busy", "authorization", "admission", "confirmation", "sequence", "does not expose", "was detached", "detached during activation", "viewer capacity", "older than retained", "authorization changed", "operation cancelled"} {
							if strings.Contains(strings.ToLower(*command.Error), class) {
								t.Log("public attach failure class", command.Status, class)
							}
						}
					}
				}
				t.Fatal("production attach ended before private bootstrap", typ.Type, typ.Reason)
			}
		}
	}
	t.Log("phase: original A private terminal attach")
	connA, metaA, secretA, keyA := attach()
	defer clear(keyA)
	if secretA.NativeSessionID == "" || secretA.NativeGeneration == "" || secretA.NativeStartIdentity == "" {
		t.Fatal("original terminal source proof incomplete")
	}

	// Read the original owner-local supervised record and prove the process is
	// still physically live; a cached record alone cannot satisfy this assertion.
	var originalNativePID int
	records, err := filepath.Glob(filepath.Join(record.Dir, "proc-ownership", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range records {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var captured struct {
			InstanceID string `json:"instance_id"`
			PID        int    `json:"pid"`
			Identity   string `json:"identity"`
		}
		if json.Unmarshal(raw, &captured) != nil {
			t.Fatal("original process record invalid")
		}
		clear(raw)
		if captured.InstanceID == launch.InstanceID && captured.Identity == secretA.NativeStartIdentity {
			birth, err := proc.StartIdentity(captured.PID)
			if err == nil && birth == captured.Identity {
				originalNativePID = captured.PID
				break
			}
		}
	}
	if originalNativePID <= 0 || originalNativePID == workerPID {
		t.Fatal("original live native PID/birth was not proved")
	}
	// Controller termination is deliberately abrupt. Only this synthetic controller
	// is killed; its detached original worker/native runtime must remain live.
	if err := a.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-aDone
	connA.Close()
	if birth, err := proc.StartIdentity(workerPID); err != nil || birth != workerBirth {
		t.Fatal("controller exit replaced original worker")
	}
	_, _ = start(bBinary)
	second := wait("controller B backend admission", func(s serveProofStatus) bool {
		return s.RunnerID != "" && s.RunnerID != current.RunnerID && s.HolderReady
	})
	helper.call(t, map[string]any{"action": "prepare_serve", "runnerId": second.RunnerID, "runnerEpoch": second.RunnerEpoch, "bootId": second.BootID, "manifest": manifest()}, &prepared)
	t.Log("phase: replacement B private terminal attach")
	connB, metaB, secretB, keyB := attach()
	defer clear(keyB)
	if secretA.NativeSessionID != secretB.NativeSessionID || secretA.NativeGeneration != secretB.NativeGeneration || secretA.NativeStartIdentity != secretB.NativeStartIdentity || secretA.SourceOriginID != secretB.SourceOriginID {
		t.Fatal("controller B changed original runtime source")
	}
	if metaA.SessionID == metaB.SessionID || metaA.SessionKeyID == metaB.SessionKeyID {
		t.Fatal("replacement view reused private input authority")
	}
	var outputKey [32]byte
	copy(outputKey[:], keyB)
	defer clear(outputKey[:])
	// Each keystroke batch is encrypted locally under the attach-bound input
	// key. This production websocket path does not use a key RPC or input ACK.
	inputBytes, err := base64.StdEncoding.Strict().DecodeString(secretB.InputKey)
	if err != nil || len(inputBytes) != 32 {
		t.Fatal("input direction key invalid")
	}
	var inputKey [32]byte
	copy(inputKey[:], inputBytes)
	clear(inputBytes)
	defer clear(inputKey[:])
	marker := []byte("isolated-original-pty-continuity")
	defer clear(marker)
	input := append(append([]byte(nil), marker...), '\n')
	defer clear(input)
	inputAAD := *metaB.AAD
	inputAAD.ObjectType = e2ee.ObjectTypeRuntimeTerminalInput
	inputAAD.KeyEpochID = metaB.SessionKeyID
	inputAAD.ObjectID, err = e2ee.TerminalFrameObjectID(metaB.InstanceID, metaB.SessionID, metaB.NativeGeneration, metaB.SessionKeyID, "input", false, 1)
	if err != nil {
		t.Fatal(err)
	}
	inputEnvelope, err := e2ee.Encrypt(input, inputKey, inputAAD)
	if err != nil {
		t.Fatal("local input encryption failed", err)
	}
	if err := connB.WriteJSON(struct {
		Type string `json:"type"`
		transport.TerminalInputPayload
	}{"input", transport.TerminalInputPayload{InstanceID: metaB.InstanceID, SessionID: metaB.SessionID, NativeGeneration: metaB.NativeGeneration, SessionKeyID: metaB.SessionKeyID, Seq: 1, Envelope: &inputEnvelope, AAD: &inputAAD}}); err != nil {
		t.Fatal("encrypted production terminal input failed", err)
	}
	// Keep only a bounded trailing window when a marker crosses PTY frames.
	trailing := make([]byte, 0, 4096)
	defer clear(trailing)

	for {
		var raw json.RawMessage
		if err := connB.ReadJSON(&raw); err != nil {
			t.Fatal("replacement view lacks original terminal bytes", err)
		}
		var frame struct {
			Type string `json:"type"`
			transport.TerminalOutputPayload
		}
		if json.Unmarshal(raw, &frame) != nil {
			t.Fatal("output frame invalid")
		}
		if frame.Type != "terminal" || frame.Envelope == nil {
			continue
		}
		if frame.AAD == nil || frame.Data != "" || frame.NativeGeneration != metaB.NativeGeneration || frame.SessionKeyID != metaB.SessionKeyID {
			t.Fatal("replacement terminal leaked or relabeled source")
		}
		plain, err := e2ee.Decrypt(*frame.Envelope, outputKey, *frame.AAD)
		if err != nil {
			t.Fatal("original terminal output integrity failed", err)
		}
		if len(plain) > 4096 {
			clear(trailing)
			trailing = append(trailing[:0], plain[len(plain)-4096:]...)
		} else {
			if len(trailing)+len(plain) > 4096 {
				n := len(trailing) + len(plain) - 4096
				copy(trailing, trailing[n:])
				clear(trailing[len(trailing)-n:])
				trailing = trailing[:len(trailing)-n]
			}
			trailing = append(trailing, plain...)
		}
		clear(plain)
		if bytes.Contains(trailing, marker) {
			break
		}
	}
	if birth, err := proc.StartIdentity(workerPID); err != nil || birth != workerBirth {
		t.Fatal("terminal reattach replaced original worker")
	}
	if birth, err := proc.StartIdentity(originalNativePID); err != nil || birth != secretB.NativeStartIdentity {
		t.Fatal("controller replacement changed original native PID/birth")
	}
	t.Log("actual serve A→B retains original worker/runtime session, generation, birth and encrypted terminal source; fresh private view keys and locally encrypted input/output")
}
