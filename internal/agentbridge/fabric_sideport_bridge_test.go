//go:build linux || darwin

package agentbridge

// The sideport reaches the bridge only through the REAL authenticated
// handshake: the daemon's auth_ok may carry "sideport" (advertised by the
// owner-administration association after every identity check has passed).
// These tests pin the client side of that contract: capture when valid,
// absence on an ordinary bridge, explicit refusal of a malformed sideport
// (the bridge still serves — it keeps its original tools), and the fact
// that unauthenticated dials get no sideport at all.

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

// sideportTestServer speaks the real daemon bridge protocol on a real unix
// socket: it validates the presented activation nonce (rejecting anything
// else with the daemon's refusal line) and advertises the optional
// sideport JSON in the auth_ok, exactly where the daemon puts it.
func sideportTestServer(t *testing.T, wantNonce, sideportRaw string) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "pagnetd.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				r := bufio.NewReader(c)
				line, readErr := readLine(r)
				var auth struct {
					Type  string `json:"type"`
					Kind  string `json:"kind"`
					Nonce string `json:"nonce"`
				}
				if readErr != nil || json.Unmarshal(line, &auth) != nil || auth.Type != "auth" || auth.Kind != "worker" || auth.Nonce != wantNonce {
					c.Write([]byte(`{"type":"error","error":"bridge nonce invalid for this instance (identity rejected)"}` + "\n"))
					return
				}
				ack := `{"type":"auth_ok","instanceId":"inst-sp"`
				if sideportRaw != "" {
					ack += `,"sideport":` + sideportRaw
				}
				ack += `}`
				c.Write(append([]byte(ack), '\n'))
				for { // answer the original tools; hold until the bridge closes
					line, err := readLine(r)
					if err != nil {
						return
					}
					var req struct {
						ID string `json:"id"`
					}
					if err := json.Unmarshal([]byte(line), &req); err == nil && req.ID != "" {
						c.Write([]byte(`{"id":"` + req.ID + `","ok":true,"result":{}}` + "\n"))
					}
				}
			}(c)
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		wg.Wait()
		_ = os.Remove(socket)
	})
	return socket
}

func sideportJSON(t *testing.T, socket string) string {
	t.Helper()
	ref, err := fabric.NewEndpointRef(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(HostedFabricSideport{Socket: socket, Endpoint: ref, Generation: "gen-sp"})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// A valid sideport in the real auth_ok is captured and exposed; the bridge
// works normally alongside it.
func TestBridgeSideportAdvertisedOnlyThroughAuthOK(t *testing.T) {
	// The sideport points at a (currently closed) socket path — the bridge
	// captures it; opening it is RunBridge's job.
	sideSocket := filepath.Join(t.TempDir(), "node.sock")
	socket := sideportTestServer(t, "nonce-sp", sideportJSON(t, sideSocket))

	b, err := Dial(socket, "inst-sp", "net-1", "nonce-sp", "worker")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	sp, ok := b.Sideport()
	if !ok {
		t.Fatal("sideport from the authenticated auth_ok was not captured")
	}
	if sp.Socket != sideSocket || sp.Generation != "gen-sp" {
		t.Fatalf("sideport = %+v, want socket %q generation gen-sp", sp, sideSocket)
	}
	if sp.Endpoint.String() == "" {
		t.Fatal("sideport endpoint ref was lost in the handshake")
	}
}

// An ordinary bridge (no owner-administration association on the daemon
// side) advertises nothing — the bridge must report "no sideport", not a
// zero value that looks valid.
func TestBridgeOrdinaryHandshakeHasNoSideport(t *testing.T) {
	socket := sideportTestServer(t, "nonce-plain", "")
	b, err := Dial(socket, "inst-sp", "net-1", "nonce-plain", "worker")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, ok := b.Sideport(); ok {
		t.Fatal("ordinary authenticated bridge reports a sideport")
	}
}

// A malformed sideport (a socket path beyond the unix bound) must be
// EXPLICITLY ignored: the bridge still comes up (the original tools keep
// working) and reports no sideport — RunBridge then logs the refusal
// instead of dialing it.
func TestBridgeMalformedSideportIgnoredBridgeStillServes(t *testing.T) {
	ref, err := fabric.NewEndpointRef(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	bad := `{"socket":"` + strings.Repeat("x", 200) + `","endpoint":"` + ref.String() + `","generation":"g"}`
	socket := sideportTestServer(t, "nonce-bad", bad)
	b, err := Dial(socket, "inst-sp", "net-1", "nonce-bad", "worker")
	if err != nil {
		t.Fatalf("a malformed advertised sideport must not break the bridge: %v", err)
	}
	defer b.Close()
	if _, ok := b.Sideport(); ok {
		t.Fatal("malformed sideport was accepted")
	}
	// The bridge is fully usable for its original tools.
	if _, err := b.Call(t.Context(), "echo", map[string]any{}); err != nil {
		t.Fatalf("bridge after sideport refusal: %v", err)
	}
}

// The refusal path of the handshake itself: a wrong nonce gets no
// auth_ok and no sideport — there is no Bridge object at all.
func TestBridgeSideportNeverWithoutAuthentication(t *testing.T) {
	socket := sideportTestServer(t, "nonce-sp", sideportJSON(t, t.TempDir()+"/node.sock"))
	_, err := Dial(socket, "inst-sp", "net-1", "WRONG", "worker")
	if err == nil {
		t.Fatal("dial with the wrong nonce must fail before any sideport")
	}
}
