package fabrichost

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/localpeer"
)

// FromEnvironment chooses only explicit owner or a complete managed credential
// set. A partial/invalid managed set cannot become a privileged owner session.
func FromEnvironment(get func(string) string) (Authentication, error) {
	if get == nil {
		return Authentication{}, failure()
	}
	endpoint, worker, generation, nonce := get(EndpointEnvironment), get(WorkerEnvironment), get(GenerationEnvironment), get(NonceEnvironment)
	if endpoint == "" && worker == "" && generation == "" && nonce == "" {
		return Authentication{Type: "fabric.auth", Mode: "owner"}, nil
	}
	ref, err := fabric.ParseEndpointRef(endpoint)
	if err != nil {
		return Authentication{}, failure()
	}
	auth := Authentication{Type: "fabric.auth", Mode: "managed", Endpoint: ref, WorkerID: worker, Generation: generation, Nonce: nonce}
	return auth, auth.Validate()
}

// Dial completes a single genuine private handshake. It never retries a failed
// authentication or falls back to a cloud/owner path. The caller owns the
// returned connection and buffered reader for original MCP initialization.
func Dial(ctx context.Context, path string, auth Authentication) (*net.UnixConn, *bufio.Reader, error) {
	return DialProtocol(ctx, path, auth, Protocol)
}

// DialProtocol requires an explicitly selected supported protocol and exact
// ready response. It never negotiates or falls back to privileged owner mode.
func DialProtocol(ctx context.Context, path string, auth Authentication, protocol string) (*net.UnixConn, *bufio.Reader, error) {
	if err := ValidateSocketPath(path); err != nil {
		return nil, nil, err
	}
	if protocol != Protocol && protocol != AdminProtocol || auth.Protocol != "" && auth.Protocol != protocol {
		return nil, nil, failure()
	}
	auth.Protocol = protocol
	if ctx == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || auth.Validate() != nil || checkSocket(path) != nil {
		return nil, nil, failure()
	}
	selected, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, nil, failure()
	}
	conn, ok := selected.(*net.UnixConn)
	if !ok {
		selected.Close()
		return nil, nil, failure()
	}
	keep := false
	defer func() {
		if !keep {
			conn.Close()
		}
	}()
	if _, uid, err := localpeer.Owner(conn); err != nil || !sameOwner(uid) {
		return nil, nil, failure()
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	raw, err := json.Marshal(auth)
	if err != nil {
		return nil, nil, failure()
	}
	defer clear(raw)
	if len(raw) > 8192 {
		return nil, nil, failure()
	}
	if _, err = conn.Write(append(raw, '\n')); err != nil {
		return nil, nil, failure()
	}
	reader := bufio.NewReader(conn)
	reply, err := authLine(reader, 1024)
	if err != nil {
		return nil, nil, failure()
	}
	var ready struct {
		Type     string `json:"type"`
		Protocol string `json:"protocol"`
	}
	if fabric.DecodeJSON(reply, &ready) != nil || ready.Type != "fabric.ready" || ready.Protocol != protocol {
		return nil, nil, failure()
	}
	if ctx.Err() != nil {
		return nil, nil, failure()
	}
	_ = conn.SetDeadline(time.Time{})
	keep = true
	return conn, reader, nil
}

// The public reference value rejects an empty URI. Owner mode has no endpoint,
// so encode its genuinely optional field as nil rather than an invalid URI.
func (a Authentication) MarshalJSON() ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	var endpoint *fabric.EndpointRef
	if a.Mode == "managed" || a.Mode == "hosted" {
		endpoint = &a.Endpoint
	}
	return json.Marshal(struct {
		Type       string              `json:"type"`
		Mode       string              `json:"mode"`
		Protocol   string              `json:"protocol,omitempty"`
		Endpoint   *fabric.EndpointRef `json:"endpoint,omitempty"`
		WorkerID   string              `json:"workerId,omitempty"`
		Generation string              `json:"generation,omitempty"`
		Nonce      string              `json:"nonce,omitempty"`
	}{a.Type, a.Mode, a.Protocol, endpoint, a.WorkerID, a.Generation, a.Nonce})
}
