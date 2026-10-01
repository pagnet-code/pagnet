// Package runtimeconnect links MCP tools to an explicitly owned native runtime
// API. It neither owns nor adopts the runtime's terminal or process lifecycle.
package runtimeconnect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

type Binding struct {
	URL       string `json:"url"`
	Workspace string `json:"workspace"`
	Session   string `json:"session"`
	Client    string `json:"client"`
	Name      string `json:"name"`
	TokenFile string `json:"tokenFile"`
}
type Qwen struct {
	http        *http.Client
	base        *url.URL
	token       string
	binding     Binding
	workspaceID string
}

func NewQwen(binding Binding, token string) (*Qwen, error) {
	u, err := url.Parse(binding.URL)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Port() == "" {
		return nil, errors.New("Qwen connection requires an explicit loopback HTTP origin with port")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return nil, errors.New("Qwen connection requires a literal loopback IP; hostnames and remote APIs are unsupported")
	}
	if !filepath.IsAbs(binding.Workspace) || binding.Session == "" || binding.Client == "" || binding.Name == "" || len(binding.Session) > 128 || len(binding.Client) > 128 || len(binding.Name) > 128 || strings.ContainsAny(binding.Client, "\r\n\x00") || strings.ContainsAny(token, "\r\n\x00") || len(token) < 16 || len(token) > 4096 {
		return nil, errors.New("Qwen connection requires an exact workspace, live session/client, generated name and private operator token")
	}
	u.Path = ""
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &Qwen{http: &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, base: u, token: token, binding: binding}, nil
}
func (q *Qwen) request(ctx context.Context, method, path string, body any, auth bool) (int, []byte, error) {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return 0, nil, errors.New("invalid runtime request")
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, q.base.String()+path, bytes.NewReader(data))
	if err != nil {
		return 0, nil, errors.New("invalid runtime request")
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+q.token)
		req.Header.Set("X-Qwen-Client-Id", q.binding.Client)
	}
	resp, err := q.http.Do(req)
	if err != nil {
		return 0, nil, errors.New("native runtime API unavailable")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return 0, nil, errors.New("native runtime response exceeds bounds")
	}
	return resp.StatusCode, raw, nil
}
func (q *Qwen) Preflight(ctx context.Context) error {
	// Prove the operator token is actually required; merely sending an ignored
	// bearer to an unauthenticated localhost process is not authentication.
	status, _, err := q.request(ctx, "GET", "/capabilities", nil, false)
	if err != nil {
		return err
	}
	if status != 401 && status != 403 {
		return errors.New("Qwen API must require operator authentication; start it with --require-auth")
	}
	status, data, err := q.request(ctx, "GET", "/capabilities", nil, true)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("Qwen operator authentication rejected (HTTP %d)", status)
	}
	var caps struct {
		V          int
		Mode       string
		Features   []string
		Workspaces []struct {
			ID, CWD string
			Trusted bool
		}
	}
	if json.Unmarshal(data, &caps) != nil || caps.V != 1 || caps.Mode != "http-bridge" {
		return errors.New("unsupported Qwen runtime protocol")
	}
	features := map[string]bool{}
	for _, f := range caps.Features {
		features[f] = true
	}
	if !features["mcp_server_runtime_mutation"] || !features["workspace_qualified_rest_core"] {
		return errors.New("Qwen does not advertise supported live workspace MCP mutation")
	}
	for _, w := range caps.Workspaces {
		if w.CWD == q.binding.Workspace && w.Trusted && w.ID != "" {
			q.workspaceID = w.ID
		}
	}
	if q.workspaceID == "" {
		return errors.New("requested workspace is not registered and trusted by this Qwen API")
	}
	status, data, err = q.request(ctx, "GET", "/session/"+url.PathEscape(q.binding.Session)+"/status", nil, true)
	if err != nil {
		return err
	}
	var live struct{ SessionID, WorkspaceCWD string }
	if status != 200 || json.Unmarshal(data, &live) != nil || live.SessionID != q.binding.Session || live.WorkspaceCWD != q.binding.Workspace {
		return errors.New("requested existing Qwen session does not belong to this exact workspace")
	}
	return nil
}
func (q *Qwen) path() string { return "/workspaces/" + url.PathEscape(q.workspaceID) + "/mcp/servers" }
func (q *Qwen) Connect(ctx context.Context, executable, profile, state string) error {
	if err := q.Preflight(ctx); err != nil {
		return err
	}
	if !filepath.IsAbs(executable) || !filepath.IsAbs(state) {
		return errors.New("MCP executable and private state paths must be absolute")
	}
	payload := map[string]any{"name": q.binding.Name, "config": map[string]any{"command": executable, "args": []string{"mcp", "external", "--profile", profile, "--state-dir", state}}}
	status, data, err := q.request(ctx, "POST", q.path(), payload, true)
	if err != nil {
		return err
	}
	var result struct {
		Name                                string
		Skipped, Replaced, ShadowedSettings bool
		ToolCount                           int
	}
	if status != 200 {
		return fmt.Errorf("Qwen MCP connection rejected (HTTP %d); session was not stopped", status)
	}
	if json.Unmarshal(data, &result) != nil || result.Name != q.binding.Name || result.Skipped || result.Replaced || result.ShadowedSettings || result.ToolCount < 1 {
		return errors.New("Qwen did not confirm a new MCP connection with available tools; disconnect the recorded entry before retrying")
	}
	return nil
}
func (q *Qwen) Disconnect(ctx context.Context) error {
	if err := q.Preflight(ctx); err != nil {
		return err
	}
	status, data, err := q.request(ctx, "DELETE", q.path()+"/"+url.PathEscape(q.binding.Name), nil, true)
	if err != nil {
		return err
	}
	var result struct {
		Name                 string
		Removed, Skipped     bool
		Reason               string
		WasShadowingSettings bool
	}
	if status != 200 {
		return fmt.Errorf("Qwen MCP disconnect rejected (HTTP %d); session was not stopped", status)
	}
	if json.Unmarshal(data, &result) != nil || result.Name != q.binding.Name || result.WasShadowingSettings || (!result.Removed && !(result.Skipped && result.Reason == "not_present")) {
		return errors.New("Qwen did not confirm removal of the recorded Pagnet MCP entry")
	}
	return nil
}
