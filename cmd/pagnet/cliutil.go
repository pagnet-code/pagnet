package main

// Shared CLI plumbing: the logged-in host config, authenticated REST
// helpers, and the name→id resolution the commands need (networks,
// hosts, agents, instances).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"pagnet/internal/config"
)

type cliCtx struct {
	base     string
	stateDir string
	cfg      config.Daemon
	// token is the user/admin bearer for REST calls. NEVER the host
	// credential (cfg.Credential): host identities are WSS-only and the
	// REST API rejects them (403 host_identity).
	token string
}

// newCLI loads the daemon state config (same file `pagnet enroll` /
// `pagnet login` write) and applies --server if given. stateDirOverride
// passes --state-dir straight through ("" = default ~/.pagnet).
func newCLI(stateDirOverride string) (*cliCtx, error) {
	c := &cliCtx{base: serverURL}
	if stateDirOverride == "" {
		home, _ := os.UserHomeDir()
		stateDirOverride = filepath.Join(home, ".pagnet")
		// Single-directory worker: standing inside a directory that `pagnet
		// worker` has enrolled targets THAT worker's host (its state lives
		// at ~/.pagnet/workers/<hash-of-cwd>), not the machine-wide daemon.
		if cwd, err := os.Getwd(); err == nil {
			if w := filepath.Join(home, ".pagnet", "workers", dirHash(cwd)); isDir(w) {
				stateDirOverride = w
			}
		}
	}
	c.stateDir = stateDirOverride
	cfg, err := config.LoadDaemon(c.stateDir)
	if err != nil {
		return nil, err
	}
	// An explicit --server flag wins over the saved config; otherwise the
	// logged-in server applies (the old code always overwrote the flag
	// with the saved value, silently ignoring --server).
	serverExplicit := root != nil &&
		root.PersistentFlags().Lookup("server") != nil &&
		root.PersistentFlags().Changed("server")
	if !serverExplicit && cfg.ServerURL != "" {
		c.base = cfg.ServerURL
	}
	c.cfg = cfg
	// Bearer precedence: --token / $PAGNET_TOKEN, then the token stored by
	// `pagnet login` (config.yaml "token" key).
	if c.token = userToken; c.token == "" {
		c.token = loadUserToken(c.stateDir)
	}
	return c, nil
}

// do performs an authenticated request against the control plane. The
// user/admin token (--token / $PAGNET_TOKEN / `pagnet login`) is the
// CLI's bearer.
func (c *cliCtx) do(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("http 401: %s (run `pagnet login` or set --token / $PAGNET_TOKEN to a user/admin bearer)", string(raw))
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("http %d: %s", resp.StatusCode, string(raw))
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func (c *cliCtx) get(path string, out any) error {
	return c.do(http.MethodGet, path, nil, out)
}

func (c *cliCtx) post(path string, body, out any) error {
	return c.do(http.MethodPost, path, body, out)
}

func (c *cliCtx) put(path string, body any) error {
	return c.do(http.MethodPut, path, body, nil)
}

// Network resolution: --network (id, name, or slug) > the saved current
// network (`pagnet network use`) > the only network > error.
func (c *cliCtx) resolveNetwork(name string) (id, label string, err error) {
	var nets []struct {
		ID   string `json:"ID"`
		Name string `json:"Name"`
		Slug string `json:"Slug"`
	}
	if err := c.get("/api/v1/networks", &nets); err != nil {
		return "", "", err
	}
	choose := func(n *struct {
		ID   string `json:"ID"`
		Name string `json:"Name"`
		Slug string `json:"Slug"`
	}) (string, string) {
		return n.ID, n.Name
	}
	for i := range nets {
		n := &nets[i]
		if name != "" && (n.ID == name || n.Name == name || n.Slug == name) {
			id, label := choose(n)
			return id, label, nil
		}
	}
	if name != "" {
		return "", "", fmt.Errorf("network %q not found", name)
	}
	if c.cfg.CurrentNetwork != "" {
		for i := range nets {
			n := &nets[i]
			if n.ID == c.cfg.CurrentNetwork || n.Name == c.cfg.CurrentNetwork {
				id, label := choose(n)
				return id, label, nil
			}
		}
		return "", "", fmt.Errorf("current network %q no longer exists (pick one with --network)", c.cfg.CurrentNetwork)
	}
	switch len(nets) {
	case 1:
		id, label := choose(&nets[0])
		return id, label, nil
	case 0:
		return "", "", fmt.Errorf("no networks exist (create one first)")
	default:
		return "", "", fmt.Errorf("multiple networks exist; choose one with --network (or `pagnet network use <name>`)")
	}
}

// wsEntry is one registered workspace (from the host detail endpoint).
type wsEntry struct {
	ID         string  `json:"ID"`
	Path       string  `json:"Path"`
	Branch     string  `json:"Branch"`
	ResourceID *string `json:"ResourceID"`
}

type cliHost struct {
	ID         string    `json:"ID"`
	Name       string    `json:"Name"`
	Status     string    `json:"Status"`
	OS         string    `json:"OS"`
	Arch       string    `json:"Arch"`
	DaemonVer  string    `json:"DaemonVersion"`
	CPUCount   int       `json:"CPUCount"`
	CPULoad    float64   `json:"CPULoad"`
	MemTotal   int64     `json:"MemTotalBytes"`
	MemUsed    int64     `json:"MemUsedBytes"`
	LastBeat   *string   `json:"LastHeartbeatAt"`
	Workspaces []wsEntry `json:"workspaces"`
}

// hostDetail fetches one host WITH its workspaces/roots/runtimes (the
// list endpoint omits them).
func (c *cliCtx) hostDetail(hostID string) (*cliHost, error) {
	var d struct {
		Host struct {
			ID     string `json:"ID"`
			Name   string `json:"Name"`
			Status string `json:"Status"`
		} `json:"host"`
		Workspaces []wsEntry `json:"workspaces"`
	}
	if err := c.get("/api/v1/hosts/"+hostID, &d); err != nil {
		return nil, err
	}
	return &cliHost{
		ID:         d.Host.ID,
		Name:       d.Host.Name,
		Status:     d.Host.Status,
		Workspaces: d.Workspaces,
	}, nil
}

// resourceKeys loads every resource of every network into id→key
// (workspaces reference resources by id; the key is the display form).
func (c *cliCtx) resourceKeys() map[string]string {
	keys := map[string]string{}
	var nets []struct {
		ID string `json:"ID"`
	}
	if c.get("/api/v1/networks", &nets) != nil {
		return keys
	}
	for _, n := range nets {
		var res []struct {
			ID           string `json:"ID"`
			CanonicalKey string `json:"CanonicalKey"`
		}
		if c.get("/api/v1/networks/"+n.ID+"/resources", &res) != nil {
			continue
		}
		for _, r := range res {
			keys[r.ID] = r.CanonicalKey
		}
	}
	return keys
}

// hostByName resolves a host by name or id (all hosts of the tenant).
func (c *cliCtx) hostByName(name string) (*cliHost, error) {
	var hosts []cliHost
	if err := c.get("/api/v1/hosts", &hosts); err != nil {
		return nil, err
	}
	for i := range hosts {
		if hosts[i].Name == name || hosts[i].ID == name {
			return &hosts[i], nil
		}
	}
	return nil, fmt.Errorf("host %q not found", name)
}

// printTable renders rows with simple column alignment.
func printTable(headers []string, rows [][]string) {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, r := range rows {
		for i, cell := range r {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}
	fmtLine := func(cells []string) {
		line := ""
		for i, cell := range cells {
			line += cell
			if i < len(cells)-1 {
				line += string(rune(' ')) + repeat(" ", widths[i]-len(cell)+2)
			}
		}
		fmt.Println(line)
	}
	fmtLine(headers)
	for _, r := range rows {
		fmtLine(r)
	}
}

func repeat(s string, n int) string {
	if n <= 0 {
		return ""
	}
	out := make([]byte, 0, n)
	for len(out) < n {
		out = append(out, []byte(s)...)
	}
	return string(out[:n])
}

func isDir(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}
