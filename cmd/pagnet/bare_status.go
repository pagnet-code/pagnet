package main

// `pagnet` (no args) on a TTY: a tiny contextual status — fresh / stopped /
// running. Non-TTY: no decorative UI (a bare command is not a dashboard).
// `pagnet --help` remains the full reference.
//
// The status is best-effort and never triggers a sign-in flow or a browser:
// it reads the stored credential and, with a short timeout, asks the server
// for the identity and the host's runtimes. If the server is unreachable the
// local facts (host name, running/stopped) still render.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"
)

func runBareStatus(cmd *cobra.Command) error {
	// Non-TTY: no decorative UI.
	if !hasTTYFn() {
		return nil
	}
	root := machineStateDir("")
	cfg, account, err := loadAccountConfig(root)
	if err != nil {
		return err
	}
	server := resolveServerURL(cfg)

	// Fresh: no host enrollment yet.
	if cfg.Credential == "" || cfg.HostID == "" {
		fmt.Println("Pagnet")
		fmt.Println()
		fmt.Println("Not connected yet.")
		fmt.Println()
		fmt.Println("Run:")
		fmt.Println("  pagnet serve")
		return nil
	}

	hostName := cfg.HostName
	if hostName == "" {
		hostName = "this host"
	}

	// Best-effort identity + runtimes (stored credential only — no sign-in
	// flow, no browser, short timeout; failures leave the fields empty).
	identity := ""
	runtimes := 0
	if tok := loadUserToken(accountConfigDir(root, account), account, server); tok != "" {
		client := &http.Client{Timeout: 3 * time.Second}
		base := server + "/"
		var me struct {
			Username string `json:"username"`
		}
		if bareGet(client, base+"auth/me", tok, &me) == nil {
			identity = me.Username
		}
		var d struct {
			Runtimes []struct{} `json:"runtimes"`
		}
		if bareGet(client, base+"api/v1/hosts/"+cfg.HostID, tok, &d) == nil {
			runtimes = len(d.Runtimes)
		}
	}

	if !daemonRunning(root) {
		fmt.Println(bareHeader(identity))
		if server != "" {
			fmt.Println(server)
		}
		fmt.Println()
		fmt.Printf("Host %s is stopped.\n", hostName)
		fmt.Println()
		fmt.Println("Run:")
		fmt.Println("  pagnet serve")
		return nil
	}

	fmt.Println(bareHeader(identity))
	fmt.Printf("%s · connected\n", hostName)
	fmt.Println()
	if runtimes > 0 {
		fmt.Printf("%d runtimes ready\n", runtimes)
	}
	if cfg.CurrentNetwork != "" {
		fmt.Printf("Network: %s\n", cfg.CurrentNetwork)
	}
	fmt.Println()
	fmt.Println("pagnet status     details")
	fmt.Println("pagnet run .      launch an agent")
	return nil
}

// bareHeader renders the first line: "Pagnet · <identity>" (or just "Pagnet"
// when the identity is unknown).
func bareHeader(identity string) string {
	if identity == "" {
		return "Pagnet"
	}
	return "Pagnet · " + identity
}

// bareGet is a best-effort authenticated GET for the bare status (short
// timeout; the caller ignores failures).
func bareGet(client *http.Client, url, token string, out any) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
