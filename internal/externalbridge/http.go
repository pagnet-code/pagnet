package externalbridge

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/mark3labs/mcp-go/server"
)

// ValidateListen refuses wildcard, LAN and hostname binds. HTTP is only a
// backend for a secure tunnel or TLS/OAuth gateway, not a public auth server.
func ValidateListen(addr, token string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("external MCP: listen requires an IP:port: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("external MCP: HTTP listener must bind a literal loopback IP")
	}
	if len(token) < 32 || strings.ContainsAny(token, " \t\r\n") {
		return fmt.Errorf("external MCP: PAGNET_MCP_HTTP_TOKEN requires at least 32 characters without whitespace")
	}
	return nil
}

// HTTPHandler verifies credentials before MCP parsing or session allocation.
// Reject browser Origins and non-loopback Host headers to prevent rebinding.
// Configure reverse proxies to send a loopback Host and strip browser Origin.
func HTTPHandler(s *server.MCPServer, token string) http.Handler {
	next := server.NewStreamableHTTPServer(s)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() || r.Header.Get("Origin") != "" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if len(token) < 32 || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="pagnet-external-backend"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/mcp" {
			http.NotFound(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
		next.ServeHTTP(w, r)
	})
}
