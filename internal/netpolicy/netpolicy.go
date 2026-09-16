// Package netpolicy is the single source of the client's
// plain-HTTP-for-remote-endpoints policy: a control-plane or release URL
// may use plain HTTP (http:// or ws://) only when its host is loopback
// (127.0.0.0/8, ::1, or the literal "localhost"); any other host must use
// HTTPS (https:// or wss://).
//
// The policy is fail-closed by default: plain HTTP to a non-loopback
// remote is refused with a clean error naming the URL, unless the operator
// opts in for development via the PAGNET_INSECURE_REMOTE_HTTP=1 environment
// variable or the --insecure-remote-http flag. Loopback HTTP stays fully
// allowed (the dev stack, the e2e suite, and the unit tests all use
// 127.0.0.1). This is the one place the rule lives — every URL resolution
// point (daemon connect/run, release download, the CLI REST/WS clients)
// calls Check, so the policy cannot drift between call sites.
package netpolicy

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
)

// EnvInsecure is the environment variable that opts into plain HTTP for
// non-loopback remote endpoints (development only).
const EnvInsecure = "PAGNET_INSECURE_REMOTE_HTTP"

// InsecureEnabled reports whether the plain-HTTP opt-in is active: the
// --insecure-remote-http flag (flagInsecure) OR the
// PAGNET_INSECURE_REMOTE_HTTP=1 environment variable.
func InsecureEnabled(flagInsecure bool) bool {
	if flagInsecure {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvInsecure))) {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}

// IsLoopbackHost reports whether host (a URL host, optionally with a port)
// is a loopback host: an IP literal that is loopback (127.0.0.0/8, ::1),
// or the literal "localhost" (case-insensitive).
func IsLoopbackHost(host string) bool {
	h := host
	// A bracketed IPv6 literal: [::1] or [::1]:port — take the address
	// inside the brackets.
	if strings.HasPrefix(h, "[") {
		if i := strings.IndexByte(h, ']'); i >= 0 {
			h = h[1:i]
		}
	} else if h2, _, err := net.SplitHostPort(h); err == nil {
		// host:port — drop the port.
		h = h2
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

var (
	warnOnceMu sync.Mutex
	warnedOnce bool
)

// warnOnce prints the one-line opt-in diagnostic to stderr, at most once
// per process — a reconnecting daemon must not spam the log on every dial.
func warnOnce(rawURL string) {
	warnOnceMu.Lock()
	defer warnOnceMu.Unlock()
	if warnedOnce {
		return
	}
	warnedOnce = true
	fmt.Fprintf(os.Stderr,
		"pagnet: WARNING: plain HTTP to non-loopback remote %s is allowed "+
			"(PAGNET_INSECURE_REMOTE_HTTP / --insecure-remote-http) — "+
			"development only, never for production\n", rawURL)
}

// Check enforces the policy on a remote endpoint URL. HTTPS (https://,
// wss://) is always allowed. Plain HTTP (http://, ws://) — and any
// unrecognized or missing scheme, which fails closed — is allowed only for
// loopback hosts, or when the opt-in is active (a one-line stderr
// diagnostic is printed the first time it is honored). An empty URL is
// allowed: absence of a URL is the caller's concern, not the policy's.
//
// A violation returns a clean error naming the URL.
func Check(rawURL string, flagInsecure bool) error {
	if rawURL == "" {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid remote URL %q: %w", rawURL, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "https" || scheme == "wss" {
		return nil
	}
	if IsLoopbackHost(u.Host) {
		return nil
	}
	if InsecureEnabled(flagInsecure) {
		warnOnce(rawURL)
		return nil
	}
	return fmt.Errorf("plain HTTP is not allowed for non-loopback remote endpoint %s — "+
		"use HTTPS, or set PAGNET_INSECURE_REMOTE_HTTP=1 / --insecure-remote-http for development",
		rawURL)
}
