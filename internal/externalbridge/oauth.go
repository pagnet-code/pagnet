package externalbridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/server"
)

const DiscoveryScope = "pagnet:discover"
const InvocationScope = "pagnet:invoke"

// OAuthConfig binds one deployed bridge to one consenting provider subject.
// The established authorization server owns login, consent, PKCE, registration
// and refresh. Neither an OAuth token nor its subject becomes a Pagnet credential.
type OAuthConfig struct {
	ResourceURL      string
	Issuer           string
	IntrospectionURL string
	ClientID         string
	ClientSecret     string
	Subject          string
	AllowInvoke      bool
}

func secureURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("external MCP OAuth: URLs must be absolute HTTPS URLs without credentials, query or fragment")
	}
	return u, nil
}

func (c OAuthConfig) Validate() error {
	resource, err := secureURL(c.ResourceURL)
	if err != nil {
		return err
	}
	if resource.Path != "/mcp" || resource.RawPath != "" {
		return errors.New("external MCP OAuth: resource URL must end in /mcp")
	}
	issuer, err := secureURL(c.Issuer)
	if err != nil {
		return err
	}
	endpoint, err := secureURL(c.IntrospectionURL)
	if err != nil {
		return err
	}
	if endpoint.Host != issuer.Host {
		return errors.New("external MCP OAuth: introspection must use the configured issuer origin")
	}
	if strings.TrimSpace(c.ClientID) == "" || strings.TrimSpace(c.ClientSecret) == "" || strings.TrimSpace(c.Subject) == "" {
		return errors.New("external MCP OAuth: introspection client ID, client secret and exact subject are required")
	}
	return nil
}

type introspection struct {
	Active    bool            `json:"active"`
	Issuer    string          `json:"iss"`
	Subject   string          `json:"sub"`
	Audience  json.RawMessage `json:"aud"`
	Expires   int64           `json:"exp"`
	NotBefore int64           `json:"nbf"`
	Scope     string          `json:"scope"`
	TokenType string          `json:"token_type"`
}

func (c OAuthConfig) accepts(p introspection) bool {
	if !p.Active || p.Issuer != c.Issuer || p.Subject != c.Subject || p.Expires <= time.Now().Unix() || p.NotBefore > time.Now().Unix() || !strings.EqualFold(p.TokenType, "Bearer") {
		return false
	}
	var one string
	if json.Unmarshal(p.Audience, &one) == nil {
		return one == c.ResourceURL
	}
	var many []string
	if json.Unmarshal(p.Audience, &many) == nil {
		for _, aud := range many {
			if aud == c.ResourceURL {
				return true
			}
		}
	}
	return false
}
func hasScope(scopes, wanted string) bool {
	for _, scope := range strings.Fields(scopes) {
		if scope == wanted {
			return true
		}
	}
	return false
}

// OAuthHTTPHandler is a fail-closed OAuth resource server. Token introspection
// happens for EVERY request (no stale positive cache after revocation). Stateless
// MCP prevents sessions created with broader scopes from bypassing later checks.
// Bind on loopback; a trusted HTTPS proxy must rewrite Host and strip Origin.
func OAuthHTTPHandler(s *server.MCPServer, cfg OAuthConfig) (http.Handler, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return oauthHTTPHandler(s, cfg, client), nil
}
func oauthHTTPHandler(s *server.MCPServer, cfg OAuthConfig, client *http.Client) http.Handler {
	introspectionSlots := make(chan struct{}, 16)
	next := server.NewStreamableHTTPServer(s, server.WithStateLess(true))
	resource, _ := url.Parse(cfg.ResourceURL)
	metadataURL := resource.Scheme + "://" + resource.Host + "/.well-known/oauth-protected-resource/mcp"
	scopes := []string{DiscoveryScope}
	if cfg.AllowInvoke {
		scopes = append(scopes, InvocationScope)
	}
	challenge := func(w http.ResponseWriter, status int, required, code string) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+metadataURL+`", scope="`+required+`", error="`+code+`"`)
		http.Error(w, http.StatusText(status), status)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if !trustedBackendRequest(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.URL.Path == "/.well-known/oauth-protected-resource" || r.URL.Path == "/.well-known/oauth-protected-resource/mcp" {
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", "GET")
				http.Error(w, "method not allowed", 405)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"resource": cfg.ResourceURL, "authorization_servers": []string{cfg.Issuer}, "scopes_supported": scopes, "bearer_methods_supported": []string{"header"}, "resource_name": "Pagnet capability bridge"})
			return
		}
		if r.URL.Path != "/mcp" {
			http.NotFound(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || len(auth) > 16<<10 || strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")) == "" || strings.ContainsAny(strings.TrimPrefix(auth, "Bearer "), " \t\r\n") {
			challenge(w, 401, DiscoveryScope, "invalid_token")
			return
		}
		select {
		case introspectionSlots <- struct{}{}:
			defer func() { <-introspectionSlots }()
		default:
			w.Header().Set("Retry-After", "1")
			http.Error(w, "authorization requests busy", 429)
			return
		}
		form := url.Values{"token": {strings.TrimPrefix(auth, "Bearer ")}, "token_type_hint": {"access_token"}}
		request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, cfg.IntrospectionURL, strings.NewReader(form.Encode()))
		if err != nil {
			http.Error(w, "authorization service unavailable", 503)
			return
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)
		response, err := client.Do(request)
		if err != nil {
			http.Error(w, "authorization service unavailable", 503)
			return
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			http.Error(w, "authorization service unavailable", 503)
			return
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
		var claims introspection
		if err != nil || len(data) > 64<<10 || json.Unmarshal(data, &claims) != nil {
			http.Error(w, "authorization service unavailable", 503)
			return
		}
		if !cfg.accepts(claims) {
			challenge(w, 401, DiscoveryScope, "invalid_token")
			return
		}
		if !hasScope(claims.Scope, DiscoveryScope) {
			challenge(w, 403, DiscoveryScope, "insufficient_scope")
			return
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "request too large", 413)
				return
			}
			var rpc struct {
				Method string `json:"method"`
				Params struct {
					Name string `json:"name"`
				} `json:"params"`
			}
			if json.Unmarshal(body, &rpc) != nil {
				http.Error(w, "invalid JSON-RPC request", 400)
				return
			}
			if rpc.Method == "tools/call" && (rpc.Params.Name != "pagnet_identity" && rpc.Params.Name != "pagnet_search") && (!cfg.AllowInvoke || !hasScope(claims.Scope, InvocationScope)) {
				challenge(w, 403, InvocationScope, "insufficient_scope")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		next.ServeHTTP(w, r)
	})
}
