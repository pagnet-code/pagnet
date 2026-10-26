// Package provider implements the fixed, text-only provider boundary for a bridge.
// Configuration must come from the local owner, never from invocation content.
package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxInputChars    = 16_000
	MaxOutputChars   = 16_000
	MaxOutputTokens  = 4_096
	MaxResponseBytes = 128 << 10
	RequestTimeout   = 30 * time.Second
	SystemMessage    = "Respond to the user's message with plain text only. Do not call tools or perform actions."
)

// Config is trusted, owner-supplied configuration. BaseURL is an origin, without
// a path (other than /); the adapter always uses /v1/chat/completions.
type Config struct {
	BaseURL string
	Model   string
	APIKey  string
}

type Client struct {
	endpoint, model, key string
	http                 *http.Client
}

func New(config Config) (*Client, error) {
	u, err := url.Parse(config.BaseURL)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(config.BaseURL, "#") || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return nil, errors.New("invalid provider base URL")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || (u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return nil, errors.New("provider requires HTTPS or HTTP loopback")
		}
	}
	if strings.TrimSpace(config.Model) == "" || len(config.Model) > 256 || strings.ContainsAny(config.Model, "\r\n") {
		return nil, errors.New("invalid provider model")
	}
	if strings.TrimSpace(config.APIKey) == "" || len(config.APIKey) > 8192 || strings.ContainsAny(config.APIKey, "\r\n") {
		return nil, errors.New("invalid provider credential")
	}
	u.Path = "/v1/chat/completions"
	return &Client{endpoint: u.String(), model: config.Model, key: config.APIKey, http: &http.Client{
		Timeout:       RequestTimeout,
		Transport:     &http.Transport{TLSHandshakeTimeout: 10 * time.Second, IdleConnTimeout: 90 * time.Second, MaxIdleConns: 10},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// Complete sends exactly the fixed system message and one bounded user message.
// Errors never contain credentials, provider response bodies, or transport errors.
func (c *Client) Complete(ctx context.Context, input string) (string, error) {
	if !utf8.ValidString(input) || strings.TrimSpace(input) == "" || len(input) > MaxInputChars*utf8.UTFMax || utf8.RuneCountInString(input) > MaxInputChars {
		return "", errors.New("invalid or oversized text input")
	}
	type message struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	body, err := json.Marshal(struct {
		Model     string    `json:"model"`
		Messages  []message `json:"messages"`
		Stream    bool      `json:"stream"`
		MaxTokens int       `json:"max_tokens"`
	}{c.model, []message{{"system", SystemMessage}, {"user", input}}, false, MaxOutputTokens})
	if err != nil {
		return "", errors.New("invalid text request")
	}
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return "", errors.New("invalid provider request")
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", errors.New("provider request failed or timed out")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("provider rejected text request")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil || len(raw) > MaxResponseBytes || !utf8.Valid(raw) {
		return "", errors.New("invalid or oversized provider response")
	}
	return decodeResponse(raw)
}

func decodeResponse(raw []byte) (string, error) {
	invalid := errors.New("provider returned an invalid text response")
	var response struct {
		Choices []struct {
			Message      map[string]json.RawMessage `json:"message"`
			FinishReason string                     `json:"finish_reason"`
		} `json:"choices"`
	}
	if json.Unmarshal(raw, &response) != nil || !uniqueFields(json.NewDecoder(bytes.NewReader(raw))) || len(response.Choices) != 1 || response.Choices[0].FinishReason != "stop" {
		return "", invalid
	}
	m := response.Choices[0].Message
	var role, content string
	if json.Unmarshal(m["role"], &role) != nil || role != "assistant" || bytes.Equal(m["content"], []byte("null")) || json.Unmarshal(m["content"], &content) != nil {
		return "", invalid
	}
	for field, value := range m {
		switch field {
		case "role", "content":
		case "tool_calls", "function_call", "audio", "refusal":
			if !bytes.Equal(value, []byte("null")) {
				return "", invalid
			}
		case "annotations":
			if !bytes.Equal(value, []byte("[]")) && !bytes.Equal(value, []byte("null")) {
				return "", invalid
			}
		default:
			return "", invalid
		}
	}
	if strings.TrimSpace(content) == "" || utf8.RuneCountInString(content) > MaxOutputChars {
		return "", invalid
	}
	return content, nil
}

// Duplicate fields must not hide an earlier tool call or change the selected
// completion through a JSON parser's last-value-wins behavior.
func uniqueFields(d *json.Decoder) bool {
	token, err := d.Token()
	if err != nil {
		return false
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return true
	}
	seen := make(map[string]bool)
	for d.More() {
		if delim == '{' {
			key, err := d.Token()
			if err != nil {
				return false
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return false
			}
			seen[name] = true
		}
		if !uniqueFields(d) {
			return false
		}
	}
	_, err = d.Token()
	return err == nil
}
