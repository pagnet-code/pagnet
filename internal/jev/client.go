// Package jev adapts TypeSafe typed judgments without treating them as actions.
package jev

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const Endpoint = "https://api.typesafe.ai/v1/systemone"
const CapabilityID = "typesafe.evaluate"
const MaxInputBytes = 128 << 10
const MaxOutputBytes = 512 << 10

var modelPattern = regexp.MustCompile(`^jev-(latest|preview|[0-9]+\.[0-9]+\.[0-9]+)$`)

type Question struct {
	Type         string          `json:"type"`
	Instructions json.RawMessage `json:"instructions"`
	Criteria     json.RawMessage `json:"criteria,omitempty"`
}
type Input struct {
	State     json.RawMessage     `json:"state"`
	Questions map[string]Question `json:"questions"`
}
type Answer struct {
	Type          string             `json:"type"`
	Noul          *float64           `json:"noul,omitempty"`
	Choice        string             `json:"choice,omitempty"`
	Score         *float64           `json:"score,omitempty"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
	Confidence    *float64           `json:"confidence,omitempty"`
	Legend        map[string]string  `json:"legend,omitempty"`
}
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

func (u *Usage) UnmarshalJSON(raw []byte) error {
	var value struct {
		InputTokens  *int `json:"input_tokens"`
		OutputTokens *int `json:"output_tokens"`
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	if value.InputTokens == nil || value.OutputTokens == nil || *value.InputTokens < 0 || *value.OutputTokens < 0 {
		return errors.New("invalid TypeSafe token usage")
	}
	u.InputTokens, u.OutputTokens = *value.InputTokens, *value.OutputTokens
	return nil
}

type Result struct {
	Model   string            `json:"model"`
	Answers map[string]Answer `json:"answers"`
	Usage   *Usage            `json:"usage"`
}
type Client struct {
	key, model string
	http       *http.Client
	mu         sync.Mutex
	next       time.Time
	slots      chan struct{}
}

func New(key, model string) (*Client, error) {
	if strings.TrimSpace(key) == "" || strings.ContainsAny(key, "\r\n") {
		return nil, errors.New("TypeSafe API key is required locally")
	}
	if !modelPattern.MatchString(model) {
		return nil, errors.New("use jev-latest, jev-preview, or a versioned Jev model")
	}
	return &Client{key: key, model: model, http: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, slots: make(chan struct{}, 4)}, nil
}
func structured(raw json.RawMessage, nullable bool) bool {
	var v any
	if len(raw) == 0 || json.Unmarshal(raw, &v) != nil {
		return false
	}
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x) != ""
	case map[string]any:
		return len(x) > 0
	case []any:
		return len(x) > 0
	case nil:
		return nullable
	default:
		return false
	}
}
func DecodeInput(raw []byte) (Input, error) {
	var in Input
	if len(raw) > MaxInputBytes {
		return in, errors.New("evaluation exceeds 128 KiB")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF {
		return in, errors.New("invalid typed evaluation input")
	}
	return in, ValidateInput(in)
}
func ValidateInput(in Input) error {
	if !structured(in.State, false) {
		return errors.New("state must be a nonempty string, object, or array")
	}
	if len(in.Questions) < 1 || len(in.Questions) > 16 {
		return errors.New("provide 1 to 16 typed questions")
	}
	for id, q := range in.Questions {
		if len(id) == 0 || len(id) > 128 || !structured(q.Instructions, false) {
			return errors.New("each question requires an ID and instructions")
		}
		switch q.Type {
		case "noul":
			if len(q.Criteria) > 0 {
				var m map[string]json.RawMessage
				if json.Unmarshal(q.Criteria, &m) != nil || len(m) == 0 || len(m) > 2 {
					return errors.New("invalid noul criteria")
				}
				for k, v := range m {
					if (k != "true" && k != "false") || !structured(v, false) {
						return errors.New("invalid noul criteria")
					}
				}
			}
		case "choice":
			var m map[string]json.RawMessage
			if json.Unmarshal(q.Criteria, &m) != nil || len(m) < 2 || len(m) > 255 {
				return errors.New("choice requires 2 to 255 criteria")
			}
			for k, v := range m {
				if k == "" || len(k) > 128 || !structured(v, true) {
					return errors.New("invalid choice criteria")
				}
			}
		case "score":
			var a []json.RawMessage
			if json.Unmarshal(q.Criteria, &a) != nil || len(a) < 2 || len(a) > 10 {
				return errors.New("score requires 2 to 10 ordered criteria")
			}
			for _, v := range a {
				if !structured(v, false) {
					return errors.New("invalid score criteria")
				}
			}
		default:
			return errors.New("question type must be noul, choice, or score")
		}
	}
	return nil
}
func probability(p *float64) bool {
	return p != nil && !math.IsNaN(*p) && !math.IsInf(*p, 0) && *p >= 0 && *p <= 1
}
func validateResult(in Input, r Result) error {
	if !modelPattern.MatchString(r.Model) || len(r.Answers) != len(in.Questions) || r.Usage == nil || r.Usage.InputTokens < 0 || r.Usage.OutputTokens < 0 {
		return errors.New("invalid TypeSafe response")
	}
	for id, q := range in.Questions {
		a, ok := r.Answers[id]
		if !ok || a.Type != q.Type {
			return errors.New("answer does not match its question")
		}
		if q.Type == "noul" {
			if !probability(a.Noul) || a.Score != nil || a.Choice != "" || a.Confidence != nil || len(a.Probabilities) > 0 || len(a.Legend) > 0 {
				return errors.New("invalid noul answer")
			}
			continue
		}
		if !probability(a.Confidence) || a.Noul != nil {
			return errors.New("invalid answer confidence")
		}
		expected := map[string]json.RawMessage{}
		if q.Type == "choice" {
			_ = json.Unmarshal(q.Criteria, &expected)
			if _, ok := expected[a.Choice]; !ok || a.Score != nil || len(a.Legend) > 0 {
				return errors.New("choice is outside its criteria")
			}
		} else {
			var levels []json.RawMessage
			_ = json.Unmarshal(q.Criteria, &levels)
			for i := range levels {
				expected[strconv.Itoa(i)] = nil
			}
			if a.Score == nil || math.IsNaN(*a.Score) || *a.Score < 0 || *a.Score > float64(len(levels)-1) || a.Choice != "" || len(a.Legend) != len(levels) {
				return errors.New("invalid score answer")
			}
			for k := range expected {
				if _, ok := a.Legend[k]; !ok {
					return errors.New("invalid score legend")
				}
			}
		}
		if len(a.Probabilities) != len(expected) {
			return errors.New("incomplete probability distribution")
		}
		sum := 0.0
		for k, p := range a.Probabilities {
			if _, ok := expected[k]; !ok || !probability(&p) {
				return errors.New("invalid probability")
			}
			sum += p
		}
		if math.Abs(sum-1) > 0.001 {
			return errors.New("probabilities must sum to one")
		}
		if q.Type == "choice" {
			selected := a.Probabilities[a.Choice]
			for _, p := range a.Probabilities {
				if p > selected+0.000001 {
					return errors.New("choice does not match its probability distribution")
				}
			}
		} else {
			weighted := 0.0
			for k, p := range a.Probabilities {
				level, _ := strconv.Atoi(k)
				weighted += float64(level) * p
			}
			if math.Abs(weighted-*a.Score) > 0.001 {
				return errors.New("score does not match its weighted probabilities")
			}
		}
	}
	return nil
}
func (c *Client) CheckKey(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.typesafe.ai/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+c.key)
	resp, err := c.http.Do(req)
	if err != nil {
		return errors.New("TypeSafe key verification failed or timed out")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("TypeSafe key verification failed (HTTP %d)", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var out struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err != nil || json.Unmarshal(raw, &out) != nil || len(out.Models) == 0 {
		return errors.New("invalid TypeSafe model discovery response")
	}
	return nil
}
func (c *Client) Evaluate(ctx context.Context, in Input) (Result, error) {
	var out Result
	if err := ValidateInput(in); err != nil {
		return out, err
	}
	raw, err := json.Marshal(struct {
		Input
		Model string `json:"model"`
	}{in, c.model})
	if err != nil || len(raw) > MaxInputBytes {
		return out, errors.New("evaluation exceeds 128 KiB")
	}
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		return out, errors.New("Jev service is busy; retry later")
	}
	c.mu.Lock()
	if time.Now().Before(c.next) {
		c.mu.Unlock()
		return out, errors.New("Jev service rate limit reached; retry later")
	}
	c.next = time.Now().Add(500 * time.Millisecond)
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	for attempt := 0; attempt < 3; attempt++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, Endpoint, bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+c.key)
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			return out, errors.New("TypeSafe request failed or timed out")
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, MaxOutputBytes+1))
		resp.Body.Close()
		if err != nil || len(body) > MaxOutputBytes {
			return out, errors.New("invalid or oversized TypeSafe response")
		}
		if (resp.StatusCode == 429 || resp.StatusCode == 529) && attempt < 2 {
			delay := time.Duration(1<<attempt) * time.Second
			if n, e := strconv.Atoi(resp.Header.Get("Retry-After")); e == nil && n > 0 {
				delay = time.Duration(n) * time.Second
				if delay > 2*time.Second {
					delay = 2 * time.Second
				}
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return out, errors.New("TypeSafe retry cancelled")
			case <-timer.C:
			}
			continue
		}
		if resp.StatusCode != 200 {
			return out, fmt.Errorf("TypeSafe evaluation failed (HTTP %d); check the local key, request, or provider limits", resp.StatusCode)
		}
		if json.Unmarshal(body, &out) != nil {
			return out, errors.New("invalid TypeSafe JSON response")
		}
		if err := validateResult(in, out); err != nil {
			return Result{}, err
		}
		if c.model != "jev-latest" && c.model != "jev-preview" && out.Model != c.model {
			return Result{}, errors.New("TypeSafe returned a different model version")
		}
		return out, nil
	}
	return out, errors.New("TypeSafe is temporarily unavailable")
}

// NewWithTransport supports trusted proxy/TLS policies and protocol tests.
// Invocation inputs cannot change the fixed provider URLs or redirect policy.
func NewWithTransport(key, model string, transport http.RoundTripper) (*Client, error) {
	c, err := New(key, model)
	if err != nil {
		return nil, err
	}
	if transport != nil {
		c.http.Transport = transport
	}
	return c, nil
}

// EvaluateValue is the JSON-decoded SDK invocation entrypoint. Unknown fields,
// arbitrary provider URLs and oversized inputs are rejected before a paid call.
func (c *Client) EvaluateValue(ctx context.Context, value any) (Result, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return Result{}, errors.New("invalid evaluation input")
	}
	in, err := DecodeInput(raw)
	if err != nil {
		return Result{}, err
	}
	return c.Evaluate(ctx, in)
}
