package jev

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

const validInput = `{"state":{"ticket":"payment failed","priority":2},"questions":{"urgent":{"type":"noul","instructions":"Is this urgent?"},"route":{"type":"choice","instructions":{"question":"Select team"},"criteria":{"billing":"Payments","other":null}},"quality":{"type":"score","instructions":"How clear?","criteria":["Unclear","Clear","Very clear"]}}}`
const validOutput = `{"model":"jev-1.13.0","answers":{"urgent":{"type":"noul","noul":0.8},"route":{"type":"choice","choice":"billing","probabilities":{"billing":0.9,"other":0.1},"confidence":0.7},"quality":{"type":"score","score":1.4,"legend":{"0":"Unclear","1":"Clear","2":"Very clear"},"probabilities":{"0":0.1,"1":0.4,"2":0.5},"confidence":0.6}},"usage":{"input_tokens":123,"output_tokens":45}}`

func TestTypedEvaluationFixedOriginAndLocalSecret(t *testing.T) {
	in, err := DecodeInput([]byte(validInput))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	client, err := NewWithTransport("local-private-key", "jev-latest", transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != Endpoint || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer local-private-key" {
			t.Fatal("incorrect provider contract")
		}
		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(string(raw), "local-private-key") {
			t.Fatal("key included in state payload")
		}
		var wire struct {
			Input
			Model string `json:"model"`
		}
		if json.Unmarshal(raw, &wire) != nil || wire.Model != "jev-latest" || len(wire.Questions) != 3 {
			t.Fatal("invalid provider request")
		}
		return response(200, validOutput), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	out, err := client.Evaluate(context.Background(), in)
	if err != nil || out.Answers["route"].Choice != "billing" || out.Usage.InputTokens != 123 || calls != 1 {
		t.Fatalf("typed result: %+v %v calls%d", out, err, calls)
	}
	if _, err := client.Evaluate(context.Background(), in); err == nil || calls != 1 {
		t.Fatal("rate limiter did not prevent a provider request")
	}
}
func TestInvalidInputAndProviderResultsFailBeforeUse(t *testing.T) {
	for _, input := range []string{`{"state":true,"questions":{}}`, strings.Replace(validInput, `"noul"`, `"tool"`, 1), strings.Replace(validInput, `"Unclear","Clear","Very clear"`, `"Unclear"`, 1), strings.Replace(validInput, `"state":`, `"providerUrl":"http://127.0.0.1/", "state":`, 1)} {
		if _, err := DecodeInput([]byte(input)); err == nil {
			t.Fatalf("invalid input accepted: %s", input)
		}
	}
	in, _ := DecodeInput([]byte(validInput))
	for _, output := range []string{strings.Replace(validOutput, `"billing","probabilities"`, `"outside","probabilities"`, 1), strings.Replace(validOutput, `"noul":0.8`, `"noul":1.1`, 1),
		strings.Replace(validOutput, `"billing":0.9,"other":0.1`, `"billing":0.1,"other":0.9`, 1),
		strings.Replace(validOutput, `"score":1.4`, `"score":0.1`, 1), strings.Replace(validOutput, `"other":0.1`, `"other":0.7`, 1), strings.Replace(validOutput, `"usage":{"input_tokens":123,"output_tokens":45}`, `"usage":null`, 1), strings.Replace(validOutput, `"usage":{"input_tokens":123,"output_tokens":45}`, `"usage":{}`, 1), strings.Repeat("x", MaxOutputBytes+1)} {
		c, _ := NewWithTransport("secret", "jev-latest", transportFunc(func(*http.Request) (*http.Response, error) { return response(200, output), nil }))
		if _, err := c.Evaluate(context.Background(), in); err == nil {
			t.Fatal("invalid provider result accepted")
		}
	}
}
func TestProviderRedirectNeverForwardsKeyAndFailuresRedacted(t *testing.T) {
	in, _ := DecodeInput([]byte(validInput))
	calls := 0
	c, _ := NewWithTransport("never-log-key", "jev-latest", transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "api.typesafe.ai" {
			t.Fatal("key sent to another origin")
		}
		resp := response(302, "never-log-key")
		resp.Header.Set("Location", "https://other.example/steal")
		return resp, nil
	}))
	_, err := c.Evaluate(context.Background(), in)
	if err == nil || calls != 1 || strings.Contains(err.Error(), "never-log-key") {
		t.Fatalf("redirect result %v calls%d", err, calls)
	}
}
func TestProviderKeyCheckAndRetryCancellation(t *testing.T) {
	c, _ := NewWithTransport("secret", "jev-latest", transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v1/models" {
			return response(200, `{"models":[{"name":"jev-latest"}]}`), nil
		}
		return response(429, "private provider detail"), nil
	}))
	if err := c.CheckKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	in, _ := DecodeInput([]byte(validInput))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := c.Evaluate(ctx, in)
	if err == nil || strings.Contains(err.Error(), "private provider detail") {
		t.Fatal("retry did not cancel safely")
	}
}

func TestCapabilitySchemasAreValid(t *testing.T) {
	c := Capability()
	if !json.Valid(c.InputSchema) || !json.Valid(c.OutputSchema) {
		t.Fatal("invalid capability JSON schema")
	}
}

func TestPinnedModelResponseMustMatch(t *testing.T) {
	in, _ := DecodeInput([]byte(validInput))
	c, _ := NewWithTransport("secret", "jev-1.12.0", transportFunc(func(*http.Request) (*http.Response, error) { return response(200, validOutput), nil }))
	if _, err := c.Evaluate(context.Background(), in); err == nil {
		t.Fatal("provider silently changed pinned model")
	}
}
