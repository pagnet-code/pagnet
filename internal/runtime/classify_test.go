package runtime

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"pagnet/internal/domain"
)

func TestClassifyProviderError_Kinds(t *testing.T) {
	cases := []struct {
		name string
		text string
		kind domain.RuntimeFailureKind
	}{
		{"429 code", "request failed with status 429", domain.RuntimeFailureRateLimited},
		{"rate limit phrase", "The server is rate limiting you, please slow down", domain.RuntimeFailureRateLimited},
		{"too many requests", "HTTP 503: Too Many Requests from upstream", domain.RuntimeFailureRateLimited},
		{"quota exhausted", "Quota exhausted: Your token-plan 1-week quota has been exhausted.", domain.RuntimeFailureRateLimited},
		{"insufficient quota code", "Error: insufficient_quota: 429 quota", domain.RuntimeFailureRateLimited},
		{"overloaded", "The model is overloaded; try again shortly", domain.RuntimeFailureRateLimited},
		{"auth 401", "request failed with status 401", domain.RuntimeFailureAuthRequired},
		{"invalid api key", "401 invalid_api_key: API key not found", domain.RuntimeFailureAuthRequired},
		{"claude oauth expired", "Failed to authenticate: OAuth session expired and could not be refreshed", domain.RuntimeFailureAuthRequired},
		{"authentication failed", "Authentication failed: please run /login", domain.RuntimeFailureAuthRequired},
		{"context limit", "prompt is too long: 200000 tokens > 131072 maximum context length", domain.RuntimeFailureContextLimit},
		{"context window", "This model's maximum context window is 128k tokens", domain.RuntimeFailureContextLimit},
		{"network refused", "fetch failed: connect ECONNREFUSED 127.0.0.1:4000", domain.RuntimeFailureNetworkError},
		{"network timeout", "TLS handshake timeout", domain.RuntimeFailureNetworkError},
		{"permission denied", "open /etc/shadow: permission denied", domain.RuntimeFailurePermissionError},
		{"unknown", "something exploded in a strange way", domain.RuntimeFailureUnknown},
		{"empty", "", domain.RuntimeFailureUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, _ := ClassifyProviderError(tc.text)
			if kind != tc.kind {
				t.Fatalf("kind = %v, want %v", kind, tc.kind)
			}
		})
	}
}

func TestLooksLikeProviderError(t *testing.T) {
	cases := []struct {
		text string
		want bool
	}{
		// Ordinary task results — must never be treated as failures.
		{"Replied \"OK\" in thread 01a0; the reply was delivered", false},
		{"Fixed the authentication bug in the login flow", false},
		{"Debugged the connection refused error in the proxy config", false},
		{"Updated the context window handling in the renderer", false},
		{"All 42 tests pass on port 4000", false},
		{"", false},
		// Strong provider signatures — must be caught on the success path.
		{"Quota exhausted: Your token-plan 1-week quota has been exhausted.", true},
		{"Error: insufficient_quota: 429 (cause: insufficient_quota)", true},
		{"request failed with status 429", true},
		{"request failed with status 401", true},
		{"401 invalid_api_key: API key not found", true},
		{"prompt is too long: 200000 tokens > 131072", true},
		{"context_length_exceeded for model", true},
		{"HTTP 429: Too Many Requests", true},
	}
	for _, tc := range cases {
		t.Run(tc.text, func(t *testing.T) {
			if got := LooksLikeProviderError(tc.text); got != tc.want {
				t.Fatalf("LooksLikeProviderError(%q) = %v, want %v", tc.text, got, tc.want)
			}
		})
	}
}

func TestClassifyProviderError_MultiSource(t *testing.T) {
	// The result text is clean but stderr carries the real error.
	kind, _ := ClassifyProviderError("PONG", "API error 429 too many requests")
	if kind != domain.RuntimeFailureRateLimited {
		t.Fatalf("kind = %v, want rate_limited", kind)
	}
}

func TestClassifyProviderError_RetryAfter(t *testing.T) {
	kind, retryAt := ClassifyProviderError("rate limited, Retry-After: 120")
	if kind != domain.RuntimeFailureRateLimited {
		t.Fatalf("kind = %v, want rate_limited", kind)
	}
	if retryAt == nil {
		t.Fatal("retryAt = nil, want provider value")
	}
	parsed, err := time.Parse(time.RFC3339, *retryAt)
	if err != nil {
		t.Fatalf("retryAt not RFC3339: %q (%v)", *retryAt, err)
	}
	delta := parsed.Sub(time.Now().UTC())
	if delta < 100*time.Second || delta > 140*time.Second {
		t.Fatalf("retryAt %v not ~120s out (%v)", *retryAt, delta)
	}
}

func TestClassifyProviderError_TryAgainIn(t *testing.T) {
	_, retryAt := ClassifyProviderError("throttled. Try again in 5 minutes.")
	if retryAt == nil {
		t.Fatal("retryAt = nil, want provider value")
	}
	parsed, _ := time.Parse(time.RFC3339, *retryAt)
	delta := parsed.Sub(time.Now().UTC())
	if delta < 4*time.Minute || delta > 6*time.Minute {
		t.Fatalf("retryAt %v not ~5min out (%v)", *retryAt, delta)
	}
}

// TestClassifyProviderError_QuotaResetAt uses the exact provider shape
// observed from the token-plan endpoint (year-less "MM-DD HH:MM:SS UTC"):
// the parsed time must land in the future (anchored to the current year,
// rolled to next year when this year's date already passed).
func TestClassifyProviderError_QuotaResetAt(t *testing.T) {
	reset := time.Now().UTC().Add(5 * 24 * time.Hour).Truncate(time.Second)
	text := fmt.Sprintf("Quota exhausted: Your token-plan 1-week quota has been exhausted. The quota will reset at %s UTC.",
		reset.Format("01-02 15:04:05"))
	kind, retryAt := ClassifyProviderError(text)
	if kind != domain.RuntimeFailureRateLimited {
		t.Fatalf("kind = %v, want rate_limited", kind)
	}
	if retryAt == nil {
		t.Fatal("retryAt = nil, want provider reset time")
	}
	parsed, err := time.Parse(time.RFC3339, *retryAt)
	if err != nil {
		t.Fatalf("retryAt not RFC3339: %q (%v)", *retryAt, err)
	}
	if delta := parsed.Sub(reset); delta < 0 || delta > time.Minute {
		t.Fatalf("retryAt = %v, want ~%v", *retryAt, reset.Format(time.RFC3339))
	}
}

func TestClassifyProviderError_NoGuessing(t *testing.T) {
	// No parseable time in the text: retryAt must stay nil (never guessed).
	_, retryAt := ClassifyProviderError("rate limited by upstream")
	if retryAt != nil {
		t.Fatalf("retryAt = %v, want nil (no provider value)", *retryAt)
	}
	// Non-rate-limit kinds never carry a retry time.
	_, retryAt = ClassifyProviderError("Retry-After: 60 — 401 unauthorized")
	if retryAt != nil {
		t.Fatalf("retryAt = %v for auth failure, want nil", *retryAt)
	}
}

func TestTrunc(t *testing.T) {
	if got := trunc("short"); got != "short" {
		t.Fatalf("trunc(short) = %q", got)
	}
	long := strings.Repeat("x", 5000)
	got := trunc(long)
	if !strings.HasSuffix(got, "…") || len(got) >= len(long) {
		t.Fatalf("trunc(long) = len %d, want capped with ellipsis and shorter than input", len(got))
	}
}
