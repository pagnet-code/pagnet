package runtime

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"agentnet/internal/domain"
)

// Provider error classification (addendum Phase I: "rate limits are
// classified, not failed"). The adapter feeds a runtime's failure text
// (result text, assistant text, or stderr) through this classifier; the
// resulting kind drives the availability state machine.
//
// Two binding rules:
//   - Classification only, no recovery guessing: a RetryAt is returned
//     ONLY when the provider text carries a parseable retry/reset time
//     (Retry-After, "reset at ...", "try again in ..."). Otherwise the
//     time stays unknown (nil) and the control plane never invents one.
//   - Provider errors can be dressed as success: some providers return a
//     429/quota message inside a "successful" turn (is_error=false), so
//     the adapter classifies the result text even on success.

var (
	reStatusCode429 = regexp.MustCompile(`\b429\b`)
	reStatusCode401 = regexp.MustCompile(`\b401\b`)

	reRetryAfter = regexp.MustCompile(`(?i)retry[- ]after:\s*(\d+)\s*(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h)?`)
	reTryAgainIn = regexp.MustCompile(`(?i)try again in (\d+)\s*(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h)`)
	// "The quota will reset at 09-07 07:45:00 UTC." — provider date has no
	// year; it is anchored to the current year (next year if the result is
	// already in the past).
	reResetAt = regexp.MustCompile(`(?i)reset (?:at|in) (\d{1,2}-\d{1,2}) (\d{1,2}):(\d{2})(?::(\d{2}))?\s*(am|pm)?\s*(utc)?`)
)

var (
	rateLimitPatterns = []string{
		"rate limit", "rate_limit", "ratelimit", "too many requests",
		"throttl", "overloaded", "insufficient_quota", "quota exhausted",
		"quota exceeded", "quota limit", "quota has been exhausted",
		"capacity error", "maximum number of requests",
	}
	authPatterns = []string{
		"unauthorized", "authentication", "invalid api key", "invalid_api_key",
		"api key not found", "api-key is invalid", "not logged in",
		"access token", "invalid authentication token", "api key expired",
	}
	contextLimitPatterns = []string{
		"context length", "context window", "maximum context",
		"too many tokens", "prompt is too long", "context_length",
		"exceeds the model's maximum", "context_length_exceeded",
	}
	networkPatterns = []string{
		"econnrefused", "econnreset", "etimedout", "eai_again",
		"fetch failed", "socket hang up", "network is unreachable",
		"tls handshake", "connection refused", "connection reset",
		"getaddrinfo",
	}
	permissionPatterns = []string{"permission denied", "eacces"}
)

// ClassifyProviderError inspects one or more provider-error texts (most
// specific first) and returns the failure kind plus a provider-supplied
// retry time (RFC3339 UTC) when the text carries one. Callers invoke it
// on text that IS a provider error (a reported failure, or success-path
// text that LooksLikeProviderError). With no recognizable pattern the
// kind is RuntimeFailureUnknown.
func ClassifyProviderError(texts ...string) (domain.RuntimeFailureKind, *string) {
	joined := strings.ToLower(strings.Join(texts, "\n"))
	if strings.TrimSpace(joined) == "" {
		return domain.RuntimeFailureUnknown, nil
	}
	retryAt := extractRetryAt(joined)
	kind := domain.RuntimeFailureUnknown
	switch {
	case reStatusCode429.MatchString(joined) || matchAny(joined, rateLimitPatterns):
		kind = domain.RuntimeFailureRateLimited
	case reStatusCode401.MatchString(joined) || matchAny(joined, authPatterns):
		kind = domain.RuntimeFailureAuthRequired
	case matchAny(joined, contextLimitPatterns):
		kind = domain.RuntimeFailureContextLimit
	case matchAny(joined, networkPatterns):
		kind = domain.RuntimeFailureNetworkError
	case matchAny(joined, permissionPatterns):
		kind = domain.RuntimeFailurePermissionError
	}
	if kind != domain.RuntimeFailureRateLimited {
		return kind, nil
	}
	return kind, retryAt
}

// strictProviderErrorPatterns are the signatures trusted inside a
// "successful" result: machine error codes and quota phrases. The looser
// phrases in the full classifier (e.g. "authentication", "connection
// refused") would false-positive on ordinary task output ("fixed the
// authentication bug") and therefore only count on paths where the
// failure is already established.
var strictProviderErrorPatterns = []string{
	"insufficient_quota", "context_length_exceeded",
	"invalid_api_key", "invalid_authentication_token",
	"api key not found", "api-key is invalid", "api key expired",
	"quota exhausted", "quota exceeded", "quota limit",
	"too many requests", "rate limit exceeded", "rate_limit",
	"prompt is too long",
}

// LooksLikeProviderError reports whether any of the texts carries a
// strong provider-error signature. Runtimes can report a 429/quota
// failure inside a "successful" turn (is_error=false), so the success
// path scans the result text with this BEFORE treating the turn as a
// success — a plain task result must never be classified as a failure.
func LooksLikeProviderError(texts ...string) bool {
	joined := strings.ToLower(strings.Join(texts, "\n"))
	if strings.TrimSpace(joined) == "" {
		return false
	}
	return reStatusCode429.MatchString(joined) ||
		reStatusCode401.MatchString(joined) ||
		matchAny(joined, strictProviderErrorPatterns)
}

func matchAny(haystack string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(haystack, p) {
			return true
		}
	}
	return false
}

func extractRetryAt(text string) *string {
	if m := reRetryAfter.FindStringSubmatch(text); m != nil {
		sec := atoiSafe(m[1])
		sec *= unitFactor(m[2])
		if sec > 0 {
			return rfc3339(time.Now().UTC().Add(time.Duration(sec) * time.Second))
		}
	}
	if m := reTryAgainIn.FindStringSubmatch(text); m != nil {
		sec := atoiSafe(m[1]) * unitFactor(m[2])
		if sec > 0 {
			return rfc3339(time.Now().UTC().Add(time.Duration(sec) * time.Second))
		}
	}
	if m := reResetAt.FindStringSubmatch(text); m != nil {
		parts := strings.SplitN(m[1], "-", 2)
		if len(parts) != 2 {
			return nil
		}
		mon, day := atoiSafe(parts[0]), atoiSafe(parts[1])
		hour, min := atoiSafe(m[2]), atoiSafe(m[3])
		sec := 0
		if m[4] != "" {
			sec = atoiSafe(m[4])
		}
		if m[5] == "pm" && hour < 12 {
			hour += 12
		}
		if mon < 1 || mon > 12 || day < 1 || day > 31 || hour > 23 || min > 59 || sec > 59 {
			return nil
		}
		now := time.Now().UTC()
		ts := time.Date(now.Year(), time.Month(mon), day, hour, min, sec, 0, time.UTC)
		if ts.Before(now.Add(-time.Hour)) {
			ts = ts.AddDate(1, 0, 0) // the provider's year-less date already passed this year
		}
		return rfc3339(ts)
	}
	return nil
}

func unitFactor(unit string) int {
	switch {
	case strings.HasPrefix(unit, "h"):
		return 3600
	case strings.HasPrefix(unit, "m"):
		return 60
	default: // "" (bare number = seconds per HTTP Retry-After) or "s"
		return 1
	}
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
		if n > 1_000_000_000 {
			return 0
		}
	}
	return n
}

func rfc3339(t time.Time) *string {
	s := t.UTC().Format(time.RFC3339)
	return &s
}

// trunc caps failure text carried in events/logs (the full transcript
// stays in the runtime's own session files).
func trunc(s string) string {
	s = strings.TrimSpace(s)
	const max = 2000
	if len(s) > max {
		return fmt.Sprintf("%s…", s[:max])
	}
	return s
}
