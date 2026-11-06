package runtimeconnect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// PromptResult retains the admission receipt when observation is interrupted.
// Uncertain must never be interpreted as permission to submit another prompt.
type PromptResult struct {
	Accepted    bool   `json:"accepted"`
	Uncertain   bool   `json:"uncertain"`
	PromptID    string `json:"promptId,omitempty"`
	LastEventID int64  `json:"lastEventId"`
	EventEpoch  string `json:"eventEpoch,omitempty"`
	ResultText  string `json:"resultText,omitempty"`
}

func (q *Qwen) inboundPreflight(ctx context.Context) error {
	if err := q.Preflight(ctx); err != nil {
		return err
	}
	status, data, err := q.request(ctx, http.MethodGet, "/capabilities", nil, true)
	if err != nil {
		return err
	}
	var caps struct {
		Features   []string
		Workspaces []struct {
			ID, CWD string
			Trusted bool
		}
	}
	if status != http.StatusOK || json.Unmarshal(data, &caps) != nil {
		return errors.New("Qwen inbound capabilities unavailable")
	}
	features := map[string]bool{}
	for _, feature := range caps.Features {
		features[feature] = true
	}
	if !features["session_prompt"] || !features["session_turn_status"] {
		return errors.New("Qwen does not advertise prompt admission and turn status")
	}
	trusted := false
	for _, workspace := range caps.Workspaces {
		if workspace.CWD == q.binding.Workspace && workspace.ID != "" && workspace.Trusted {
			trusted = true
		}
	}
	if !trusted {
		return errors.New("Qwen inbound workspace is no longer registered and trusted")
	}
	return nil
}

func (q *Qwen) inboundRequest(ctx context.Context, method, path string, data []byte) (*http.Request, error) {
	// Hide GetBody from net/http: mutation requests must not be replayed by the
	// transport, including when a reused connection fails while sending.
	req, err := http.NewRequestWithContext(ctx, method, q.base.String()+path, io.NopCloser(bytes.NewReader(data)))
	if err != nil {
		return nil, errors.New("invalid Qwen inbound request")
	}
	req.Header.Set("Authorization", "Bearer "+q.token)
	req.Header.Set("X-Qwen-Client-Id", q.binding.Client)
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// Prompt submits exactly one native turn using the stable Pagnet ASK ID.
// Errors after dispatch can carry an uncertain admission, with no automatic retry.
func (q *Qwen) Prompt(ctx context.Context, askID, text string) (PromptResult, error) {
	result, err := q.AdmitPrompt(ctx, askID, text)
	if err != nil {
		return result, err
	}
	return q.ResumePrompt(ctx, result)
}

// AdmitPrompt returns the admission receipt without opening an event stream.
// Callers can persist this receipt before observing completion with ResumePrompt.
func (q *Qwen) AdmitPrompt(ctx context.Context, askID, text string) (PromptResult, error) {
	var result PromptResult
	if strings.TrimSpace(askID) == "" || len(askID) > 200 || strings.TrimSpace(text) == "" || len(text) > 65536 {
		return result, errors.New("Qwen prompt requires a stable ASK ID (at most 200 bytes) and text (at most 64 KiB)")
	}
	if err := q.inboundPreflight(ctx); err != nil {
		return result, err
	}
	data, _ := json.Marshal(map[string]any{"prompt": []any{map[string]string{"type": "text", "text": text}}, "idempotencyKey": askID})
	req, err := q.inboundRequest(ctx, http.MethodPost, "/session/"+url.PathEscape(q.binding.Session)+"/prompt", data)
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := q.http.Do(req)
	if err != nil {
		result.Uncertain = true
		return result, errors.New("Qwen prompt admission uncertain; do not automatically retry")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return result, fmt.Errorf("Qwen prompt rejected (HTTP %d)", resp.StatusCode)
	}
	result.Accepted, result.Uncertain = true, true
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	var receipt struct {
		PromptID    string `json:"promptId"`
		LastEventID *int64 `json:"lastEventId"`
		EventEpoch  string `json:"eventEpoch"`
	}
	if err != nil || len(raw) > 65536 || json.Unmarshal(raw, &receipt) != nil || receipt.PromptID == "" || receipt.LastEventID == nil || *receipt.LastEventID < 0 || strings.ContainsAny(receipt.EventEpoch, "\r\n\x00") {
		return result, errors.New("Qwen accepted prompt but admission receipt is uncertain")
	}
	result.PromptID, result.LastEventID, result.EventEpoch = receipt.PromptID, *receipt.LastEventID, receipt.EventEpoch
	return result, nil
}

// ResumePrompt observes a saved admission without submitting another prompt.
func (q *Qwen) ResumePrompt(ctx context.Context, result PromptResult) (PromptResult, error) {
	result.ResultText = ""
	result.Uncertain = true
	if !result.Accepted || result.PromptID == "" || result.LastEventID < 0 || strings.ContainsAny(result.EventEpoch, "\r\n\x00") {
		return result, errors.New("Qwen resume requires a valid accepted prompt receipt")
	}
	if err := q.inboundPreflight(ctx); err != nil {
		return result, err
	}
	return q.observePrompt(ctx, result)
}

func (q *Qwen) observePrompt(ctx context.Context, result PromptResult) (PromptResult, error) {
	req, err := q.inboundRequest(ctx, http.MethodGet, "/session/"+url.PathEscape(q.binding.Session)+"/events", nil)
	if err != nil {
		return result, err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Last-Event-ID", strconv.FormatInt(result.LastEventID, 10))
	if result.EventEpoch != "" {
		req.Header.Set("X-Qwen-Event-Epoch", result.EventEpoch)
	}
	// A turn can take longer than the ordinary REST timeout. Keep the same
	// hardened transport and redirect policy while letting ctx bound observation.
	streamClient := *q.http
	streamClient.Timeout = 0
	resp, err := streamClient.Do(req)
	if err != nil {
		return result, errors.New("Qwen accepted prompt observation interrupted")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		return result, errors.New("Qwen accepted prompt event stream unavailable")
	}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var data strings.Builder
	var frameID *int64
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			if strings.HasPrefix(line, "id:") {
				id, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "id:")), 10, 64)
				if err != nil || id < 0 {
					return result, errors.New("Qwen event cursor uncertain")
				}
				frameID = &id
			}
			if strings.HasPrefix(line, "data:") {
				data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
				data.WriteByte('\n')
				if data.Len() > 1<<20 {
					return result, errors.New("Qwen event exceeds observation bounds")
				}
			}
			continue
		}
		if data.Len() == 0 {
			frameID = nil
			continue
		}
		var event struct {
			V    int
			ID   *int64
			Type string
			Data struct{ PromptID string }
		}
		err := json.Unmarshal([]byte(data.String()), &event)
		data.Reset()
		if err != nil || event.V != 1 {
			return result, errors.New("Qwen event protocol uncertain")
		}
		if frameID != nil {
			if event.ID != nil && *event.ID != *frameID {
				return result, errors.New("Qwen event cursor mismatch")
			}
			event.ID = frameID
		}
		frameID = nil
		switch event.Type {
		case "state_resync_required", "client_evicted", "stream_error", "session_died":
			return result, errors.New("Qwen accepted prompt event history unavailable")
		}
		if event.ID != nil && *event.ID <= result.LastEventID {
			continue
		}
		if event.Data.PromptID != result.PromptID {
			if event.ID != nil {
				result.LastEventID = *event.ID
			}
			continue
		}
		switch event.Type {
		case "turn_error":
			result.Uncertain = false
			return result, errors.New("Qwen native prompt failed")
		case "turn_complete":
			// Preserve the cursor before completion until the result is read so a
			// caller can replay this terminal event after an interrupted GET.
			completed, err := q.promptText(ctx, result)
			if err == nil && event.ID != nil {
				completed.LastEventID = *event.ID
			}
			return completed, err
		}
		if event.ID != nil {
			result.LastEventID = *event.ID
		}
	}
	return result, errors.New("Qwen accepted prompt observation interrupted")
}

func (q *Qwen) promptText(ctx context.Context, result PromptResult) (PromptResult, error) {
	req, err := q.inboundRequest(ctx, http.MethodGet, "/session/"+url.PathEscape(q.binding.Session)+"/turns/"+url.PathEscape(result.PromptID), nil)
	if err != nil {
		return result, err
	}
	resp, err := q.http.Do(req)
	if err != nil {
		return result, errors.New("Qwen final result unavailable")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	var turn struct {
		PromptID        string
		ResultText      *string
		ResultTruncated bool
		ResultCode      string
	}
	if err != nil || resp.StatusCode != http.StatusOK || len(raw) > 1<<20 || json.Unmarshal(raw, &turn) != nil || turn.PromptID != result.PromptID || turn.ResultText == nil || turn.ResultTruncated || turn.ResultCode == "RESULT_TEXT_TRUNCATED" || len(*turn.ResultText) > 65536 {
		return result, errors.New("Qwen final result missing, truncated or uncorrelated")
	}
	result.ResultText, result.Uncertain = *turn.ResultText, false
	return result, nil
}
