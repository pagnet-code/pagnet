package domain

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MaxTaskAttachmentBytes = 256 * 1024

// TaskContent is encrypted as one task payload. Filenames, media types and
// bytes never appear in unencrypted task metadata or public download URLs.
type TaskContent struct {
	Version     int              `json:"pagnet_task_version"`
	Objective   string           `json:"objective"`
	Attachments []TaskAttachment `json:"attachments"`
}

type TaskAttachment struct {
	Name string `json:"name"`
	MIME string `json:"mime"`
	Data string `json:"data"`
}

// DecodeTaskContent keeps legacy raw objectives intact. Explicit versioned
// payloads fail closed on malformed content rather than losing attachments.
func DecodeTaskContent(plain string) (TaskContent, error) {
	legacy := TaskContent{Objective: plain}
	if !strings.HasPrefix(strings.TrimSpace(plain), "{") {
		return legacy, nil
	}
	var marker map[string]json.RawMessage
	if err := json.Unmarshal([]byte(plain), &marker); err != nil || marker["pagnet_task_version"] == nil {
		return legacy, nil
	}
	if len(plain) > 512*1024 {
		return TaskContent{}, fmt.Errorf("task attachment payload exceeds limit")
	}
	var content TaskContent
	decoder := json.NewDecoder(strings.NewReader(plain))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&content); err != nil {
		return TaskContent{}, fmt.Errorf("invalid task content: %w", err)
	}
	if content.Version != 1 || len(content.Attachments) > 8 || !utf8.ValidString(content.Objective) || len(content.Objective) > 64*1024 {
		return TaskContent{}, fmt.Errorf("unsupported or oversized task content")
	}
	total := 0
	for _, a := range content.Attachments {
		if len(a.Name) == 0 || len(a.Name) > 255 || !utf8.ValidString(a.Name) || strings.ContainsAny(a.Name, "/\\") || strings.IndexFunc(a.Name, unicode.IsControl) >= 0 || len(a.MIME) > 128 || strings.IndexFunc(a.MIME, unicode.IsControl) >= 0 {
			return TaskContent{}, fmt.Errorf("invalid task attachment name or media type")
		}
		// Bound allocation before base64 decoding, including invalid input.
		if len(a.Data) > base64.StdEncoding.EncodedLen(MaxTaskAttachmentBytes) {
			return TaskContent{}, fmt.Errorf("task attachment exceeds limit")
		}
		data, err := base64.StdEncoding.Strict().DecodeString(a.Data)
		if err != nil {
			return TaskContent{}, fmt.Errorf("invalid task attachment encoding")
		}
		total += len(data)
		if total > MaxTaskAttachmentBytes {
			return TaskContent{}, fmt.Errorf("task attachments exceed limit")
		}
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return TaskContent{}, fmt.Errorf("trailing task content")
	}
	return content, nil
}

func EncodeTaskContent(content TaskContent) (string, error) {
	content.Version = 1
	raw, err := json.Marshal(content)
	if err != nil {
		return "", err
	}
	if _, err := DecodeTaskContent(string(raw)); err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(raw)), nil
}
