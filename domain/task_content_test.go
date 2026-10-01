package domain

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestTaskContentLegacyAndPrivateAttachments(t *testing.T) {
	for _, raw := range []string{"plain objective", `{"a":"legacy JSON task"}`} {
		got, err := DecodeTaskContent(raw)
		if err != nil || got.Objective != raw {
			t.Fatalf("legacy changed: %+v %v", got, err)
		}
	}
	raw, err := EncodeTaskContent(TaskContent{Objective: "review", Attachments: []TaskAttachment{{Name: "report.txt", MIME: "text/plain", Data: base64.StdEncoding.EncodeToString([]byte("private"))}}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeTaskContent(raw)
	if err != nil || got.Objective != "review" || len(got.Attachments) != 1 {
		t.Fatalf("roundtrip: %+v %v", got, err)
	}
	for _, bad := range []string{
		strings.Replace(raw, `"pagnet_task_version":1`, `"pagnet_task_version":2`, 1),
		strings.Replace(raw, "report.txt", "../secret", 1),
		strings.Replace(raw, "cHJpdmF0ZQ==", "not-base64", 1),
		`{"pagnet_task_version":1,"objective":"a","attachments":[],"extra":true}`,
	} {
		if _, err := DecodeTaskContent(bad); err == nil {
			t.Fatalf("accepted malformed payload: %s", bad)
		}
	}
	_, err = EncodeTaskContent(TaskContent{Attachments: []TaskAttachment{{Name: "too-large", Data: base64.StdEncoding.EncodeToString(make([]byte, MaxTaskAttachmentBytes+1))}}})
	if err == nil {
		t.Fatal("oversized attachment accepted")
	}
}
