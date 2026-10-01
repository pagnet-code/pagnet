package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
)

func TestDelegateUsesEncryptedTaskAndPrincipal(t *testing.T) {
	_, key := activeCryptoHome(t, testNetID, testTenantID)
	routes := sendTestRoutes(t, `[]`)
	path := "/api/v1/networks/" + testNetID + "/tasks"
	routes["POST "+path] = `{"ID":"task-1","Status":"pending"}`
	srv := newRecordServer(t, routes)
	cliFlags(t, srv.ts)
	cmd := delegateCmd()
	cmd.SetArgs([]string{"atlas", "--objective", "private objective", "--title", "private title", "--criteria", "private condition"})
	_, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err != nil {
		t.Fatal(err)
	}
	body, ok := srv.lastBody("POST", path)
	if !ok {
		t.Fatal("no delegated task")
	}
	if strings.Contains(body, "private") || strings.Contains(body, "targetAgent") {
		t.Fatal("obsolete plaintext fields sent")
	}
	var wire struct {
		Target   string                  `json:"targetPrincipalId"`
		ID       string                  `json:"id"`
		Envelope e2ee.EncryptedPayloadV1 `json:"envelope"`
		AAD      e2ee.AAD                `json:"aad"`
	}
	if err := json.Unmarshal([]byte(body), &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Target != "principal-atlas" || wire.AAD.ObjectID != wire.ID || wire.AAD.ObjectType != e2ee.ObjectTypeTask {
		t.Fatal("incorrect task binding")
	}
	plain, err := e2ee.Decrypt(wire.Envelope, key, wire.AAD)
	if err != nil {
		t.Fatal(err)
	}
	content, err := domain.DecodeTaskContent(string(plain))
	if err != nil || !strings.Contains(content.Objective, "private objective") || !strings.Contains(content.Objective, "private condition") {
		t.Fatalf("content lost: %+v %v", content, err)
	}
}
