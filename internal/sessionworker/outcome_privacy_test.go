//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/pagnet-code/pagnet/internal/session"
)

func TestWorkerNativeOutcomeDoesNotJournalProtectedFailureBodies(t *testing.T) {
	j, _ := testJournal(t)
	a := lease(t, j)
	owner := &SessionOwner{journal: j}
	secret := "private-provider-failure-request-and-credentials"
	for i := int64(1); i <= 3; i++ {
		if _, _, err := j.Admit(context.Background(), a, i, logicalWorkerTurn(i), "prompt", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
		result := session.TurnResult{Failed: true, FailureKind: "rate_limited", Error: secret, SessionID: "native"}
		var failure error
		if i == 2 {
			failure = errors.New(secret)
		}
		var nativeResult any = result
		if i == 3 {
			nativeResult = &result
		}
		owner.finish(i, nativeResult, failure)
		outcome, err := j.Outcome(context.Background(), i)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(outcome.Result, []byte(secret)) {
			t.Fatal("protected native failure body escaped to durable outcome")
		}
		var raw []byte
		if err = j.db.QueryRow(`SELECT result FROM worker_intent WHERE sequence=?`, i).Scan(&raw); err != nil || bytes.Contains(raw, []byte(secret)) {
			t.Fatal("SQLite retained protected native failure body")
		}
	}
}
