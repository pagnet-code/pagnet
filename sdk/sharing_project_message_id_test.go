package sdk

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestSharingProjectMessageWithIDRoundTripAndDuplicate(t *testing.T) {
	project, clients := projectMessageFixture(t)
	alice, bob := clients[0], clients[1]
	id := "019a1357-2468-7abc-8def-0123456789ab"
	prepared, err := alice.PrepareSharingProjectMessageWithID(project, bob.PrincipalID(), "ASK", id, []byte("stable question"), nil)
	if err != nil || prepared.ID != id {
		t.Fatalf("prepare: %+v %v", prepared, err)
	}
	opened, err := bob.DecryptSharingProjectMessage(project, prepared.Wire, nil)
	if err != nil || opened.Header.ID != id || opened.Header.ThreadID != id || string(opened.Plaintext) != "stable question" {
		t.Fatalf("decrypt: %+v %v", opened, err)
	}
	for _, plaintext := range []string{"stable question", "replacement"} {
		duplicate, err := alice.PrepareSharingProjectMessageWithID(project, bob.PrincipalID(), "ASK", id, []byte(plaintext), nil)
		if err == nil || duplicate.ID != id || len(duplicate.Wire) != 0 {
			t.Fatalf("duplicate: %+v %v", duplicate, err)
		}
		loaded, err := alice.LoadPreparedSharingProjectMessage(project, id)
		if err != nil || loaded.ID != id || !bytes.Equal(loaded.Wire, prepared.Wire) {
			t.Fatalf("duplicate changed prepared wire: %+v %v", loaded, err)
		}
	}
	replyID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	reply, err := bob.PrepareSharingProjectMessageWithID(project, alice.PrincipalID(), "REPLY", replyID.String(), []byte("stable answer"), prepared.Wire)
	if err != nil {
		t.Fatal(err)
	}
	opened, err = alice.DecryptSharingProjectMessage(project, reply.Wire, prepared.Wire)
	if err != nil || opened.Header.ID != replyID.String() || opened.Header.ThreadID != id || opened.Header.CorrelationID == nil || *opened.Header.CorrelationID != id || string(opened.Plaintext) != "stable answer" {
		t.Fatalf("reply: %+v %v", opened, err)
	}
}

func TestSharingProjectMessageWithIDRejectsInvalidIDs(t *testing.T) {
	project, clients := projectMessageFixture(t)
	alice, bob := clients[0], clients[1]
	id := "019a1357-2468-7abc-8def-0123456789ab"
	for _, invalid := range []string{"", "invalid", uuid.Nil.String(), uuid.NewString(), strings.ToUpper(id), strings.ReplaceAll(id, "-", ""), "urn:uuid:" + id, "{" + id + "}", "019a1357-2468-7abc-0def-0123456789ab"} {
		t.Run(invalid, func(t *testing.T) {
			result, err := alice.PrepareSharingProjectMessageWithID(project, bob.PrincipalID(), "ASK", invalid, nil, nil)
			if err == nil || result.ID != invalid || len(result.Wire) != 0 {
				t.Fatalf("invalid ID result: %+v %v", result, err)
			}
		})
	}
	if _, err := os.Stat(alice.kr.projectMessageDir(alice.PrincipalID())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid ID touched spool: %v", err)
	}
}

func TestSharingProjectMessageWithIDPreservesIDOnValidationError(t *testing.T) {
	project, clients := projectMessageFixture(t)
	alice, bob := clients[0], clients[1]
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, project, recipient, kind string
		plaintext, predecessor         []byte
	}{
		{name: "descriptor", project: uuid.NewString(), recipient: bob.PrincipalID(), kind: "ASK"},
		{name: "self recipient", project: project, recipient: alice.PrincipalID(), kind: "ASK"},
		{name: "outside roster", project: project, recipient: uuid.NewString(), kind: "ASK"},
		{name: "plaintext limit", project: project, recipient: bob.PrincipalID(), kind: "ASK", plaintext: make([]byte, 4097)},
		{name: "kind", project: project, recipient: bob.PrincipalID(), kind: "invalid"},
		{name: "predecessor", project: project, recipient: bob.PrincipalID(), kind: "REPLY", predecessor: []byte("invalid")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := alice.PrepareSharingProjectMessageWithID(tc.project, tc.recipient, tc.kind, id.String(), tc.plaintext, tc.predecessor)
			if err == nil || result.ID != id.String() || len(result.Wire) != 0 {
				t.Fatalf("validation result: %+v %v", result, err)
			}
		})
	}
}

func TestSharingProjectMessageWithIDRecoversDurabilityFailure(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(map[bool]string{false: "reservation", true: "wire commit"}[commit], func(t *testing.T) {
			project, clients := projectMessageFixture(t)
			alice, bob := clients[0], clients[1]
			id, err := uuid.NewV7()
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(alice.kr.projectMessageDir(alice.PrincipalID()), id.String()+".json")
			injected := errors.New("injected sync failure")
			var captured []byte
			alice.kr.pendingPairSyncDir = func(dir string) error {
				if dir == alice.kr.projectMessageDir(alice.PrincipalID()) {
					raw, err := os.ReadFile(path)
					var record projectMessageRecord
					if err == nil && json.Unmarshal(raw, &record) == nil && ((len(record.Wire) > 0) == commit) {
						captured = append([]byte(nil), record.Wire...)
						return injected
					}
				}
				return nil
			}
			result, err := alice.PrepareSharingProjectMessageWithID(project, bob.PrincipalID(), "ASK", id.String(), []byte("uncertain"), nil)
			if !errors.Is(err, injected) || result.ID != id.String() || len(result.Wire) != 0 {
				t.Fatalf("fault result: %+v %v", result, err)
			}
			alice.kr.pendingPairSyncDir = nil
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			result, err = alice.PrepareSharingProjectMessageWithID(project, bob.PrincipalID(), "ASK", id.String(), []byte("regenerated"), nil)
			if err == nil || result.ID != id.String() || len(result.Wire) != 0 {
				t.Fatalf("reused reservation: %+v %v", result, err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("reservation changed: %v", err)
			}
			loaded, err := alice.LoadPreparedSharingProjectMessage(project, id.String())
			if !commit {
				if err == nil || len(loaded.Wire) != 0 {
					t.Fatal("incomplete reservation became prepared wire")
				}
			} else if err != nil || loaded.ID != id.String() || !bytes.Equal(loaded.Wire, captured) {
				t.Fatalf("committed wire did not recover: %+v %v", loaded, err)
			}
		})
	}
}
