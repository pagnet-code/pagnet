package e2ee

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

const NativeContentBindingFormat = "pagnet.native-content-aad.v1"
const ObjectTypeNativeContentFragment = "native_content_fragment"
const NativeContentMaxFragments = 320

// NativeContentBinding is part of authenticated AAD. None of these fields or
// the public fragment ID is derived from private plaintext or its digest.
type NativeContentBinding struct {
	Format            string `json:"format"`
	ContentID         string `json:"content_id"`
	ObservationID     string `json:"observation_id"`
	OriginID          string `json:"origin_id"`
	InstanceID        string `json:"instance_id"`
	NativeGeneration  string `json:"native_generation"`
	NativeSessionID   string `json:"native_session_id"`
	SubjectType       string `json:"subject_type"`
	SubjectID         string `json:"subject_id"`
	Purpose           string `json:"purpose"`
	FragmentCount     int    `json:"fragment_count"`
	SourceCommandID   string `json:"source_command_id,omitempty"`
	SourceAdmissionID string `json:"source_admission_id,omitempty"`
	LogicalTurnID     string `json:"logical_turn_id,omitempty"`
	Ordinal           *int   `json:"ordinal,omitempty"`
}

// Reject unknown authenticated fields rather than silently discarding them.
func (b *NativeContentBinding) UnmarshalJSON(raw []byte) error {
	type descriptor NativeContentBinding
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var parsed descriptor
	if err := decoder.Decode(&parsed); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid native content binding")
	}
	*b = NativeContentBinding(parsed)
	return nil
}

func NativeContentFragmentID(contentID string, ordinal int) (string, error) {
	id, err := uuid.Parse(contentID)
	if err != nil || ordinal < 0 || ordinal >= NativeContentMaxFragments {
		return "", errors.New("invalid native content fragment identity")
	}
	hash := sha256.New()
	hash.Write([]byte("pagnet/native-content/fragment-id/v1\x00"))
	hash.Write(id[:])
	var index [4]byte
	binary.BigEndian.PutUint32(index[:], uint32(ordinal))
	hash.Write(index[:])
	var result uuid.UUID
	copy(result[:], hash.Sum(nil))
	result[6] = (result[6] & 0x0f) | 0x80
	result[8] = (result[8] & 0x3f) | 0x80
	return result.String(), nil
}

func (a AAD) validateNativeContentBinding() error {
	b := a.NativeContent
	if b == nil {
		return nil
	}
	if b.Format != NativeContentBindingFormat || b.FragmentCount < 1 || b.FragmentCount > NativeContentMaxFragments || b.NativeGeneration == "" || len(b.NativeGeneration) > 256 || b.NativeSessionID == "" || len(b.NativeSessionID) > 512 || a.Sender != b.InstanceID {
		return errors.New("invalid native content binding")
	}
	for _, id := range []string{b.ContentID, b.ObservationID, b.OriginID, b.InstanceID, b.SubjectID} {
		if parsed, err := uuid.Parse(id); err != nil || parsed.String() != id {
			return errors.New("invalid native content scope identity")
		}
	}
	subjectType := ""
	switch b.Purpose {
	case "interaction_detail", "interaction_answer":
		subjectType = ObjectTypeRuntimeInteraction
	case "native_turn_output", "native_turn_plan":
		subjectType = "runtime_turn"
		for _, id := range []string{b.SourceCommandID, b.SourceAdmissionID} {
			if parsed, err := uuid.Parse(id); err != nil || parsed.String() != id {
				return errors.New("invalid native turn command authority")
			}
		}
		ordinal, err := strconv.ParseInt(strings.TrimPrefix(b.LogicalTurnID, "pagnet-worker-turn-"), 10, 64)
		if err != nil || ordinal <= 0 || b.LogicalTurnID != fmt.Sprintf("pagnet-worker-turn-%d", ordinal) {
			return errors.New("invalid original native logical turn")
		}
		expected := uuid.NewSHA1(uuid.NameSpaceOID, []byte("pagnet-native-turn:"+b.OriginID+":"+b.LogicalTurnID)).String()
		if b.SubjectID != expected {
			return errors.New("native turn subject/source mismatch")
		}
	case "runtime_error":
		subjectType = "runtime_turn"
	case "task_progress":
		subjectType = "runtime_task_progress"
	case "task_result":
		subjectType = ObjectTypeTask
	case "network_result":
		subjectType = ObjectTypeArtifact
	default:
		return errors.New("invalid native content purpose")
	}
	if b.Purpose != "native_turn_output" && b.Purpose != "native_turn_plan" && (b.SourceCommandID != "" || b.SourceAdmissionID != "" || b.LogicalTurnID != "") {
		return errors.New("unexpected native turn authority")
	}
	if b.SubjectType != subjectType {
		return errors.New("native content subject/purpose mismatch")
	}
	if b.Ordinal == nil {
		if a.ObjectType != b.SubjectType || a.ObjectID != b.SubjectID {
			return errors.New("native content manifest subject mismatch")
		}
	} else {
		if *b.Ordinal < 0 || *b.Ordinal >= b.FragmentCount {
			return errors.New("invalid native content ordinal")
		}
		expected, err := NativeContentFragmentID(b.ContentID, *b.Ordinal)
		if err != nil || a.ObjectType != ObjectTypeNativeContentFragment || a.ObjectID != expected {
			return fmt.Errorf("invalid native fragment AAD identity")
		}
	}
	return nil
}
