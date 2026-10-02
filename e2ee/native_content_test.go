package e2ee

import (
	"encoding/json"
	"testing"
)

func TestNativeContentAADRejectsUnknownFieldsAndContradictoryIdentity(t *testing.T) {
	a := AAD{TenantID: "00000000-0000-0000-0000-000000000001", NetworkID: "00000000-0000-0000-0000-000000000002", ObjectType: ObjectTypeRuntimeInteraction, ObjectID: "00000000-0000-0000-0000-000000000003", Sender: "00000000-0000-0000-0000-000000000004", NativeContent: &NativeContentBinding{Format: NativeContentBindingFormat, ContentID: "00000000-0000-0000-0000-000000000005", ObservationID: "00000000-0000-0000-0000-000000000006", OriginID: "00000000-0000-0000-0000-000000000007", InstanceID: "00000000-0000-0000-0000-000000000004", NativeGeneration: "generation", NativeSessionID: "session", SubjectType: ObjectTypeRuntimeInteraction, SubjectID: "00000000-0000-0000-0000-000000000003", Purpose: "interaction_detail", FragmentCount: 2}}
	if err := a.ValidateScope(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(a.NativeContent)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw[:len(raw)-1], []byte(`,"discarded_security_field":true}`)...)
	var parsed NativeContentBinding
	if json.Unmarshal(raw, &parsed) == nil {
		t.Fatal("unknown authenticated field discarded")
	}
	for _, scenario := range []string{"sender", "subject", "purpose", "ordinal", "count"} {
		t.Run(scenario, func(t *testing.T) {
			copy := a
			binding := *a.NativeContent
			copy.NativeContent = &binding
			switch scenario {
			case "sender":
				copy.Sender = "other"
			case "subject":
				copy.ObjectID = "other"
			case "purpose":
				binding.Purpose = "task_result"
			case "ordinal":
				index := 2
				binding.Ordinal = &index
			case "count":
				binding.FragmentCount = 0
			}
			if err := copy.ValidateScope(); err == nil {
				t.Fatal("contradictory AAD accepted")
			}
		})
	}
}
