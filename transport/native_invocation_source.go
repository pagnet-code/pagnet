package transport

import (
	"errors"
	"github.com/pagnet-code/pagnet/e2ee"
	"unicode/utf8"
)

// NativeInvocationSource is the exact original invocation input association.
// It is bound by native dispatch authority and pinned before native acceptance;
// it conveys no key, prompt body or new grant. InvocationID is not a task ID.
type NativeInvocationSource struct {
	InvocationID string   `json:"invocationId"`
	InputAAD     e2ee.AAD `json:"inputAAD"`
}

func (s NativeInvocationSource) Validate() error {
	if s.InvocationID == "" || len(s.InvocationID) > 256 || !utf8.ValidString(s.InvocationID) || s.InputAAD.ObjectType != e2ee.ObjectTypeInvocationInput || s.InputAAD.ObjectID != s.InvocationID || s.InputAAD.KeyEpochID == "" || s.InputAAD.NativeContent != nil || s.InputAAD.ValidateScope() != nil {
		return errors.New("invalid original invocation source descriptor")
	}
	for _, r := range s.InvocationID {
		if r < 32 || r == 127 {
			return errors.New("invalid original invocation identity")
		}
	}
	return nil
}
