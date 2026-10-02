package e2ee

import (
	"errors"
	"fmt"
	"regexp"
)

const (
	ObjectTypeRuntimeTerminalSession        = "runtime_terminal_session"
	ObjectTypeRuntimeTerminal               = "runtime_terminal"
	ObjectTypeRuntimeTerminalInput          = "runtime_terminal_input"
	TerminalSessionFormat                   = "pagnet.terminal-session.v1"
	TerminalMaxSafeSequence          uint64 = 9007199254740991
)

var terminalID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var terminalGeneration = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)

func TerminalKeyObjectID(instance, session, generation, keyID string) (string, error) {
	if !terminalID.MatchString(instance) || !terminalID.MatchString(session) || !terminalID.MatchString(keyID) || !terminalGeneration.MatchString(generation) {
		return "", errors.New("invalid terminal crypto source identity")
	}
	return fmt.Sprintf("terminal-key:v1:%s:%s:%s:%s", instance, session, generation, keyID), nil
}
func TerminalFrameObjectID(instance, session, generation, keyID, direction string, snapshot bool, sequence uint64) (string, error) {
	if _, err := TerminalKeyObjectID(instance, session, generation, keyID); err != nil {
		return "", err
	}
	if sequence > TerminalMaxSafeSequence {
		return "", errors.New("terminal sequence exceeds browser integer bound")
	}
	mode := direction
	switch direction {
	case "output":
		if snapshot {
			mode = "output-snapshot"
		} else {
			mode = "output-live"
		}
	case "input":
		if snapshot || sequence == 0 {
			return "", errors.New("invalid terminal input sequence")
		}
	default:
		return "", errors.New("invalid terminal crypto direction")
	}
	return fmt.Sprintf("terminal-frame:v1:%s:%s:%s:%s:%s:%d", instance, session, generation, keyID, mode, sequence), nil
}
