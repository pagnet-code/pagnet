//go:build linux || darwin

package sessionworker

import "testing"

func TestStopReapsGenuineAcceptedInvocationWithoutErasingUncertainty(t *testing.T) {
	testStopAcceptedPrompt(t, false, true)
}
func TestFailedStopCannotCompleteAcceptedInvocation(t *testing.T) {
	testStopAcceptedPrompt(t, true, true)
}
