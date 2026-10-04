package sessionworker

import "encoding/json"

// privateCaptureAuthority keeps original Cloud key/AAD bytes exact. Local
// captures bind the explicit independent domain/physical ownership instead.
func (j *Journal) privateCaptureAuthority() any {
	if j.isLocal() {
		return j.authority
	}
	return j.scope
}
func (j *Journal) sealNativeCapture(key []byte, observation NativeObservation, source any) (*NativeCaptureRef, []byte, error) {
	return sealNativeCaptureBound(key, j.privateCaptureAuthority(), j.dir, observation, source)
}

// OpenAuthorityNativeCapture authenticates private source ciphertext only. The
// caller must separately authenticate the peer/source origin and current lease;
// it grants no native actuation, publication or Cloud receipt.
func OpenAuthorityNativeCapture(key []byte, scope AuthorityScope, directory string, observation NativeObservation, encrypted []byte) (json.RawMessage, error) {
	if e := scope.Validate(); e != nil {
		return nil, e
	}
	if cloud, ok := scope.Cloud(); ok {
		return OpenNativeCapture(key, cloud, directory, observation, encrypted)
	}
	return openNativeCaptureBound(key, scope, directory, observation, encrypted)
}
