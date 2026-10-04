package sessionworker

// Public failure metadata contains only a bounded classification. Vendor
// diagnostics remain in their original private encrypted event capture.
type NativeOperationFailure struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}
