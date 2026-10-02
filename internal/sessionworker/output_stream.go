package sessionworker

import "time"

const NativeOutputStreamCaptureFormat = "pagnet.worker-native-output-stream.v1"
const nativeOutputBatchBytes = 64 << 10

// This is an original captured stream range, NOT a vendor-generated frame.
// The rolling digest/count commits to actual parser deltas before coalescing.
type NativeOutputStreamProof struct {
	Format          string    `json:"format"`
	StreamID        string    `json:"streamId"`
	BatchID         string    `json:"batchId"`
	DeltaCount      int64     `json:"deltaCount"`
	RollingDigest   string    `json:"rollingDigest"`
	ByteOffset      int64     `json:"byteOffset"`
	ByteLength      int       `json:"byteLength"`
	FirstObservedAt time.Time `json:"firstObservedAt"`
	LastObservedAt  time.Time `json:"lastObservedAt"`
}
