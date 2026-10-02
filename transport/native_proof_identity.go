package transport

import "reflect"

// SameNativeDispatchProof compares the complete original proof. Time identity
// is the exact instant, independent of JSON's Z/+00:00 location representation.
// Comparison copies never rewrite stored proof, ciphertext or source metadata.
func SameNativeDispatchProof(a, b NativeDispatchProof) bool {
	a.SourceRunnerEpoch = a.SourceRunnerEpoch.UTC()
	b.SourceRunnerEpoch = b.SourceRunnerEpoch.UTC()
	return reflect.DeepEqual(a, b)
}

func comparisonDeletionProof(p NativeOwnershipDeletionProof) NativeOwnershipDeletionProof {
	p.StopProof.SourceRunnerEpoch = p.StopProof.SourceRunnerEpoch.UTC()
	p.StoppedObservedAt = p.StoppedObservedAt.UTC()
	p.StoppedExpiresAt = p.StoppedExpiresAt.UTC()
	return p
}
func SameNativeOwnershipDeletionProof(a, b NativeOwnershipDeletionProof) bool {
	return reflect.DeepEqual(comparisonDeletionProof(a), comparisonDeletionProof(b))
}
func SameNativeWorkerOwnership(a, b NativeWorkerOwnership) bool {
	if a.DeletionProof != nil {
		p := comparisonDeletionProof(*a.DeletionProof)
		a.DeletionProof = &p
	}
	if b.DeletionProof != nil {
		p := comparisonDeletionProof(*b.DeletionProof)
		b.DeletionProof = &p
	}
	return reflect.DeepEqual(a, b)
}
func SameNativeDispatchCancellationProposal(a, b NativeDispatchCancellationProposal) bool {
	a.Proof.SourceRunnerEpoch = a.Proof.SourceRunnerEpoch.UTC()
	b.Proof.SourceRunnerEpoch = b.Proof.SourceRunnerEpoch.UTC()
	return reflect.DeepEqual(a, b)
}
