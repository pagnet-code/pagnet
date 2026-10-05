package identity

import "bytes"

// These are private infrastructure fence purposes, not business permissions or
// caller-selectable operation fields. Unknown purposes must fail closed.
const (
	PurposeInvokeAdmission   = "pagnet.local.invoke-admission.v1"
	PurposeNativeReservation = "pagnet.local.native-reservation.v1"
	PurposeNativeIntent      = "pagnet.local.native-intent.v1"
	PurposeNativeOrigin      = "pagnet.local.native-origin.v1"
)

func withNativeSourceFacts(f AdmissionFacts, purpose string, source Admission) AdmissionFacts {
	f.Purpose = purpose
	copy := source
	copy.Provenance.Ancestry = append([]string(nil), source.Provenance.Ancestry...)
	copy.Provenance.ExtensionChain = append([]string(nil), source.Provenance.ExtensionChain...)
	copy.Provenance.TriggerLineage = append([]string(nil), source.Provenance.TriggerLineage...)
	copy.CallerSignature = bytes.Clone(source.CallerSignature)
	copy.DispatchSignature = bytes.Clone(source.DispatchSignature)
	copy.Witness = cloneWitness(source.Witness)
	copy.Proof.Value = bytes.Clone(source.Proof.Value)
	copy.Proof.Signature = bytes.Clone(source.Proof.Signature)
	f.Source = &copy
	return f
}
