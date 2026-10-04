package nativeauthority

import (
	"bytes"
	"errors"

	"github.com/pagnet-code/pagnet/fabric"
	fabricidentity "github.com/pagnet-code/pagnet/fabric/identity"
)

// CancellationIntent reconstructs only the exact retained stop target. It does
// not reserve a command, refresh its deadline, or authorize a provider effect.
// The caller must hold the separate current cancellation fence through the
// worker's FULL acknowledgement.
func (c *LocalController) CancellationIntent(current fabricidentity.Controller, originalBinding fabricidentity.Binding, source fabricidentity.Admission, reservation fabricidentity.NativeDispatchReservation, finalized []byte) (VerifiedIntent, error) {
	if c == nil || c.binder == nil || c.authority == nil {
		return VerifiedIntent{}, errors.New("local cancellation controller missing")
	}
	var final fabric.Envelope
	if err := fabric.DecodeJSON(finalized, &final); err != nil {
		return VerifiedIntent{}, err
	}
	operation, err := c.binder.Bind(final)
	if err != nil {
		return VerifiedIntent{}, err
	}
	binding := originalBinding
	i := VerifiedIntent{Scope: c.scope, CurrentBinding: c.binding, CurrentController: current, OriginalBinding: &binding, OriginalAdmission: source, Reservation: reservation, Commitment: reservation.Commitment(), Operation: operation, Finalized: bytes.Clone(finalized)}
	if err = ValidateCancellationIntent(c.scope, c.binder, i); err != nil {
		return VerifiedIntent{}, err
	}
	return i, nil
}
