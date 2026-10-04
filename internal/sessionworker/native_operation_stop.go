package sessionworker

import "context"

type nativeOwnedOperation struct {
	ctx              context.Context
	cancel           context.CancelFunc
	done             chan struct{}
	nativeOwned      bool
	kind             string
	activationCancel context.CancelFunc
}

// Registration shares the admission-to-execution fence. Stop cancels and
// joins earlier operations, including an activation not yet scheduled or still
// awaiting its original authority. Later work cannot overtake its stop effect.
// Completion remains the original operation's durable outcome, not a synthetic
// native stopped event.
func (o *SessionOwner) registerOperationLocked(out Outcome) (*nativeOwnedOperation, chan struct{}, []*nativeOwnedOperation) {
	if o.operations == nil {
		o.operations = make(map[int64]*nativeOwnedOperation)
	}
	ctx, cancel := context.WithCancel(o.ctx)
	operation := &nativeOwnedOperation{ctx: ctx, cancel: cancel, done: make(chan struct{}), kind: out.Kind}
	previousStop := o.lastStopDone
	var earlier []*nativeOwnedOperation
	if out.Kind == "stop" {
		if out.Sequence > o.stopSequence {
			o.stopSequence = out.Sequence
		}
		for sequence, pending := range o.operations {
			if sequence < out.Sequence {
				if pending.kind == "prompt" {
					// A runtime-accepted turn must settle from its genuine EOF,
					// not a generic cancelled context that erases uncertainty.
					if pending.activationCancel != nil {
						pending.activationCancel()
					}
				} else if pending.kind != "stop" {
					pending.cancel()
				}
				earlier = append(earlier, pending)
			}
		}
		o.lastStopDone = operation.done
	} else if out.Sequence < o.stopSequence {
		cancel()
	}
	o.operations[out.Sequence] = operation
	return operation, previousStop, earlier
}

func (o *SessionOwner) finishOwnedOperation(sequence int64, operation *nativeOwnedOperation) {
	o.mu.Lock()
	delete(o.operations, sequence)
	close(operation.done)
	o.mu.Unlock()
	operation.cancel()
}
