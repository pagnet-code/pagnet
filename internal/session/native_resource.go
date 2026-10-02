package session

import "errors"

// ErrNativeResourceLimit means the original captured accepted stream has hit
// its declared durable bound. Drivers stop that exact supervised endpoint and
// report genuine EOF; it is not a vendor turn failure or completion.
var ErrNativeResourceLimit = errors.New("native accepted source resource limit")
