package sdk

import "sync/atomic"

// atomicString is a thread-safe string holder. (This Go toolchain's
// sync/atomic has no atomic.String; Pointer[string] is the equivalent.)
type atomicString struct {
	p atomic.Pointer[string]
}

// Store sets the value.
func (a *atomicString) Store(s string) { a.p.Store(&s) }

// Load returns the current value ("" when unset).
func (a *atomicString) Load() string {
	if p := a.p.Load(); p != nil {
		return *p
	}
	return ""
}
