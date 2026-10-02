package sessionworker

// Done allows observers to discard a view when its ephemeral input authority
// closes, without polling or retaining a goroutine after explicit detach.
func (s *TerminalStream) Done() <-chan struct{} { return s.done }
