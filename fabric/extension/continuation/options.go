package continuation

// ValidateOptions validates finite configured storage admission before an
// installation persists its setup pin. It creates no directory or database.
func ValidateOptions(o Options) error { return o.validate() }
