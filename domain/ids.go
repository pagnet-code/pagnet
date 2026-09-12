package domain

import "github.com/google/uuid"

// ID is a time-sortable UUIDv7 identifier, stored as TEXT.
type ID string

// NewID generates a new UUIDv7 (time-sortable) identifier.
func NewID() ID {
	u, err := uuid.NewV7()
	if err != nil {
		u, _ = uuid.NewRandom()
	}
	return ID(u.String())
}

// MustParseID parses s into an ID. It panics on malformed input; use it only
// for trusted, fixed values (tests, constants).
func MustParseID(s string) ID {
	if _, err := uuid.Parse(s); err != nil {
		panic("domain: bad id " + s)
	}
	return ID(s)
}

// ParseID validates that s is a well-formed UUID and returns it
// normalized. IDs crossing the server→daemon boundary are validated with
// this before they may become filesystem path components (SEC-407): a
// crafted value like "../../x" must never reach a filepath.Join.
func ParseID(s string) (ID, error) {
	u, err := uuid.Parse(s)
	if err != nil {
		return "", err
	}
	return ID(u.String()), nil
}

// String implements sql scanning targets and display.
func (id ID) String() string { return string(id) }

// IsZero reports whether the ID is empty.
func (id ID) IsZero() bool { return id == "" }

// ShortID returns the first 8 characters, for display (e.g. task short ids).
func (id ID) ShortID() string {
	s := string(id)
	if len(s) > 8 {
		return s[:8]
	}
	return s
}
