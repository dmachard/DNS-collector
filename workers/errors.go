package workers

import (
	"errors"
	"fmt"
)

// Sentinel errors for workers
var (
	ErrDefaultRoutingNotSupported = errors.New("default routing not supported")
)

// DefaultRoutingError represents an error when default routing to a stanza is not supported
type DefaultRoutingError struct {
	StanzaName string
	Reason     string
}

func (e *DefaultRoutingError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("default routing to stanza=[%s] not supported: %s", e.StanzaName, e.Reason)
	}
	return fmt.Sprintf("default routing to stanza=[%s] not supported", e.StanzaName)
}

func (e *DefaultRoutingError) Is(target error) bool {
	return target == ErrDefaultRoutingNotSupported
}
