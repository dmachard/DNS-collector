package pkginit

import (
	"errors"
	"fmt"
)

// Sentinel errors for pkginit
var (
	ErrNoRoutesDefined = errors.New("no routes are defined")
	ErrDuplicateStanza = errors.New("duplicate stanza name")
	ErrRouteNotFound   = errors.New("route not found")
	ErrRoutingLoop     = errors.New("routing loop detected")
	ErrStanzaNotFound  = errors.New("stanza not found")
	ErrStanzaConfig    = errors.New("stanza config error")
	ErrYAMLConfig      = errors.New("yaml config error")
)

// StanzaConfigError represents an error during stanza configuration retrieval
type StanzaConfigError struct {
	Message string
	Err     error
}

func (e *StanzaConfigError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("stanza config error: %s - %v", e.Message, e.Err)
	}
	return fmt.Sprintf("stanza config error: %s", e.Message)
}

func (e *StanzaConfigError) Unwrap() error {
	return e.Err
}

func (e *StanzaConfigError) Is(target error) bool {
	return target == ErrStanzaConfig
}

// YAMLConfigError represents an error during YAML unmarshaling for pipeline config
type YAMLConfigError struct {
	Section string
	Err     error
}

func (e *YAMLConfigError) Error() string {
	return fmt.Sprintf("yaml %s config error: %v", e.Section, e.Err)
}

func (e *YAMLConfigError) Unwrap() error {
	return e.Err
}

func (e *YAMLConfigError) Is(target error) bool {
	return target == ErrYAMLConfig
}

// StanzaNotFoundError represents a pipeline stanza that was not found
type StanzaNotFoundError struct {
	Name string
}

func (e *StanzaNotFoundError) Error() string {
	return fmt.Sprintf("stanza not found: %s", e.Name)
}

func (e *StanzaNotFoundError) Is(target error) bool {
	return target == ErrStanzaNotFound
}

// DuplicateStanzaError represents an error when a stanza name is duplicated
type DuplicateStanzaError struct {
	Name string
}

func (e *DuplicateStanzaError) Error() string {
	return fmt.Sprintf("stanza with name=[%s] is duplicated", e.Name)
}

func (e *DuplicateStanzaError) Is(target error) bool {
	return target == ErrDuplicateStanza
}

// RouteNotFoundError represents an error when a configured route target does not exist
type RouteNotFoundError struct {
	Name string
	From string
}

func (e *RouteNotFoundError) Error() string {
	if e.From != "" {
		return fmt.Sprintf("stanza=[%s] route=[%s] does not exist", e.From, e.Name)
	}
	return fmt.Sprintf("route=[%s] does not exist", e.Name)
}

func (e *RouteNotFoundError) Is(target error) bool {
	return target == ErrRouteNotFound
}

// RoutingLoopError represents an error when a stanza routes to itself
type RoutingLoopError struct {
	From string
	To   string
}

func (e *RoutingLoopError) Error() string {
	return fmt.Sprintf("routing error loop with stanza=%s to stanza=%s", e.From, e.To)
}

func (e *RoutingLoopError) Is(target error) bool {
	return target == ErrRoutingLoop
}
