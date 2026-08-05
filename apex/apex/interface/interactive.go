package main

import (
	"fmt"
)

type InteractiveSetupUnavailableError struct {
	Message string
}

func (e *InteractiveSetupUnavailableError) Error() string {
	return e.Message
}

// Stubs for TUI - these will be replaced/implemented when the TUI is ported
func runGoTUI(args *CliArgs) error {
	return nil
}

func RunTUI(args *CliArgs) error {
	err := runGoTUI(args)
	if err != nil {
		return &InteractiveSetupUnavailableError{
			Message: fmt.Sprintf("The interactive interface could not start: %v", err),
		}
	}
	return nil
}
