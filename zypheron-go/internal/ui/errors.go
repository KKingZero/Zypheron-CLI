package ui

import (
	"fmt"
)

// ErrorWithSuggestion creates an error message with actionable next steps
func ErrorWithSuggestion(message, suggestion string) string {
	if suggestion == "" {
		return Error(message)
	}
	return Error(message) + "\n" + InfoMsg("Tip: "+suggestion)
}

// ErrorWithCommand creates an error message with a command suggestion
func ErrorWithCommand(message, command string) string {
	return ErrorWithSuggestion(message, fmt.Sprintf("Try: %s", command))
}

// ValidationError creates a validation error with examples
func ValidationError(field, reason string, examples ...string) string {
	msg := fmt.Sprintf("Invalid %s: %s", field, reason)
	if len(examples) > 0 {
		msg += "\n" + InfoMsg("Examples:")
		for _, ex := range examples {
			msg += "\n  " + Accent.Sprint("• ") + Muted.Sprint(ex)
		}
	}
	return Error(msg)
}

// ErrorWithHelp creates an error message with help text reference
func ErrorWithHelp(message, helpCommand string) string {
	return Error(message) + "\n" + InfoMsg(fmt.Sprintf("For more information, run: %s", helpCommand))
}

// WrapError wraps an error with user-friendly context
func WrapError(context string, err error) string {
	if err == nil {
		return Error(context)
	}
	return Error(fmt.Sprintf("%s: %v", context, err))
}

// ErrorWithRecovery provides an error message with recovery steps
func ErrorWithRecovery(message string, steps ...string) string {
	msg := Error(message)
	if len(steps) > 0 {
		msg += "\n" + InfoMsg("To resolve:")
		for i, step := range steps {
			msg += fmt.Sprintf("\n  %d. %s", i+1, step)
		}
	}
	return msg
}

