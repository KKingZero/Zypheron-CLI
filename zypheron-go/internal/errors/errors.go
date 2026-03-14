package errors

import (
	"fmt"
)

// ErrorType represents the category of error
type ErrorType string

const (
	ErrorTypeValidation    ErrorType = "VALIDATION"
	ErrorTypeNetwork       ErrorType = "NETWORK"
	ErrorTypeSecurity      ErrorType = "SECURITY"
	ErrorTypeConfiguration ErrorType = "CONFIG"
	ErrorTypeInternal      ErrorType = "INTERNAL"
	ErrorTypeNotFound      ErrorType = "NOT_FOUND"
	ErrorTypePermission    ErrorType = "PERMISSION"
	ErrorTypeTimeout       ErrorType = "TIMEOUT"
)

// ZypheronError is a structured error type
type ZypheronError struct {
	Type    ErrorType
	Message string
	Err     error
	Code    int
	Context map[string]interface{}
}

// Error implements the error interface
func (e *ZypheronError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Type, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] %s", e.Type, e.Message)
}

// Unwrap implements the unwrap interface for error chains
func (e *ZypheronError) Unwrap() error {
	return e.Err
}

// New creates a new ZypheronError
func New(errType ErrorType, message string) *ZypheronError {
	return &ZypheronError{
		Type:    errType,
		Message: message,
		Context: make(map[string]interface{}),
	}
}

// Wrap wraps an existing error
func Wrap(errType ErrorType, message string, err error) *ZypheronError {
	return &ZypheronError{
		Type:    errType,
		Message: message,
		Err:     err,
		Context: make(map[string]interface{}),
	}
}

// WithContext adds context to the error
func (e *ZypheronError) WithContext(key string, value interface{}) *ZypheronError {
	e.Context[key] = value
	return e
}

// WithCode sets the error code
func (e *ZypheronError) WithCode(code int) *ZypheronError {
	e.Code = code
	return e
}

// Validation error constructors
func ValidationError(message string) *ZypheronError {
	return New(ErrorTypeValidation, message)
}

func WrapValidationError(message string, err error) *ZypheronError {
	return Wrap(ErrorTypeValidation, message, err)
}

// Network error constructors
func NetworkError(message string) *ZypheronError {
	return New(ErrorTypeNetwork, message)
}

func WrapNetworkError(message string, err error) *ZypheronError {
	return Wrap(ErrorTypeNetwork, message, err)
}

// Security error constructors
func SecurityError(message string) *ZypheronError {
	return New(ErrorTypeSecurity, message)
}

func WrapSecurityError(message string, err error) *ZypheronError {
	return Wrap(ErrorTypeSecurity, message, err)
}

// Configuration error constructors
func ConfigError(message string) *ZypheronError {
	return New(ErrorTypeConfiguration, message)
}

func WrapConfigError(message string, err error) *ZypheronError {
	return Wrap(ErrorTypeConfiguration, message, err)
}

// Internal error constructors
func InternalError(message string) *ZypheronError {
	return New(ErrorTypeInternal, message)
}

func WrapInternalError(message string, err error) *ZypheronError {
	return Wrap(ErrorTypeInternal, message, err)
}

// NotFound error constructors
func NotFoundError(message string) *ZypheronError {
	return New(ErrorTypeNotFound, message)
}

// Permission error constructors
func PermissionError(message string) *ZypheronError {
	return New(ErrorTypePermission, message)
}

// Timeout error constructors
func TimeoutError(message string) *ZypheronError {
	return New(ErrorTypeTimeout, message)
}

// IsType checks if an error is of a specific type
func IsType(err error, errType ErrorType) bool {
	if zErr, ok := err.(*ZypheronError); ok {
		return zErr.Type == errType
	}
	return false
}

// GetContext retrieves context from error if it's a ZypheronError
func GetContext(err error) map[string]interface{} {
	if zErr, ok := err.(*ZypheronError); ok {
		return zErr.Context
	}
	return nil
}

