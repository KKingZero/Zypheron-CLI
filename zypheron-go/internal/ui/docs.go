package ui

import "fmt"

// docsBaseURL is the base URL for Zypheron documentation
const docsBaseURL = "https://docs.zypheron.io"

// docsTopicMap maps topic names to documentation paths
var docsTopicMap = map[string]string{
	"setup":         "/getting-started/setup",
	"python":        "/setup/python",
	"api-keys":      "/configuration/api-keys",
	"ai-engine":     "/ai/engine",
	"tools":         "/tools/installation",
	"configuration": "/configuration",
	"network":       "/troubleshooting/network",
	"scan":          "/commands/scan",
}

// GetDocsURL returns the documentation URL for a given topic
func GetDocsURL(topic string) string {
	if path, ok := docsTopicMap[topic]; ok {
		return docsBaseURL + path
	}
	return docsBaseURL + "/troubleshooting"
}

// ErrorWithDocs creates an error message with a documentation link
func ErrorWithDocs(message, topic string) string {
	url := GetDocsURL(topic)
	return Error(message) + "\n" + InfoMsg("Documentation: " + url)
}

// ErrorWithCommandAndDocs creates an error message with a command suggestion and docs link
func ErrorWithCommandAndDocs(message, command, topic string) string {
	url := GetDocsURL(topic)
	return Error(message) + "\n" + InfoMsg("Try: "+command) + "\n" + InfoMsg("Docs: "+url)
}

// ValidationErrorWithDocs creates a validation error with examples and a docs link
func ValidationErrorWithDocs(field, reason, topic string, examples ...string) string {
	msg := fmt.Sprintf("Invalid %s: %s", field, reason)
	result := Error(msg)
	if len(examples) > 0 {
		result += "\n" + InfoMsg("Examples:")
		for _, ex := range examples {
			result += "\n  " + Accent.Sprint("• ") + Muted.Sprint(ex)
		}
	}
	url := GetDocsURL(topic)
	result += "\n" + InfoMsg("Docs: "+url)
	return result
}

// ErrorWithRecoveryAndDocs provides an error message with recovery steps and docs link
func ErrorWithRecoveryAndDocs(message, topic string, steps ...string) string {
	msg := Error(message)
	if len(steps) > 0 {
		msg += "\n" + InfoMsg("To resolve:")
		for i, step := range steps {
			msg += fmt.Sprintf("\n  %d. %s", i+1, step)
		}
	}
	url := GetDocsURL(topic)
	msg += "\n" + InfoMsg("Documentation: "+url)
	return msg
}

// ToolNotFoundError creates a formatted error for missing security tools
func ToolNotFoundError(toolName string) string {
	return ErrorWithRecoveryAndDocs(
		fmt.Sprintf("%s is not installed", toolName),
		"tools",
		fmt.Sprintf("Install with: zypheron tools install %s", toolName),
		"Or install manually using your package manager",
	)
}

// AIEngineError creates a formatted error for AI engine issues
func AIEngineError(details string) string {
	return ErrorWithRecoveryAndDocs(
		fmt.Sprintf("AI Engine error: %s", details),
		"ai-engine",
		"Check if the AI engine is running: zypheron ai status",
		"Start the AI engine: zypheron ai start",
		"Check logs for details",
	)
}

// ConfigError creates a formatted error for configuration issues
func ConfigError(details string) string {
	return ErrorWithRecoveryAndDocs(
		fmt.Sprintf("Configuration error: %s", details),
		"configuration",
		"Run initial setup: zypheron setup",
		"Or manually edit the configuration file",
	)
}

// APIKeyError creates a formatted error for missing API keys
func APIKeyError(provider string) string {
	return ErrorWithRecoveryAndDocs(
		fmt.Sprintf("API key not configured for %s", provider),
		"api-keys",
		fmt.Sprintf("Set key: zypheron config set-key %s <your-key>", provider),
		fmt.Sprintf("Or set environment variable for %s", provider),
	)
}

// WrapErrorWithDocs wraps an error with user-friendly context and a docs link
func WrapErrorWithDocs(context string, err error, topic string) string {
	var msg string
	if err != nil {
		msg = Error(fmt.Sprintf("%s: %v", context, err))
	} else {
		msg = Error(context)
	}
	url := GetDocsURL(topic)
	return msg + "\n" + InfoMsg("Docs: "+url)
}
