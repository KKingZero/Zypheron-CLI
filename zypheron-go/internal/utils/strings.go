package utils

import "strings"

// Capitalize returns the string with first letter uppercased.
// This is a simple ASCII-only implementation to replace deprecated strings.Title.
func Capitalize(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
