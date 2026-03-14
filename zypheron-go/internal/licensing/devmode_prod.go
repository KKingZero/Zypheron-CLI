//go:build !devmode
// +build !devmode

package licensing

func isDevModeEnabled() bool {
	return false
}
