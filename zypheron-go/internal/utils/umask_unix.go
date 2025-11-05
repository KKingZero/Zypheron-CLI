//go:build unix

package utils

import "syscall"

// syscallUmask sets the file mode creation mask
func syscallUmask(mask int) int {
	return syscall.Umask(mask)
}
