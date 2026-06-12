//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package commands

import "errors"

func availableDiskGB(path string) (float64, error) {
	return 0, errors.New("disk space check is not implemented on this platform")
}
