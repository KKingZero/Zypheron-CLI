//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package loot

func noFollowOpenFlag() int {
	return 0
}
