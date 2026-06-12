//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package loot

import "syscall"

func noFollowOpenFlag() int {
	return syscall.O_NOFOLLOW
}
