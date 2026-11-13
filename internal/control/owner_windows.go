//go:build windows

package control

import "os"

func ownedBySelf(os.FileInfo) bool { return true }
