//go:build windows

package daemon

import "os"

// ownedBy cannot check owners on Windows: file evidence is not used there.
func ownedBy(os.FileInfo, int) bool { return false }
