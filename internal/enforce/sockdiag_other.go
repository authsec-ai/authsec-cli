//go:build !linux

package enforce

import "errors"

// DestroySockets is Linux only.
func DestroySockets([]int) (int, error) { return 0, errors.New("not supported on this OS") }
