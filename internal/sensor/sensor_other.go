//go:build !linux

package sensor

import "fmt"

// Start reports that the kernel sensor exists only on Linux.
func Start() (Sensor, error) {
	return nil, fmt.Errorf("%w: kernel monitoring is Linux only; using process polling", ErrUnsupported)
}

// OpensDirectory is never true off Linux (no open events).
func OpensDirectory(int32) bool { return false }
