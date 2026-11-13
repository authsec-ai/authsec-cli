//go:build windows

package daemon

// lockInstance is not enforced on Windows.
func lockInstance(string) (func(), error) { return func() {}, nil }
