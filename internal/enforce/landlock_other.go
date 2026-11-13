//go:build !linux

package enforce

import "errors"

// LandlockABI is 0 off Linux.
func LandlockABI() int { return 0 }

// ExecConfined is Linux only.
func (s Sandbox) ExecConfined(bin string, argv, env []string) (Applied, error) {
	return Applied{}, errors.New("the native sandbox (Landlock) is Linux only; use --sandbox openshell")
}
