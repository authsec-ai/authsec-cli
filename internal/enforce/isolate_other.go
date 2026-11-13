//go:build !linux

package enforce

import (
	"errors"
	"syscall"
)

// Hidden is one path covered in the agent's mount namespace (Linux only).
type Hidden struct {
	Path string `json:"path"`
	Dir  bool   `json:"dir"`
}

// HideTargets is Linux only.
func HideTargets(int, string, map[string]string) []Hidden { return nil }

// IsolationAttr is Linux only.
func IsolationAttr() *syscall.SysProcAttr { return nil }

// Hide is Linux only.
func Hide([]Hidden) ([]string, error) { return nil, errors.New("not supported on this OS") }
