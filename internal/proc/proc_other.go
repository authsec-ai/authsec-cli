//go:build !linux && !darwin && !windows

package proc

import "errors"

func take() (*Snapshot, error) { return nil, errors.New("process listing is not supported on this OS") }
