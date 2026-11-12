//go:build !linux && !darwin && !windows

package proc

import "errors"

func take() (*Snapshot, error) { return nil, errors.New("process listing is not supported on this OS") }

func get(pid int) (*Process, bool) {
	s, err := take()
	if err != nil {
		return nil, false
	}
	p, ok := s.Procs[pid]
	return p, ok
}
