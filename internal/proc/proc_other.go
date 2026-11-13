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

func startTime(pid int) (uint64, bool) {
	p, ok := get(pid)
	if !ok {
		return 0, false
	}
	return uint64(p.Started.Unix()), true
}
