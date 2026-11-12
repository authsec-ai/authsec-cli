package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/events"
	"github.com/authsec-ai/authsec-cli/internal/proc"
	"github.com/authsec-ai/authsec-cli/internal/recognise"
	"github.com/authsec-ai/authsec-cli/internal/sensor"
)

// Options configures the daemon.
type Options struct {
	LogPath string
	NoEBPF  bool          // poll the process table even where eBPF works
	Rescan  time.Duration // process table check with eBPF (default 60s)
	Poll    time.Duration // process table poll without eBPF (default 5s)
	Status  io.Writer     // human-readable progress
	// Tee receives every record (SIEM forwarding, control plane).
	Tee func(events.Record)
}

// Run follows agents until ctx is done.
func Run(ctx context.Context, opt Options) error {
	if opt.Rescan == 0 {
		opt.Rescan = time.Minute
	}
	if opt.Poll == 0 {
		opt.Poll = 5 * time.Second
	}
	if opt.Status == nil {
		opt.Status = io.Discard
	}
	debug.SetMemoryLimit(64 << 20) // footprint: GC harder before growing past 64 MiB

	w, err := events.Open(opt.LogPath)
	if err != nil {
		return fmt.Errorf("event log: %w", err)
	}
	defer w.Close()
	w.Tee = opt.Tee
	write := func(r events.Record) {
		if err := w.Write(r); err != nil {
			fmt.Fprintln(opt.Status, "event log:", err)
		}
	}

	llm := recognise.ResolveLLMHosts(ctx, nil)
	var s sensor.Sensor
	mode := "polling"
	if !opt.NoEBPF {
		s, err = sensor.Start()
		if err != nil {
			if !errors.Is(err, sensor.ErrUnsupported) {
				return err
			}
			fmt.Fprintf(opt.Status, "%v; falling back to polling every %s\n", err, opt.Poll)
		} else {
			mode = "ebpf"
			defer s.Close()
		}
	}
	deps := Deps{Get: proc.Get, Snapshot: proc.Take}
	if s != nil {
		deps.Track = func(pid int) { _ = s.Track(pid) }
		deps.Untrack = s.Untrack
	}
	m := NewMonitor(deps, write, llm)
	write(events.Record{Type: events.Sensor, Note: "started (" + mode + ")"})
	fmt.Fprintf(opt.Status, "authsec-cli daemon: %s mode, writing %s\n", mode, opt.LogPath)

	snap, err := proc.Take()
	if err != nil {
		return err
	}
	m.Seed(snap)
	fmt.Fprintf(opt.Status, "following %d agents\n", len(m.Agents()))

	every := opt.Rescan
	if s == nil {
		every = opt.Poll
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	resolve := time.NewTicker(30 * time.Minute)
	defer resolve.Stop()
	var evs <-chan sensor.Event
	var dns <-chan sensor.DNSAnswer
	if s != nil {
		evs, dns = s.Events(), s.DNS()
	}
	var dropped uint64
	for {
		select {
		case <-ctx.Done():
			write(events.Record{Type: events.Sensor, Note: "stopped"})
			return nil
		case ev, ok := <-evs:
			if !ok {
				return errors.New("sensor stopped")
			}
			m.Handle(ev)
		case a, ok := <-dns:
			if ok {
				m.HandleDNS(a)
			}
		case <-tick.C:
			if snap, err := proc.Take(); err == nil {
				m.Reconcile(snap, s == nil)
			}
			if s != nil {
				if d := s.Dropped(); d > dropped {
					write(events.Record{Type: events.Sensor, Note: fmt.Sprintf("%d kernel events lost (ring buffer full)", d-dropped)})
					dropped = d
				}
			}
		case <-resolve.C:
			for ip, h := range recognise.ResolveLLMHosts(ctx, nil) {
				m.llm[ip] = h
			}
		}
	}
}
