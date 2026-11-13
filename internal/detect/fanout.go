package detect

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Defaults used when NewFanOut gets a zero or negative value.
const (
	DefaultFanOutWindow    = time.Minute
	DefaultFanOutThreshold = 50
)

// FanOut flags an agent connecting to many distinct destinations quickly
// (scanning).
type FanOut struct {
	Window    time.Duration
	Threshold int // distinct ip:port

	mu        sync.Mutex
	agents    map[int]*fanAgent
	lastSweep time.Time
}

// fanAgent holds one agent's recent destinations. dsts never holds more
// than Threshold keys.
type fanAgent struct {
	dsts     map[string]time.Time // ip:port -> last seen
	lastSeen time.Time
	firedAt  time.Time
}

// NewFanOut returns a FanOut that fires when an agent reaches threshold
// distinct ip:port destinations within window.
func NewFanOut(window time.Duration, threshold int) *FanOut {
	if window <= 0 {
		window = DefaultFanOutWindow
	}
	if threshold <= 0 {
		threshold = DefaultFanOutThreshold
	}
	return &FanOut{Window: window, Threshold: threshold, agents: map[int]*fanAgent{}}
}

// Observe records one connection of an agent and returns a detection when
// the agent has reached Threshold distinct destinations within Window. It
// fires at most once per agent per Window. A zero or negative Window or
// Threshold means the default.
func (f *FanOut) Observe(agentPID int, ip string, port int, now time.Time) *Detection {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.agents == nil {
		f.agents = map[int]*fanAgent{}
	}
	window, threshold := f.limits()
	f.sweep(now, window)
	a := f.agents[agentPID]
	if a == nil {
		a = &fanAgent{dsts: map[string]time.Time{}}
		f.agents[agentPID] = a
	}
	a.lastSeen = now
	if !a.firedAt.IsZero() && now.Sub(a.firedAt) < window {
		return nil
	}
	key := net.JoinHostPort(ip, strconv.Itoa(port))
	if _, ok := a.dsts[key]; !ok {
		expire(a, now, window)
	}
	a.dsts[key] = now
	if len(a.dsts) < threshold {
		return nil
	}
	d := &Detection{Rule: RuleFanOut, Severity: Medium, Title: "Agent connected to many destinations quickly",
		PID: agentPID, Evidence: []string{
			fmt.Sprintf("%d distinct destinations within %s", len(a.dsts), window),
			"for example: " + joinCapped(sample(a.dsts, 5), 5),
		}}
	a.firedAt = now
	a.dsts = map[string]time.Time{}
	return d
}

// Forget drops what is known of an agent (it exited).
func (f *FanOut) Forget(agentPID int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.agents, agentPID)
}

// limits returns Window and Threshold, or their defaults when not set.
func (f *FanOut) limits() (time.Duration, int) {
	window, threshold := f.Window, f.Threshold
	if window <= 0 {
		window = DefaultFanOutWindow
	}
	if threshold <= 0 {
		threshold = DefaultFanOutThreshold
	}
	return window, threshold
}

// expire drops destinations older than the window.
func expire(a *fanAgent, now time.Time, window time.Duration) {
	for k, t := range a.dsts {
		if now.Sub(t) >= window {
			delete(a.dsts, k)
		}
	}
}

// sweep forgets agents not seen for two windows, at most once per window
// (and again whenever the clock went back).
func (f *FanOut) sweep(now time.Time, window time.Duration) {
	if !f.lastSweep.IsZero() && !now.Before(f.lastSweep) && now.Sub(f.lastSweep) < window {
		return
	}
	f.lastSweep = now
	for pid, a := range f.agents {
		if now.Sub(a.lastSeen) >= 2*window {
			delete(f.agents, pid)
		}
	}
}

// sample returns up to n destinations, sorted.
func sample(dsts map[string]time.Time, n int) []string {
	out := make([]string, 0, len(dsts))
	for k := range dsts {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > n {
		out = out[:n]
	}
	return out
}
