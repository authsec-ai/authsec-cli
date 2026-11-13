package detect

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

func TestFanOutFiresOncePerWindow(t *testing.T) {
	f := NewFanOut(10*time.Second, 5)
	var fired []*Detection
	for i := 0; i < 12; i++ {
		if d := f.Observe(100, fmt.Sprintf("10.0.0.%d", i), 22, t0.Add(time.Duration(i)*100*time.Millisecond)); d != nil {
			fired = append(fired, d)
		}
	}
	if len(fired) != 1 {
		t.Fatalf("fired %d times, want once per window", len(fired))
	}
	d := fired[0]
	if d.Rule != RuleFanOut || d.Severity != Medium || d.PID != 100 || d.Title == "" {
		t.Fatalf("detection = %+v", d)
	}
	ev := strings.Join(d.Evidence, " ")
	if !strings.Contains(ev, "5 distinct destinations within 10s") || !strings.Contains(ev, "10.0.0.0:22") {
		t.Fatalf("evidence = %q", ev)
	}
	// After the window, a new scan fires again.
	var again *Detection
	for i := 0; i < 5; i++ {
		if d := f.Observe(100, "10.0.1.1", 1000+i, t0.Add(11*time.Second)); d != nil {
			again = d
		}
	}
	if again == nil {
		t.Fatal("a scan in the next window must fire again")
	}
}

func TestFanOutNearMisses(t *testing.T) {
	f := NewFanOut(10*time.Second, 5)
	// Same destination many times: one key.
	for i := 0; i < 100; i++ {
		if d := f.Observe(1, "160.79.104.10", 443, t0.Add(time.Duration(i)*time.Millisecond)); d != nil {
			t.Fatalf("repeated destination fired: %+v", d)
		}
	}
	// Distinct destinations spread wider than the window.
	for i := 0; i < 20; i++ {
		if d := f.Observe(2, fmt.Sprintf("10.0.0.%d", i), 80, t0.Add(time.Duration(i)*3*time.Second)); d != nil {
			t.Fatalf("slow connections fired: %+v", d)
		}
	}
	// Several agents each below the threshold.
	for pid := 10; pid < 20; pid++ {
		for i := 0; i < 4; i++ {
			if d := f.Observe(pid, fmt.Sprintf("10.1.0.%d", i), 443, t0); d != nil {
				t.Fatalf("agent %d below threshold fired", pid)
			}
		}
	}
	// IPv6 keys are distinct by port too.
	for p := 0; p < 4; p++ {
		if d := f.Observe(3, "2001:db8::1", 8000+p, t0); d != nil {
			t.Fatal("4 < threshold")
		}
	}
	if d := f.Observe(3, "2001:db8::1", 9000, t0); d == nil || !strings.Contains(strings.Join(d.Evidence, " "), "[2001:db8::1]:8000") {
		t.Fatalf("IPv6 scan = %+v", d)
	}
}

func TestFanOutBoundedAndForget(t *testing.T) {
	f := NewFanOut(time.Second, 3)
	f.Observe(1, "10.0.0.1", 1, t0)
	f.Observe(1, "10.0.0.2", 1, t0)
	f.Forget(1)
	if d := f.Observe(1, "10.0.0.3", 1, t0); d != nil {
		t.Fatal("Forget must drop what was seen")
	}
	// Suppressed after firing: keys are not kept.
	f.Observe(1, "10.0.0.4", 1, t0)
	if d := f.Observe(1, "10.0.0.5", 1, t0); d == nil {
		t.Fatal("expected a detection")
	}
	for i := 0; i < 1000; i++ {
		f.Observe(1, fmt.Sprintf("10.2.%d.%d", i/250, i%250), 1, t0.Add(time.Millisecond))
	}
	f.mu.Lock()
	n := len(f.agents[1].dsts)
	f.mu.Unlock()
	if n >= f.Threshold {
		t.Fatalf("an agent keeps %d keys, cap is below %d", n, f.Threshold)
	}
	// Agents not seen for two windows are forgotten.
	f.Observe(2, "10.0.0.1", 1, t0)
	f.Observe(9, "10.0.0.1", 1, t0.Add(3*time.Second))
	f.mu.Lock()
	_, kept1 := f.agents[1]
	_, kept2 := f.agents[2]
	f.mu.Unlock()
	if kept1 || kept2 {
		t.Fatal("idle agents must be forgotten after two windows")
	}
}

func TestNewFanOutDefaults(t *testing.T) {
	f := NewFanOut(0, -1)
	if f.Window != DefaultFanOutWindow || f.Threshold != DefaultFanOutThreshold {
		t.Fatalf("defaults = %v %d", f.Window, f.Threshold)
	}
	var zero FanOut // a zero value is usable once fields are set
	zero.Window, zero.Threshold = time.Second, 1
	if d := zero.Observe(1, "10.0.0.1", 1, t0); d == nil {
		t.Fatal("threshold 1 fires on the first destination")
	}
}

func TestFanOutConcurrent(t *testing.T) {
	f := NewFanOut(time.Minute, 1000)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				f.Observe(g%3, fmt.Sprintf("10.%d.0.%d", g, i), 80, t0)
				if i%50 == 0 {
					f.Forget(g % 3)
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestFanOutZeroValueUsesDefaults(t *testing.T) {
	var f FanOut // Window and Threshold left at zero
	for i := 0; i < DefaultFanOutThreshold-1; i++ {
		if d := f.Observe(1, fmt.Sprintf("10.0.0.%d", i), 80, t0); d != nil {
			t.Fatalf("zero value fired after %d destinations", i+1)
		}
	}
	d := f.Observe(1, "10.0.1.1", 80, t0)
	if d == nil || !strings.Contains(d.Evidence[0], "within 1m0s") {
		t.Fatalf("zero value at the default threshold = %+v", d)
	}
	if d := f.Observe(1, "10.0.1.2", 80, t0.Add(time.Second)); d != nil {
		t.Fatal("zero value must be suppressed for the default window")
	}
}

func TestFanOutSweepsOncePerWindowAtTheSameInstant(t *testing.T) {
	f := NewFanOut(time.Minute, 50)
	f.Observe(1, "10.0.0.1", 80, t0)
	// An agent last seen long ago, planted after the sweep at t0.
	f.mu.Lock()
	f.agents[2] = &fanAgent{dsts: map[string]time.Time{}, lastSeen: t0.Add(-time.Hour)}
	f.mu.Unlock()
	f.Observe(1, "10.0.0.2", 80, t0) // same instant: no second sweep
	f.mu.Lock()
	_, kept := f.agents[2]
	f.mu.Unlock()
	if !kept {
		t.Fatal("observations at the same instant must not sweep again")
	}
	f.Observe(1, "10.0.0.3", 80, t0.Add(-time.Second)) // the clock went back: sweep
	f.mu.Lock()
	_, kept = f.agents[2]
	f.mu.Unlock()
	if kept {
		t.Fatal("a clock that went back must sweep")
	}
}
