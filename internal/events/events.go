// Package events is the agent event log: one JSON object per line, written
// by the daemon and read by `access`, `policy generate` and `push`. Records
// carry names, paths and scrubbed command lines, never secret values.
package events

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Record types.
const (
	AgentStarted = "agent_started" // an agent began (or was found running at start)
	AgentStopped = "agent_stopped"
	Process      = "process" // an agent started a program
	Network      = "network" // an agent connected somewhere
	File         = "file"    // an agent opened a file
	Sensor       = "sensor"  // the daemon started, stopped or lost events
	Detection    = "detection"
	Decision     = "decision" // an enforcement decision (allow, deny, quarantine)
)

// Agent identifies the agent a record is about. PID is the agent's top
// process.
type Agent struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	PID        int    `json:"pid"`
	User       string `json:"user,omitempty"`
	Confidence string `json:"confidence,omitempty"`
}

// Dst is a network destination.
type Dst struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Host    string `json:"host,omitempty"`
	Service string `json:"service,omitempty"`
	LLM     bool   `json:"llm,omitempty"`
}

// Record is one line of the log.
type Record struct {
	Time      time.Time `json:"ts"`
	Type      string    `json:"type"`
	Agent     *Agent    `json:"agent,omitempty"`
	PID       int       `json:"pid,omitempty"`
	Comm      string    `json:"comm,omitempty"`
	Exe       string    `json:"exe,omitempty"`
	Args      []string  `json:"args,omitempty"` // scrubbed
	Dst       *Dst      `json:"dst,omitempty"`
	Path      string    `json:"path,omitempty"`
	Access    string    `json:"access,omitempty"` // read | write
	Sensitive bool      `json:"sensitive,omitempty"`
	Via       string    `json:"via,omitempty"`
	Version   string    `json:"version,omitempty"`
	Evidence  []string  `json:"evidence,omitempty"`
	Threat    bool      `json:"threat,omitempty"`
	Rule      string    `json:"rule,omitempty"`     // detection or policy rule
	Severity  string    `json:"severity,omitempty"` // detections
	Action    string    `json:"action,omitempty"`   // decisions: allow, deny, quarantine, release
	Note      string    `json:"note,omitempty"`
}

// Writer appends records to a file and rotates it at MaxBytes, keeping Keep
// old files (path.1 is the newest).
type Writer struct {
	Path     string
	MaxBytes int64
	Keep     int

	mu   sync.Mutex
	f    *os.File
	size int64
	// Tee receives every record after it is written (SIEM, console).
	Tee func(Record)
}

// Open opens (creating) the log for appending. The file is 0600: it names
// the files and hosts of every user's agents.
func Open(path string) (*Writer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &Writer{Path: path, MaxBytes: 50 << 20, Keep: 3, f: f, size: st.Size()}, nil
}

// Write appends one record.
func (w *Writer) Write(r Record) error {
	if r.Time.IsZero() {
		r.Time = time.Now()
	}
	r.Time = r.Time.UTC().Truncate(time.Millisecond)
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	w.mu.Lock()
	if w.size+int64(len(b)) > w.MaxBytes {
		if err := w.rotate(); err != nil {
			w.mu.Unlock()
			return err
		}
	}
	n, err := w.f.Write(b)
	w.size += int64(n)
	tee := w.Tee
	w.mu.Unlock()
	if tee != nil {
		tee(r)
	}
	return err
}

func (w *Writer) rotate() error {
	w.f.Close()
	for i := w.Keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", w.Path, i), fmt.Sprintf("%s.%d", w.Path, i+1))
	}
	_ = os.Rename(w.Path, w.Path+".1")
	f, err := os.OpenFile(w.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	w.f, w.size = f, 0
	return nil
}

// Close closes the file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.f.Close()
}

// Read returns the records of the log and its rotated files at or after
// since, oldest first. Lines that do not parse are skipped.
func Read(path string, since time.Time) ([]Record, error) {
	files := []string{}
	for i := 9; i >= 1; i-- {
		p := fmt.Sprintf("%s.%d", path, i)
		if _, err := os.Stat(p); err == nil {
			files = append(files, p)
		}
	}
	files = append(files, path)
	var out []Record
	found := false
	for _, p := range files {
		f, err := os.Open(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		found = true
		recs := scan(f, since)
		f.Close()
		out = append(out, recs...)
	}
	if !found {
		return nil, fmt.Errorf("no event log at %s (is the daemon running? `sudo authsec-cli daemon`)", path)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out, nil
}

func scan(r io.Reader, since time.Time) []Record {
	var out []Record
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var rec Record
		if json.Unmarshal(sc.Bytes(), &rec) != nil {
			continue
		}
		if !since.IsZero() && rec.Time.Before(since) {
			continue
		}
		out = append(out, rec)
	}
	return out
}

// DefaultPath is where the daemon writes: /var/lib/authsec when root,
// otherwise the user's state directory.
func DefaultPath() string {
	if os.Geteuid() == 0 {
		return "/var/lib/authsec/events.jsonl"
	}
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "authsec", "events.jsonl")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "authsec", "events.jsonl")
}

// ReadablePath returns the log a reader should use: the system log if it is
// readable, else the user's.
func ReadablePath() string {
	sys := "/var/lib/authsec/events.jsonl"
	if f, err := os.Open(sys); err == nil {
		f.Close()
		return sys
	}
	return DefaultPath()
}
