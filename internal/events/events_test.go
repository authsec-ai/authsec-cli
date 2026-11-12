package events

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteRotateRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "events.jsonl")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	w.MaxBytes = 400
	var teed int
	w.Tee = func(Record) { teed++ }
	t0 := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 20; i++ {
		if err := w.Write(Record{Time: t0.Add(time.Duration(i) * time.Second), Type: File, Path: "/w/f"}); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	if teed != 20 {
		t.Errorf("tee got %d", teed)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("log mode %v, want 0600", st.Mode().Perm())
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatal("not rotated")
	}
	if _, err := os.Stat(path + ".4"); err == nil {
		t.Error("kept more than Keep files")
	}
	recs, err := Read(path, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(recs); i++ {
		if recs[i].Time.Before(recs[i-1].Time) {
			t.Fatal("records out of order")
		}
	}
	if recs[len(recs)-1].Time != t0.Add(19*time.Second) {
		t.Errorf("last = %v", recs[len(recs)-1].Time)
	}
	since, _ := Read(path, t0.Add(18*time.Second))
	if len(since) != 2 {
		t.Errorf("since: %d records", len(since))
	}
	if _, err := Read(filepath.Join(t.TempDir(), "none.jsonl"), time.Time{}); err == nil {
		t.Error("missing log should be an error")
	}
}
