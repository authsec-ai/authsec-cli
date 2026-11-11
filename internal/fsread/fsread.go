// Package fsread is the only way collectors open files. It refuses anything
// larger than MaxFileSize and anything that resolves outside the roots it was
// given (the home directory, the projects named, the managed-settings
// directories), and it remembers every file it read so the report can list
// them.
package fsread

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// MaxFileSize caps every read: configuration files are small.
const MaxFileSize = 1 << 20

var (
	ErrTooLarge     = errors.New("file larger than 1 MiB")
	ErrOutsideRoots = errors.New("path resolves outside the scanned roots")
	ErrNotRegular   = errors.New("not a regular file")
)

// Reader opens files under a fixed set of roots.
type Reader struct {
	roots []string

	mu    sync.Mutex
	reads map[string]bool
}

// New returns a Reader confined to roots.
func New(roots ...string) *Reader {
	r := &Reader{reads: map[string]bool{}}
	for _, root := range roots {
		if root == "" {
			continue
		}
		r.roots = append(r.roots, clean(root))
	}
	return r
}

// AddRoots widens the reader to more directories (the projects a scan found).
func (r *Reader) AddRoots(roots ...string) {
	for _, root := range roots {
		if root != "" {
			r.roots = append(r.roots, clean(root))
		}
	}
}

func clean(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		p = real
	}
	return filepath.Clean(p)
}

func (r *Reader) inRoots(p string) bool {
	for _, root := range r.roots {
		if p == root || strings.HasPrefix(p, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// resolve follows symlinks and checks the target stays under a root: a
// dotfiles symlink into the home is fine, one into /etc/shadow is not.
func (r *Reader) resolve(p string) (string, error) {
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", err
	}
	real = clean(real)
	if !r.inRoots(real) {
		return "", fmt.Errorf("%s: %w", p, ErrOutsideRoots)
	}
	return real, nil
}

// File is what ReadFile returns: the bytes and their sha256.
type File struct {
	Path   string
	Data   []byte
	SHA256 string
}

// ReadFile reads one file. A missing file is fs.ErrNotExist, which collectors
// treat as "not configured", not as an error.
func (r *Reader) ReadFile(p string) (*File, error) {
	real, err := r.resolve(p)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(real)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", p, ErrNotRegular)
	}
	if st.Size() > MaxFileSize {
		return nil, fmt.Errorf("%s: %w", p, ErrTooLarge)
	}
	fh, err := os.Open(real)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	data, err := io.ReadAll(io.LimitReader(fh, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("%s: %w", p, ErrTooLarge)
	}
	r.mu.Lock()
	r.reads[p] = true
	r.mu.Unlock()
	sum := sha256.Sum256(data)
	return &File{Path: p, Data: data, SHA256: hex.EncodeToString(sum[:])}, nil
}

// Exists reports whether p exists under the roots (file or directory).
func (r *Reader) Exists(p string) bool {
	real, err := r.resolve(p)
	if err != nil {
		return false
	}
	_, err = os.Stat(real)
	return err == nil
}

// Walk lists regular files under dir, at most maxDepth levels down, whose base
// name satisfies match. Directories that resolve outside the roots are skipped.
func (r *Reader) Walk(dir string, maxDepth int, match func(name string) bool) ([]string, error) {
	real, err := r.resolve(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	var walk func(d, shown string, depth int)
	walk = func(d, shown string, depth int) {
		entries, err := os.ReadDir(d)
		if err != nil {
			return
		}
		for _, e := range entries {
			full, show := filepath.Join(d, e.Name()), filepath.Join(shown, e.Name())
			info, err := os.Stat(full) // follows symlinks
			if err != nil {
				continue
			}
			if info.IsDir() {
				if depth < maxDepth {
					if target, err := r.resolve(full); err == nil {
						walk(target, show, depth+1)
					}
				}
				continue
			}
			if info.Mode().IsRegular() && match(e.Name()) {
				out = append(out, show)
			}
		}
	}
	walk(real, dir, 1)
	sort.Strings(out)
	return out, nil
}

// Reads lists every file read, sorted.
func (r *Reader) Reads() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.reads))
	for p := range r.reads {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// IsNotExist reports a missing file or directory.
func IsNotExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }
