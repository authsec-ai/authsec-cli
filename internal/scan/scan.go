// Package scan runs the collectors and rules and builds a report. `scan` and
// `push` both use it.
package scan

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/catalogue"
	"github.com/authsec-ai/authsec-cli/internal/collect"
	"github.com/authsec-ai/authsec-cli/internal/finding"
	"github.com/authsec-ai/authsec-cli/internal/fsread"
	"github.com/authsec-ai/authsec-cli/internal/report"
	"github.com/authsec-ai/authsec-cli/internal/rules"
)

// Options configures a scan. Zero values mean "this machine, this user".
type Options struct {
	Home          string   // default: the user's home directory
	Projects      []string // extra project directories
	KnownProjects bool     // also scan the projects the tools list
	Only          []finding.Kind
	CLIVersion    string

	// For tests: a fake OS, a prefix for system paths, a fixed clock and
	// machine, and no PATH lookups.
	GOOS     string
	SysRoot  string
	Now      func() time.Time
	Machine  *report.Machine
	LookPath func(string) string
}

// Run scans and returns the report.
func Run(opt Options) (*report.Report, error) {
	if opt.Home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		opt.Home = h
	}
	home, err := filepath.Abs(opt.Home)
	if err != nil {
		return nil, err
	}
	if opt.GOOS == "" {
		opt.GOOS = runtime.GOOS
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.LookPath == nil {
		opt.LookPath = func(name string) string {
			p, err := exec.LookPath(name)
			if err != nil {
				return ""
			}
			return p
		}
	}

	cat := catalogueEnv(opt.GOOS, home, opt.SysRoot)
	reader := fsread.New(append([]string{home}, systemRoots(cat)...)...)
	env := &collect.Env{Cat: cat, Reader: reader, LookPath: opt.LookPath}
	env.Projects = collect.DiscoverProjects(env, opt.Projects, opt.KnownProjects)
	reader.AddRoots(env.Projects...)

	fs := collect.Run(env, collect.All())
	fs = only(fs, opt.Only)

	machine := opt.Machine
	if machine == nil {
		m := ThisMachine("")
		machine = &m
	}
	for i := range fs {
		fs[i].SetFingerprint(machine.ID)
	}
	rules.Apply(fs)
	finding.Sort(fs)

	r := &report.Report{
		Schema:           report.Schema,
		CLIVersion:       opt.CLIVersion,
		CatalogueVersion: catalogue.Version,
		ScannedAt:        opt.Now().UTC().Truncate(time.Second),
		Machine:          *machine,
		Home:             home,
		Projects:         env.Projects,
		FilesRead:        reader.Reads(),
		Findings:         fs,
	}
	if r.Projects == nil {
		r.Projects = []string{}
	}
	if r.Findings == nil {
		r.Findings = []finding.Finding{}
	}
	r.Summarize()
	return r, nil
}

// ThisMachine describes the machine the CLI runs on. salt is the workspace id
// once logged in ("" for a local scan).
func ThisMachine(salt string) report.Machine {
	host, _ := os.Hostname()
	name := ""
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	return report.Machine{ID: finding.MachineID(salt), Hostname: host, OS: runtime.GOOS, Arch: runtime.GOARCH, User: name}
}

func catalogueEnv(goos, home, sysRoot string) catalogue.Env {
	env := catalogue.Env{GOOS: goos, Home: home, SysRoot: sysRoot}
	switch goos {
	case "windows":
		env.AppData = envOr("APPDATA", filepath.Join(home, "AppData", "Roaming"))
		env.ProgramData = envOr("ProgramData", `C:\ProgramData`)
		env.ProgramFile = envOr("ProgramFiles", `C:\Program Files`)
	case "darwin":
		env.ConfigHome = filepath.Join(home, ".config")
	default:
		env.ConfigHome = envOr("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	}
	if sysRoot != "" { // tests: keep every directory inside the fixture
		env.ConfigHome = filepath.Join(home, ".config")
		if goos == "windows" {
			env.AppData = filepath.Join(home, "AppData", "Roaming")
			env.ProgramData = filepath.Join(sysRoot, "ProgramData")
			env.ProgramFile = filepath.Join(sysRoot, "Program Files")
		}
	}
	return env
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// systemRoots are the directories of catalogue paths outside the home
// directory (managed settings): the reader may open those and nothing else
// outside home and the projects.
func systemRoots(cat catalogue.Env) []string {
	var out []string
	for _, e := range catalogue.Entries() {
		if e.PerProject() {
			continue
		}
		for _, p := range e.Resolve(cat, "") {
			if strings.HasPrefix(p, cat.Home+string(filepath.Separator)) {
				continue
			}
			if e.Dir {
				out = append(out, p)
			} else {
				out = append(out, filepath.Dir(p))
			}
		}
	}
	return out
}

func only(fs []finding.Finding, kinds []finding.Kind) []finding.Finding {
	if len(kinds) == 0 {
		return fs
	}
	keep := map[finding.Kind]bool{}
	for _, k := range kinds {
		keep[k] = true
	}
	var out []finding.Finding
	for _, f := range fs {
		if keep[f.Kind] {
			out = append(out, f)
		}
	}
	return out
}
