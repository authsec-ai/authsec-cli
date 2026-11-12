// Package access summarises the event log per agent: the files it read and
// wrote, where it connected, which services those are, and the programs it
// ran. It is the "review access" view and the input to policy generation.
package access

import (
	"net"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/events"
)

// Summary is everything one agent (by id, across runs) was seen doing.
type Summary struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	PIDs         []int         `json:"pids"`
	Users        []string      `json:"users,omitempty"`
	FirstSeen    time.Time     `json:"first_seen"`
	LastSeen     time.Time     `json:"last_seen"`
	Running      bool          `json:"running"`
	Threat       bool          `json:"threat,omitempty"`
	Files        []File        `json:"files"`
	Destinations []Destination `json:"destinations"`
	Services     []string      `json:"services"`
	Commands     []Command     `json:"commands"`
}

// File is one path an agent opened.
type File struct {
	Path      string    `json:"path"`
	Access    string    `json:"access"` // read | write (write wins)
	Sensitive bool      `json:"sensitive,omitempty"`
	Count     int       `json:"count"`
	Last      time.Time `json:"last"`
}

// Destination is one host and port an agent connected to.
type Destination struct {
	Host     string    `json:"host,omitempty"`
	IP       string    `json:"ip"`
	Port     int       `json:"port"`
	Service  string    `json:"service,omitempty"`
	Category string    `json:"category"`
	LLM      bool      `json:"llm,omitempty"`
	Count    int       `json:"count"`
	Last     time.Time `json:"last"`
}

// Command is one program an agent ran.
type Command struct {
	Program string    `json:"program"`
	Example []string  `json:"example,omitempty"` // scrubbed arguments of the last run
	Count   int       `json:"count"`
	Last    time.Time `json:"last"`
}

// Summarize groups records by agent id. match, if not nil, selects agents.
func Summarize(recs []events.Record, match func(events.Agent) bool) []Summary {
	by := map[string]*Summary{}
	files := map[string]map[string]*File{}
	dsts := map[string]map[string]*Destination{}
	cmds := map[string]map[string]*Command{}
	running := map[string]map[int]bool{}
	get := func(a *events.Agent, t time.Time) *Summary {
		s := by[a.ID]
		if s == nil {
			s = &Summary{ID: a.ID, Name: a.Name, FirstSeen: t}
			by[a.ID] = s
			files[a.ID], dsts[a.ID], cmds[a.ID], running[a.ID] = map[string]*File{}, map[string]*Destination{}, map[string]*Command{}, map[int]bool{}
		}
		if t.After(s.LastSeen) {
			s.LastSeen = t
		}
		return s
	}
	for _, r := range recs {
		if r.Agent == nil || (match != nil && !match(*r.Agent)) {
			continue
		}
		s := get(r.Agent, r.Time)
		switch r.Type {
		case events.AgentStarted:
			if !containsInt(s.PIDs, r.Agent.PID) {
				s.PIDs = append(s.PIDs, r.Agent.PID)
			}
			if r.Agent.User != "" && !containsStr(s.Users, r.Agent.User) {
				s.Users = append(s.Users, r.Agent.User)
			}
			s.Threat = s.Threat || r.Threat
			running[s.ID][r.Agent.PID] = true
		case events.AgentStopped:
			delete(running[s.ID], r.Agent.PID)
		case events.File:
			f := files[s.ID][r.Path]
			if f == nil {
				f = &File{Path: r.Path, Access: r.Access, Sensitive: r.Sensitive}
				files[s.ID][r.Path] = f
			}
			if r.Access == "write" {
				f.Access = "write"
			}
			f.Count++
			f.Last = r.Time
		case events.Network:
			if r.Dst == nil {
				continue
			}
			key := r.Dst.Host
			if key == "" {
				key = r.Dst.IP
			}
			key += "|" + itoa(r.Dst.Port)
			d := dsts[s.ID][key]
			if d == nil {
				d = &Destination{Host: r.Dst.Host, IP: r.Dst.IP, Port: r.Dst.Port, Service: r.Dst.Service, LLM: r.Dst.LLM}
				d.Category = Category(*r.Dst)
				dsts[s.ID][key] = d
			}
			d.Count++
			d.Last = r.Time
		case events.Process:
			prog := filepath.Base(r.Exe)
			if prog == "." || prog == "" {
				prog = r.Comm
			}
			c := cmds[s.ID][prog]
			if c == nil {
				c = &Command{Program: prog}
				cmds[s.ID][prog] = c
			}
			c.Count++
			c.Last, c.Example = r.Time, r.Args
		}
	}
	out := make([]Summary, 0, len(by))
	for id, s := range by {
		s.Running = len(running[id]) > 0
		for _, f := range files[id] {
			s.Files = append(s.Files, *f)
		}
		sort.Slice(s.Files, func(i, j int) bool {
			a, b := s.Files[i], s.Files[j]
			if a.Sensitive != b.Sensitive {
				return a.Sensitive
			}
			if a.Access != b.Access {
				return a.Access == "write"
			}
			return a.Path < b.Path
		})
		svc := map[string]bool{}
		for _, d := range dsts[id] {
			s.Destinations = append(s.Destinations, *d)
			svc[d.Category] = true
		}
		sort.Slice(s.Destinations, func(i, j int) bool {
			a, b := s.Destinations[i], s.Destinations[j]
			if a.Category != b.Category {
				return a.Category < b.Category
			}
			return a.Count > b.Count
		})
		for c := range svc {
			s.Services = append(s.Services, c)
		}
		sort.Strings(s.Services)
		for _, c := range cmds[id] {
			s.Commands = append(s.Commands, *c)
		}
		sort.Slice(s.Commands, func(i, j int) bool { return s.Commands[i].Count > s.Commands[j].Count })
		sort.Ints(s.PIDs)
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// hostCategories name external services by host suffix.
var hostCategories = []struct{ suffix, category string }{
	{"github.com", "github"}, {"githubusercontent.com", "github"}, {"githubcopilot.com", "github-copilot"},
	{"gitlab.com", "gitlab"}, {"aliyuncs.com", "alibaba-cloud"}, {"alibabacloud.com", "alibaba-cloud"},
	{"amazonaws.com", "aws"}, {"azure.com", "azure"}, {"windows.net", "azure"}, {"microsoft.com", "microsoft"},
	{"googleapis.com", "google-cloud"}, {"npmjs.org", "npm"}, {"pypi.org", "pypi"}, {"pythonhosted.org", "pypi"},
	{"docker.io", "docker-hub"}, {"slack.com", "slack"}, {"atlassian.net", "atlassian"},
}

// Category is the kind of service a destination is: an LLM provider, a
// database or cache by port, a cloud or SaaS by host, else "internet" or
// "private-network".
func Category(d events.Dst) string {
	if d.LLM {
		return "llm"
	}
	switch d.Service {
	case "postgres", "mysql", "mssql", "oracle", "mongodb", "redshift", "redis", "vault", "kafka", "rabbitmq",
		"elasticsearch", "etcd", "kubernetes-api", "ssh", "rdp":
		return d.Service
	}
	h := strings.ToLower(d.Host)
	for _, c := range hostCategories {
		if h == c.suffix || strings.HasSuffix(h, "."+c.suffix) {
			return c.category
		}
	}
	if ip := net.ParseIP(d.IP); ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
		if ip.IsLoopback() {
			return "localhost"
		}
		return "private-network"
	}
	return "internet"
}

func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func containsStr(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	b := [20]byte{}
	i := len(b)
	if n == 0 {
		return "0"
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
