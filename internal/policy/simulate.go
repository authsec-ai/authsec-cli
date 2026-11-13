package policy

import (
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/authsec-ai/authsec-cli/internal/events"
)

// Hit is an action a policy would deny (or send to a person), with how often
// the agent did it.
type Hit struct {
	Kind   string `json:"kind"` // network | file | command
	What   string `json:"what"`
	Action string `json:"action"` // deny | ask
	Rule   string `json:"rule"`
	Count  int    `json:"count"`
}

// Impact is what a policy would have done to recorded activity.
type Impact struct {
	Agents  []string `json:"agents"` // agent ids the records belonged to
	Checked int      `json:"checked"`
	Hits    []Hit    `json:"hits"`
}

// Simulate replays recorded activity against a policy. match selects the
// records the policy applies to; home expands {home}.
func Simulate(p *Policy, recs []events.Record, match func(events.Agent) bool, home string) Impact {
	ep := p.Expand(home, "")
	hits := map[string]*Hit{}
	agents := map[string]bool{}
	var imp Impact
	add := func(kind, what string, d Decision) {
		key := kind + "|" + what + "|" + d.Rule
		h := hits[key]
		if h == nil {
			h = &Hit{Kind: kind, What: what, Action: d.Action, Rule: d.Rule}
			hits[key] = h
		}
		h.Count++
	}
	for _, r := range recs {
		if r.Agent == nil || !match(*r.Agent) {
			continue
		}
		switch r.Type {
		case events.Network:
			if r.Dst == nil {
				continue
			}
			imp.Checked++
			agents[r.Agent.ID] = true
			d := ep.DecideNetwork(r.Dst.Host, net.ParseIP(r.Dst.IP), r.Dst.Port)
			if d.Action != Allow {
				what := r.Dst.Host
				if what == "" {
					what = r.Dst.IP
				}
				add("network", net.JoinHostPort(what, itoa(r.Dst.Port)), d)
			}
		case events.File:
			imp.Checked++
			agents[r.Agent.ID] = true
			fp := ep
			if root := GitRoot(r.Path); root != "" {
				fp = p.Expand(home, root) // {project}: the project the file is in
			}
			if d := fp.DecideFile(r.Path, r.Access == "write"); d.Action != Allow {
				add("file", r.Access+" "+r.Path, d)
			}
		case events.Process:
			imp.Checked++
			agents[r.Agent.ID] = true
			cmd := strings.Join(r.Args, " ")
			if d := ep.DecideArgv(r.Args); d.Action != Allow {
				if len(cmd) > 120 {
					cmd = cmd[:119] + "…"
				}
				add("command", cmd, d)
			}
		}
	}
	for id := range agents {
		imp.Agents = append(imp.Agents, id)
	}
	sort.Strings(imp.Agents)
	for _, h := range hits {
		imp.Hits = append(imp.Hits, *h)
	}
	order := map[string]int{"network": 0, "file": 1, "command": 2}
	sort.Slice(imp.Hits, func(i, j int) bool {
		a, b := imp.Hits[i], imp.Hits[j]
		if a.Kind != b.Kind {
			return order[a.Kind] < order[b.Kind]
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.What < b.What
	})
	return imp
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// GitRoot returns the git project a path is in, or "".
func GitRoot(path string) string {
	for d := filepath.Dir(path); d != "/" && d != "." && d != ""; d = filepath.Dir(d) {
		if st, err := os.Stat(filepath.Join(d, ".git")); err == nil && st.IsDir() {
			return d
		}
	}
	return ""
}
