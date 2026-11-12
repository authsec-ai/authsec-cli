package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/recognise"
)

// AgentsSchema names the JSON format of `authsec-cli agents`.
const AgentsSchema = "authsec-cli.agents/v1"

// Installed is an agent found in configuration only.
type Installed struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Path string `json:"path"`
}

// Agents is the output of `authsec-cli agents`.
type Agents struct {
	Schema    string            `json:"schema"`
	TakenAt   time.Time         `json:"taken_at"`
	Machine   Machine           `json:"machine"`
	Partial   bool              `json:"partial"` // other users' processes were not fully readable
	Running   []recognise.Agent `json:"running"`
	Installed []Installed       `json:"installed"` // in config, not running
}

// AgentsJSON writes the agents report as indented JSON.
func AgentsJSON(w io.Writer, a *Agents) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(a)
}

// AgentsTable writes running agents, then installed ones.
func AgentsTable(w io.Writer, a *Agents, home string) error {
	b := &strings.Builder{}
	fmt.Fprintf(b, "Running AI agents on %s: %d\n", a.Machine.Hostname, len(a.Running))
	for _, ag := range a.Running {
		b.WriteString("\n")
		head := fmt.Sprintf("  %s  [%s]  pid %d", ag.Name, ag.Confidence, ag.PID)
		if ag.Threat {
			head = "  !! " + strings.TrimSpace(head) + "  THREAT"
		}
		if ag.Role == recognise.RoleModelServer {
			head += "  (model server)"
		}
		if ag.User != "" {
			head += "  user " + ag.User
		}
		if ag.Version != "" {
			head += "  v" + ag.Version
		}
		b.WriteString(head + "\n")
		if ag.Via != "" {
			fmt.Fprintf(b, "      started by:  %s\n", ag.Via)
		}
		if ag.Exe != "" {
			fmt.Fprintf(b, "      binary:      %s\n", clipLeft(Tilde(ag.Exe, home), 90))
		}
		fmt.Fprintf(b, "      why:         %s\n", strings.Join(ag.Evidence, "; "))
		var mcp []string
		other := 0
		for _, c := range ag.Children {
			if c.Role == "mcp_server" {
				mcp = append(mcp, fmt.Sprintf("%s (pid %d)", c.Name, c.PID))
			} else {
				other++
			}
		}
		if len(mcp) > 0 {
			fmt.Fprintf(b, "      mcp servers: %s\n", strings.Join(mcp, ", "))
		}
		if other > 0 {
			fmt.Fprintf(b, "      processes:   %d more started by it\n", other)
		}
		if len(ag.Endpoints) > 0 {
			fmt.Fprintf(b, "      connects to: %s\n", endpoints(ag.Endpoints, 6))
		}
		if len(ag.Listening) > 0 {
			fmt.Fprintf(b, "      listening:   %s\n", ints(ag.Listening))
		}
		if len(ag.LLMKeyNames) > 0 {
			fmt.Fprintf(b, "      llm keys:    %s (names only)\n", strings.Join(ag.LLMKeyNames, ", "))
		}
	}
	if len(a.Installed) > 0 {
		b.WriteString("\nInstalled, not running:\n")
		for _, i := range a.Installed {
			fmt.Fprintf(b, "  %-20s %s\n", i.Name, Tilde(i.Path, home))
		}
	}
	if a.Partial && os.Geteuid() != 0 {
		b.WriteString("\nSome processes of other users could not be read. Run with sudo to see every agent.\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func endpoints(es []recognise.Endpoint, max int) string {
	var parts []string
	seen := map[string]bool{}
	for _, e := range es {
		host := e.IP
		if e.Host != "" {
			host = e.Host
		}
		s := net.JoinHostPort(host, fmt.Sprint(e.Port))
		if e.Service != "" && e.Service != "https" && !e.LLM {
			s += " (" + e.Service + ")"
		}
		if !seen[s] {
			seen[s] = true
			parts = append(parts, s)
		}
	}
	if len(parts) > max {
		parts = append(parts[:max:max], fmt.Sprintf("+%d more", len(parts)-max))
	}
	return strings.Join(parts, ", ")
}

func ints(xs []int) string {
	s := make([]string, len(xs))
	for i, x := range xs {
		s[i] = fmt.Sprint(x)
	}
	return strings.Join(s, ", ")
}
