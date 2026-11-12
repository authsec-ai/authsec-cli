package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/authsec-ai/authsec-cli/internal/access"
	"github.com/authsec-ai/authsec-cli/internal/events"
	"github.com/authsec-ai/authsec-cli/internal/report"
)

func newAccessCmd() *cobra.Command {
	var (
		logPath string
		since   time.Duration
		asJSON  bool
		limit   int
	)
	cmd := &cobra.Command{
		Use:   "access [AGENT]",
		Short: "Review what agents accessed: files, network destinations, services, programs",
		Long: `Summarises the daemon's event log per agent: files read and written (credential
files first), destinations grouped into services (LLM providers, databases,
Redis, Vault, GitHub, cloud APIs), and the programs it ran.

AGENT is an agent id (claude-code, codex, ...), a name, or a pid. Without it,
every agent is shown.`,
		Example: `  authsec-cli access
  authsec-cli access claude-code --since 24h
  authsec-cli access --json > access.json`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if logPath == "" {
				logPath = events.ReadablePath()
			}
			var from time.Time
			if since > 0 {
				from = time.Now().Add(-since)
			}
			recs, err := events.Read(logPath, from)
			if err != nil {
				return ioErr(err)
			}
			var match func(events.Agent) bool
			if len(args) == 1 {
				match = agentMatcher(args[0])
			}
			sums := access.Summarize(recs, match)
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{"schema": "authsec-cli.access/v1", "log": logPath, "since": from, "agents": sums})
			}
			if len(sums) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No agent activity in the log for that selection.")
				return nil
			}
			home, _ := os.UserHomeDir()
			for _, s := range sums {
				accessTable(cmd.OutOrStdout(), s, home, limit)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&logPath, "log", "", "event log (default: the daemon's)")
	f.DurationVar(&since, "since", 7*24*time.Hour, "only activity in this period (0: all)")
	f.BoolVar(&asJSON, "json", false, "print JSON")
	f.IntVar(&limit, "limit", 15, "rows per section in the table")
	return cmd
}

// agentMatcher selects agents by id, name (case-insensitive substring) or pid.
func agentMatcher(sel string) func(events.Agent) bool {
	if pid, err := strconv.Atoi(sel); err == nil {
		return func(a events.Agent) bool { return a.PID == pid }
	}
	low := strings.ToLower(sel)
	return func(a events.Agent) bool {
		return a.ID == sel || strings.Contains(strings.ToLower(a.Name), low)
	}
}

func accessTable(w io.Writer, s access.Summary, home string, limit int) {
	state := "stopped"
	if s.Running {
		state = "running"
	}
	threat := ""
	if s.Threat {
		threat = "  !! THREAT"
	}
	fmt.Fprintf(w, "%s  (%s)%s  seen %s – %s  pids %v\n", s.Name, state, threat,
		s.FirstSeen.Local().Format("Jan 2 15:04"), s.LastSeen.Local().Format("Jan 2 15:04"), s.PIDs)
	if len(s.Services) > 0 {
		fmt.Fprintf(w, "  services:  %s\n", strings.Join(s.Services, ", "))
	}
	if len(s.Destinations) > 0 {
		fmt.Fprintf(w, "  network (%d):\n", len(s.Destinations))
		for i, d := range s.Destinations {
			if i == limit {
				fmt.Fprintf(w, "    … %d more (--json for all)\n", len(s.Destinations)-limit)
				break
			}
			host := d.Host
			if host == "" {
				host = d.IP
			}
			fmt.Fprintf(w, "    %-16s %s  ×%d\n", d.Category, net.JoinHostPort(host, strconv.Itoa(d.Port)), d.Count)
		}
	}
	if len(s.Files) > 0 {
		sens, writes := 0, 0
		for _, f := range s.Files {
			if f.Sensitive {
				sens++
			}
			if f.Access == "write" {
				writes++
			}
		}
		fmt.Fprintf(w, "  files (%d; %d written, %d credential files):\n", len(s.Files), writes, sens)
		for i, f := range s.Files {
			if i == limit {
				fmt.Fprintf(w, "    … %d more (--json for all)\n", len(s.Files)-limit)
				break
			}
			mark := "  "
			if f.Sensitive {
				mark = "!!"
			}
			fmt.Fprintf(w, "    %s %-5s %s\n", mark, f.Access, report.Tilde(f.Path, home))
		}
	}
	if len(s.Commands) > 0 {
		fmt.Fprintf(w, "  programs (%d):\n", len(s.Commands))
		for i, c := range s.Commands {
			if i == limit {
				fmt.Fprintf(w, "    … %d more\n", len(s.Commands)-limit)
				break
			}
			ex := strings.Join(strings.Fields(strings.Join(c.Example, " ")), " ")
			if len(ex) > 90 {
				ex = ex[:89] + "…"
			}
			fmt.Fprintf(w, "    %-14s ×%-4d %s\n", c.Program, c.Count, ex)
		}
	}
	fmt.Fprintln(w)
}
