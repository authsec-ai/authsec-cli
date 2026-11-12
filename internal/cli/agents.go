package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"

	"github.com/authsec-ai/authsec-cli/internal/finding"
	"github.com/authsec-ai/authsec-cli/internal/proc"
	"github.com/authsec-ai/authsec-cli/internal/recognise"
	"github.com/authsec-ai/authsec-cli/internal/report"
	"github.com/authsec-ai/authsec-cli/internal/scan"
)

func newAgentsCmd() *cobra.Command {
	var (
		asJSON, all, noDNS, noInstalled bool
		watch                           time.Duration
	)
	cmd := &cobra.Command{
		Use:   "agents",
		Short: "List the AI agents running on this machine (and installed ones)",
		Long: `Lists AI agents: running processes recognised by binary, install path or
package, editors whose AI features are active, and any process talking to an
LLM API. Each agent shows the MCP servers and processes it started and what it
is connected to. Agents found only in configuration are listed as installed.

Run with sudo to see the agents of every user.`,
		Example: `  authsec-cli agents
  authsec-cli agents --json
  authsec-cli agents --watch 5s`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opt := agentsOptions{all: all, noDNS: noDNS, installed: !noInstalled}
			if watch > 0 {
				if watch < time.Second {
					return usageErr("--watch: at least 1s")
				}
				return watchAgents(cmd.OutOrStdout(), opt, watch)
			}
			a, err := collectAgents(context.Background(), opt)
			if err != nil {
				return ioErr(err)
			}
			if asJSON {
				return report.AgentsJSON(cmd.OutOrStdout(), a)
			}
			home, _ := os.UserHomeDir()
			return report.AgentsTable(cmd.OutOrStdout(), a, home)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&asJSON, "json", false, "print JSON")
	f.BoolVar(&all, "all", false, `also list "possible" agents (an interpreter holding an LLM key, no LLM traffic)`)
	f.BoolVar(&noDNS, "no-dns", false, "do not resolve LLM API hosts (LLM traffic is then not recognised)")
	f.BoolVar(&noInstalled, "running-only", false, "skip agents found only in configuration")
	f.DurationVar(&watch, "watch", 0, "keep running and print agents as they start and stop (e.g. 5s)")
	return cmd
}

type agentsOptions struct {
	all, noDNS, installed bool
	llm                   map[string]string // cached resolution for --watch
}

func collectAgents(ctx context.Context, opt agentsOptions) (*report.Agents, error) {
	snap, err := proc.Take()
	if err != nil {
		return nil, err
	}
	llm := opt.llm
	if llm == nil && !opt.noDNS {
		llm = recognise.ResolveLLMHosts(ctx, nil)
	}
	running := recognise.Recognise(snap, recognise.Options{LLMAddrs: llm, Possible: opt.all})
	a := &report.Agents{
		Schema: report.AgentsSchema, TakenAt: snap.Taken.UTC().Truncate(time.Second),
		Machine: scan.ThisMachine(""), Partial: snap.Partial,
		Running: running, Installed: []report.Installed{},
	}
	if a.Running == nil {
		a.Running = []recognise.Agent{}
	}
	if opt.installed {
		isRunning := map[string]bool{}
		for _, r := range running {
			isRunning[r.ID] = true
		}
		r, err := scan.Run(scan.Options{KnownProjects: false, Only: []finding.Kind{finding.Agent}, CLIVersion: Version})
		if err == nil {
			for _, f := range r.Findings {
				if !isRunning[f.Tool] {
					a.Installed = append(a.Installed, report.Installed{ID: f.Tool, Name: f.Name, Path: f.Path})
				}
			}
		}
	}
	return a, nil
}

// watchAgents prints the agents once, then a line per agent that starts or
// stops, until interrupted.
func watchAgents(w io.Writer, opt agentsOptions, every time.Duration) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if !opt.noDNS {
		opt.llm = recognise.ResolveLLMHosts(ctx, nil)
	}
	opt.installed = false
	home, _ := os.UserHomeDir()
	prev := map[string]recognise.Agent{}
	first := true
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		a, err := collectAgents(ctx, opt)
		if err != nil {
			return ioErr(err)
		}
		cur := map[string]recognise.Agent{}
		for _, ag := range a.Running {
			cur[fmt.Sprintf("%s/%d", ag.ID, ag.PID)] = ag
		}
		if first {
			if err := report.AgentsTable(w, a, home); err != nil {
				return err
			}
			fmt.Fprintf(w, "\nWatching every %s. Ctrl-C to stop.\n", every)
			first = false
		} else {
			now := time.Now().Format("15:04:05")
			for k, ag := range cur {
				if _, ok := prev[k]; !ok {
					fmt.Fprintf(w, "%s  + started  %s (pid %d) %s\n", now, ag.Name, ag.PID, ag.Via)
				}
			}
			for k, ag := range prev {
				if _, ok := cur[k]; !ok {
					fmt.Fprintf(w, "%s  - stopped  %s (pid %d)\n", now, ag.Name, ag.PID)
				}
			}
		}
		prev = cur
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}
