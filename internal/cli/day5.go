package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/authsec-ai/authsec-cli/internal/cloud"
	"github.com/authsec-ai/authsec-cli/internal/detect"
	"github.com/authsec-ai/authsec-cli/internal/events"
	"github.com/authsec-ai/authsec-cli/internal/proc"
	"github.com/authsec-ai/authsec-cli/internal/recognise"
	"github.com/authsec-ai/authsec-cli/internal/siem"
)

// --- detect ---

func newDetectCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "detect",
		Short: "Look for offensive AI agents (ARTEX) and agents running attack tools, now",
		Long: `One scan of this machine:

  artex_present      ARTEX (an autonomous AI pentest agent) by its binary, ARTEX_*
                     variables, ports, files or containers
  offensive_tool     a running agent started an attack tool (nmap, sqlmap, nuclei, ...)

The daemon runs the same rules continuously (sudo authsec-cli daemon), adds
connection fan-out (scanning), logs detections and can quarantine the agent
(--quarantine-threats). Exit code 1 when a high-severity detection is found.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			snap, err := proc.Take()
			if err != nil {
				return ioErr(err)
			}
			var found []detect.Detection
			listen := map[int][]int{}
			for _, c := range snap.Conns {
				if c.Listen {
					listen[c.PID] = append(listen[c.PID], c.LocalPort)
				}
			}
			artex := map[int]bool{}
			for pid, p := range snap.Procs {
				if d := detect.ARTEXProcess(detect.Process{PID: pid, PPID: p.PPID, Comm: p.Comm, Exe: p.Exe, Args: p.Args, EnvNames: p.EnvNames, Listen: listen[pid]}, statExists); d != nil {
					artex[pid] = true
					found = append(found, *d)
				}
			}
			// Report the top-most ARTEX process only.
			kept := found[:0]
			for _, d := range found {
				if !artex[snap.Procs[d.PID].PPID] {
					kept = append(kept, d)
				}
			}
			found = kept
			for _, a := range recognise.Recognise(snap, recognise.Options{}) {
				for _, c := range a.Children {
					if p := snap.Procs[c.PID]; p != nil {
						if tool, ok := detect.OffensiveTool(p.Args); ok {
							found = append(found, detect.Detection{Rule: detect.RuleOffensiveTool, Severity: detect.High, PID: c.PID, AgentID: a.ID,
								Title: a.Name + " is running the offensive security tool " + tool, Evidence: []string{"program " + tool, fmt.Sprintf("started by %s (pid %d)", a.Name, a.PID)}})
						}
					}
				}
			}
			if d := detect.ARTEXContainers(detect.Containers()); d != nil {
				found = append(found, *d)
			}
			rank := map[string]int{detect.High: 0, detect.Medium: 1, detect.Low: 2}
			sort.SliceStable(found, func(i, j int) bool {
				a, b := found[i], found[j]
				if rank[a.Severity] != rank[b.Severity] {
					return rank[a.Severity] < rank[b.Severity]
				}
				return a.PID < b.PID
			})
			w := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				type detJSON struct {
					Rule     string   `json:"rule"`
					Severity string   `json:"severity"`
					Title    string   `json:"title"`
					PID      int      `json:"pid,omitempty"`
					AgentID  string   `json:"agent_id,omitempty"`
					Evidence []string `json:"evidence"`
				}
				type ruleJSON struct {
					ID          string `json:"id"`
					Title       string `json:"title"`
					Severity    string `json:"severity"`
					Description string `json:"description"`
				}
				dets := []detJSON{}
				for _, d := range found {
					ev := d.Evidence
					if ev == nil {
						ev = []string{}
					}
					dets = append(dets, detJSON{d.Rule, d.Severity, d.Title, d.PID, d.AgentID, ev})
				}
				var rules []ruleJSON
				for _, r := range detect.Rules() {
					rules = append(rules, ruleJSON{r.ID, r.Title, r.Severity, r.Description})
				}
				if err := enc.Encode(map[string]any{"schema": "authsec-cli.detect/v1", "detections": dets, "rules": rules}); err != nil {
					return err
				}
			} else if len(found) == 0 {
				fmt.Fprintln(w, "No offensive agents found.")
			} else {
				for _, d := range found {
					fmt.Fprintf(w, "%-6s %-18s pid %-7d %s\n", strings.ToUpper(d.Severity), d.Rule, d.PID, termSafe(d.Title))
					for _, e := range d.Evidence {
						fmt.Fprintf(w, "         - %s\n", termSafe(e))
					}
				}
			}
			for _, d := range found {
				if d.Severity == detect.High {
					return &ExitError{Code: ExitSignal, Err: errors.New("")}
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

func statExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// --- logs ---

func newLogsCmd() *cobra.Command {
	var (
		logPath, format, types, siemSpec, tokenEnv string
		since                                      time.Duration
	)
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Print the event log, or send it to a SIEM",
		Long: `Prints the daemon's records (decisions, detections, agents started and
stopped), as text, JSON lines or CEF, each with its compliance tags.

--siem sends them to a SIEM instead (a backfill; the daemon forwards new records
itself with 'daemon --siem'):

  syslog+udp://host:514  syslog+tcp://host:601  syslog+tls://host:6514   (CEF)
  webhook+https://host/path   (JSON batches; Bearer token from --token-env)
  splunk+https://host:8088    (Splunk HEC; token from --token-env)`,
		Example: `  authsec-cli logs --since 1h
  authsec-cli logs --type decision,detection --format cef
  AUTHSEC_SIEM_TOKEN=... authsec-cli logs --siem splunk+https://splunk.example.com:8088 --since 24h`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
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
			want := map[string]bool{}
			for _, t := range strings.Split(types, ",") {
				if t = strings.TrimSpace(t); t != "" {
					want[t] = true
				}
			}
			var sel []events.Record
			for _, r := range recs {
				if len(want) == 0 || want[r.Type] {
					sel = append(sel, r)
				}
			}
			host, _ := os.Hostname()
			if siemSpec != "" {
				te, err := tokenEnvFor(cmd.Flags().Changed("token-env"), tokenEnv)
				if err != nil {
					return err
				}
				// A backfill may be large: give delivery time in proportion.
				wait := 30*time.Second + time.Duration(len(sel))*20*time.Millisecond
				if wait > 30*time.Minute {
					wait = 30 * time.Minute
				}
				opt := siem.Options{Version: Version, Hostname: host, TokenEnv: te, QueueSize: len(sel) + 10, CloseTimeout: wait}
				if len(want) > 0 {
					for t := range want {
						opt.Types = append(opt.Types, t)
					}
				}
				sink, err := siem.Open(siemSpec, opt)
				if err != nil {
					return usageErr("--siem: %v", err)
				}
				for _, r := range sel {
					sink.Send(r)
				}
				cerr := sink.Close()
				st := sink.Stats()
				fmt.Fprintf(cmd.OutOrStdout(), "sent %d, failed %d, dropped %d\n", st.Sent, st.Failed, st.Dropped)
				if cerr != nil || st.Failed > 0 || st.Dropped > 0 {
					last := ""
					if len(sel) > 0 {
						last = "; resend from " + sel[0].Time.Format(time.RFC3339) + " with --since if needed"
					}
					return &ExitError{Code: ExitRemote, Err: fmt.Errorf("SIEM: %v %s%s", cerr, st.LastError, last)}
				}
				return nil
			}
			return writeLogs(cmd.OutOrStdout(), sel, format, host)
		},
	}
	f := cmd.Flags()
	f.StringVar(&logPath, "log", "", "event log (default: the daemon's)")
	f.DurationVar(&since, "since", 24*time.Hour, "records in this period (0: all)")
	f.StringVar(&types, "type", "", "only these record types (e.g. decision,detection)")
	f.StringVar(&format, "format", "text", "text | json | cef")
	f.StringVar(&siemSpec, "siem", "", "send to a SIEM instead of printing")
	f.StringVar(&tokenEnv, "token-env", "AUTHSEC_SIEM_TOKEN", "environment variable holding the SIEM token (the name, never the value)")
	return cmd
}

func writeLogs(w io.Writer, recs []events.Record, format, host string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		for _, r := range recs {
			out := struct {
				events.Record
				Tags []string `json:"tags,omitempty"`
			}{r, siem.Tags(r)}
			if err := enc.Encode(out); err != nil {
				return err
			}
		}
	case "cef":
		for _, r := range recs {
			fmt.Fprintln(w, siem.FormatCEF(r, Version, host))
		}
	case "text":
		for _, r := range recs {
			agent := ""
			if r.Agent != nil {
				agent = r.Agent.Name
			}
			what := r.Note
			switch {
			case r.Dst != nil:
				what = fmt.Sprintf("%s:%d %s", firstNonEmpty(r.Dst.Host, r.Dst.IP), r.Dst.Port, r.Note)
			case r.Path != "":
				what = r.Access + " " + r.Path
			case len(r.Args) > 0:
				what = strings.Join(r.Args, " ")
			}
			act := r.Action
			if r.Enforced {
				act += " (blocked)"
			}
			if r.Severity != "" {
				act = r.Severity + " " + r.Rule
			}
			fmt.Fprintf(w, "%s  %-13s %-18s %-22s %s  [%s]\n", r.Time.Local().Format("Jan 02 15:04:05"), termSafe(r.Type), termSafe(act), termSafe(clipText(agent, 22)),
				termSafe(clipText(strings.Join(strings.Fields(what), " "), 120)), strings.Join(siem.Tags(r), ","))
		}
	default:
		return usageErr("--format %q: use text, json or cef", format)
	}
	return nil
}

// --- cloud ---

func newCloudCmd() *cobra.Command {
	var envPath string
	cmd := &cobra.Command{
		Use:   "cloud",
		Short: "Find AI agents in AWS and Azure; quarantine an AWS agent",
		Long: `Reads the cloud settings from a .env file (default ./.env):

  AUTHSEC_CLOUDS=aws,azure
  AWS_PROFILE=audit                  AWS_REGIONS=us-east-1,eu-west-1
  AZURE_TENANT_ID=...                AZURE_SUBSCRIPTION_IDS=...
  (AZURE_CLIENT_ID and AZURE_CLIENT_SECRET, or 'az login')

Profiles, SSO and 'az login' are preferred to keys in the file. Finds Bedrock
agents and AgentCore runtimes (AWS), Azure OpenAI deployments and AI Foundry
agents (Azure).`,
	}
	cmd.PersistentFlags().StringVar(&envPath, "env", ".env", "cloud settings file")
	var asJSON bool
	agents := &cobra.Command{
		Use:   "agents",
		Short: "List the AI agents in the configured clouds",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			found, errs, err := discoverCloud(cmd, envPath)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				var es []string
				for _, e := range errs {
					es = append(es, e.Error())
				}
				if found == nil {
					found = []cloud.Agent{}
				}
				return enc.Encode(map[string]any{"schema": "authsec-cli.cloud-agents/v1", "agents": found, "errors": es})
			}
			fmt.Fprintf(w, "AI agents in the cloud: %d\n", len(found))
			for _, a := range found {
				fmt.Fprintf(w, "\n  %s  [%s %s]  %s\n", termSafe(a.Name), a.Cloud, a.Kind, termSafe(firstNonEmpty(a.Region, a.Account)))
				if a.Model != "" {
					fmt.Fprintf(w, "      model:    %s\n", termSafe(a.Model))
				}
				if a.Identity != "" {
					fmt.Fprintf(w, "      identity: %s\n", termSafe(a.Identity))
				}
				fmt.Fprintf(w, "      id:       %s\n", termSafe(a.ID))
			}
			for _, e := range errs {
				fmt.Fprintf(cmd.ErrOrStderr(), "note: %s\n", termSafe(e.Error()))
			}
			if len(errs) > 0 && len(found) == 0 {
				return &ExitError{Code: ExitRemote, Err: fmt.Errorf("%d cloud calls failed and no agent was found", len(errs))}
			}
			return nil
		},
	}
	agents.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	cmd.AddCommand(agents, newCloudQuarantineCmd(&envPath, false), newCloudQuarantineCmd(&envPath, true))
	return cmd
}

func discoverCloud(cmd *cobra.Command, envPath string) ([]cloud.Agent, []error, error) {
	cfg, warns, err := cloud.LoadEnv(envPath)
	if err != nil {
		return nil, nil, usageErr("%s: %v", envPath, err)
	}
	for _, w := range warns {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", w)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var found []cloud.Agent
	var errs []error
	for _, c := range cfg.Clouds {
		switch c {
		case "aws":
			a, e := cloud.DiscoverAWS(ctx, cfg.AWS)
			found, errs = append(found, a...), append(errs, e...)
		case "azure":
			a, e := cloud.DiscoverAzure(ctx, cfg.Azure)
			found, errs = append(found, a...), append(errs, e...)
		}
	}
	if len(cfg.Clouds) == 0 {
		return nil, nil, usageErr("%s names no cloud: set AUTHSEC_CLOUDS=aws,azure", envPath)
	}
	return found, errs, nil
}

func newCloudQuarantineCmd(envPath *string, release bool) *cobra.Command {
	var apply bool
	use, short := "quarantine AGENT", "Deny everything to an AWS agent's execution role (inline policy AuthSecQuarantine)"
	if release {
		use, short = "release AGENT", "Remove the AuthSecQuarantine policy from an AWS agent's role"
	}
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Long: short + `.
AGENT is an agent's id (ARN) or name from 'authsec-cli cloud agents'. Nothing
changes without --apply: the plan is printed first.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			found, errs, err := discoverCloud(cmd, *envPath)
			if err != nil {
				return err
			}
			for _, e := range errs {
				fmt.Fprintf(cmd.ErrOrStderr(), "note: %s\n", termSafe(e.Error()))
			}
			var matches []cloud.Agent
			byID := false
			for _, a := range found {
				if a.Cloud == "aws" && (a.ID == args[0] || a.Name == args[0]) {
					matches = append(matches, a)
					byID = byID || a.ID == args[0]
				}
			}
			switch {
			case len(matches) == 0 && len(errs) > 0:
				return &ExitError{Code: ExitRemote, Err: fmt.Errorf("no AWS agent %q found, and %d cloud calls failed (see the notes)", args[0], len(errs))}
			case len(matches) == 1 && !byID && len(errs) > 0 && apply:
				return usageErr("some cloud calls failed, so the name %q may not be unique: use the agent's id (ARN)", args[0])
			case len(matches) == 0:
				return usageErr("no AWS agent %q (see 'authsec-cli cloud agents'); Azure agents are governed by the console's access policies", args[0])
			case len(matches) > 1:
				return usageErr("%d AWS agents are named %q: use the id", len(matches), args[0])
			}
			cfg, _, _ := cloud.LoadEnv(*envPath)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			var plan cloud.Plan
			if release {
				plan, err = cloud.ReleaseAWS(ctx, cfg.AWS, matches[0], apply)
			} else {
				plan, err = cloud.QuarantineAWS(ctx, cfg.AWS, matches[0], apply)
			}
			w := cmd.OutOrStdout()
			for _, a := range plan.Actions {
				fmt.Fprintf(w, "  %s\n", a)
			}
			if err != nil {
				return &ExitError{Code: ExitRemote, Err: err}
			}
			if plan.Applied {
				fmt.Fprintln(w, "applied")
			} else {
				fmt.Fprintln(w, "dry run: nothing changed (add --apply)")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&apply, "apply", false, "make the change (default: print the plan only)")
	return cmd
}

// tokenEnvIfSet names the token variable only when it holds a value: syslog
// needs no token, and an unset default must not make it fail.
func tokenEnvIfSet(name string) string {
	if name != "" && os.Getenv(name) != "" {
		return name
	}
	return ""
}

// tokenEnvFor names the token variable for a SIEM: an explicitly named one
// must be set; the default is used only when it is.
func tokenEnvFor(explicit bool, name string) (string, error) {
	if explicit && name != "" && os.Getenv(name) == "" {
		return "", usageErr("the token variable %s is not set", name)
	}
	return tokenEnvIfSet(name), nil
}

// termSafe makes text safe for a terminal: control characters (which could
// forge or hide lines) are shown escaped.
func termSafe(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == '\u2028' || r == '\u2029' {
			fmt.Fprintf(&b, "\\x%02x", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
