package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/authsec-ai/authsec-cli/internal/access"
	"github.com/authsec-ai/authsec-cli/internal/events"
	"github.com/authsec-ai/authsec-cli/internal/finding"
	"github.com/authsec-ai/authsec-cli/internal/policy"
	"github.com/authsec-ai/authsec-cli/internal/scan"
)

const defaultPolicyDir = "policies"

func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Generate, edit, check and test agent policies (YAML)",
		Long: `Agent policies are YAML files, one per agent, in a policy folder (default
./policies). 'generate' writes them from what the daemon saw each agent do;
edit them with any editor; 'check' validates them and shows what they would
have blocked; 'test' asks one question of a policy.

A policy starts in monitor mode (log only). Set mode: enforce to block.`,
	}
	cmd.AddCommand(newPolicyGenerateCmd(), newPolicyCheckCmd(), newPolicyEditCmd(), newPolicyTestCmd(), newPolicyExportCmd())
	return cmd
}

func newPolicyGenerateCmd() *cobra.Command {
	var (
		dir, logPath, only string
		since              time.Duration
		force              bool
	)
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Write one policy per agent from what it was seen doing",
		Example: `  authsec-cli policy generate
  authsec-cli policy generate --dir /etc/authsec/policies --since 72h
  authsec-cli policy generate --agent claude-code --force`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := cmd.OutOrStdout()
			if logPath == "" {
				logPath = events.ReadablePath()
			}
			now := time.Now()
			var from time.Time
			if since > 0 {
				from = now.Add(-since)
			}
			recs, err := events.Read(logPath, from)
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "note: %v\n      policies will hold defaults only.\n", err)
			}
			activity := map[string]access.Summary{}
			for _, s := range access.Summarize(recs, nil) {
				if s.ID != "unknown" {
					activity[s.ID] = s
				}
			}
			// Installed agents and their configured MCP servers.
			names := map[string]string{}
			mcp := map[string][]string{}
			if r, err := scan.Run(scan.Options{KnownProjects: true, Only: []finding.Kind{finding.Agent, finding.MCPServer}, CLIVersion: Version}); err == nil {
				for _, f := range r.Findings {
					switch f.Kind {
					case finding.Agent:
						names[f.Tool] = f.Name
					case finding.MCPServer:
						mcp[f.Tool] = append(mcp[f.Tool], f.Name)
					}
				}
			}
			for id, s := range activity {
				names[id] = s.Name
			}
			ids := make([]string, 0, len(names))
			for id := range names {
				if only == "" || id == only {
					ids = append(ids, id)
				}
			}
			sort.Strings(ids)
			if only != "" && len(ids) == 0 {
				return usageErr("--agent %s: not seen running and not installed", only)
			}
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return ioErr(err)
			}
			wrote, failed := 0, 0
			write := func(file string, g *policy.Generated) error {
				path := filepath.Join(dir, file)
				if _, err := os.Stat(path); err == nil && !force {
					fmt.Fprintf(w, "  kept     %s (exists; --force to replace)\n", path)
					return nil
				}
				data := policy.Render(g)
				// What is written must read back as exactly the policy that
				// was generated: nothing observed may add to it.
				back, issues := policy.Parse(data)
				if hasErrors(issues) || back == nil || !samePolicy(back, g.Policy) {
					return fmt.Errorf("generated policy for %s does not read back as generated (%v); not written", g.Policy.Agent.ID, issues)
				}
				if err := os.WriteFile(path, data, 0o644); err != nil {
					return err
				}
				wrote++
				p := g.Policy
				fmt.Fprintf(w, "  wrote    %-34s %d destinations, %d paths, %d MCP servers\n", path,
					len(p.Network.Allow), len(p.Filesystem.ReadWrite)+len(p.Filesystem.ReadOnly), len(p.MCPServers.Allow))
				return nil
			}
			fmt.Fprintf(w, "Policies in %s/ (activity from %s):\n", dir, logOrNone(recs, logPath))
			for _, id := range ids {
				s, seen := activity[id]
				if !seen {
					fmt.Fprintf(w, "  skipped  %-34s installed, not seen running: default.yaml applies until it is\n", id)
					continue
				}
				in := policy.GenInput{AgentID: id, AgentName: names[id], MCPConfigured: mcp[id], Home: homeOf(s.Users),
					Since: from, Now: now, Version: Version, Activity: &s}
				if err := write(id+".yaml", policy.Generate(in)); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "  failed   %s: %v\n", id, err)
					failed++
				}
			}
			if only == "" {
				if err := write("default.yaml", policy.DefaultPolicy(Version, now)); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "  failed   default.yaml: %v\n", err)
					failed++
				}
			}
			if wrote > 0 {
				fmt.Fprintf(w, "\nNext: review and edit them (vi %s/<agent>.yaml or authsec-cli policy edit <agent>),\nthen run: authsec-cli policy check --dir %s\n", dir, dir)
			}
			if failed > 0 {
				return ioErr(fmt.Errorf("%d policies could not be generated", failed))
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&dir, "dir", defaultPolicyDir, "policy folder")
	f.StringVar(&logPath, "log", "", "event log (default: the daemon's)")
	f.DurationVar(&since, "since", 7*24*time.Hour, "activity to learn from (0: all)")
	f.StringVar(&only, "agent", "", "only this agent id")
	f.BoolVar(&force, "force", false, "replace existing policy files")
	return cmd
}

func newPolicyCheckCmd() *cobra.Command {
	var (
		dir, logPath string
		since        time.Duration
		asJSON       bool
	)
	cmd := &cobra.Command{
		Use:   "check [FILE...]",
		Short: "Validate policies and show what they would have blocked",
		Long: `Validates each policy (errors with line numbers) and replays the daemon's
recent activity against it: which destinations, files and commands it would
deny or send for approval. Exit code 1 if any policy has errors.`,
		Example: `  authsec-cli policy check
  authsec-cli policy check policies/claude-code.yaml --since 72h`,
		RunE: func(cmd *cobra.Command, args []string) error {
			w := cmd.OutOrStdout()
			var files []*policy.File
			if len(args) > 0 {
				for _, a := range args {
					files = append(files, policy.Load(a))
				}
			} else {
				var err error
				if files, err = policy.LoadDir(dir); err != nil {
					return ioErr(err)
				}
				if len(files) == 0 {
					return usageErr("no policy files in %s (run 'authsec-cli policy generate')", dir)
				}
			}
			if logPath == "" {
				logPath = events.ReadablePath()
			}
			var from time.Time
			if since > 0 {
				from = time.Now().Add(-since)
			}
			recs, logErr := events.Read(logPath, from)
			// Which agents have their own policy is decided by the whole
			// folder, also when single files are checked.
			setFiles := files
			if len(args) > 0 {
				dirs := map[string]bool{}
				for _, a := range args {
					dirs[filepath.Dir(a)] = true
				}
				setFiles = nil
				for d := range dirs {
					if fs, err := policy.LoadDir(d); err == nil {
						setFiles = append(setFiles, fs...)
					}
				}
				setFiles = append(setFiles, files...)
			}
			set := policy.NewSet(setFiles)
			type result struct {
				File   string         `json:"file"`
				Agent  string         `json:"agent,omitempty"`
				Mode   string         `json:"mode,omitempty"`
				OK     bool           `json:"ok"`
				Issues []policy.Issue `json:"issues"`
				Impact *policy.Impact `json:"impact,omitempty"`
			}
			var results []result
			failed := 0
			for _, f := range files {
				r := result{File: f.Path, OK: f.OK(), Issues: f.Issues}
				if r.Issues == nil {
					r.Issues = []policy.Issue{}
				}
				if !r.OK {
					failed++
				}
				if f.Policy != nil {
					r.Agent, r.Mode = f.Policy.Agent.ID, f.Policy.Mode
					if r.OK && logErr == nil {
						id := f.Policy.Agent.ID
						match := func(a events.Agent) bool { return a.ID == id }
						if id == policy.AnyAgent {
							match = func(a events.Agent) bool { return !set.Has(a.ID) }
						}
						imp := policy.Simulate(f.Policy, recs, match, homeOfRecords(recs, match))
						r.Impact = &imp
					}
				}
				results = append(results, r)
			}
			if asJSON {
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				if err := enc.Encode(map[string]any{"schema": "authsec-cli.policy-check/v1", "results": results}); err != nil {
					return err
				}
			} else {
				for _, r := range results {
					status := "ok"
					if !r.OK {
						status = "ERRORS"
					}
					fmt.Fprintf(w, "%s  [%s]  agent %s, mode %s\n", r.File, status, orDash(r.Agent), orDash(r.Mode))
					for _, i := range r.Issues {
						fmt.Fprintf(w, "  %s\n", i)
					}
					if r.Impact != nil {
						printImpact(w, r.Mode, *r.Impact, since)
					}
					fmt.Fprintln(w)
				}
				if logErr != nil {
					fmt.Fprintf(w, "Not replayed against activity: %v\n", logErr)
				}
			}
			if failed > 0 {
				return &ExitError{Code: ExitSignal, Err: fmt.Errorf("%d of %d policy files have errors", failed, len(files))}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&dir, "dir", defaultPolicyDir, "policy folder")
	f.StringVar(&logPath, "log", "", "event log (default: the daemon's)")
	f.DurationVar(&since, "since", 24*time.Hour, "activity to replay (0: all)")
	f.BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

func printImpact(w io.Writer, mode string, imp policy.Impact, since time.Duration) {
	if imp.Checked == 0 {
		fmt.Fprintf(w, "  no recorded activity %s to replay\n", window(since))
		return
	}
	verb := "would block"
	if mode == policy.Monitor {
		verb = "would log as blocked (monitor mode)"
	}
	deny, ask := 0, 0
	for _, h := range imp.Hits {
		if h.Action == policy.Deny {
			deny++
		} else {
			ask++
		}
	}
	fmt.Fprintf(w, "  replayed %d actions %s (%s): %d %s, %d need approval\n",
		imp.Checked, window(since), strings.Join(imp.Agents, ", "), deny, verb, ask)
	for i, h := range imp.Hits {
		if i == 12 {
			fmt.Fprintf(w, "    … %d more (--json for all)\n", len(imp.Hits)-12)
			break
		}
		fmt.Fprintf(w, "    %-5s %-8s %s  ×%d  (%s)\n", h.Action, h.Kind, h.What, h.Count, h.Rule)
	}
}

func newPolicyEditCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "edit AGENT|FILE",
		Short: "Open a policy in $EDITOR (vi by default) and check it when you save",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
				path = filepath.Join(dir, path+".yaml")
			}
			if _, err := os.Stat(path); err != nil {
				return usageErr("%s: no such policy (run 'authsec-cli policy generate')", path)
			}
			editor := firstNonEmpty(os.Getenv("VISUAL"), os.Getenv("EDITOR"), "vi")
			in := bufio.NewReader(cmd.InOrStdin())
			for {
				parts := strings.Fields(editor)
				c := exec.Command(parts[0], append(parts[1:], path)...)
				c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
				if err := c.Run(); err != nil {
					return ioErr(fmt.Errorf("%s: %w", editor, err))
				}
				f := policy.Load(path)
				for _, i := range f.Issues {
					fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", i)
				}
				if f.OK() {
					fmt.Fprintf(cmd.OutOrStdout(), "%s: ok (mode %s)\n", path, f.Policy.Mode)
					return nil
				}
				fmt.Fprint(cmd.OutOrStdout(), "The policy has errors. Edit again? [Y/n] ")
				ans, _ := in.ReadString('\n')
				if a := strings.TrimSpace(strings.ToLower(ans)); a == "n" || a == "no" {
					return &ExitError{Code: ExitSignal, Err: errors.New("policy left with errors; it will not be applied")}
				}
			}
		},
	}
	cmd.Flags().StringVar(&dir, "dir", defaultPolicyDir, "policy folder")
	return cmd
}

func newPolicyTestCmd() *cobra.Command {
	var (
		dir, host, file, command, mcp, home, project string
		port                                         int
		write                                        bool
	)
	cmd := &cobra.Command{
		Use:   "test AGENT",
		Short: "Ask a policy one question: may the agent connect, open, run or load this?",
		Example: `  authsec-cli policy test claude-code --host api.anthropic.com --port 443
  authsec-cli policy test claude-code --file ~/.aws/credentials
  authsec-cli policy test claude-code --command "git push --force origin main"
  authsec-cli policy test codex --mcp github`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			files, err := policy.LoadDir(dir)
			if err != nil {
				return ioErr(err)
			}
			p, err := policy.NewSet(files).For(args[0])
			if err != nil {
				return &ExitError{Code: ExitSignal, Err: fmt.Errorf("%s: %v (the default policy is not used instead); run 'authsec-cli policy check'", args[0], err)}
			}
			if p == nil {
				return usageErr("no usable policy for %s in %s (and no default.yaml)", args[0], dir)
			}
			if home == "" {
				home, _ = os.UserHomeDir()
			}
			if project != "" {
				if project, err = filepath.Abs(expandTilde(project, home)); err != nil {
					return usageErr("--project: %v", err)
				}
			}
			p = p.Expand(home, project)
			var d policy.Decision
			var what string
			switch {
			case host != "":
				ip := net.ParseIP(host)
				h := host
				if ip != nil {
					h = ""
				}
				d, what = p.DecideNetwork(h, ip, port), fmt.Sprintf("connect to %s", net.JoinHostPort(host, fmt.Sprint(port)))
			case file != "":
				abs, _ := filepath.Abs(expandTilde(file, home))
				d, what = p.DecideFile(abs, write), "open "+abs
				if write {
					what += " for writing"
				}
			case command != "":
				d, what = p.DecideCommand(command), "run "+command
			case mcp != "":
				d, what = p.DecideMCP(mcp), "load MCP server "+mcp
			default:
				return usageErr("give one of --host, --file, --command, --mcp")
			}
			effect := ""
			if d.Action != policy.Allow && p.Mode == policy.Monitor {
				effect = " (monitor mode: logged, not blocked)"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s: %s by %s%s\n", p.Agent.ID, what, strings.ToUpper(d.Action), d.Rule, effect)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&dir, "dir", defaultPolicyDir, "policy folder")
	f.StringVar(&host, "host", "", "destination host or IP")
	f.IntVar(&port, "port", 443, "destination port")
	f.StringVar(&file, "file", "", "file path")
	f.BoolVar(&write, "write", false, "with --file: open for writing")
	f.StringVar(&command, "command", "", "shell command line")
	f.StringVar(&mcp, "mcp", "", "MCP server name")
	f.StringVar(&home, "home", "", "home directory for {home} (default: yours)")
	f.StringVar(&project, "project", "", "project directory for {project} (default: none, so {project} paths match nothing)")
	return cmd
}

func newPolicyExportCmd() *cobra.Command {
	var (
		dir, out, home string
		binaries       []string
		openshell      bool
	)
	cmd := &cobra.Command{
		Use:   "export AGENT|FILE --openshell",
		Short: "Translate a policy into an NVIDIA OpenShell sandbox policy",
		Long: `Writes the policy as an OpenShell sandbox policy (schema version 1) for
'openshell sandbox create --policy'. OpenShell allows only what is listed: deny
rules, commands and MCP servers cannot be carried over, and each such case is
listed as a note at the top of the file and on stderr.`,
		Example: `  authsec-cli policy export claude-code --openshell -o claude-code.openshell.yaml
  authsec-cli policy export codex --openshell --binary /usr/lib/node_modules/@openai/codex/bin/codex.js --home /home/sandbox`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !openshell {
				return usageErr("choose a format: --openshell")
			}
			path := args[0]
			if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
				path = filepath.Join(dir, path+".yaml")
			}
			f := policy.Load(path)
			if !f.OK() {
				for _, i := range f.Issues {
					fmt.Fprintf(cmd.ErrOrStderr(), "  %s\n", i)
				}
				return &ExitError{Code: ExitSignal, Err: fmt.Errorf("%s has errors; fix them first (authsec-cli policy check)", path)}
			}
			exp, err := policy.ExportOpenShell(f.Policy, policy.OpenShellOptions{Home: home, Binaries: binaries, Source: path})
			if err != nil {
				return usageErr("%v", err)
			}
			for _, n := range exp.Notes {
				fmt.Fprintf(cmd.ErrOrStderr(), "note: %s\n", n)
			}
			if out == "" || out == "-" {
				_, err := cmd.OutOrStdout().Write(exp.YAML)
				return err
			}
			if err := os.WriteFile(out, exp.YAML, 0o644); err != nil {
				return ioErr(err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s\n", out)
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&dir, "dir", defaultPolicyDir, "policy folder")
	fl.BoolVar(&openshell, "openshell", false, "OpenShell sandbox policy (the only format so far)")
	fl.StringVarP(&out, "output", "o", "", "write to this file (default: stdout)")
	fl.StringVar(&home, "home", "", "home directory inside the sandbox image, for {home} paths (default: {home} paths are skipped)")
	fl.StringArrayVar(&binaries, "binary", nil, "the agent's executable inside the image, real path (repeatable)")
	return cmd
}

// samePolicy compares two policies, treating nil and empty lists alike.
func samePolicy(a, b *policy.Policy) bool {
	x, err1 := policy.Marshal(a)
	y, err2 := policy.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

func window(since time.Duration) string {
	if since <= 0 {
		return "from the whole log"
	}
	return "from the last " + since.String()
}

func hasErrors(issues []policy.Issue) bool {
	for _, i := range issues {
		if !i.Warning {
			return true
		}
	}
	return false
}

// homeOf returns the home directory of the first user an agent ran as.
func homeOf(users []string) string {
	for _, u := range users {
		if pw, err := user.Lookup(u); err == nil {
			return pw.HomeDir
		}
	}
	h, _ := os.UserHomeDir()
	return h
}

func homeOfRecords(recs []events.Record, match func(events.Agent) bool) string {
	for _, r := range recs {
		if r.Agent != nil && r.Agent.User != "" && match(*r.Agent) {
			return homeOf([]string{r.Agent.User})
		}
	}
	return homeOf(nil)
}

func logOrNone(recs []events.Record, path string) string {
	if len(recs) == 0 {
		return "none"
	}
	return path
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

func expandTilde(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}
