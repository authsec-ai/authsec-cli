package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/authsec-ai/authsec-cli/internal/control"
	"github.com/authsec-ai/authsec-cli/internal/enforce"
	"github.com/authsec-ai/authsec-cli/internal/events"
	"github.com/authsec-ai/authsec-cli/internal/policy"
	"github.com/authsec-ai/authsec-cli/internal/recognise"
)

// SystemPolicyDir is where root-installed policies live; the daemon and
// the Claude Code hook read it by default when it exists.
const SystemPolicyDir = "/etc/authsec/policies"

// enforcementDir is the policy folder enforcement reads by default.
func enforcementDir() string {
	if st, err := os.Stat(SystemPolicyDir); err == nil && st.IsDir() {
		return SystemPolicyDir
	}
	return defaultPolicyDir
}

func newEnforceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enforce",
		Short: "See and control what the daemon enforces",
		Long: `The daemon enforces every agent whose policy says mode: enforce:

  network   only the policy's destinations (nftables, per agent cgroup)
  commands  a denied program the agent starts is stopped at once
  files     logged for running agents; confined with 'authsec-cli run --enforce'
  Claude    a PreToolUse hook decides each tool call ('enforce claude install')

Policies are read from /etc/authsec/policies (or ./policies), and reloaded when
they change.`,
	}
	cmd.AddCommand(
		&cobra.Command{Use: "status", Short: "Show enforced agents, quarantines and policies", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error { return enforceStatus(cmd.OutOrStdout()) }},
		&cobra.Command{Use: "reload", Short: "Reload the policy folder now (root)", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				if _, err := callDaemon(control.Request{Op: control.OpReload}); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), "policies reloaded")
				return nil
			}},
		newEnforceClaudeCmd(),
	)
	return cmd
}

func callDaemon(req control.Request) (control.Response, error) {
	resp, err := control.Call(control.SocketPath(), req, 10*time.Second)
	if err != nil {
		if strings.Contains(err.Error(), "not running") {
			return resp, &ExitError{Code: ExitIO, Err: fmt.Errorf("%v\nstart it with: sudo authsec-cli daemon --policies %s", err, enforcementDir())}
		}
		return resp, &ExitError{Code: ExitSignal, Err: err}
	}
	return resp, nil
}

func enforceStatus(w io.Writer) error {
	resp, err := callDaemon(control.Request{Op: control.OpStatus})
	if err != nil {
		return err
	}
	var st struct {
		Enforcement enforce.Status `json:"enforcement"`
		Agents      []events.Agent `json:"agents"`
	}
	if err := json.Unmarshal(resp.Data, &st); err != nil {
		return ioErr(err)
	}
	e := st.Enforcement
	active := "on"
	if !e.Active {
		active = "off (decisions are logged; blocking needs the daemon to run as root on Linux)"
	}
	fmt.Fprintf(w, "enforcement:  %s\npolicies:     %s\n", active, strings.Join(e.Policies, ", "))
	if len(e.Quarantined) > 0 {
		fmt.Fprintf(w, "quarantined:  %s\n", strings.Join(e.Quarantined, ", "))
	}
	if e.LastError != "" {
		fmt.Fprintf(w, "last error:   %s\n", e.LastError)
	}
	fmt.Fprintf(w, "\nagents running: %d\n", len(st.Agents))
	enforced := map[int]enforce.GroupStatus{}
	for _, g := range e.Enforced {
		enforced[g.Agent.PID] = g
	}
	for _, a := range st.Agents {
		state := "monitor"
		if g, ok := enforced[a.PID]; ok {
			state = "ENFORCED"
			if g.Quarantined {
				state = "QUARANTINED (frozen, no network)"
			} else if g.Forced {
				state += " (run --enforce)"
			}
			state += fmt.Sprintf(", %d allowed addresses", g.Allowed)
		}
		fmt.Fprintf(w, "  %-24s pid %-8d %s\n", a.Name, a.PID, state)
	}
	return nil
}

func newQuarantineCmd(release bool) *cobra.Command {
	use, short, op := "quarantine AGENT|PID", "Freeze an agent and cut its network (every instance of an id, now and later)", control.OpQuarantine
	if release {
		use, short, op = "release AGENT|PID", "Lift a quarantine", control.OpRelease
	}
	return &cobra.Command{
		Use:   use,
		Short: short,
		Example: "  sudo authsec-cli " + strings.Fields(use)[0] + " claude-code\n" +
			"  sudo authsec-cli " + strings.Fields(use)[0] + " 4242",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := control.Request{Op: op}
			if pid, err := strconv.Atoi(args[0]); err == nil {
				req.PID = pid
			} else {
				req.Agent = args[0]
			}
			resp, err := callDaemon(req)
			if err != nil {
				return err
			}
			var r struct {
				Instances int `json:"instances"`
			}
			_ = json.Unmarshal(resp.Data, &r)
			verb := "quarantined"
			if release {
				verb = "released"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s (%d running instance(s))\n", verb, args[0], r.Instances)
			if !release && req.Agent != "" {
				fmt.Fprintln(cmd.OutOrStdout(), "new instances are quarantined as they start, until 'authsec-cli release "+args[0]+"'")
			}
			return nil
		},
	}
}

// --- Claude Code ---

func newEnforceClaudeCmd() *cobra.Command {
	var dir, bin string
	cmd := &cobra.Command{
		Use:   "claude",
		Short: "Enforce the claude-code policy inside Claude Code (managed settings)",
		Long: `Writes a managed-settings drop-in for Claude Code (users cannot override it):

  - a PreToolUse hook for every tool, which applies the claude-code policy to
    shell commands, web fetches, file paths and MCP tools; it blocks the call if
    the hook fails or times out;
  - when the policy is in enforce mode, the MCP servers Claude Code may load.`,
	}
	install := &cobra.Command{
		Use:   "install",
		Short: "Write the managed-settings drop-in (root)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, notes, path, err := claudeSettings(dir, bin)
			if err != nil {
				return err
			}
			b, _ := json.MarshalIndent(s, "", "  ")
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return ioErr(fmt.Errorf("%w (run with sudo)", err))
			}
			if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
				return ioErr(fmt.Errorf("%w (run with sudo)", err))
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", path)
			for _, n := range notes {
				fmt.Fprintf(cmd.OutOrStdout(), "note: %s\n", n)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Claude Code applies it to sessions started from now on.")
			return nil
		},
	}
	show := &cobra.Command{
		Use:   "show",
		Short: "Print the drop-in without writing it",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, notes, path, err := claudeSettings(dir, bin)
			if err != nil {
				return err
			}
			b, _ := json.MarshalIndent(s, "", "  ")
			fmt.Fprintf(cmd.OutOrStdout(), "// %s\n%s\n", path, b)
			for _, n := range notes {
				fmt.Fprintf(cmd.ErrOrStderr(), "note: %s\n", n)
			}
			return nil
		},
	}
	uninstall := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the drop-in (root)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path := enforce.ClaudeDropIn()
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return ioErr(fmt.Errorf("%w (run with sudo)", err))
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed %s\n", path)
			return nil
		},
	}
	for _, c := range []*cobra.Command{install, show} {
		c.Flags().StringVar(&dir, "dir", "", "policy folder the hook reads (default /etc/authsec/policies, else ./policies made absolute)")
		c.Flags().StringVar(&bin, "bin", "", "authsec-cli path the hook runs (default /usr/local/bin/authsec-cli if present, else this binary)")
	}
	cmd.AddCommand(install, show, uninstall)
	return cmd
}

func claudeSettings(dir, bin string) (map[string]any, []string, string, error) {
	if dir == "" {
		dir = enforcementDir()
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, nil, "", usageErr("%v", err)
	}
	if bin == "" {
		if _, err := os.Stat(installPath); err == nil {
			bin = installPath
		} else if self, err := os.Executable(); err == nil {
			bin = self
		}
	}
	var notes []string
	if abs != SystemPolicyDir {
		notes = append(notes, fmt.Sprintf("the hook reads %s; for a tamper-proof setup put policies in %s (root-owned)", abs, SystemPolicyDir))
	}
	var p *policy.Policy
	if files, err := policy.LoadDir(abs); err == nil {
		p, _ = policy.NewSet(files).For("claude-code")
	} else {
		notes = append(notes, fmt.Sprintf("no policy folder at %s yet: the hook allows everything until there is one", abs))
	}
	hook := fmt.Sprintf("%s hook claude-pretooluse --dir %s", shellQuote(bin), shellQuote(abs))
	s, more := enforce.ClaudeManagedSettings(p, hook)
	return s, append(notes, more...), enforce.ClaudeDropIn(), nil
}

func shellQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n'\"\\$`;&|<>()*?[]#~!{}") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func newHookCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "hook", Short: "Agent hooks (run by the agents, not by people)", Hidden: true}
	var dir string
	pre := &cobra.Command{
		Use:   "claude-pretooluse",
		Short: "Claude Code PreToolUse hook: decide one tool call from stdin",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runClaudeHook(cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), dir)
		},
	}
	pre.Flags().StringVar(&dir, "dir", "", "policy folder (default /etc/authsec/policies, else ./policies)")
	cmd.AddCommand(pre)
	return cmd
}

// runClaudeHook decides one tool call. Fail closed: a broken claude-code
// policy denies (exit 2); a missing folder or policy allows (nothing to
// enforce yet).
func runClaudeHook(in io.Reader, out, errOut io.Writer, dir string) error {
	if dir == "" {
		dir = enforcementDir()
	}
	var hin enforce.HookInput
	if err := json.NewDecoder(io.LimitReader(in, 4<<20)).Decode(&hin); err != nil {
		fmt.Fprintln(errOut, "AuthSec hook: unreadable tool call; blocked")
		return &ExitError{Code: 2, Err: errors.New("unreadable hook input")}
	}
	files, err := policy.LoadDir(dir)
	if err != nil {
		return nil // no policy folder: nothing to enforce
	}
	p, err := policy.NewSet(files).For("claude-code")
	if err != nil {
		fmt.Fprintf(errOut, "AuthSec: the claude-code policy has errors (%v); tool calls are blocked until it is fixed\n", err)
		return &ExitError{Code: 2, Err: err}
	}
	if p == nil {
		return nil
	}
	home, _ := os.UserHomeDir()
	d := enforce.DecideClaudeTool(p, hin, home)
	if d.Action != policy.Allow {
		agent := &events.Agent{ID: "claude-code", Name: "Claude Code", PID: os.Getppid()}
		rec := &events.Record{Type: events.Decision, Kind: d.Kind, Action: d.Action, Rule: d.Rule, Agent: agent,
			Enforced: p.Mode == policy.Enforce, Note: fmt.Sprintf("%s: %s", hin.ToolName, clipText(d.What, 300))}
		if d.Kind == "file" {
			rec.Path = d.What
		}
		// Best effort: the decision is made whether the daemon hears of it.
		_, _ = control.Call(control.SocketPath(), control.Request{Op: control.OpReport, Record: rec}, 300*time.Millisecond)
	}
	if b := enforce.HookOutput(d, p.Mode); b != nil {
		_, _ = out.Write(append(b, '\n'))
	}
	return nil
}

func clipText(s string, n int) string {
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

// --- run --enforce ---

func newRunCmd() *cobra.Command {
	var (
		enforceFlag, dryRun, noDaemon, acceptUncovered bool
		sandbox, agentID, isolate                      string
		dir, project, image                            string
	)
	cmd := &cobra.Command{
		Use:   "run --enforce [flags] -- AGENT [ARGS...]",
		Short: "Re-run an agent confined by its policy",
		Long: `Starts an agent confined by its policy (in enforce mode, whatever the file says):

  --sandbox landlock   (Linux, no root) Landlock confines the files and, when the
                       policy denies the network by default, the TCP ports; the
                       daemon, if running, also limits destinations by host
  --sandbox openshell  the agent runs in an NVIDIA OpenShell sandbox built from the
                       policy (needs openshell and --image with the agent inside)
  --sandbox auto       openshell when --image is given and openshell is installed,
                       else landlock`,
		Example: `  authsec-cli run --enforce -- claude
  authsec-cli run --enforce --dry-run -- codex
  authsec-cli run --enforce --sandbox openshell --image ghcr.io/acme/claude:latest -- claude`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !enforceFlag {
				return usageErr("run needs --enforce (to run an agent without a policy, run it directly)")
			}
			return runEnforced(cmd, args, runOptions{sandbox: sandbox, agentID: agentID, dir: dir, project: project, image: image,
				dryRun: dryRun, noDaemon: noDaemon, acceptUncovered: acceptUncovered, isolate: isolate})
		},
	}
	f := cmd.Flags()
	f.BoolVar(&enforceFlag, "enforce", false, "confine the agent by its policy")
	f.StringVar(&sandbox, "sandbox", "auto", "auto | landlock | openshell")
	f.StringVar(&agentID, "agent", "", "agent id whose policy applies (default: recognised from the program)")
	f.StringVar(&dir, "dir", "", "policy folder (default /etc/authsec/policies, else ./policies)")
	f.StringVar(&project, "project", "", "project directory for {project} (default: the git project of the current directory, else it)")
	f.StringVar(&image, "image", "", "with --sandbox openshell: an OCI image that contains the agent")
	f.BoolVar(&dryRun, "dry-run", false, "print what would be applied and exit")
	f.BoolVar(&noDaemon, "no-daemon", false, "run without the daemon: only TCP ports are limited (not host names, not UDP)")
	f.BoolVar(&acceptUncovered, "accept-uncovered", false, "run even when a denied credential store stays readable inside an allowed path")
	f.StringVar(&isolate, "isolate", "auto", "hide session sockets (systemd --user, docker, ssh-agent, X11) in a private mount namespace: auto | on | off")
	return cmd
}

type runOptions struct {
	sandbox, agentID, dir, project, image, isolate string
	dryRun, noDaemon, acceptUncovered              bool
	explicitProject                                bool
}

func runEnforced(cmd *cobra.Command, args []string, o runOptions) error {
	errOut := cmd.ErrOrStderr()
	bin, err := exec.LookPath(args[0])
	if err != nil {
		return usageErr("%s: %v", args[0], err)
	}
	if abs, err := filepath.Abs(bin); err == nil {
		bin = abs
	}
	id := o.agentID
	if id == "" {
		real, _ := filepath.EvalSymlinks(bin)
		if sig, _ := recognise.Match(real, filepath.Base(bin), args); sig != nil {
			id = sig.ID
		} else {
			id = "unknown"
		}
	}
	if o.dir == "" {
		o.dir = enforcementDir()
	}
	files, err := policy.LoadDir(o.dir)
	if err != nil {
		return usageErr("policy folder %s: %v (run 'authsec-cli policy generate')", o.dir, err)
	}
	p, err := policy.NewSet(files).For(id)
	if err != nil {
		return &ExitError{Code: ExitSignal, Err: fmt.Errorf("%s: %v; fix it first (authsec-cli policy check)", id, err)}
	}
	if p == nil {
		return usageErr("no policy for %s in %s and no default.yaml", id, o.dir)
	}
	enforced := *p
	enforced.Mode = policy.Enforce
	home, _ := os.UserHomeDir()
	if o.project == "" {
		wd, _ := os.Getwd()
		o.project = enforce.ProjectRoot(wd)
	} else if o.project, err = filepath.Abs(o.project); err != nil {
		return usageErr("--project: %v", err)
	}
	// The project is writable: it must not be the home directory, a parent
	// of it, or the root.
	if o.project == "/" || (home != "" && (o.project == home || strings.HasPrefix(home, o.project+"/"))) {
		return usageErr("the project would be %s, which would make the whole home directory writable; run from a project directory or pass --project", o.project)
	}

	backend := o.sandbox
	if backend == "auto" {
		backend = "landlock"
		if _, err := exec.LookPath("openshell"); err == nil && o.image != "" {
			backend = "openshell"
		}
	}
	switch backend {
	case "openshell":
		return runOpenShell(cmd, &enforced, id, args, o)
	case "landlock":
	default:
		return usageErr("--sandbox %q: use auto, landlock or openshell", o.sandbox)
	}

	plan := enforce.PlanSandbox(&enforced, home, o.project, bin)
	fmt.Fprintf(errOut, "authsec: running %s under the %s policy (%s), Landlock ABI %d\n", filepath.Base(bin), id, o.dir, enforce.LandlockABI())
	fmt.Fprintf(errOut, "authsec:   project %s; writable: %s\n", o.project, strings.Join(shortPaths(plan.Sandbox.ReadWrite, home), ", "))
	if plan.Sandbox.RestrictNet {
		fmt.Fprintf(errOut, "authsec:   TCP connect only to ports %v\n", plan.Sandbox.ConnectPorts)
	}
	for _, w := range plan.Warnings {
		fmt.Fprintf(errOut, "authsec:   note: %s\n", w)
	}
	for _, b := range plan.Blocking {
		fmt.Fprintf(errOut, "authsec:   %s\n", b)
	}
	if len(plan.Blocking) > 0 && !o.acceptUncovered {
		return &ExitError{Code: ExitSignal, Err: errors.New("a credential store the policy denies would stay readable; narrow the allowed paths, or pass --accept-uncovered")}
	}
	if o.dryRun {
		fmt.Fprintf(cmd.OutOrStdout(), "read-only:  %s\nread-write: %s\nscratch:    %s\n", strings.Join(plan.Sandbox.ReadOnly, " "), strings.Join(plan.Sandbox.ReadWrite, " "), strings.Join(plan.Sandbox.ScratchRW, " "))
		return nil
	}
	if plan.Sandbox.RestrictNet && enforce.LandlockABI() < 4 {
		return &ExitError{Code: ExitSignal, Err: fmt.Errorf("this kernel's Landlock (ABI %d) cannot limit the network; the policy denies it by default", enforce.LandlockABI())}
	}
	// Without the daemon, a default-deny network is limited by TCP port
	// only: refuse unless asked.
	daemonUp := false
	if _, err := control.Call(control.SocketPath(), control.Request{Op: control.OpStatus}, 2*time.Second); err == nil {
		daemonUp = true
	}
	if enforced.Network.Default == policy.Deny && !daemonUp && !o.noDaemon {
		return &ExitError{Code: ExitSignal, Err: errors.New("the daemon is not running, so only TCP ports would be limited (not host names, not UDP); start it (sudo authsec-cli daemon) or pass --no-daemon")}
	}
	env := map[string]string{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	job := confineJob{Sandbox: plan.Sandbox, Bin: bin, Args: args, Agent: id, Register: daemonUp, Env: scrubEnv(os.Environ())}
	if o.isolate != "off" {
		job.Hide = enforce.HideTargets(os.Getuid(), o.project, env)
	}
	return startConfined(cmd, job, o.isolate)
}

// confineJob is handed to the hidden "__confine" step, which runs in the
// agent's own namespaces when isolation is possible.
type confineJob struct {
	Sandbox  enforce.Sandbox  `json:"sandbox"`
	Hide     []enforce.Hidden `json:"hide"`
	Bin      string           `json:"bin"`
	Args     []string         `json:"args"`
	Env      []string         `json:"env"`
	Agent    string           `json:"agent"`
	Register bool             `json:"register"`
	Isolate  string           `json:"isolate"`
}

const confineEnv = "AUTHSEC_CONFINE_JOB"

// sessionEnv are variables that point an agent at session services outside
// its sandbox.
var sessionEnv = []string{"DBUS_SESSION_BUS_ADDRESS", "SSH_AUTH_SOCK", "SSH_AGENT_PID", "DOCKER_HOST", "TMUX", "TMUX_PANE", "STY",
	"DISPLAY", "WAYLAND_DISPLAY", "GPG_AGENT_INFO", "XDG_SESSION_ID"}

func scrubEnv(env []string) []string {
	drop := map[string]bool{confineEnv: true}
	for _, k := range sessionEnv {
		drop[k] = true
	}
	var out []string
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if !drop[k] {
			out = append(out, kv)
		}
	}
	return out
}

// startConfined runs the agent: in a new user and mount namespace (to hide
// session sockets) when isolation is on or available, else in this process.
func startConfined(cmd *cobra.Command, job confineJob, isolate string) error {
	errOut := cmd.ErrOrStderr()
	job.Isolate = isolate
	if isolate == "off" || len(job.Hide) == 0 || enforce.IsolationAttr() == nil {
		return confine(errOut, job, false)
	}
	b, err := json.Marshal(job)
	if err != nil {
		return ioErr(err)
	}
	self, err := os.Executable()
	if err != nil {
		return ioErr(err)
	}
	c := exec.Command(self, "__confine")
	c.Env = append(os.Environ(), confineEnv+"="+string(b))
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	c.SysProcAttr = enforce.IsolationAttr()
	if err := c.Start(); err != nil {
		if isolate == "on" {
			return ioErr(fmt.Errorf("isolation (a user and mount namespace) is not available: %w", err))
		}
		fmt.Fprintf(errOut, "authsec:   note: isolation is not available (%v); session sockets stay reachable\n", err)
		return confine(errOut, job, false)
	}
	err = c.Wait()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return &ExitError{Code: ee.ExitCode(), Err: errors.New("")}
	}
	return err
}

func newConfineCmd() *cobra.Command {
	return &cobra.Command{
		Use: "__confine", Hidden: true, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var job confineJob
			if err := json.Unmarshal([]byte(os.Getenv(confineEnv)), &job); err != nil {
				return usageErr("__confine is started by 'authsec-cli run --enforce'")
			}
			return confine(cmd.ErrOrStderr(), job, true)
		},
	}
}

// confine hides session sockets (in a private namespace), registers with
// the daemon, applies Landlock and execs the agent.
func confine(errOut io.Writer, job confineJob, inNamespace bool) error {
	if inNamespace && len(job.Hide) > 0 {
		hidden, err := enforce.Hide(job.Hide)
		switch {
		case err != nil && job.Isolate == "on":
			return ioErr(fmt.Errorf("could not hide session sockets: %w", err))
		case err != nil:
			fmt.Fprintf(errOut, "authsec:   note: session sockets stay reachable (%v).\n", err)
			fmt.Fprintf(errOut, "authsec:   On Ubuntu 24.04+ allow user namespaces for authsec-cli; see docs/notes/enforcement-formats.md.\n")
		default:
			fmt.Fprintf(errOut, "authsec:   hidden: %s\n", strings.Join(hidden, ", "))
		}
	} else if len(job.Hide) > 0 {
		var paths []string
		for _, h := range job.Hide {
			paths = append(paths, h.Path)
		}
		fmt.Fprintf(errOut, "authsec:   note: not isolated: reachable session sockets: %s\n", strings.Join(paths, ", "))
	}
	if job.Register {
		if _, err := control.Call(control.SocketPath(), control.Request{Op: control.OpEnforcePID, PID: os.Getpid(), Agent: job.Agent}, 3*time.Second); err != nil {
			return ioErr(fmt.Errorf("the daemon did not take the agent under host rules: %w", err))
		}
		fmt.Fprintf(errOut, "authsec:   destinations limited to the policy's hosts by the daemon\n")
	}
	a, err := job.Sandbox.ExecConfined(job.Bin, job.Args, job.Env)
	_ = a
	return ioErr(fmt.Errorf("could not start %s confined: %w", job.Bin, err))
}

func shortPaths(ps []string, home string) []string {
	var out []string
	for _, p := range ps {
		if home != "" && (p == home || strings.HasPrefix(p, home+"/")) {
			p = "~" + strings.TrimPrefix(p, home)
		}
		out = append(out, p)
	}
	return out
}

func runOpenShell(cmd *cobra.Command, p *policy.Policy, id string, args []string, o runOptions) error {
	errOut := cmd.ErrOrStderr()
	if o.image == "" {
		return usageErr("--sandbox openshell needs --image: an OCI image with %s installed", args[0])
	}
	osBin, err := exec.LookPath("openshell")
	if err != nil && !o.dryRun {
		return usageErr("openshell is not installed (https://github.com/NVIDIA/OpenShell); or use --sandbox landlock")
	}
	exp, err := policy.ExportOpenShell(p, policy.OpenShellOptions{Source: filepath.Join(o.dir, id+".yaml")})
	if err != nil {
		return usageErr("%v", err)
	}
	for _, n := range exp.Notes {
		fmt.Fprintf(errOut, "authsec: note: %s\n", n)
	}
	tmp, err := os.CreateTemp("", "authsec-openshell-*.yaml")
	if err != nil {
		return ioErr(err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(exp.YAML); err != nil {
		return ioErr(err)
	}
	tmp.Close()
	name := fmt.Sprintf("authsec-%s-%d", strings.ReplaceAll(id, "_", "-"), os.Getpid())
	create := []string{"sandbox", "create", "--name", name, "--from", o.image, "--policy", tmp.Name(), "--upload", o.project, "--detach"}
	execArgs := append([]string{"sandbox", "exec", "-n", name, "--tty", "--"}, args...)
	del := []string{"sandbox", "delete", name}
	if o.dryRun {
		fmt.Fprintf(cmd.OutOrStdout(), "openshell %s\nopenshell %s\nopenshell %s\n\n%s", strings.Join(create, " "), strings.Join(execArgs, " "), strings.Join(del, " "), exp.YAML)
		return nil
	}
	run := func(a []string, interactive bool) error {
		c := exec.Command(osBin, a...)
		c.Stdout, c.Stderr = os.Stdout, os.Stderr
		if interactive {
			c.Stdin = os.Stdin
		}
		return c.Run()
	}
	fmt.Fprintf(errOut, "authsec: creating OpenShell sandbox %s from %s\n", name, o.image)
	if err := run(create, false); err != nil {
		return ioErr(fmt.Errorf("openshell sandbox create: %w", err))
	}
	defer func() { _ = run(del, false) }()
	err = run(execArgs, true)
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return &ExitError{Code: ee.ExitCode(), Err: fmt.Errorf("%s exited with %d", args[0], ee.ExitCode())}
	}
	return err
}
