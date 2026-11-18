package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/authsec-ai/authsec-cli/internal/collector"
	"github.com/authsec-ai/authsec-cli/internal/daemon"
	"github.com/authsec-ai/authsec-cli/internal/events"
	"github.com/authsec-ai/authsec-cli/internal/link"
	"github.com/authsec-ai/authsec-cli/internal/siem"
)

const (
	unitName    = "authsec-agent-kit.service"
	unitPath    = "/etc/systemd/system/" + unitName
	installPath = "/usr/local/bin/authsec-cli"
)

func newDaemonCmd() *cobra.Command {
	var (
		logPath, policies, siemTokenEnv string
		noEBPF, noEnforce, noDetect     bool
		noConnect                       bool
		collectorState                  string
		quarantineThreats, siemInsecure bool
		poll                            time.Duration
		siemSpecs                       []string
	)
	run := func(cmd *cobra.Command, _ []string) error {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if logPath == "" {
			logPath = events.DefaultPath()
		}
		if policies == "" {
			policies = enforcementDir()
		}
		if policies == "none" {
			policies = ""
		} else if abs, err := filepath.Abs(policies); err == nil {
			policies = abs
		}
		host, _ := os.Hostname()
		te, err := tokenEnvFor(cmd.Flags().Changed("siem-token-env"), siemTokenEnv)
		if err != nil {
			return err
		}
		httpSinks := 0
		for _, spec := range siemSpecs {
			if strings.HasPrefix(spec, "webhook+") || strings.HasPrefix(spec, "splunk+") {
				httpSinks++
			}
		}
		if te != "" && httpSinks > 1 {
			return usageErr("one SIEM token would go to %d HTTP destinations: use one webhook or Splunk destination per daemon", httpSinks)
		}
		var sinks []daemon.Sink
		for i, spec := range siemSpecs {
			ste := ""
			if strings.HasPrefix(spec, "webhook+") || strings.HasPrefix(spec, "splunk+") {
				ste = te // the token goes only to the HTTP destination
			}
			sk, err := siem.Open(spec, siem.Options{Version: Version, Hostname: host, TokenEnv: ste, InsecureSkipVerify: siemInsecure})
			if err != nil {
				return usageErr("--siem #%d: %v", i+1, err)
			}
			defer sk.Close()
			sinks = append(sinks, sk)
		}
		opts := daemon.Options{LogPath: logPath, PolicyDir: policies, NoEBPF: noEBPF, NoEnforce: noEnforce, Poll: poll,
			Status: cmd.ErrOrStderr(), Detect: !noDetect, QuarantineThreats: quarantineThreats, SIEM: sinks}
		if collectorState != "" {
			// A v2 collector (authsec-local): enrolled, synced through
			// /api/iga/v2/agent-sync, policies delivered signed.
			errOut := cmd.ErrOrStderr()
			col, err := collector.New(collector.Options{Version: Version, StateDir: collectorState,
				PolicyDir: filepath.Join(collectorState, "policies"), Status: func(s string) { fmt.Fprintln(errOut, s) }})
			if err != nil {
				return ioErr(fmt.Errorf("collector: %w (enroll with 'authsec-cli collector enroll')", err))
			}
			opts.Link, opts.ConsolePolicyDir = col, filepath.Join(collectorState, "policies")
			fmt.Fprintf(errOut, "collector %s: %s\n", col.State().CollectorID, col.State().URL)
		} else if !noConnect {
			lc, err := link.Load(link.Path())
			switch {
			case err == nil:
				errOut := cmd.ErrOrStderr()
				opts.ConsolePolicyDir = consolePolicyDir(logPath)
				opts.Link = link.New(lc, link.Options{Version: Version, ConsoleDir: opts.ConsolePolicyDir,
					LogPath: logPath, Status: func(s string) { fmt.Fprintln(errOut, s) }})
				fmt.Fprintf(errOut, "console: %s, workspace %s\n", lc.Base(), lc.WorkspaceID)
			case !errors.Is(err, os.ErrNotExist):
				return ioErr(fmt.Errorf("console connection: %w (fix it, run 'authsec-cli disconnect', or pass --no-connect)", err))
			}
		}
		err = daemon.Run(ctx, opts)
		if err != nil {
			return ioErr(err)
		}
		return nil
	}
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Follow agents in the background and log what they do",
		Long: `Runs the sensor in the foreground: it follows every running AI agent and logs
the programs it starts, the files it opens and where it connects (see
'authsec-cli access').

On Linux as root it uses eBPF (kernel 5.8+ with BTF). Otherwise it polls the
process table and logs agents and their connections, but not files.`,
		Example: `  sudo authsec-cli daemon                 # foreground, Ctrl-C to stop
  sudo authsec-cli daemon install         # systemd service, starts at boot
  authsec-cli daemon status`,
		Args: cobra.NoArgs,
		RunE: run,
	}
	f := cmd.PersistentFlags()
	f.StringVar(&logPath, "log", "", "event log (default /var/lib/authsec/events.jsonl as root, else ~/.local/state/authsec/events.jsonl)")
	runCmd := &cobra.Command{Use: "run", Short: "Run in the foreground (what the service runs)", Args: cobra.NoArgs, RunE: run}
	for _, c := range []*cobra.Command{cmd, runCmd} {
		c.Flags().BoolVar(&noEBPF, "no-ebpf", false, "poll the process table instead of using eBPF")
		c.Flags().DurationVar(&poll, "poll", 5*time.Second, "poll interval without eBPF")
		c.Flags().StringVar(&policies, "policies", "", "policy folder to apply (default /etc/authsec/policies, else ./policies; \"none\" to only observe)")
		c.Flags().BoolVar(&noEnforce, "no-enforce", false, "log what policies would block, block nothing")
		c.Flags().BoolVar(&noDetect, "no-detect", false, "turn off threat detections (ARTEX, offensive tools, connection fan-out)")
		c.Flags().BoolVar(&quarantineThreats, "quarantine-threats", false, "quarantine an agent on a high-severity detection")
		c.Flags().StringArrayVar(&siemSpecs, "siem", nil, "forward records to a SIEM: syslog+udp|tcp|tls://host:port, webhook+https://..., splunk+https://host:8088 (repeatable)")
		c.Flags().StringVar(&siemTokenEnv, "siem-token-env", "AUTHSEC_SIEM_TOKEN", "environment variable holding the SIEM token (the name, never the value)")
		c.Flags().BoolVar(&siemInsecure, "siem-insecure", false, "do not verify the SIEM's TLS certificate (testing only)")
		c.Flags().BoolVar(&noConnect, "no-connect", false, "do not use the console connection saved by 'authsec-cli connect'")
		c.Flags().StringVar(&collectorState, "collector-state", "", "run as the enrolled v2 collector kept in this folder (see 'authsec-cli collector')")
	}

	cmd.AddCommand(runCmd,
		newDaemonInstallCmd(&logPath),
		&cobra.Command{Use: "uninstall", Short: "Stop and remove the systemd service (root); the log is kept", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error { return uninstallService(cmd.OutOrStdout()) }},
		&cobra.Command{Use: "status", Short: "Show whether the service runs and what it logged", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error { return serviceStatus(cmd.OutOrStdout(), logPath) }},
	)
	return cmd
}

// unit is the systemd service. CPU and memory are capped: the sensor must
// never be the thing slowing a machine down.
func newDaemonInstallCmd(logPath *string) *cobra.Command {
	var (
		siemSpecs                   []string
		tokenEnv                    string
		quarantineThreats, noDetect bool
	)
	c := &cobra.Command{
		Use:   "install",
		Short: "Install and start the systemd service (root)",
		Long: `Installs authsec-cli as a systemd service reading /etc/authsec/policies.
A SIEM token goes in /etc/authsec/siem.env (root, mode 0600) as
NAME=value, with NAME given by --siem-token-env; it is never written into the
unit.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var extra []string
			for _, spec := range siemSpecs {
				if !(strings.HasPrefix(spec, "syslog+") || strings.HasPrefix(spec, "webhook+") || strings.HasPrefix(spec, "splunk+")) {
					return usageErr("--siem: use syslog+udp|tcp|tls://, webhook+https:// or splunk+https://")
				}
				extra = append(extra, "--siem", spec)
			}
			if tokenEnv != "" {
				extra = append(extra, "--siem-token-env", tokenEnv)
			}
			if quarantineThreats {
				extra = append(extra, "--quarantine-threats")
			}
			if noDetect {
				extra = append(extra, "--no-detect")
			}
			return installService(cmd.OutOrStdout(), *logPath, extra)
		},
	}
	c.Flags().StringArrayVar(&siemSpecs, "siem", nil, "forward records to a SIEM (repeatable; see 'daemon --help')")
	c.Flags().StringVar(&tokenEnv, "siem-token-env", "", "name of the token variable set in /etc/authsec/siem.env")
	c.Flags().BoolVar(&quarantineThreats, "quarantine-threats", false, "quarantine an agent on a high-severity detection")
	c.Flags().BoolVar(&noDetect, "no-detect", false, "turn off threat detections")
	return c
}

// systemdQuote quotes one ExecStart argument.
func systemdQuote(a string) string {
	if a != "" && !strings.ContainsAny(a, " \t\"'\\$%;") {
		return a
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "$", "$$", "%", "%%")
	return `"` + r.Replace(a) + `"`
}

func unit(bin, logPath string, extra []string) string {
	var args []string
	for _, a := range extra {
		args = append(args, systemdQuote(a))
	}
	tail := ""
	if len(args) > 0 {
		tail = " " + strings.Join(args, " ")
	}
	return fmt.Sprintf(`[Unit]
Description=AuthSec Agent Kit (finds AI agents, logs what they do, enforces their policies)
Documentation=https://authsec.ai
After=network-online.target

[Service]
ExecStart=%s daemon run --log %s --policies /etc/authsec/policies%s
EnvironmentFile=-/etc/authsec/siem.env
Restart=on-failure
RestartSec=5
Nice=10
MemoryMax=128M
CPUQuota=20%%
RuntimeDirectory=authsec
ProtectHome=read-only
ProtectSystem=full
# The folders the daemon writes: its log and state, and the connection
# folder (the console's actuation credential). '-' keeps a missing one from
# stopping the service (status 226/NAMESPACE); install creates them.
ReadWritePaths=-%s -%s /sys/fs/cgroup /run/authsec

[Install]
WantedBy=multi-user.target
`, bin, logPath, tail, path.Dir(filepath.ToSlash(logPath)), connDir)
}

// connDir is the root connection folder (link.Dir as root).
const connDir = "/etc/authsec"

func installService(w io.Writer, logPath string, extra []string) error {
	if runtime.GOOS != "linux" {
		return usageErr("daemon install supports systemd (Linux) for now; run 'authsec-cli daemon' under your service manager")
	}
	if os.Geteuid() != 0 {
		return usageErr("daemon install needs root: sudo authsec-cli daemon install")
	}
	if logPath == "" {
		logPath = "/var/lib/authsec/events.jsonl"
	}
	self, err := os.Executable()
	if err != nil {
		return ioErr(err)
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return ioErr(err)
	}
	if self != installPath {
		if err := copyFile(self, installPath, 0o755); err != nil {
			return ioErr(fmt.Errorf("copy binary to %s: %w", installPath, err))
		}
		fmt.Fprintf(w, "installed %s\n", installPath)
	}
	// The unit makes these writable; systemd refuses to start a service whose
	// ReadWritePaths are missing, so they exist before it starts.
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{{filepath.Dir(logPath), 0o755}, {connDir, 0o755}, {SystemPolicyDir, 0o755}} {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return ioErr(fmt.Errorf("create %s: %w", d.path, err))
		}
	}
	if err := os.WriteFile(unitPath, []byte(unit(installPath, logPath, extra)), 0o644); err != nil {
		return ioErr(err)
	}
	fmt.Fprintf(w, "wrote %s\n", unitPath)
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", unitName}} {
		if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
			return ioErr(fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, out))
		}
	}
	fmt.Fprintf(w, "started %s; events go to %s\nCheck it with: authsec-cli daemon status\n", unitName, logPath)
	return nil
}

func uninstallService(w io.Writer) error {
	if os.Geteuid() != 0 {
		return usageErr("daemon uninstall needs root")
	}
	_ = exec.Command("systemctl", "disable", "--now", unitName).Run()
	if err := os.Remove(unitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return ioErr(err)
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	fmt.Fprintf(w, "removed %s (the event log is kept)\n", unitName)
	return nil
}

func serviceStatus(w io.Writer, logPath string) error {
	state := "not installed"
	if _, err := os.Stat(unitPath); err == nil {
		out, _ := exec.Command("systemctl", "is-active", unitName).Output()
		state = strings.TrimSpace(string(out))
	}
	fmt.Fprintf(w, "service:   %s (%s)\n", unitName, state)
	if logPath == "" {
		logPath = events.ReadablePath()
	}
	recs, err := events.Read(logPath, time.Now().Add(-24*time.Hour))
	if err != nil {
		fmt.Fprintf(w, "event log: %v\n", err)
		return nil
	}
	count := map[string]int{}
	var mode, last string
	for _, r := range recs {
		count[r.Type]++
		if r.Type == events.Sensor && (strings.HasPrefix(r.Note, "started") || r.Note == "stopped") {
			mode = r.Note // "started (ebpf)", "started (polling)" or "stopped"
		}
		last = r.Time.Local().Format("2006-01-02 15:04:05")
	}
	fmt.Fprintf(w, "event log: %s\nsensor:    %s\nlast 24h:  %d agents started, %d programs, %d files, %d connections (last event %s)\n",
		logPath, mode, count[events.AgentStarted], count[events.Process], count[events.File], count[events.Network], last)
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	tmp := dst + ".new"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
