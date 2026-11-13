package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/authsec-ai/authsec-cli/internal/daemon"
	"github.com/authsec-ai/authsec-cli/internal/events"
)

const (
	unitName    = "authsec-agent-kit.service"
	unitPath    = "/etc/systemd/system/" + unitName
	installPath = "/usr/local/bin/authsec-cli"
)

func newDaemonCmd() *cobra.Command {
	var (
		logPath, policies string
		noEBPF, noEnforce bool
		poll              time.Duration
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
		err := daemon.Run(ctx, daemon.Options{LogPath: logPath, PolicyDir: policies, NoEBPF: noEBPF, NoEnforce: noEnforce, Poll: poll, Status: cmd.ErrOrStderr()})
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
	}

	cmd.AddCommand(runCmd,
		&cobra.Command{Use: "install", Short: "Install and start the systemd service (root)", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error { return installService(cmd.OutOrStdout(), logPath) }},
		&cobra.Command{Use: "uninstall", Short: "Stop and remove the systemd service (root); the log is kept", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error { return uninstallService(cmd.OutOrStdout()) }},
		&cobra.Command{Use: "status", Short: "Show whether the service runs and what it logged", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error { return serviceStatus(cmd.OutOrStdout(), logPath) }},
	)
	return cmd
}

// unit is the systemd service. CPU and memory are capped: the sensor must
// never be the thing slowing a machine down.
func unit(bin, logPath string) string {
	return fmt.Sprintf(`[Unit]
Description=AuthSec Agent Kit (finds AI agents, logs what they do, enforces their policies)
Documentation=https://authsec.ai
After=network-online.target

[Service]
ExecStart=%s daemon run --log %s --policies /etc/authsec/policies
Restart=on-failure
RestartSec=5
Nice=10
MemoryMax=128M
CPUQuota=20%%
RuntimeDirectory=authsec
ProtectHome=read-only
ProtectSystem=full
ReadWritePaths=%s /sys/fs/cgroup /run/authsec

[Install]
WantedBy=multi-user.target
`, bin, logPath, filepath.Dir(logPath))
}

func installService(w io.Writer, logPath string) error {
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
	if err := os.WriteFile(unitPath, []byte(unit(installPath, logPath)), 0o644); err != nil {
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
