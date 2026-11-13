package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/authsec-ai/authsec-cli/internal/collector"
)

// LocalAlias is the collector's name in the console's enrollment command
// (`authsec-local run --enrollment-token-file F`). Run under that name,
// authsec-cli reads `run`, `enroll` and `status` as the collector's.
const LocalAlias = "authsec-local"

// AliasArgs rewrites the arguments of a binary invoked as authsec-local.
func AliasArgs(argv0 string, args []string) []string {
	if filepath.Base(argv0) != LocalAlias || len(args) == 0 {
		return args
	}
	switch args[0] {
	case "run", "enroll", "status":
		return append([]string{"collector"}, args...)
	}
	return args
}

func collectorURL(flag string) string {
	if flag != "" {
		return flag
	}
	return os.Getenv("AUTHSEC_URL")
}

func enrollIfNeeded(ctx context.Context, out func(string), url, tokenFile, dir string) error {
	if st, err := collector.LoadState(dir); err == nil {
		if tokenFile != "" {
			out(fmt.Sprintf("already enrolled as collector %s; %s is not used", st.CollectorID, tokenFile))
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return ioErr(err)
	}
	if tokenFile == "" {
		return usageErr("not enrolled: give --enrollment-token-file (from the console's Enroll collector)")
	}
	if url == "" {
		return usageErr("give the control plane with --url or AUTHSEC_URL")
	}
	tok, err := collector.ReadToken(tokenFile)
	if err != nil {
		return usageErr("%v", err)
	}
	ectx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	st, err := collector.Enroll(ectx, url, tok, dir, Version)
	if err != nil {
		return ioErr(err)
	}
	out(fmt.Sprintf("enrolled as collector %s (credential valid until %s, rotated automatically)", st.CollectorID, st.CredentialExpires.Format(time.RFC3339)))
	return nil
}

// splitCollectorFlags takes run's own flags out of args; the rest go to the
// daemon.
func splitCollectorFlags(args []string) (url, token, dir string, help bool, rest []string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, val, hasVal := strings.Cut(a, "=")
		take := func() (string, error) {
			if hasVal {
				return val, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", name)
			}
			i++
			return args[i], nil
		}
		switch name {
		case "--url":
			url, err = take()
		case "--enrollment-token-file":
			token, err = take()
		case "--state-dir":
			dir, err = take()
		case "-h", "--help":
			help = true
		default:
			rest = append(rest, a)
		}
		if err != nil {
			return
		}
	}
	return
}

func newCollectorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "collector",
		Short: "Run as an enrolled AuthSec host collector (" + LocalAlias + ")",
		Long: `Makes this machine a Linux host collector of the AuthSec control plane
(/api/iga/v2). Enroll it once with the one-time token from the console's
Enroll collector; it then reports the agents that run here and what they
do through agent-sync, and applies the runtime policy published for them:
the signed manifest is verified against the control plane's policy keys,
both artifacts against the manifest's hashes, and only the pinned
authsec.runtime.v1 template is accepted. What it applied is reported back.

The credential lasts 24 hours and is rotated automatically, signed with the
installation key kept in the state folder (0600).`,
		Example: `  sudo AUTHSEC_URL=https://api.authsec.ai authsec-cli collector run --enrollment-token-file /tmp/t
  # the console's command, unchanged:
  authsec-local run --enrollment-token-file /tmp/t
  authsec-cli collector status`,
	}

	var url, tokenFile, dir string
	enroll := &cobra.Command{
		Use:   "enroll",
		Short: "Exchange a one-time enrollment token for a collector credential",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if dir == "" {
				dir = collector.DefaultStateDir()
			}
			if tokenFile == "" {
				return usageErr("--enrollment-token-file is required")
			}
			return enrollIfNeeded(cmd.Context(), func(s string) { fmt.Fprintln(cmd.OutOrStdout(), s) }, collectorURL(url), tokenFile, dir)
		},
	}
	enroll.Flags().StringVar(&url, "url", "", "control plane API URL (default $AUTHSEC_URL)")
	enroll.Flags().StringVar(&tokenFile, "enrollment-token-file", "", "file holding the one-time enrollment token")
	enroll.Flags().StringVar(&dir, "state-dir", "", "state folder (default /var/lib/authsec-local as root)")

	run := &cobra.Command{
		Use:   "run [--url URL] [--enrollment-token-file FILE] [--state-dir DIR] [daemon flags]",
		Short: "Enroll if needed, then follow agents and sync with the control plane",
		Long: `Enrolls with --enrollment-token-file when this machine is not enrolled yet,
then runs the daemon (see 'authsec-cli daemon --help' for its flags) with the
control plane as its uplink.`,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			u, tok, d, help, rest, err := splitCollectorFlags(args)
			if err != nil {
				return usageErr("%v", err)
			}
			if help {
				return cmd.Help()
			}
			if d == "" {
				d = collector.DefaultStateDir()
			}
			errOut := cmd.ErrOrStderr()
			if err := enrollIfNeeded(cmd.Context(), func(s string) { fmt.Fprintln(errOut, s) }, collectorURL(u), tok, d); err != nil {
				return err
			}
			dm := newDaemonCmd()
			dm.SetOut(cmd.OutOrStdout())
			dm.SetErr(errOut)
			if err := dm.ParseFlags(append(rest, "--collector-state", d)); err != nil {
				return usageErr("%v", err)
			}
			if extra := dm.Flags().Args(); len(extra) > 0 {
				return usageErr("unexpected arguments %v", extra)
			}
			return dm.RunE(dm, nil)
		},
	}

	var statusDir string
	status := &cobra.Command{
		Use:   "status",
		Short: "Show the enrolled collector (never its credential)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if statusDir == "" {
				statusDir = collector.DefaultStateDir()
			}
			out := cmd.OutOrStdout()
			st, err := collector.LoadState(statusDir)
			if errors.Is(err, os.ErrNotExist) {
				fmt.Fprintf(out, "not enrolled (%s)\n", statusDir)
				return nil
			}
			if err != nil {
				return ioErr(err)
			}
			fmt.Fprintf(out, "collector:   %s\ncontrol:     %s\nworkspace:   %s\ncredential:  valid until %s (rotated automatically)\nepoch:       %s, sequence %d\npolicy keys: %d\n",
				st.CollectorID, st.URL, orDash(st.WorkspaceID), st.CredentialExpires.Format(time.RFC3339), st.Epoch, st.Sequence, len(st.PolicyKeys))
			ids := make([]string, 0, len(st.Applied))
			for w := range st.Applied {
				ids = append(ids, w)
			}
			sort.Strings(ids)
			for _, w := range ids {
				a := st.Applied[w]
				q := ""
				if a.Quarantine {
					q = ", quarantined"
				}
				fmt.Fprintf(out, "delivery:    workload %s -> %s, revision %d%s\n", w, orDash(a.AgentID), a.Revision, q)
			}
			return nil
		},
	}
	status.Flags().StringVar(&statusDir, "state-dir", "", "state folder")

	cmd.AddCommand(enroll, run, status)
	return cmd
}
