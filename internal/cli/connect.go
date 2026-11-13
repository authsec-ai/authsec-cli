package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/events"
	"github.com/authsec-ai/authsec-cli/internal/link"
	"github.com/spf13/cobra"
)

// consolePolicyDir is where the daemon keeps the policies saved in the
// console, next to its log.
func consolePolicyDir(logPath string) string {
	return filepath.Join(filepath.Dir(logPath), "console-policies")
}

func readToken(stdin io.Reader, fromStdin bool, file string) (string, error) {
	switch {
	case fromStdin && file != "":
		return "", usageErr("give the token with --token-stdin or --token-file, not both")
	case fromStdin:
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		return strings.TrimSpace(line), nil
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return "", ioErr(err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return strings.TrimSpace(os.Getenv("AUTHSEC_INGEST_TOKEN")), nil
}

func newConnectCmd() *cobra.Command {
	var (
		cfg            link.Config
		tokenStdin     bool
		tokenFile      string
		noCheck, force bool
	)
	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Connect this machine to the AuthSec console",
		Long: `Saves the control plane connection the daemon uses: the API URL, the
workspace id and an ingest token, all shown in the console under
Add > Machine. The token is read from --token-stdin, --token-file or
AUTHSEC_INGEST_TOKEN, never from the command line, and kept in
` + link.Path() + ` (mode 0600).

Once connected, the daemon registers the machine, reports its agents, sends
decisions and detections to the console's logs, applies the policies saved
in the console (they win over a local policy for the same agent) and carries
out quarantine and release from the console once enforcement is turned on
there.`,
		Example: `  sudo authsec-cli connect --url https://api.authsec.ai --workspace <id> --token-stdin
  sudo systemctl restart authsec-agent-kit
  authsec-cli connect status`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tok, err := readToken(cmd.InOrStdin(), tokenStdin, tokenFile)
			if err != nil {
				return err
			}
			cfg.IngestToken = tok
			if err := cfg.Validate(); err != nil {
				return usageErr("%v", err)
			}
			path := link.Path()
			if _, err := os.Stat(path); err == nil && !force {
				return usageErr("%s exists: run 'authsec-cli disconnect' first, or add --force", path)
			}
			out := cmd.OutOrStdout()
			if !noCheck {
				ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
				defer cancel()
				reg, err := link.New(&cfg, link.Options{Version: Version}).Register(ctx)
				if err != nil {
					return ioErr(fmt.Errorf("the control plane refused the connection: %w", err))
				}
				fmt.Fprintf(out, "registered as machine %s (source %s)\n", hostLabel(&cfg), reg.SourceID)
			}
			if err := link.Save(path, &cfg); err != nil {
				return ioErr(err)
			}
			fmt.Fprintf(out, "saved %s\n", path)
			if os.Geteuid() == 0 {
				fmt.Fprintln(out, "restart the daemon to use it: sudo systemctl restart authsec-agent-kit")
			} else {
				fmt.Fprintln(out, "note: a daemon running as root reads /etc/authsec/connect.json; run connect with sudo for it")
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.URL, "url", "", "control plane API URL, e.g. https://api.authsec.ai")
	f.StringVar(&cfg.WorkspaceID, "workspace", "", "workspace id")
	f.StringVar(&cfg.Name, "name", "", "name shown in the console (default: host name)")
	f.BoolVar(&tokenStdin, "token-stdin", false, "read the ingest token from standard input")
	f.StringVar(&tokenFile, "token-file", "", "read the ingest token from a file")
	f.BoolVar(&noCheck, "no-check", false, "save without contacting the control plane")
	f.BoolVar(&force, "force", false, "replace an existing connection")

	cmd.AddCommand(&cobra.Command{
		Use: "status", Short: "Show the saved connection (never the token)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			c, err := link.Load(link.Path())
			if errors.Is(err, os.ErrNotExist) {
				fmt.Fprintln(out, "not connected ("+link.Path()+" does not exist)")
				return nil
			}
			if err != nil {
				return ioErr(err)
			}
			fmt.Fprintf(out, "url:        %s\nworkspace:  %s\nmachine:    %s\ntoken:      %s…\nfile:       %s\n",
				c.Base(), c.WorkspaceID, hostLabel(c), prefix(c.IngestToken, 8), link.Path())
			if _, err := os.Stat(filepath.Join(link.Dir(), "actuation.token")); err == nil {
				fmt.Fprintln(out, "enforcement from the console: credential present")
			}
			return nil
		},
	})
	return cmd
}

func newDisconnectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disconnect",
		Short: "Forget the console connection (the console keeps the machine's history)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			removed := 0
			for _, p := range []string{link.Path(), filepath.Join(link.Dir(), "actuation.token")} {
				if err := os.Remove(p); err == nil {
					removed++
					fmt.Fprintln(out, "removed", p)
				} else if !errors.Is(err, os.ErrNotExist) {
					return ioErr(err)
				}
			}
			dir := consolePolicyDir(events.DefaultPath())
			if ents, err := os.ReadDir(dir); err == nil && len(ents) > 0 {
				if err := os.RemoveAll(dir); err != nil {
					return ioErr(err)
				}
				fmt.Fprintln(out, "removed console policies", dir)
			}
			if removed == 0 {
				fmt.Fprintln(out, "not connected")
				return nil
			}
			fmt.Fprintln(out, "restart the daemon to stop using it: sudo systemctl restart authsec-agent-kit")
			return nil
		},
	}
}

func hostLabel(c *link.Config) string {
	if c.Name != "" {
		return c.Name
	}
	h, _ := os.Hostname()
	return h
}

func prefix(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return ""
}
