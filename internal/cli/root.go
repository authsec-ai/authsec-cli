// Package cli holds the authsec-cli commands.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

// Set at build time (-ldflags "-X ...").
var (
	Version = "dev"
	Commit  = "none"
)

// Exit codes. Scripts and CI rely on them.
const (
	ExitOK     = 0
	ExitSignal = 1 // a --fail-on signal was found
	ExitUsage  = 2
	ExitIO     = 3
	ExitRemote = 4 // login or push failed
)

// ExitError carries an exit code up to main.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

func usageErr(format string, a ...any) error {
	return &ExitError{Code: ExitUsage, Err: fmt.Errorf(format, a...)}
}

func ioErr(err error) error { return &ExitError{Code: ExitIO, Err: err} }

// NewRoot builds the command tree. out and errOut are injected for tests.
func NewRoot(out, errOut io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:   "authsec-cli",
		Short: "Find the AI agents on this machine and what they may do",
		Long: `authsec-cli finds the AI agents on this machine (Claude Code, Cursor, Copilot,
Codex, ...), what each is allowed to do without asking, the MCP servers and
extensions they load, and the credentials they can reach.

It reads only the files listed by 'authsec-cli catalogue' and never reads or
prints a secret value. 'scan' sends nothing anywhere.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(out)
	root.SetErr(errOut)
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageErr("%v", err) })
	root.AddCommand(newAgentsCmd(), newScanCmd(), newDaemonCmd(), newAccessCmd(), newPolicyCmd(), newEnforceCmd(), newQuarantineCmd(false), newQuarantineCmd(true), newRunCmd(), newConfineCmd(), newHookCmd(), newCatalogueCmd(), newVersionCmd())
	return root
}

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	err := NewRoot(os.Stdout, os.Stderr).Execute()
	code := exitCode(err)
	if err != nil && err.Error() != "" {
		var ee *ExitError
		if errors.As(err, &ee) {
			err = ee.Err
		}
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	return code
}

// exitCode maps an error to the documented exit codes. Errors cobra raises
// itself (unknown command or flag, wrong argument count) are usage errors.
func exitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	return ExitUsage
}
