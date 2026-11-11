package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/authsec-ai/authsec-cli/internal/catalogue"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "authsec-cli %s (%s) · catalogue %s · %s/%s · %s\n",
				Version, Commit, catalogue.Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		},
	}
}
