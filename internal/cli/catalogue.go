package cli

import (
	"fmt"
	"runtime"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/authsec-ai/authsec-cli/internal/catalogue"
	"github.com/authsec-ai/authsec-cli/internal/collect"
)

func newCatalogueCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "catalogue",
		Short: "List every file a scan may read, per tool",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := cmd.OutOrStdout()
			goos := runtime.GOOS
			fmt.Fprintf(w, "catalogue %s", catalogue.Version)
			if !all {
				fmt.Fprintf(w, " · %s (--all for every OS)", goos)
			}
			fmt.Fprint(w, "\n\n")
			tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "TOOL\tSCOPE\tPATH\tREAD FOR")
			for _, e := range catalogue.Entries() {
				if !all && !e.On(goos) {
					continue
				}
				for _, p := range e.Paths {
					if e.Dir {
						p += "/"
					}
					if len(e.OS) > 0 && all {
						p += "  [" + strings.Join(e.OS, ",") + "]"
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", collect.DisplayName(e.Tool), e.Scope, p, e.What)
				}
			}
			tw.Flush()
			fmt.Fprintln(w, "\n{project} is each directory given with --project and each project the agents list.")
			fmt.Fprintln(w, "Files over 1 MiB are not read. Values are scrubbed before anything is kept.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "show the paths for every OS")
	return cmd
}
