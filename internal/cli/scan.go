package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/authsec-ai/authsec-cli/internal/collect"
	"github.com/authsec-ai/authsec-cli/internal/finding"
	"github.com/authsec-ai/authsec-cli/internal/report"
	"github.com/authsec-ai/authsec-cli/internal/scan"
)

// onlyNames maps --only values to finding kinds.
var onlyNames = map[string]finding.Kind{
	"agents":     finding.Agent,
	"policies":   finding.Policy,
	"extensions": finding.Extension,
	"mcp":        finding.MCPServer,
	"identities": finding.Identity,
	"secrets":    finding.SecretRef,
	"unreadable": finding.Unreadable,
}

func newScanCmd() *cobra.Command {
	var (
		home     string
		projects []string
		noKnown  bool
		asJSON   bool
		only     []string
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan this machine and print what was found (sends nothing)",
		Example: `  authsec-cli scan
  authsec-cli scan --project ~/work/payments-api
  authsec-cli scan --json > report.json
  authsec-cli scan --only mcp,policies`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var kinds []finding.Kind
			for _, o := range only {
				k, ok := onlyNames[strings.TrimSpace(o)]
				if !ok {
					return usageErr("--only: unknown kind %q (use %s)", o, strings.Join(onlyList(), ", "))
				}
				kinds = append(kinds, k)
			}
			r, err := scan.Run(scan.Options{
				Home: home, Projects: projects, KnownProjects: !noKnown, Only: kinds, CLIVersion: Version,
			})
			if err != nil {
				return ioErr(err)
			}
			if asJSON {
				return report.JSON(cmd.OutOrStdout(), r)
			}
			return report.Table(cmd.OutOrStdout(), r, collect.DisplayName)
		},
	}
	f := cmd.Flags()
	f.StringVar(&home, "home", "", "home directory to scan (default: yours)")
	f.StringArrayVar(&projects, "project", nil, "also scan this project directory (repeatable)")
	f.BoolVar(&noKnown, "no-known-projects", false, "do not scan the projects the agents list (e.g. in ~/.claude.json)")
	f.BoolVar(&asJSON, "json", false, "print the full report as JSON")
	f.StringSliceVar(&only, "only", nil, "only these kinds: "+strings.Join(onlyList(), ","))
	return cmd
}

func onlyList() []string {
	return []string{"agents", "policies", "extensions", "mcp", "identities", "secrets", "unreadable"}
}
