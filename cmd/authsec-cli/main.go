// Command authsec-cli finds the AI agents on a machine and what they may do.
package main

import (
	"os"

	"github.com/authsec-ai/authsec-cli/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
