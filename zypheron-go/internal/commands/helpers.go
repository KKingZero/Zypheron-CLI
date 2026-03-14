package commands

import (
    "os"

    "github.com/spf13/cobra"
    "golang.org/x/term"
)

func isInteractive(cmd *cobra.Command) bool {
    stdin := cmd.InOrStdin()
    inFile, ok := stdin.(*os.File)
    if !ok {
        return false
    }

    return term.IsTerminal(int(inFile.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}
