package commands

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"

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

func readLineFromInput(cmd *cobra.Command) (string, error) {
	reader := bufio.NewReader(cmd.InOrStdin())
	line, err := reader.ReadString('\n')
	if errors.Is(err, io.EOF) {
		return strings.TrimSpace(line), nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
