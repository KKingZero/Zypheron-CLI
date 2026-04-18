package commands

import (
	"fmt"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/kali"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
)

func printSecurityEnvironment() (*kali.Environment, error) {
	fmt.Println(ui.InfoMsg("Detecting security Linux environment..."))
	env, err := kali.DetectEnvironment()
	if err != nil {
		return nil, err
	}

	if env.IsSecurityOS {
		fmt.Println(ui.SuccessMsg(fmt.Sprintf("Running on %s %s", env.DisplayName(), env.Version)))
	} else {
		fmt.Println(ui.WarningMsg("No supported security distro detected - some tools may not be available"))
	}

	if env.IsWSL {
		fmt.Println(ui.InfoMsg(fmt.Sprintf("WSL Environment: %s", env.Distribution)))
	}

	return env, nil
}
