package ui

import (
	"github.com/fatih/color"
)

// Color is an alias for fatih/color.Color for easy imports
type Color = color.Color

var (
	// Kali Linux color scheme
	Primary   *color.Color
	Secondary *color.Color
	Success   *color.Color
	Warning   *color.Color
	Danger    *color.Color
	Info      *color.Color
	Muted     *color.Color
	Accent    *color.Color

	// Status indicators
	IndicatorSuccess string
	IndicatorInfo    string
	IndicatorWarning string
	IndicatorError   string
)

func init() {
	initColors()
}

func initColors() {
	Primary = color.New(color.FgGreen, color.Bold)
	Secondary = color.New(color.FgCyan)
	Success = color.New(color.FgGreen)
	Warning = color.New(color.FgYellow)
	Danger = color.New(color.FgRed, color.Bold)
	Info = color.New(color.FgCyan)
	Muted = color.New(color.FgHiBlack)
	Accent = color.New(color.FgHiGreen)

	IndicatorSuccess = Success.Sprint("[+]")
	IndicatorInfo = Info.Sprint("[*]")
	IndicatorWarning = Warning.Sprint("[!]")
	IndicatorError = Danger.Sprint("[-]")
}

// DisableColors turns off color output
func DisableColors() {
	color.NoColor = true
}

// Banner returns the Zypheron ASCII banner
func Banner() string {
	header := Primary.Sprint(`
╔══════════════════════════════════════════════════════════════════════╗
║  ███████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗  ██████╗ ██╗   ██╗ ║ 
║  ╚══███╔╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗██╔═══██╗████╗ ██║ ║  
║    ███╔╝  ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝██║   ██║██╔██╗██║ ║ 
║   ███╔╝    ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██║   ██║██║╚████║ ║  
║  ███████╗   ██║   ██║     ██║  ██║███████╗██║  ██║╚██████╔╝██║ ╚███║ ║ 
║  ╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚══╝ ║ 
╚══════════════════════════════════════════════════════════════════════╝
    AI-Powered Penetration Testing Platform
`)

	snake := Danger.Sprint(`
             /^\\/^\\
           _|__|  O|
  \\/     /~     \\_/ \\
   \\____|__________/  \\
          \\_______      \\
                   \     \\                 \\
                    |     |                  \\
                   /      /                    \\
                  /     /                       \\\\
                /      /                         \\ \\
               /     /                            \\  \\
             /     /             _----_            \\   \\
            /     /           _-~      ~-_         |   |
           (      (        _-~    _--_    ~-_     _/   |
            \\      ~-____-~    _-~    ~-_    ~-_-~    /
              ~-_           _-~          ~-_       _-~   
                 ~--______-~                ~-___-~
`) + Danger.Sprint(" (snake)")

	return header + "\n" + snake
}

// Success formats a success message
func SuccessMsg(msg string) string {
	return Success.Sprintf("%s %s", IndicatorSuccess, msg)
}

// Info formats an info message
func InfoMsg(msg string) string {
	return Info.Sprintf("%s %s", IndicatorInfo, msg)
}

// Warning formats a warning message
func WarningMsg(msg string) string {
	return Warning.Sprintf("%s %s", IndicatorWarning, msg)
}

// Error formats an error message
func Error(msg string) string {
	return Danger.Sprintf("%s %s", IndicatorError, msg)
}

// Target formats target information
func Target(name, value string) string {
	return Accent.Sprintf("%s: ", name) + Primary.Sprint(value)
}

// Separator returns a separator line
func Separator(length int) string {
	sep := ""
	for i := 0; i < length; i++ {
		sep += "─"
	}
	return Muted.Sprint(sep)
}

// Box creates a box around text
func Box(title string) (string, string) {
	titleLen := len(title)
	padding := 60 - titleLen - 6

	top := Primary.Sprint("╔═══ ") + Primary.Sprint(title) + Primary.Sprint(" ")
	for i := 0; i < padding; i++ {
		top += Primary.Sprint("═")
	}
	top += Primary.Sprint("╗")

	bottom := Primary.Sprint("╚")
	for i := 0; i < 58; i++ {
		bottom += Primary.Sprint("═")
	}
	bottom += Primary.Sprint("╝")

	return top, bottom
}
