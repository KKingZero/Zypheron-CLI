package platform

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Distro identifies a Linux distribution family relevant to Zypheron tooling.
type Distro string

const (
	DistroUnknown   Distro = "unknown"
	DistroKali      Distro = "kali"
	DistroParrot    Distro = "parrot"
	DistroBlackArch Distro = "blackarch"
	DistroLinux     Distro = "linux"
)

// Environment describes the current OS and security-distro context.
type Environment struct {
	IsKali       bool
	IsParrot     bool
	IsBlackArch  bool
	IsSecurityOS bool
	IsWSL        bool
	Version      string
	Distribution string
	WSLVersion   string
	Distro       Distro
	ID           string
	IDLike       []string
	PrettyName   string
}

// DetectEnvironment detects supported security Linux distributions and WSL.
func DetectEnvironment() (*Environment, error) {
	fields := readOSRelease("/etc/os-release")
	env := DetectFromOSRelease(fields, fileExists)

	env.IsWSL = isWSL()
	if env.IsWSL {
		env.Distribution = getWSLDistribution()
		env.WSLVersion = getWSLVersion()
	}

	return env, nil
}

// DetectFromOSRelease returns distro metadata from parsed os-release fields.
// The fileExists hook lets tests model distro-specific marker files.
func DetectFromOSRelease(fields map[string]string, fileExists func(string) bool) *Environment {
	env := &Environment{
		Distro:     DistroUnknown,
		ID:         strings.ToLower(fields["ID"]),
		PrettyName: fields["PRETTY_NAME"],
		Version:    firstNonEmpty(fields["VERSION"], fields["VERSION_ID"], "Unknown"),
	}
	env.IDLike = splitIDLike(fields["ID_LIKE"])
	if env.PrettyName == "" {
		env.PrettyName = env.ID
	}

	idMatches := func(values ...string) bool {
		for _, value := range values {
			if env.ID == value {
				return true
			}
			for _, like := range env.IDLike {
				if like == value {
					return true
				}
			}
		}
		return false
	}

	switch {
	case idMatches("kali") || fileExists("/etc/apt/sources.list.d/kali.list"):
		env.Distro = DistroKali
		env.IsKali = true
	case idMatches("parrot", "parrotos") || fileExists("/etc/apt/sources.list.d/parrot.list"):
		env.Distro = DistroParrot
		env.IsParrot = true
	case idMatches("blackarch") || fileExists("/etc/pacman.d/blackarch-mirrorlist"):
		env.Distro = DistroBlackArch
		env.IsBlackArch = true
	case env.ID != "":
		env.Distro = DistroLinux
	default:
		env.Distro = DistroUnknown
	}
	env.IsSecurityOS = env.IsKali || env.IsParrot || env.IsBlackArch
	return env
}

// DisplayName returns a concise user-facing distro label.
func (e *Environment) DisplayName() string {
	if e == nil {
		return "Unknown"
	}
	switch e.Distro {
	case DistroKali:
		return "Kali Linux"
	case DistroParrot:
		return "Parrot OS"
	case DistroBlackArch:
		return "BlackArch Linux"
	case DistroLinux:
		return firstNonEmpty(e.PrettyName, "Linux")
	default:
		return firstNonEmpty(e.PrettyName, "Unknown")
	}
}

// PackageManager returns the preferred package manager for the detected distro.
func (e *Environment) PackageManager() string {
	if e == nil {
		return ""
	}
	switch e.Distro {
	case DistroKali, DistroParrot:
		return "apt"
	case DistroBlackArch:
		return "pacman"
	default:
		if _, err := exec.LookPath("apt"); err == nil {
			return "apt"
		}
		if _, err := exec.LookPath("pacman"); err == nil {
			return "pacman"
		}
		if _, err := exec.LookPath("dnf"); err == nil {
			return "dnf"
		}
	}
	return ""
}

// PrintInfo prints detected environment information.
func (e *Environment) PrintInfo() {
	fmt.Println("╔═══ ENVIRONMENT DETECTED ═══════════════════════════╗")
	if e.IsSecurityOS {
		fmt.Printf("║  ✓ Security OS: %-36s║\n", e.DisplayName()+" "+e.Version)
	} else {
		fmt.Printf("║  ⚠  Security OS: %-35s║\n", "not detected")
	}
	if e.IsWSL {
		fmt.Printf("║  ℹ  WSL Environment: %-33s║\n", e.Distribution)
	}
	fmt.Println("╚════════════════════════════════════════════════════╝")
	fmt.Println()
}

func readOSRelease(path string) map[string]string {
	data, err := os.Open(path)
	if err != nil {
		return map[string]string{}
	}
	defer data.Close()

	fields := make(map[string]string)
	scanner := bufio.NewScanner(data)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		fields[key] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	return fields
}

func splitIDLike(value string) []string {
	parts := strings.Fields(strings.ToLower(value))
	if len(parts) == 0 {
		return nil
	}
	return parts
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func isWSL() bool {
	data, err := os.ReadFile("/proc/version")
	if err == nil {
		content := strings.ToLower(string(data))
		if strings.Contains(content, "microsoft") || strings.Contains(content, "wsl") {
			return true
		}
	}
	if fileExists("/proc/sys/fs/binfmt_misc/WSLInterop") {
		return true
	}
	return os.Getenv("WSL_DISTRO_NAME") != ""
}

func getWSLDistribution() string {
	if distro := os.Getenv("WSL_DISTRO_NAME"); distro != "" {
		return distro
	}
	return "Unknown"
}

func getWSLVersion() string {
	cmd := exec.Command("wsl.exe", "--version")
	output, err := cmd.Output()
	if err != nil {
		return "WSL 1"
	}
	return strings.TrimSpace(string(output))
}
