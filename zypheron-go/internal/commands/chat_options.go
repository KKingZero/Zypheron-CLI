package commands

import (
	"encoding/base64"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/aibridge"
)

const maxChatImageBytes = 20 * 1024 * 1024

var (
	openAIEffortValues = map[string]bool{"none": true, "minimal": true, "low": true, "medium": true, "high": true, "xhigh": true}
	claudeEffortValues = map[string]bool{"low": true, "medium": true, "high": true, "xhigh": true, "max": true}
	allowedImageTypes  = map[string]bool{"image/png": true, "image/jpeg": true, "image/gif": true, "image/webp": true}
)

type chatFlagOptions struct {
	Provider    string
	Interactive bool
	Temperature float64
	Images      []string
	Effort      string
	MCPLabels   []string
	MCPConfig   string
}

func defaultMCPConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "~/.config/zypheron/mcp.json"
	}
	return filepath.Join(home, ".config", "zypheron", "mcp.json")
}

func rejectCloudUnsupportedChatOptions(flags chatFlagOptions) error {
	if strings.TrimSpace(flags.Effort) != "" {
		return fmt.Errorf("--effort is not supported with provider zypheron-cloud")
	}
	if len(flags.Images) > 0 {
		return fmt.Errorf("--image is not supported with provider zypheron-cloud")
	}
	if len(flags.MCPLabels) > 0 {
		return fmt.Errorf("--mcp is not supported with provider zypheron-cloud")
	}
	return nil
}

func buildChatOptions(provider string, effort string, imageRefs []string, mcpLabels []string, mcpConfig string) (aibridge.ChatOptions, error) {
	normalizedProvider := normalizeChatProvider(provider)
	normalizedEffort := strings.ToLower(strings.TrimSpace(effort))
	if normalizedEffort != "" {
		if err := validateChatEffort(normalizedProvider, normalizedEffort); err != nil {
			return aibridge.ChatOptions{}, err
		}
	}

	images, err := prepareChatImages(normalizedProvider, imageRefs)
	if err != nil {
		return aibridge.ChatOptions{}, err
	}

	selections := make([]aibridge.MCPSelection, 0, len(mcpLabels))
	for _, label := range mcpLabels {
		label = strings.TrimSpace(label)
		if label == "" {
			return aibridge.ChatOptions{}, fmt.Errorf("--mcp labels cannot be empty")
		}
		selections = append(selections, aibridge.MCPSelection{Label: label})
	}

	options := aibridge.ChatOptions{
		Effort: normalizedEffort,
		Images: images,
		MCP:    selections,
	}
	if len(selections) > 0 {
		options.MCPConfig = expandHomePath(mcpConfig)
	}
	return options, nil
}

func normalizeChatProvider(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "", "anthropic":
		return "claude"
	case "gpt", "gpt-4":
		return "openai"
	default:
		return strings.ToLower(strings.TrimSpace(provider))
	}
}

func validateChatEffort(provider string, effort string) error {
	switch provider {
	case "openai":
		if openAIEffortValues[effort] {
			return nil
		}
		return fmt.Errorf("invalid --effort %q for OpenAI; allowed: none, minimal, low, medium, high, xhigh", effort)
	case "claude":
		if claudeEffortValues[effort] {
			return nil
		}
		return fmt.Errorf("invalid --effort %q for Claude; allowed: low, medium, high, xhigh, max", effort)
	default:
		return fmt.Errorf("--effort is not supported with provider %s", provider)
	}
}

func prepareChatImages(provider string, refs []string) ([]aibridge.ImageInput, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	if provider != "openai" && provider != "claude" {
		return nil, fmt.Errorf("--image is not supported with provider %s", provider)
	}
	images := make([]aibridge.ImageInput, 0, len(refs))
	for _, ref := range refs {
		image, err := prepareChatImage(ref)
		if err != nil {
			return nil, err
		}
		images = append(images, image)
	}
	return images, nil
}

func prepareChatImage(ref string) (aibridge.ImageInput, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return aibridge.ImageInput{}, fmt.Errorf("--image value cannot be empty")
	}
	if parsed, err := url.Parse(ref); err == nil && parsed.Scheme != "" {
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return aibridge.ImageInput{}, fmt.Errorf("image URL must use http or https: %s", ref)
		}
		if parsed.Host == "" {
			return aibridge.ImageInput{}, fmt.Errorf("image URL is missing a host: %s", ref)
		}
		return aibridge.ImageInput{Source: "url", URL: ref}, nil
	}

	path := expandHomePath(ref)
	info, err := os.Stat(path)
	if err != nil {
		return aibridge.ImageInput{}, fmt.Errorf("image file not found: %s", ref)
	}
	if info.IsDir() {
		return aibridge.ImageInput{}, fmt.Errorf("image path is a directory: %s", ref)
	}
	if info.Size() > maxChatImageBytes {
		return aibridge.ImageInput{}, fmt.Errorf("image file exceeds %d bytes: %s", maxChatImageBytes, ref)
	}

	extensionType := mime.TypeByExtension(strings.ToLower(filepath.Ext(path)))
	if !allowedImageTypes[extensionType] {
		return aibridge.ImageInput{}, fmt.Errorf("unsupported image extension for %s; use png, jpg, jpeg, gif, or webp", ref)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return aibridge.ImageInput{}, fmt.Errorf("read image file: %w", err)
	}
	detectedType := http.DetectContentType(data)
	if !allowedImageTypes[detectedType] {
		return aibridge.ImageInput{}, fmt.Errorf("unsupported image content type %q for %s", detectedType, ref)
	}
	if detectedType != extensionType {
		return aibridge.ImageInput{}, fmt.Errorf("image extension type %q does not match detected content type %q for %s", extensionType, detectedType, ref)
	}

	return aibridge.ImageInput{
		Source:     "file",
		MimeType:   detectedType,
		DataBase64: base64.StdEncoding.EncodeToString(data),
	}, nil
}

func expandHomePath(path string) string {
	if path == "~" {
		home, err := os.UserHomeDir()
		if err == nil {
			return home
		}
	}
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}
