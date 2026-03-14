package reports

import (
	"fmt"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/session"
)

const proReportsMessage = "rich report presentation is not enabled in this OSS build"

// ReportConfig holds configuration options for report generation
type ReportConfig struct {
	IncludeRawOutput       bool `json:"include_raw_output"`
	IncludeChatHistory     bool `json:"include_chat_history"`
	GroupBySeverity        bool `json:"group_by_severity"`
	IncludeRecommendations bool `json:"include_recommendations"`
	CompactMode            bool `json:"compact_mode"`
}

// ExportHTML exports a session to HTML format
func ExportHTML(sess *session.Session, outputPath string) error {
	if sess == nil {
		return fmt.Errorf("session cannot be nil")
	}
	return fmt.Errorf("%s", proReportsMessage)
}

// ExportMarkdown exports a session to Markdown format
func ExportMarkdown(sess *session.Session, outputPath string) error {
	if sess == nil {
		return fmt.Errorf("session cannot be nil")
	}
	return fmt.Errorf("%s", proReportsMessage)
}

// ExportPDF exports a session to PDF format
func ExportPDF(sess *session.Session, outputPath string) error {
	if sess == nil {
		return fmt.Errorf("session cannot be nil")
	}
	return fmt.Errorf("%s", proReportsMessage)
}

// ExportHTMLWithConfig exports a session to HTML with custom configuration
func ExportHTMLWithConfig(sess *session.Session, outputPath string, config *ReportConfig) error {
	if sess == nil {
		return fmt.Errorf("session cannot be nil")
	}
	return fmt.Errorf("%s", proReportsMessage)
}

// ExportMarkdownWithConfig exports a session to Markdown with custom configuration
func ExportMarkdownWithConfig(sess *session.Session, outputPath string, config *ReportConfig) error {
	if sess == nil {
		return fmt.Errorf("session cannot be nil")
	}
	return fmt.Errorf("%s", proReportsMessage)
}
