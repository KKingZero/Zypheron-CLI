package export

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/pkg/types"
)

// SARIF schema version constants
const (
	SARIFVersion = "2.1.0"
	SchemaURI    = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

// SARIF level constants as defined in SARIF 2.1.0 specification
const (
	LevelNone    = "none"
	LevelNote    = "note"
	LevelWarning = "warning"
	LevelError   = "error"
)

// SARIFLog represents the top-level SARIF document structure
type SARIFLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single run of a static analysis tool
type SARIFRun struct {
	Tool           SARIFTool           `json:"tool"`
	Results        []SARIFResult       `json:"results"`
	Invocations    []SARIFInvocation   `json:"invocations,omitempty"`
	Artifacts      []SARIFArtifact     `json:"artifacts,omitempty"`
	ColumnKind     string              `json:"columnKind,omitempty"`
	OriginalURIRef map[string]string   `json:"originalUriBaseIds,omitempty"`
	Properties     *SARIFProperties    `json:"properties,omitempty"`
}

// SARIFTool represents information about the analysis tool
type SARIFTool struct {
	Driver SARIFToolComponent `json:"driver"`
}

// SARIFToolComponent represents a component of the analysis tool
type SARIFToolComponent struct {
	Name            string             `json:"name"`
	Version         string             `json:"version,omitempty"`
	InformationURI  string             `json:"informationUri,omitempty"`
	Organization    string             `json:"organization,omitempty"`
	SemanticVersion string             `json:"semanticVersion,omitempty"`
	Rules           []SARIFRule        `json:"rules,omitempty"`
	Properties      *SARIFProperties   `json:"properties,omitempty"`
}

// SARIFRule represents a reporting descriptor (rule) that was applied during analysis
type SARIFRule struct {
	ID                   string                `json:"id"`
	Name                 string                `json:"name,omitempty"`
	ShortDescription     *SARIFMessage         `json:"shortDescription,omitempty"`
	FullDescription      *SARIFMessage         `json:"fullDescription,omitempty"`
	Help                 *SARIFMessage         `json:"help,omitempty"`
	HelpURI              string                `json:"helpUri,omitempty"`
	DefaultConfiguration *SARIFConfiguration   `json:"defaultConfiguration,omitempty"`
	Properties           *SARIFProperties      `json:"properties,omitempty"`
}

// SARIFConfiguration represents the default configuration for a rule
type SARIFConfiguration struct {
	Level   string           `json:"level,omitempty"`
	Enabled bool             `json:"enabled,omitempty"`
	Parameters *SARIFProperties `json:"parameters,omitempty"`
}

// SARIFResult represents a single result produced by the tool
type SARIFResult struct {
	RuleID          string              `json:"ruleId"`
	RuleIndex       int                 `json:"ruleIndex,omitempty"`
	Level           string              `json:"level,omitempty"`
	Message         SARIFMessage        `json:"message"`
	Locations       []SARIFLocation     `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Fingerprints    map[string]string   `json:"fingerprints,omitempty"`
	Properties      *SARIFProperties    `json:"properties,omitempty"`
	Fixes           []SARIFFix          `json:"fixes,omitempty"`
	Rank            float64             `json:"rank,omitempty"`
	HostedViewerURI string              `json:"hostedViewerUri,omitempty"`
}

// SARIFLocation represents the location where a result was detected
type SARIFLocation struct {
	PhysicalLocation *SARIFPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []SARIFLogicalLocation `json:"logicalLocations,omitempty"`
	Message          *SARIFMessage          `json:"message,omitempty"`
	Properties       *SARIFProperties       `json:"properties,omitempty"`
}

// SARIFPhysicalLocation represents a physical location in a file
type SARIFPhysicalLocation struct {
	ArtifactLocation *SARIFArtifactLocation `json:"artifactLocation,omitempty"`
	Region           *SARIFRegion           `json:"region,omitempty"`
	ContextRegion    *SARIFRegion           `json:"contextRegion,omitempty"`
	Address          *SARIFAddress          `json:"address,omitempty"`
}

// SARIFArtifactLocation represents the location of an artifact
type SARIFArtifactLocation struct {
	URI       string `json:"uri,omitempty"`
	URIBaseID string `json:"uriBaseId,omitempty"`
	Index     int    `json:"index,omitempty"`
}

// SARIFRegion represents a region within an artifact
type SARIFRegion struct {
	StartLine      int              `json:"startLine,omitempty"`
	StartColumn    int              `json:"startColumn,omitempty"`
	EndLine        int              `json:"endLine,omitempty"`
	EndColumn      int              `json:"endColumn,omitempty"`
	CharOffset     int              `json:"charOffset,omitempty"`
	CharLength     int              `json:"charLength,omitempty"`
	ByteOffset     int              `json:"byteOffset,omitempty"`
	ByteLength     int              `json:"byteLength,omitempty"`
	Snippet        *SARIFArtifactContent `json:"snippet,omitempty"`
	Message        *SARIFMessage    `json:"message,omitempty"`
	Properties     *SARIFProperties `json:"properties,omitempty"`
}

// SARIFAddress represents a physical or virtual address
type SARIFAddress struct {
	AbsoluteAddress int              `json:"absoluteAddress,omitempty"`
	RelativeAddress int              `json:"relativeAddress,omitempty"`
	Length          int              `json:"length,omitempty"`
	Name            string           `json:"name,omitempty"`
	FullyQualifiedName string        `json:"fullyQualifiedName,omitempty"`
	OffsetFromParent int             `json:"offsetFromParent,omitempty"`
	Index           int              `json:"index,omitempty"`
	ParentIndex     int              `json:"parentIndex,omitempty"`
}

// SARIFLogicalLocation represents a logical location
type SARIFLogicalLocation struct {
	Name               string           `json:"name,omitempty"`
	FullyQualifiedName string           `json:"fullyQualifiedName,omitempty"`
	DecoratedName      string           `json:"decoratedName,omitempty"`
	Kind               string           `json:"kind,omitempty"`
	Index              int              `json:"index,omitempty"`
	ParentIndex        int              `json:"parentIndex,omitempty"`
	Properties         *SARIFProperties `json:"properties,omitempty"`
}

// SARIFMessage represents a message in various SARIF structures
type SARIFMessage struct {
	Text      string            `json:"text,omitempty"`
	Markdown  string            `json:"markdown,omitempty"`
	ID        string            `json:"id,omitempty"`
	Arguments []string          `json:"arguments,omitempty"`
	Properties *SARIFProperties `json:"properties,omitempty"`
}

// SARIFArtifact represents an artifact referenced by results
type SARIFArtifact struct {
	Location    *SARIFArtifactLocation `json:"location,omitempty"`
	Length      int                    `json:"length,omitempty"`
	Offset      int                    `json:"offset,omitempty"`
	Roles       []string               `json:"roles,omitempty"`
	MimeType    string                 `json:"mimeType,omitempty"`
	Encoding    string                 `json:"encoding,omitempty"`
	SourceLanguage string              `json:"sourceLanguage,omitempty"`
	Hashes      map[string]string      `json:"hashes,omitempty"`
	Properties  *SARIFProperties       `json:"properties,omitempty"`
}

// SARIFArtifactContent represents the contents of an artifact
type SARIFArtifactContent struct {
	Text       string           `json:"text,omitempty"`
	Binary     string           `json:"binary,omitempty"`
	Rendered   *SARIFRendered   `json:"rendered,omitempty"`
	Properties *SARIFProperties `json:"properties,omitempty"`
}

// SARIFRendered represents a rendered version of content
type SARIFRendered struct {
	Text       string           `json:"text,omitempty"`
	Markdown   string           `json:"markdown,omitempty"`
	Properties *SARIFProperties `json:"properties,omitempty"`
}

// SARIFFix represents a proposed fix for a result
type SARIFFix struct {
	Description       *SARIFMessage          `json:"description,omitempty"`
	ArtifactChanges   []SARIFArtifactChange  `json:"artifactChanges,omitempty"`
	Properties        *SARIFProperties       `json:"properties,omitempty"`
}

// SARIFArtifactChange represents a change to a single artifact
type SARIFArtifactChange struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Replacements     []SARIFReplacement    `json:"replacements"`
	Properties       *SARIFProperties      `json:"properties,omitempty"`
}

// SARIFReplacement represents a replacement in an artifact
type SARIFReplacement struct {
	DeletedRegion  SARIFRegion          `json:"deletedRegion"`
	InsertedContent *SARIFArtifactContent `json:"insertedContent,omitempty"`
	Properties     *SARIFProperties     `json:"properties,omitempty"`
}

// SARIFInvocation represents runtime information about the tool invocation
type SARIFInvocation struct {
	CommandLine          string            `json:"commandLine,omitempty"`
	Arguments            []string          `json:"arguments,omitempty"`
	ResponseFiles        []SARIFArtifactLocation `json:"responseFiles,omitempty"`
	StartTimeUTC         string            `json:"startTimeUtc,omitempty"`
	EndTimeUTC           string            `json:"endTimeUtc,omitempty"`
	ExitCode             int               `json:"exitCode,omitempty"`
	ExecutionSuccessful  bool              `json:"executionSuccessful"`
	Machine              string            `json:"machine,omitempty"`
	Account              string            `json:"account,omitempty"`
	ProcessID            int               `json:"processId,omitempty"`
	WorkingDirectory     *SARIFArtifactLocation `json:"workingDirectory,omitempty"`
	EnvironmentVariables map[string]string `json:"environmentVariables,omitempty"`
	Properties           *SARIFProperties  `json:"properties,omitempty"`
}

// SARIFProperties represents a property bag for additional metadata
type SARIFProperties struct {
	Tags []string               `json:"tags,omitempty"`
	Data map[string]interface{} `json:"-"`
}

// MarshalJSON implements custom JSON marshaling for SARIFProperties
func (p *SARIFProperties) MarshalJSON() ([]byte, error) {
	if p == nil {
		return []byte("null"), nil
	}

	result := make(map[string]interface{})
	if len(p.Tags) > 0 {
		result["tags"] = p.Tags
	}
	for k, v := range p.Data {
		result[k] = v
	}
	return json.Marshal(result)
}

// UnmarshalJSON implements custom JSON unmarshaling for SARIFProperties
func (p *SARIFProperties) UnmarshalJSON(data []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	p.Data = make(map[string]interface{})
	for k, v := range raw {
		if k == "tags" {
			if tags, ok := v.([]interface{}); ok {
				p.Tags = make([]string, len(tags))
				for i, tag := range tags {
					if s, ok := tag.(string); ok {
						p.Tags[i] = s
					}
				}
			}
		} else {
			p.Data[k] = v
		}
	}
	return nil
}

// SARIFExporter handles exporting scan results to SARIF format
type SARIFExporter struct {
	toolName       string
	toolVersion    string
	informationURI string
	organization   string
	rules          map[string]*SARIFRule
	results        []SARIFResult
	invocations    []SARIFInvocation
	artifacts      []SARIFArtifact
	properties     *SARIFProperties
}

// NewSARIFExporter creates a new SARIF exporter instance
func NewSARIFExporter(toolName, toolVersion string) *SARIFExporter {
	return &SARIFExporter{
		toolName:       toolName,
		toolVersion:    toolVersion,
		informationURI: "https://github.com/KKingZero/Cobra-AI/zypheron-go",
		organization:   "Zypheron Security",
		rules:          make(map[string]*SARIFRule),
		results:        make([]SARIFResult, 0),
		invocations:    make([]SARIFInvocation, 0),
		artifacts:      make([]SARIFArtifact, 0),
		properties:     &SARIFProperties{Data: make(map[string]interface{})},
	}
}

// SetInformationURI sets the URI for tool information
func (e *SARIFExporter) SetInformationURI(uri string) {
	e.informationURI = uri
}

// SetOrganization sets the organization name
func (e *SARIFExporter) SetOrganization(org string) {
	e.organization = org
}

// AddProperty adds a custom property to the run
func (e *SARIFExporter) AddProperty(key string, value interface{}) {
	if e.properties == nil {
		e.properties = &SARIFProperties{Data: make(map[string]interface{})}
	}
	e.properties.Data[key] = value
}

// AddInvocation adds an invocation record to the run
func (e *SARIFExporter) AddInvocation(inv SARIFInvocation) {
	e.invocations = append(e.invocations, inv)
}

// AddResult adds a scan finding as a SARIF result
func (e *SARIFExporter) AddResult(vuln types.Vulnerability) error {
	// Get or create rule
	ruleID := e.getRuleID(vuln)
	if _, exists := e.rules[ruleID]; !exists {
		e.rules[ruleID] = e.createRule(vuln)
	}

	// Map severity to SARIF level
	level := e.mapSeverityToLevel(vuln.Severity)

	// Create message
	message := SARIFMessage{
		Text: vuln.Description,
	}

	// Create result
	result := SARIFResult{
		RuleID:  ruleID,
		Level:   level,
		Message: message,
		PartialFingerprints: e.generateFingerprints(vuln),
		Properties: &SARIFProperties{
			Data: make(map[string]interface{}),
		},
	}

	// Add rank based on CVSS score
	if vuln.CVSSScore != nil {
		result.Rank = *vuln.CVSSScore * 10 // Normalize to 0-100
		result.Properties.Data["cvss_score"] = *vuln.CVSSScore
	}

	// Add CVE ID if available
	if vuln.CVEID != nil {
		result.Properties.Data["cve_id"] = *vuln.CVEID
	}

	// Add exploit availability
	if vuln.ExploitAvailable {
		result.Properties.Data["exploit_available"] = true
		result.Properties.Tags = append(result.Properties.Tags, "exploit-available")
	}

	// Add references
	if len(vuln.References) > 0 {
		result.Properties.Data["references"] = vuln.References
	}

	// Add remediation if available
	if vuln.Remediation != nil && *vuln.Remediation != "" {
		result.Properties.Data["remediation"] = *vuln.Remediation
	}

	// Create location if host/port information is available
	if vuln.Host != nil || vuln.Port != nil {
		location := SARIFLocation{
			Properties: &SARIFProperties{
				Data: make(map[string]interface{}),
			},
		}

		if vuln.Host != nil {
			location.Properties.Data["host"] = *vuln.Host
		}

		if vuln.Port != nil {
			location.Properties.Data["port"] = *vuln.Port
		}

		result.Locations = []SARIFLocation{location}
	}

	e.results = append(e.results, result)
	return nil
}

// AddResultFromScanResult adds multiple results from a ScanResult
func (e *SARIFExporter) AddResultFromScanResult(scanResult *types.ScanResult) error {
	// Add invocation information
	invocation := SARIFInvocation{
		StartTimeUTC:        scanResult.Timestamp.UTC().Format(time.RFC3339),
		EndTimeUTC:          scanResult.Timestamp.Add(time.Duration(scanResult.Duration * float64(time.Second))).UTC().Format(time.RFC3339),
		ExecutionSuccessful: scanResult.Success,
		Properties: &SARIFProperties{
			Data: map[string]interface{}{
				"target":    scanResult.Target,
				"tool":      scanResult.Tool,
				"ports":     scanResult.Ports,
				"scan_id":   scanResult.ID,
			},
		},
	}

	if !scanResult.Success && scanResult.ErrorMessage != "" {
		invocation.ExitCode = 1
		invocation.Properties.Data["error_message"] = scanResult.ErrorMessage
	}

	e.AddInvocation(invocation)

	// Add scan metadata as properties
	e.AddProperty("scan_target", scanResult.Target)
	e.AddProperty("scan_tool", scanResult.Tool)
	e.AddProperty("scan_id", scanResult.ID)
	e.AddProperty("scan_timestamp", scanResult.Timestamp.Format(time.RFC3339))

	if scanResult.AIAnalysis != "" {
		e.AddProperty("ai_analysis", scanResult.AIAnalysis)
	}

	// Add all vulnerabilities
	for _, vuln := range scanResult.Vulnerabilities {
		if err := e.AddResult(vuln); err != nil {
			return fmt.Errorf("failed to add vulnerability %s: %w", vuln.ID, err)
		}
	}

	return nil
}

// Export generates and returns the SARIF JSON document
func (e *SARIFExporter) Export() ([]byte, error) {
	// Build rules array
	rules := make([]SARIFRule, 0, len(e.rules))
	for _, rule := range e.rules {
		rules = append(rules, *rule)
	}

	// Create SARIF log structure
	sarifLog := SARIFLog{
		Version: SARIFVersion,
		Schema:  SchemaURI,
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFToolComponent{
						Name:            e.toolName,
						Version:         e.toolVersion,
						InformationURI:  e.informationURI,
						Organization:    e.organization,
						SemanticVersion: e.toolVersion,
						Rules:           rules,
					},
				},
				Results:     e.results,
				Invocations: e.invocations,
				Artifacts:   e.artifacts,
				ColumnKind:  "utf16CodeUnits", // Standard for most tools
				Properties:  e.properties,
			},
		},
	}

	// Marshal to JSON with proper formatting
	jsonData, err := json.MarshalIndent(sarifLog, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SARIF to JSON: %w", err)
	}

	return jsonData, nil
}

// ExportToFile exports the SARIF document to a file
func (e *SARIFExporter) ExportToFile(path string) error {
	// Generate SARIF JSON
	jsonData, err := e.Export()
	if err != nil {
		return fmt.Errorf("failed to export SARIF: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Write to file
	if err := os.WriteFile(path, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write SARIF file %s: %w", path, err)
	}

	return nil
}

// mapSeverityToLevel maps vulnerability severity to SARIF level
func (e *SARIFExporter) mapSeverityToLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return LevelError
	case "medium":
		return LevelWarning
	case "low":
		return LevelNote
	case "info", "informational":
		return LevelNote
	default:
		return LevelWarning
	}
}

// getRuleID generates a rule ID from a vulnerability
func (e *SARIFExporter) getRuleID(vuln types.Vulnerability) string {
	// Use CVE ID if available
	if vuln.CVEID != nil && *vuln.CVEID != "" {
		return *vuln.CVEID
	}

	// Use vulnerability ID if available
	if vuln.ID != "" {
		return vuln.ID
	}

	// Generate a rule ID based on title
	ruleID := strings.ToLower(vuln.Title)
	ruleID = strings.ReplaceAll(ruleID, " ", "-")
	ruleID = strings.ReplaceAll(ruleID, "_", "-")

	// Remove special characters
	var cleaned strings.Builder
	for _, r := range ruleID {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			cleaned.WriteRune(r)
		}
	}

	return cleaned.String()
}

// createRule creates a SARIF rule from a vulnerability
func (e *SARIFExporter) createRule(vuln types.Vulnerability) *SARIFRule {
	rule := &SARIFRule{
		ID:   e.getRuleID(vuln),
		Name: vuln.Title,
		ShortDescription: &SARIFMessage{
			Text: vuln.Title,
		},
		FullDescription: &SARIFMessage{
			Text: vuln.Description,
		},
		DefaultConfiguration: &SARIFConfiguration{
			Level:   e.mapSeverityToLevel(vuln.Severity),
			Enabled: true,
		},
		Properties: &SARIFProperties{
			Data: map[string]interface{}{
				"severity": vuln.Severity,
			},
		},
	}

	// Add help information if remediation is available
	if vuln.Remediation != nil && *vuln.Remediation != "" {
		rule.Help = &SARIFMessage{
			Text: *vuln.Remediation,
		}
	}

	// Add CVSS score
	if vuln.CVSSScore != nil {
		rule.Properties.Data["cvss_score"] = *vuln.CVSSScore
	}

	// Add CVE ID
	if vuln.CVEID != nil {
		rule.Properties.Data["cve_id"] = *vuln.CVEID
	}

	// Add references as help URI (use first reference if available)
	if len(vuln.References) > 0 {
		rule.HelpURI = vuln.References[0]
		rule.Properties.Data["references"] = vuln.References
	}

	// Add security tags
	tags := []string{"security"}
	if vuln.ExploitAvailable {
		tags = append(tags, "exploit-available")
	}
	rule.Properties.Tags = tags

	return rule
}

// generateFingerprints generates fingerprints for deduplication
func (e *SARIFExporter) generateFingerprints(vuln types.Vulnerability) map[string]string {
	fingerprints := make(map[string]string)

	// Primary fingerprint based on CVE ID or vulnerability ID
	if vuln.CVEID != nil && *vuln.CVEID != "" {
		fingerprints["cve"] = *vuln.CVEID
		fingerprints["primary"] = *vuln.CVEID
	} else if vuln.ID != "" {
		fingerprints["vulnerability_id"] = vuln.ID
		fingerprints["primary"] = vuln.ID
	}

	// Location-based fingerprint
	if vuln.Host != nil && vuln.Port != nil {
		locationKey := fmt.Sprintf("%s:%d", *vuln.Host, *vuln.Port)
		fingerprints["location"] = hashString(locationKey)
	} else if vuln.Host != nil {
		fingerprints["location"] = hashString(*vuln.Host)
	}

	// Content-based fingerprint (title + severity)
	contentKey := fmt.Sprintf("%s:%s", vuln.Title, vuln.Severity)
	fingerprints["content"] = hashString(contentKey)

	// If no primary fingerprint, use content hash
	if _, hasPrimary := fingerprints["primary"]; !hasPrimary {
		fingerprints["primary"] = fingerprints["content"]
	}

	return fingerprints
}

// hashString generates a SHA-256 hash of a string
func hashString(s string) string {
	hash := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", hash)
}

// ExportScanResultToSARIF is a convenience function to export a scan result to SARIF format
func ExportScanResultToSARIF(scanResult *types.ScanResult, outputPath string) error {
	exporter := NewSARIFExporter(scanResult.Tool, "1.0.0")

	if err := exporter.AddResultFromScanResult(scanResult); err != nil {
		return fmt.Errorf("failed to add scan results: %w", err)
	}

	if err := exporter.ExportToFile(outputPath); err != nil {
		return fmt.Errorf("failed to export to file: %w", err)
	}

	return nil
}

// ExportScanResultToSARIFBytes is a convenience function to export a scan result to SARIF bytes
func ExportScanResultToSARIFBytes(scanResult *types.ScanResult) ([]byte, error) {
	exporter := NewSARIFExporter(scanResult.Tool, "1.0.0")

	if err := exporter.AddResultFromScanResult(scanResult); err != nil {
		return nil, fmt.Errorf("failed to add scan results: %w", err)
	}

	data, err := exporter.Export()
	if err != nil {
		return nil, fmt.Errorf("failed to export SARIF: %w", err)
	}

	return data, nil
}
