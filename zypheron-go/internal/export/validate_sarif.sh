#!/bin/bash
# SARIF Validation Script
# This script validates SARIF output files for compliance and correctness

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored messages
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Check if file argument is provided
if [ $# -eq 0 ]; then
    print_error "Usage: $0 <sarif-file>"
    exit 1
fi

SARIF_FILE="$1"

# Check if file exists
if [ ! -f "$SARIF_FILE" ]; then
    print_error "File not found: $SARIF_FILE"
    exit 1
fi

print_info "Validating SARIF file: $SARIF_FILE"
echo ""

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    print_error "jq is required but not installed. Install with: sudo apt-get install jq"
    exit 1
fi

# 1. Validate JSON structure
print_info "1. Checking JSON structure..."
if jq empty "$SARIF_FILE" 2>/dev/null; then
    print_success "Valid JSON structure"
else
    print_error "Invalid JSON structure"
    exit 1
fi

# 2. Check SARIF version
print_info "2. Checking SARIF version..."
VERSION=$(jq -r '.version' "$SARIF_FILE")
if [ "$VERSION" = "2.1.0" ]; then
    print_success "SARIF version: $VERSION"
else
    print_warning "SARIF version $VERSION (expected 2.1.0)"
fi

# 3. Check schema
print_info "3. Checking schema..."
SCHEMA=$(jq -r '.$schema' "$SARIF_FILE")
if [ -n "$SCHEMA" ] && [ "$SCHEMA" != "null" ]; then
    print_success "Schema defined: $SCHEMA"
else
    print_warning "No schema defined"
fi

# 4. Check runs
print_info "4. Checking runs..."
RUNS_COUNT=$(jq '.runs | length' "$SARIF_FILE")
if [ "$RUNS_COUNT" -gt 0 ]; then
    print_success "Found $RUNS_COUNT run(s)"
else
    print_error "No runs found"
    exit 1
fi

# 5. Check tool information
print_info "5. Checking tool information..."
TOOL_NAME=$(jq -r '.runs[0].tool.driver.name' "$SARIF_FILE")
TOOL_VERSION=$(jq -r '.runs[0].tool.driver.version' "$SARIF_FILE")
if [ -n "$TOOL_NAME" ] && [ "$TOOL_NAME" != "null" ]; then
    print_success "Tool: $TOOL_NAME"
    if [ -n "$TOOL_VERSION" ] && [ "$TOOL_VERSION" != "null" ]; then
        print_success "Version: $TOOL_VERSION"
    fi
else
    print_error "Missing tool name"
    exit 1
fi

# 6. Check results
print_info "6. Checking results..."
RESULTS_COUNT=$(jq '.runs[0].results | length' "$SARIF_FILE")
if [ "$RESULTS_COUNT" -ge 0 ]; then
    print_success "Found $RESULTS_COUNT result(s)"
else
    print_warning "No results array found"
fi

# 7. Validate result structure
if [ "$RESULTS_COUNT" -gt 0 ]; then
    print_info "7. Validating result structure..."

    # Check if all results have required fields
    MISSING_RULE_ID=$(jq '[.runs[0].results[] | select(.ruleId == null or .ruleId == "")] | length' "$SARIF_FILE")
    if [ "$MISSING_RULE_ID" -eq 0 ]; then
        print_success "All results have ruleId"
    else
        print_warning "$MISSING_RULE_ID result(s) missing ruleId"
    fi

    MISSING_MESSAGE=$(jq '[.runs[0].results[] | select(.message.text == null or .message.text == "")] | length' "$SARIF_FILE")
    if [ "$MISSING_MESSAGE" -eq 0 ]; then
        print_success "All results have message text"
    else
        print_warning "$MISSING_MESSAGE result(s) missing message text"
    fi
fi

# 8. Check rules
print_info "8. Checking rules..."
RULES_COUNT=$(jq '.runs[0].tool.driver.rules | length' "$SARIF_FILE")
if [ "$RULES_COUNT" -gt 0 ]; then
    print_success "Found $RULES_COUNT rule(s)"
else
    print_warning "No rules defined"
fi

# 9. Check severity levels
if [ "$RESULTS_COUNT" -gt 0 ]; then
    print_info "9. Analyzing severity levels..."

    ERROR_COUNT=$(jq '[.runs[0].results[] | select(.level == "error")] | length' "$SARIF_FILE")
    WARNING_COUNT=$(jq '[.runs[0].results[] | select(.level == "warning")] | length' "$SARIF_FILE")
    NOTE_COUNT=$(jq '[.runs[0].results[] | select(.level == "note")] | length' "$SARIF_FILE")

    echo "   Error:   $ERROR_COUNT"
    echo "   Warning: $WARNING_COUNT"
    echo "   Note:    $NOTE_COUNT"
fi

# 10. Check for fingerprints
if [ "$RESULTS_COUNT" -gt 0 ]; then
    print_info "10. Checking fingerprints..."

    WITH_FINGERPRINTS=$(jq '[.runs[0].results[] | select(.partialFingerprints != null)] | length' "$SARIF_FILE")
    if [ "$WITH_FINGERPRINTS" -gt 0 ]; then
        print_success "$WITH_FINGERPRINTS result(s) have fingerprints"
    else
        print_warning "No fingerprints found (recommended for deduplication)"
    fi
fi

# 11. Check invocations
print_info "11. Checking invocations..."
INVOCATIONS_COUNT=$(jq '.runs[0].invocations | length' "$SARIF_FILE")
if [ "$INVOCATIONS_COUNT" -gt 0 ]; then
    print_success "Found $INVOCATIONS_COUNT invocation(s)"
else
    print_warning "No invocations (optional but recommended)"
fi

# 12. File size check
print_info "12. Checking file size..."
FILE_SIZE=$(stat -f%z "$SARIF_FILE" 2>/dev/null || stat -c%s "$SARIF_FILE" 2>/dev/null)
FILE_SIZE_MB=$(echo "scale=2; $FILE_SIZE / 1048576" | bc)
echo "   File size: ${FILE_SIZE_MB} MB"

if (( $(echo "$FILE_SIZE_MB > 10" | bc -l) )); then
    print_warning "File size exceeds 10 MB (GitHub limit)"
fi

# Summary
echo ""
echo "================================================"
echo "                  SUMMARY"
echo "================================================"
echo "SARIF Version:    $VERSION"
echo "Tool:             $TOOL_NAME $TOOL_VERSION"
echo "Runs:             $RUNS_COUNT"
echo "Results:          $RESULTS_COUNT"
echo "Rules:            $RULES_COUNT"
echo "File Size:        ${FILE_SIZE_MB} MB"
echo "================================================"

# List unique rule IDs
if [ "$RESULTS_COUNT" -gt 0 ]; then
    echo ""
    print_info "Unique Rule IDs:"
    jq -r '.runs[0].results[].ruleId' "$SARIF_FILE" | sort -u | head -20 | while read -r rule; do
        echo "   - $rule"
    done
fi

# Check for common issues
echo ""
print_info "Additional Checks:"

# Check for very long messages
LONG_MESSAGES=$(jq '[.runs[0].results[] | select(.message.text | length > 1000)] | length' "$SARIF_FILE")
if [ "$LONG_MESSAGES" -gt 0 ]; then
    print_warning "$LONG_MESSAGES result(s) have very long messages (>1000 chars)"
fi

# Check for results without locations
NO_LOCATIONS=$(jq '[.runs[0].results[] | select(.locations == null or (.locations | length == 0))] | length' "$SARIF_FILE")
if [ "$NO_LOCATIONS" -gt 0 ]; then
    print_warning "$NO_LOCATIONS result(s) without locations"
fi

echo ""
print_success "Validation complete!"

# Optional: Validate against schema using online validator
echo ""
print_info "For complete schema validation, use one of these tools:"
echo "   • SARIF Multitool: npm install -g @microsoft/sarif-multitool"
echo "   • Online validator: https://sarifweb.azurewebsites.net/Validation"
echo "   • GitHub validator: Upload directly to test compatibility"

exit 0
