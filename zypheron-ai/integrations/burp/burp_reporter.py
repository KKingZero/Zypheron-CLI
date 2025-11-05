"""
Burp Reporter - Import and process Burp Suite findings
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class BurpFinding:
    """Burp Suite finding/issue"""
    issue_id: str
    name: str
    severity: str
    confidence: str
    url: str
    
    # Details
    description: str = ""
    remediation: str = ""
    vulnerability_classifications: List[str] = field(default_factory=list)
    
    # Evidence
    http_messages: List[Dict] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    
    # References
    references: List[str] = field(default_factory=list)
    cwe_id: Optional[str] = None
    
    # Metadata
    discovered_at: datetime = field(default_factory=datetime.now)
    burp_issue_type: str = ""
    
    def to_zypheron_format(self) -> Dict[str, Any]:
        """Convert to Zypheron vulnerability format"""
        # Map Burp severity to Zypheron severity
        severity_map = {
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'info': 'info',
            'information': 'info'
        }
        
        return {
            'id': self.issue_id,
            'title': self.name,
            'description': self.description,
            'severity': severity_map.get(self.severity.lower(), 'medium'),
            'url': self.url,
            'remediation': self.remediation,
            'cwe_id': self.cwe_id,
            'evidence': self.evidence,
            'references': self.references,
            'source': 'burp_suite',
            'confidence': self.confidence,
            'discovered_at': self.discovered_at.isoformat()
        }


class BurpReporter:
    """
    Import and process Burp Suite findings
    
    Features:
    - Parse Burp issues
    - Convert to Zypheron format
    - Deduplicate findings
    - Merge with existing results
    """
    
    def __init__(self):
        self.findings: List[BurpFinding] = []
    
    def import_burp_issues(
        self,
        issues: List[Dict],
        source_scan_id: Optional[str] = None
    ) -> int:
        """
        Import issues from Burp Suite
        
        Args:
            issues: List of Burp issues
            source_scan_id: Optional scan ID for tracking
            
        Returns:
            Number of issues imported
        """
        logger.info(f"Importing {len(issues)} Burp issues")
        imported = 0
        
        for issue in issues:
            try:
                finding = self._parse_burp_issue(issue)
                if finding:
                    self.findings.append(finding)
                    imported += 1
            except Exception as e:
                logger.error(f"Failed to parse Burp issue: {e}")
        
        logger.info(f"Successfully imported {imported} Burp issues")
        return imported
    
    def _parse_burp_issue(self, issue: Dict) -> Optional[BurpFinding]:
        """Parse individual Burp issue"""
        try:
            finding = BurpFinding(
                issue_id=issue.get('issue_id', f"burp_{hash(str(issue))}"),
                name=issue.get('name', 'Unknown Issue'),
                severity=issue.get('severity', 'medium'),
                confidence=issue.get('confidence', 'certain'),
                url=issue.get('url', ''),
                description=issue.get('issue_detail', ''),
                remediation=issue.get('remediation_detail', ''),
                burp_issue_type=issue.get('issue_type', ''),
                references=issue.get('references', [])
            )
            
            # Extract CWE if present
            for ref in finding.references:
                if 'CWE-' in ref:
                    import re
                    cwe_match = re.search(r'CWE-(\d+)', ref)
                    if cwe_match:
                        finding.cwe_id = f"CWE-{cwe_match.group(1)}"
            
            # Extract vulnerability classifications
            if 'vulnerability_classifications' in issue:
                finding.vulnerability_classifications = issue['vulnerability_classifications']
            
            return finding
            
        except Exception as e:
            logger.error(f"Failed to parse Burp issue: {e}")
            return None
    
    def deduplicate_findings(
        self,
        existing_findings: List[Dict]
    ) -> List[BurpFinding]:
        """
        Deduplicate Burp findings against existing Zypheron findings
        
        Args:
            existing_findings: Existing Zypheron vulnerabilities
            
        Returns:
            List of unique Burp findings
        """
        unique_findings = []
        
        for burp_finding in self.findings:
            is_duplicate = False
            
            for existing in existing_findings:
                # Check if same vulnerability at same URL
                if (burp_finding.url == existing.get('url') and
                    self._is_same_vulnerability(burp_finding, existing)):
                    is_duplicate = True
                    logger.debug(f"Duplicate finding: {burp_finding.name} at {burp_finding.url}")
                    break
            
            if not is_duplicate:
                unique_findings.append(burp_finding)
        
        logger.info(f"After deduplication: {len(unique_findings)} unique Burp findings")
        return unique_findings
    
    def _is_same_vulnerability(
        self,
        burp_finding: BurpFinding,
        existing_finding: Dict
    ) -> bool:
        """Check if two findings represent the same vulnerability"""
        # Simple name matching (can be improved with fuzzy matching)
        burp_name_lower = burp_finding.name.lower()
        existing_title_lower = existing.get('title', '').lower()
        
        # Check for key vulnerability types
        vuln_keywords = [
            'xss', 'sql injection', 'csrf', 'lfi', 'rfi',
            'command injection', 'path traversal', 'xxe'
        ]
        
        for keyword in vuln_keywords:
            if keyword in burp_name_lower and keyword in existing_title_lower:
                return True
        
        # Check if names are very similar
        if burp_name_lower == existing_title_lower:
            return True
        
        return False
    
    def merge_with_zypheron_results(
        self,
        zypheron_vulnerabilities: List[Dict]
    ) -> List[Dict]:
        """
        Merge Burp findings with Zypheron vulnerabilities
        
        Returns:
            Combined list of vulnerabilities
        """
        # Deduplicate first
        unique_burp = self.deduplicate_findings(zypheron_vulnerabilities)
        
        # Convert to Zypheron format
        burp_as_zypheron = [
            finding.to_zypheron_format()
            for finding in unique_burp
        ]
        
        # Merge
        combined = zypheron_vulnerabilities + burp_as_zypheron
        
        logger.info(
            f"Merged results: {len(zypheron_vulnerabilities)} Zypheron + "
            f"{len(burp_as_zypheron)} Burp = {len(combined)} total"
        )
        
        return combined
    
    def generate_summary(self) -> Dict[str, Any]:
        """Generate summary of Burp findings"""
        severity_counts = {}
        confidence_counts = {}
        
        for finding in self.findings:
            severity = finding.severity.lower()
            confidence = finding.confidence.lower()
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1
        
        return {
            'total_findings': len(self.findings),
            'by_severity': severity_counts,
            'by_confidence': confidence_counts,
            'high_confidence_critical': sum(
                1 for f in self.findings
                if f.severity.lower() in ['high', 'critical'] and
                   f.confidence.lower() in ['certain', 'firm']
            )
        }
    
    def get_critical_findings(self) -> List[BurpFinding]:
        """Get critical/high severity findings"""
        return [
            f for f in self.findings
            if f.severity.lower() in ['critical', 'high']
        ]
    
    def export_findings(self, output_file: str) -> bool:
        """Export findings to JSON file"""
        try:
            import json
            
            data = {
                'summary': self.generate_summary(),
                'findings': [f.to_zypheron_format() for f in self.findings]
            }
            
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Exported Burp findings to {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export findings: {e}")
            return False

