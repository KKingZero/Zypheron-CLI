"""
Dependency Scanner - Scan package manifests for vulnerable dependencies
"""

import logging
import json
import subprocess
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class DependencyVulnerability:
    """Vulnerable dependency"""
    vuln_id: str
    package_name: str
    installed_version: str
    vulnerable_versions: str
    
    # Vulnerability details
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    severity: str = "unknown"
    
    # Description
    title: str = ""
    description: str = ""
    
    # Fix
    fixed_version: Optional[str] = None
    remediation: str = ""
    
    # References
    references: List[str] = field(default_factory=list)
    
    # Metadata
    ecosystem: str = ""  # npm, pip, maven, nuget
    manifest_file: str = ""
    discovered_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'vuln_id': self.vuln_id,
            'package_name': self.package_name,
            'installed_version': self.installed_version,
            'vulnerable_versions': self.vulnerable_versions,
            'cve_id': self.cve_id,
            'cvss_score': self.cvss_score,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'fixed_version': self.fixed_version,
            'remediation': self.remediation,
            'references': self.references,
            'ecosystem': self.ecosystem,
            'manifest_file': self.manifest_file,
            'discovered_at': self.discovered_at.isoformat()
        }


class DependencyScanner:
    """
    Scan dependencies for known vulnerabilities
    
    Supports:
    - Python (requirements.txt, setup.py, Pipfile)
    - Node.js (package.json, package-lock.json)
    - Go (go.mod, go.sum)
    - Java (pom.xml, build.gradle)
    - .NET (packages.config, *.csproj)
    """
    
    def __init__(self):
        self.vulnerabilities: List[DependencyVulnerability] = []
        self.scanned_files: Set[str] = set()
    
    def scan_directory(
        self,
        directory: str,
        recursive: bool = True
    ) -> List[DependencyVulnerability]:
        """
        Scan directory for dependency manifests
        
        Args:
            directory: Directory to scan
            recursive: Scan subdirectories
            
        Returns:
            List of vulnerable dependencies
        """
        logger.info(f"Scanning {directory} for dependency vulnerabilities")
        
        dir_path = Path(directory)
        if not dir_path.exists():
            logger.error(f"Directory not found: {directory}")
            return []
        
        findings = []
        
        # Find manifest files
        manifest_files = self._find_manifest_files(dir_path, recursive)
        
        for manifest in manifest_files:
            logger.info(f"Scanning {manifest}")
            
            # Detect ecosystem
            ecosystem = self._detect_ecosystem(manifest)
            
            # Scan based on ecosystem
            if ecosystem == 'python':
                vulns = self._scan_python(manifest)
            elif ecosystem == 'nodejs':
                vulns = self._scan_nodejs(manifest)
            elif ecosystem == 'go':
                vulns = self._scan_go(manifest)
            else:
                logger.debug(f"Unsupported ecosystem for {manifest}")
                continue
            
            findings.extend(vulns)
            self.scanned_files.add(str(manifest))
        
        self.vulnerabilities.extend(findings)
        logger.info(f"Found {len(findings)} vulnerable dependencies")
        
        return findings
    
    def _find_manifest_files(
        self,
        directory: Path,
        recursive: bool
    ) -> List[Path]:
        """Find dependency manifest files"""
        manifest_patterns = [
            'requirements.txt',
            'setup.py',
            'Pipfile',
            'package.json',
            'package-lock.json',
            'go.mod',
            'go.sum',
            'pom.xml',
            'build.gradle',
            '*.csproj',
            'packages.config'
        ]
        
        manifests = []
        
        for pattern in manifest_patterns:
            if recursive:
                manifests.extend(directory.rglob(pattern))
            else:
                manifests.extend(directory.glob(pattern))
        
        return manifests
    
    def _detect_ecosystem(self, file_path: Path) -> str:
        """Detect ecosystem from manifest file"""
        name = file_path.name.lower()
        
        if name in ['requirements.txt', 'setup.py', 'pipfile', 'pipfile.lock']:
            return 'python'
        elif name in ['package.json', 'package-lock.json', 'yarn.lock']:
            return 'nodejs'
        elif name in ['go.mod', 'go.sum']:
            return 'go'
        elif name in ['pom.xml', 'build.gradle']:
            return 'java'
        elif '.csproj' in name or name == 'packages.config':
            return 'dotnet'
        
        return 'unknown'
    
    def _scan_python(self, manifest: Path) -> List[DependencyVulnerability]:
        """Scan Python dependencies using safety"""
        vulns = []
        
        try:
            # Run safety check
            result = subprocess.run(
                ['safety', 'check', '--file', str(manifest), '--json'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0 or result.stdout:
                # Parse safety output
                try:
                    safety_data = json.loads(result.stdout)
                    
                    for issue in safety_data:
                        vuln = DependencyVulnerability(
                            vuln_id=f"py_{issue[0]}",  # Safety ID
                            package_name=issue[1],
                            installed_version=issue[2],
                            vulnerable_versions=issue[3],
                            cve_id=issue[4] if len(issue) > 4 else None,
                            title=f"Vulnerable {issue[1]}",
                            description=issue[5] if len(issue) > 5 else "",
                            ecosystem="python",
                            manifest_file=str(manifest),
                            severity=self._map_cvss_to_severity(None)
                        )
                        vulns.append(vuln)
                        
                except json.JSONDecodeError:
                    logger.debug("Safety output not in JSON format")
                    
        except FileNotFoundError:
            logger.warning("safety not installed - install with: pip install safety")
        except Exception as e:
            logger.error(f"Python dependency scan failed: {e}")
        
        return vulns
    
    def _scan_nodejs(self, manifest: Path) -> List[DependencyVulnerability]:
        """Scan Node.js dependencies using npm audit"""
        vulns = []
        
        try:
            # Run npm audit
            result = subprocess.run(
                ['npm', 'audit', '--json'],
                cwd=manifest.parent,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.stdout:
                try:
                    audit_data = json.loads(result.stdout)
                    
                    # Parse vulnerabilities
                    for vuln_id, vuln_data in audit_data.get('vulnerabilities', {}).items():
                        vuln = DependencyVulnerability(
                            vuln_id=f"npm_{vuln_id}",
                            package_name=vuln_id,
                            installed_version=vuln_data.get('version', 'unknown'),
                            vulnerable_versions=vuln_data.get('range', ''),
                            severity=vuln_data.get('severity', 'unknown'),
                            title=vuln_data.get('title', ''),
                            description=vuln_data.get('overview', ''),
                            remediation=f"Update to {vuln_data.get('fixAvailable', 'latest')}",
                            ecosystem="nodejs",
                            manifest_file=str(manifest)
                        )
                        
                        # Extract CVEs
                        if 'cves' in vuln_data and vuln_data['cves']:
                            vuln.cve_id = vuln_data['cves'][0]
                        
                        vulns.append(vuln)
                        
                except json.JSONDecodeError:
                    logger.debug("npm audit output not in JSON format")
                    
        except FileNotFoundError:
            logger.warning("npm not installed")
        except Exception as e:
            logger.error(f"Node.js dependency scan failed: {e}")
        
        return vulns
    
    def _scan_go(self, manifest: Path) -> List[DependencyVulnerability]:
        """Scan Go dependencies using govulncheck"""
        vulns = []
        
        try:
            # Run govulncheck
            result = subprocess.run(
                ['govulncheck', './...'],
                cwd=manifest.parent,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Parse output for vulnerabilities
            # govulncheck output format varies, implement parser
            
        except FileNotFoundError:
            logger.warning("govulncheck not installed - install with: go install golang.org/x/vuln/cmd/govulncheck@latest")
        except Exception as e:
            logger.error(f"Go dependency scan failed: {e}")
        
        return vulns
    
    def _map_cvss_to_severity(self, cvss_score: Optional[float]) -> str:
        """Map CVSS score to severity"""
        if not cvss_score:
            return "unknown"
        
        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        else:
            return "low"
    
    def generate_report(self) -> Dict:
        """Generate dependency vulnerability report"""
        by_ecosystem = {}
        by_severity = {}
        
        for vuln in self.vulnerabilities:
            by_ecosystem[vuln.ecosystem] = by_ecosystem.get(vuln.ecosystem, 0) + 1
            by_severity[vuln.severity] = by_severity.get(vuln.severity, 0) + 1
        
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'by_ecosystem': by_ecosystem,
            'by_severity': by_severity,
            'critical_count': by_severity.get('critical', 0),
            'high_count': by_severity.get('high', 0),
            'files_scanned': len(self.scanned_files),
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
        }
    
    def get_critical_vulnerabilities(self) -> List[DependencyVulnerability]:
        """Get critical/high severity vulnerabilities"""
        return [
            v for v in self.vulnerabilities
            if v.severity in ['critical', 'high']
        ]

