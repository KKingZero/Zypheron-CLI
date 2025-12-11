"""
SBOM Generator - Generate Software Bill of Materials
"""

import logging
import json
from typing import Dict, List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class Component:
    """Software component"""
    name: str
    version: str
    purl: str  # Package URL
    
    # Type
    type: str = "library"  # library, application, framework, etc.
    
    # Metadata
    supplier: Optional[str] = None
    author: Optional[str] = None
    license: Optional[str] = None
    
    # Hashes
    sha256: Optional[str] = None
    sha1: Optional[str] = None
    
    # Dependencies
    dependencies: List[str] = field(default_factory=list)
    
    # Vulnerabilities
    known_vulnerabilities: List[str] = field(default_factory=list)
    
    def to_cyclonedx_component(self) -> Dict:
        """Convert to CycloneDX format"""
        component = {
            'type': self.type,
            'name': self.name,
            'version': self.version,
            'purl': self.purl
        }
        
        if self.license:
            component['licenses'] = [{'license': {'id': self.license}}]
        
        if self.sha256:
            component['hashes'] = [
                {'alg': 'SHA-256', 'content': self.sha256}
            ]
        
        return component


class SBOMGenerator:
    """
    Generate Software Bill of Materials (SBOM)
    
    Supports:
    - CycloneDX format
    - SPDX format (basic)
    - Custom JSON format
    """
    
    def __init__(self):
        self.components: List[Component] = []
        self.metadata = {
            'tool': 'Zypheron',
            'version': '2.0',
            'generated_at': datetime.now().isoformat()
        }
    
    def add_component(self, component: Component):
        """Add component to SBOM"""
        self.components.append(component)
    
    def scan_python_requirements(self, requirements_file: str) -> int:
        """Scan Python requirements.txt"""
        count = 0
        
        try:
            with open(requirements_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse package and version
                    if '>=' in line:
                        parts = line.split('>=')
                    elif '==' in line:
                        parts = line.split('==')
                    else:
                        parts = [line, 'latest']
                    
                    package = parts[0].strip()
                    version = parts[1].strip() if len(parts) > 1 else 'latest'
                    
                    # Create component
                    component = Component(
                        name=package,
                        version=version,
                        purl=f"pkg:pypi/{package}@{version}",
                        type='library'
                    )
                    
                    self.add_component(component)
                    count += 1
            
            logger.info(f"Added {count} Python components from {requirements_file}")
            
        except Exception as e:
            logger.error(f"Failed to scan Python requirements: {e}")
        
        return count
    
    def scan_nodejs_package(self, package_json: str) -> int:
        """Scan Node.js package.json"""
        count = 0
        
        try:
            with open(package_json, 'r') as f:
                data = json.load(f)
            
            # Scan dependencies
            for dep_type in ['dependencies', 'devDependencies']:
                deps = data.get(dep_type, {})
                
                for package, version in deps.items():
                    # Clean version string
                    version = version.lstrip('^~')
                    
                    component = Component(
                        name=package,
                        version=version,
                        purl=f"pkg:npm/{package}@{version}",
                        type='library'
                    )
                    
                    self.add_component(component)
                    count += 1
            
            logger.info(f"Added {count} Node.js components from {package_json}")
            
        except Exception as e:
            logger.error(f"Failed to scan package.json: {e}")
        
        return count
    
    def _detect_ecosystem(self, file_path: Path) -> str:
        """Detect ecosystem from file"""
        name = file_path.name.lower()
        
        if name in ['requirements.txt', 'setup.py', 'pipfile']:
            return 'python'
        elif name in ['package.json', 'package-lock.json']:
            return 'nodejs'
        elif name in ['go.mod', 'go.sum']:
            return 'go'
        elif name in ['pom.xml', 'build.gradle']:
            return 'java'
        elif '.csproj' in name:
            return 'dotnet'
        
        return 'unknown'
    
    def generate_cyclonedx(self) -> Dict:
        """Generate SBOM in CycloneDX format"""
        bom = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.4',
            'version': 1,
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'tools': [{
                    'vendor': 'Zypheron',
                    'name': 'Zypheron Security Scanner',
                    'version': '2.0'
                }]
            },
            'components': [
                comp.to_cyclonedx_component()
                for comp in self.components
            ]
        }
        
        return bom
    
    def export_sbom(
        self,
        output_file: str,
        format: str = 'cyclonedx'
    ) -> bool:
        """
        Export SBOM to file
        
        Args:
            output_file: Output file path
            format: Format (cyclonedx, spdx, json)
            
        Returns:
            Success status
        """
        try:
            if format == 'cyclonedx':
                data = self.generate_cyclonedx()
            else:
                data = {
                    'metadata': self.metadata,
                    'components': [asdict(c) for c in self.components],
                    'total_components': len(self.components)
                }
            
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Exported SBOM to {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export SBOM: {e}")
            return False
    
    def get_statistics(self) -> Dict:
        """Get SBOM statistics"""
        by_type = {}
        licenses = set()
        
        for comp in self.components:
            by_type[comp.type] = by_type.get(comp.type, 0) + 1
            if comp.license:
                licenses.add(comp.license)
        
        return {
            'total_components': len(self.components),
            'by_type': by_type,
            'unique_licenses': len(licenses),
            'licenses': list(licenses)
        }

