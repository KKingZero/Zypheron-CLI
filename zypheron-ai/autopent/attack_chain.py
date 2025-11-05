"""
Attack Chain - Model and execute multi-stage attacks
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum

logger = logging.getLogger(__name__)


class AttackStepType(Enum):
    """Types of attack steps"""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    DATA_EXFILTRATION = "data_exfiltration"


@dataclass
class AttackStep:
    """Individual step in an attack chain"""
    step_id: str
    name: str
    description: str
    step_type: AttackStepType
    
    # Prerequisites
    requires: List[str] = field(default_factory=list)  # IDs of required previous steps
    
    # Technical details
    technique: str = ""  # MITRE ATT&CK technique
    tool: str = ""
    command: str = ""
    
    # Risk assessment
    risk_level: str = "medium"  # low, medium, high, critical
    detection_likelihood: str = "medium"  # low, medium, high
    
    # Execution
    executed: bool = False
    success: bool = False
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


@dataclass
class AttackChain:
    """
    Complete attack chain from initial access to objective
    
    Models MITRE ATT&CK-style attack sequences
    """
    chain_id: str
    name: str
    objective: str
    
    # Steps in order
    steps: List[AttackStep] = field(default_factory=list)
    
    # Metadata
    mitre_tactics: List[str] = field(default_factory=list)
    target: str = ""
    
    def add_step(self, step: AttackStep):
        """Add step to chain"""
        self.steps.append(step)
    
    def get_next_steps(self) -> List[AttackStep]:
        """Get executable next steps"""
        executable = []
        
        for step in self.steps:
            if step.executed:
                continue
            
            # Check if all prerequisites are met
            prereqs_met = all(
                any(s.step_id == req_id and s.success for s in self.steps)
                for req_id in step.requires
            ) if step.requires else True
            
            if prereqs_met:
                executable.append(step)
        
        return executable
    
    def is_complete(self) -> bool:
        """Check if all steps executed"""
        return all(step.executed for step in self.steps)
    
    def success_rate(self) -> float:
        """Calculate success rate of executed steps"""
        executed = [s for s in self.steps if s.executed]
        if not executed:
            return 0.0
        
        successful = [s for s in executed if s.success]
        return len(successful) / len(executed)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'chain_id': self.chain_id,
            'name': self.name,
            'objective': self.objective,
            'target': self.target,
            'mitre_tactics': self.mitre_tactics,
            'steps': [
                {
                    'step_id': s.step_id,
                    'name': s.name,
                    'type': s.step_type.value,
                    'technique': s.technique,
                    'executed': s.executed,
                    'success': s.success,
                    'risk_level': s.risk_level
                }
                for s in self.steps
            ],
            'progress': {
                'total_steps': len(self.steps),
                'executed': sum(1 for s in self.steps if s.executed),
                'successful': sum(1 for s in self.steps if s.success),
                'success_rate': self.success_rate()
            }
        }


class AttackChainBuilder:
    """Build attack chains based on vulnerabilities and objectives"""
    
    @staticmethod
    def build_web_app_chain(target: str) -> AttackChain:
        """Build attack chain for web application"""
        chain = AttackChain(
            chain_id="web_app_001",
            name="Web Application Attack",
            objective="Gain unauthorized access to web application",
            target=target,
            mitre_tactics=["Initial Access", "Execution", "Persistence"]
        )
        
        # Step 1: Reconnaissance
        chain.add_step(AttackStep(
            step_id="recon_1",
            name="Web Application Fingerprinting",
            description="Identify web technologies and frameworks",
            step_type=AttackStepType.RECONNAISSANCE,
            technique="T1592.002",
            tool="whatweb",
            risk_level="low"
        ))
        
        # Step 2: Vulnerability Scanning
        chain.add_step(AttackStep(
            step_id="scan_1",
            name="Vulnerability Scanning",
            description="Scan for common web vulnerabilities",
            step_type=AttackStepType.INITIAL_ACCESS,
            technique="T1190",
            tool="nikto",
            requires=["recon_1"],
            risk_level="low"
        ))
        
        # Step 3: SQL Injection Attempt
        chain.add_step(AttackStep(
            step_id="exploit_1",
            name="SQL Injection",
            description="Attempt SQL injection on identified parameters",
            step_type=AttackStepType.INITIAL_ACCESS,
            technique="T1190",
            tool="sqlmap",
            requires=["scan_1"],
            risk_level="high",
            detection_likelihood="high"
        ))
        
        return chain
    
    @staticmethod
    def build_network_chain(target: str) -> AttackChain:
        """Build attack chain for network penetration"""
        chain = AttackChain(
            chain_id="network_001",
            name="Network Penetration",
            objective="Compromise network host",
            target=target,
            mitre_tactics=["Reconnaissance", "Initial Access", "Lateral Movement"]
        )
        
        # Step 1: Port Scanning
        chain.add_step(AttackStep(
            step_id="scan_ports",
            name="Port Scanning",
            description="Identify open ports and services",
            step_type=AttackStepType.RECONNAISSANCE,
            technique="T1046",
            tool="nmap",
            command="nmap -sV -sC target",
            risk_level="low"
        ))
        
        # Step 2: Service Enumeration
        chain.add_step(AttackStep(
            step_id="enum_services",
            name="Service Enumeration",
            description="Enumerate services and versions",
            step_type=AttackStepType.RECONNAISSANCE,
            technique="T1046",
            requires=["scan_ports"],
            risk_level="low"
        ))
        
        # Step 3: Exploit Attempt
        chain.add_step(AttackStep(
            step_id="exploit_service",
            name="Service Exploitation",
            description="Attempt exploitation of vulnerable service",
            step_type=AttackStepType.INITIAL_ACCESS,
            technique="T1210",
            tool="metasploit",
            requires=["enum_services"],
            risk_level="critical",
            detection_likelihood="high"
        ))
        
        return chain

