"""
Compliance Framework Templates

Pre-built control sets for various compliance frameworks
"""

from .compliance_reporter import ComplianceControl, ComplianceFramework, ComplianceStatus
from typing import List


class PCIDSSTemplate:
    """PCI-DSS (Payment Card Industry Data Security Standard) v4.0"""
    
    @staticmethod
    def get_controls() -> List[ComplianceControl]:
        """Get PCI-DSS control set"""
        return [
            # Requirement 1: Install and maintain network security controls
            ComplianceControl(
                control_id="PCI-1.1",
                name="Network Security Controls",
                description="Processes and mechanisms for installing and maintaining network security controls",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Install and maintain network security controls",
                category="network_security",
                severity="critical",
                remediation_steps=[
                    "Implement firewall rules to restrict unauthorized access",
                    "Document network security architecture",
                    "Review firewall rules quarterly"
                ]
            ),
            ComplianceControl(
                control_id="PCI-1.2",
                name="Network Connections",
                description="Network security controls restrict connections between untrusted networks",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Restrict connections between untrusted networks and system components",
                category="network_security",
                severity="critical"
            ),
            
            # Requirement 2: Apply Secure Configurations
            ComplianceControl(
                control_id="PCI-2.1",
                name="Secure Configuration",
                description="Processes and mechanisms for applying secure configurations",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Apply secure configurations to all system components",
                category="configuration_management",
                severity="high",
                remediation_steps=[
                    "Remove default passwords and accounts",
                    "Disable unnecessary services and protocols",
                    "Implement configuration standards"
                ]
            ),
            ComplianceControl(
                control_id="PCI-2.2",
                name="Vendor Defaults",
                description="System components configured securely, vendor defaults changed",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Change vendor-supplied defaults before use",
                category="configuration_management",
                severity="critical"
            ),
            
            # Requirement 3: Protect Stored Account Data
            ComplianceControl(
                control_id="PCI-3.1",
                name="Data Retention",
                description="Processes for protecting stored account data",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Protect stored account data",
                category="data_protection",
                severity="critical",
                remediation_steps=[
                    "Implement data retention policies",
                    "Encrypt cardholder data at rest",
                    "Minimize data storage duration"
                ]
            ),
            ComplianceControl(
                control_id="PCI-3.5",
                name="Primary Account Number Protection",
                description="PAN is secured wherever stored",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Render PAN unreadable anywhere it is stored",
                category="data_protection",
                severity="critical"
            ),
            
            # Requirement 4: Protect Cardholder Data with Strong Cryptography
            ComplianceControl(
                control_id="PCI-4.1",
                name="Cryptographic Controls",
                description="Strong cryptography protects PAN in transit",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Use strong cryptography to protect PAN during transmission",
                category="cryptography",
                severity="critical",
                remediation_steps=[
                    "Implement TLS 1.2 or higher",
                    "Disable weak ciphers (SSLv3, TLS 1.0)",
                    "Use only strong cryptographic protocols"
                ]
            ),
            
            # Requirement 6: Develop and Maintain Secure Systems
            ComplianceControl(
                control_id="PCI-6.1",
                name="Security Updates",
                description="Processes to identify security vulnerabilities",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Identify and address security vulnerabilities",
                category="vulnerability_management",
                severity="critical",
                remediation_steps=[
                    "Apply security patches within 30 days",
                    "Maintain vulnerability management program",
                    "Subscribe to security bulletins"
                ]
            ),
            ComplianceControl(
                control_id="PCI-6.4",
                name="Secure Development",
                description="Secure coding practices applied",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Public-facing web applications protected from attacks",
                category="application_security",
                severity="high"
            ),
            
            # Requirement 8: Identify Users and Authenticate Access
            ComplianceControl(
                control_id="PCI-8.2",
                name="User Authentication",
                description="Strong authentication for users and administrators",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Authenticate all access to system components",
                category="access_control",
                severity="critical",
                remediation_steps=[
                    "Implement multi-factor authentication",
                    "Enforce strong password policies",
                    "Monitor authentication attempts"
                ]
            ),
            
            # Requirement 11: Test Security of Systems and Networks
            ComplianceControl(
                control_id="PCI-11.3",
                name="Vulnerability Scanning",
                description="External and internal vulnerability scans performed",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Perform regular vulnerability scans",
                category="vulnerability_management",
                severity="high",
                remediation_steps=[
                    "Quarterly external vulnerability scans by ASV",
                    "Internal scans after significant changes",
                    "Remediate all high-risk vulnerabilities"
                ]
            ),
        ]


class HIPAATemplate:
    """HIPAA (Health Insurance Portability and Accountability Act) Security Rule"""
    
    @staticmethod
    def get_controls() -> List[ComplianceControl]:
        """Get HIPAA control set"""
        return [
            # Administrative Safeguards
            ComplianceControl(
                control_id="HIPAA-164.308(a)(1)",
                name="Security Management Process",
                description="Implement policies and procedures to prevent, detect, contain, and correct security violations",
                framework=ComplianceFramework.HIPAA,
                requirement="Security Management Process",
                category="administrative",
                severity="critical",
                remediation_steps=[
                    "Conduct risk analysis",
                    "Implement risk management procedures",
                    "Create sanction policy",
                    "Establish information system activity review"
                ]
            ),
            ComplianceControl(
                control_id="HIPAA-164.308(a)(3)",
                name="Workforce Security",
                description="Implement policies and procedures to ensure workforce members have appropriate access to ePHI",
                framework=ComplianceFramework.HIPAA,
                requirement="Workforce Security",
                category="administrative",
                severity="high",
                remediation_steps=[
                    "Implement authorization procedures",
                    "Establish workforce clearance procedure",
                    "Create termination procedures"
                ]
            ),
            ComplianceControl(
                control_id="HIPAA-164.308(a)(4)",
                name="Information Access Management",
                description="Implement policies and procedures for authorizing access to ePHI",
                framework=ComplianceFramework.HIPAA,
                requirement="Information Access Management",
                category="access_control",
                severity="critical",
                remediation_steps=[
                    "Implement access authorization policies",
                    "Review access controls regularly",
                    "Implement access establishment and modification procedures"
                ]
            ),
            ComplianceControl(
                control_id="HIPAA-164.308(a)(5)",
                name="Security Awareness and Training",
                description="Implement security awareness and training program",
                framework=ComplianceFramework.HIPAA,
                requirement="Security Awareness and Training",
                category="administrative",
                severity="medium",
                remediation_steps=[
                    "Conduct security reminders",
                    "Provide protection from malicious software training",
                    "Implement login monitoring",
                    "Train on password management"
                ]
            ),
            
            # Physical Safeguards
            ComplianceControl(
                control_id="HIPAA-164.310(a)(1)",
                name="Facility Access Controls",
                description="Limit physical access to electronic information systems and facilities",
                framework=ComplianceFramework.HIPAA,
                requirement="Facility Access Controls",
                category="physical_security",
                severity="high",
                remediation_steps=[
                    "Implement facility security plan",
                    "Control facility access",
                    "Validate person access"
                ]
            ),
            ComplianceControl(
                control_id="HIPAA-164.310(d)(1)",
                name="Device and Media Controls",
                description="Implement policies for disposal, removal, and re-use of devices",
                framework=ComplianceFramework.HIPAA,
                requirement="Device and Media Controls",
                category="physical_security",
                severity="high",
                remediation_steps=[
                    "Implement disposal procedures",
                    "Control media re-use",
                    "Document media movements"
                ]
            ),
            
            # Technical Safeguards
            ComplianceControl(
                control_id="HIPAA-164.312(a)(1)",
                name="Access Control",
                description="Implement technical policies to allow only authorized access to ePHI",
                framework=ComplianceFramework.HIPAA,
                requirement="Access Control",
                category="access_control",
                severity="critical",
                remediation_steps=[
                    "Implement unique user identification",
                    "Establish emergency access procedure",
                    "Implement automatic logoff",
                    "Use encryption and decryption"
                ]
            ),
            ComplianceControl(
                control_id="HIPAA-164.312(b)",
                name="Audit Controls",
                description="Implement hardware, software, and procedural mechanisms to record and examine activity",
                framework=ComplianceFramework.HIPAA,
                requirement="Audit Controls",
                category="logging_monitoring",
                severity="high",
                remediation_steps=[
                    "Implement audit logging",
                    "Review audit logs regularly",
                    "Protect audit log integrity"
                ]
            ),
            ComplianceControl(
                control_id="HIPAA-164.312(c)(1)",
                name="Integrity Controls",
                description="Implement policies to ensure ePHI is not improperly altered or destroyed",
                framework=ComplianceFramework.HIPAA,
                requirement="Integrity",
                category="data_protection",
                severity="high",
                remediation_steps=[
                    "Implement mechanisms to authenticate ePHI",
                    "Protect against improper alteration"
                ]
            ),
            ComplianceControl(
                control_id="HIPAA-164.312(d)",
                name="Person or Entity Authentication",
                description="Implement procedures to verify identity of person or entity",
                framework=ComplianceFramework.HIPAA,
                requirement="Person or Entity Authentication",
                category="access_control",
                severity="critical",
                remediation_steps=[
                    "Implement user authentication",
                    "Use strong authentication methods"
                ]
            ),
            ComplianceControl(
                control_id="HIPAA-164.312(e)(1)",
                name="Transmission Security",
                description="Implement technical security measures for ePHI transmission",
                framework=ComplianceFramework.HIPAA,
                requirement="Transmission Security",
                category="cryptography",
                severity="critical",
                remediation_steps=[
                    "Implement encryption for transmission",
                    "Use secure communication protocols"
                ]
            ),
        ]


class SOC2Template:
    """SOC 2 (Service Organization Control 2) Trust Services Criteria"""
    
    @staticmethod
    def get_controls() -> List[ComplianceControl]:
        """Get SOC 2 control set"""
        return [
            # Security (Common Criteria)
            ComplianceControl(
                control_id="CC1.1",
                name="Control Environment",
                description="Demonstrate commitment to integrity and ethical values",
                framework=ComplianceFramework.SOC2,
                requirement="COSO Control Environment",
                category="governance",
                severity="high",
                remediation_steps=[
                    "Establish code of conduct",
                    "Define security policies",
                    "Assign security responsibilities"
                ]
            ),
            ComplianceControl(
                control_id="CC2.1",
                name="Communication and Information",
                description="Obtain or generate relevant quality information to support control functioning",
                framework=ComplianceFramework.SOC2,
                requirement="Information and Communication",
                category="governance",
                severity="medium"
            ),
            ComplianceControl(
                control_id="CC6.1",
                name="Logical and Physical Access Controls",
                description="Implement logical and physical access controls",
                framework=ComplianceFramework.SOC2,
                requirement="Logical and Physical Access Controls",
                category="access_control",
                severity="critical",
                remediation_steps=[
                    "Implement access management procedures",
                    "Review access rights periodically",
                    "Restrict physical access to facilities"
                ]
            ),
            ComplianceControl(
                control_id="CC6.6",
                name="Vulnerability Management",
                description="Implement controls to prevent or detect and act upon security incidents",
                framework=ComplianceFramework.SOC2,
                requirement="Response to Security Incidents",
                category="vulnerability_management",
                severity="critical",
                remediation_steps=[
                    "Establish incident response procedures",
                    "Conduct regular vulnerability scans",
                    "Patch management process"
                ]
            ),
            ComplianceControl(
                control_id="CC6.7",
                name="System Operations",
                description="Identify, develop, and detect unauthorized changes to software",
                framework=ComplianceFramework.SOC2,
                requirement="System Operations",
                category="change_management",
                severity="high"
            ),
            ComplianceControl(
                control_id="CC7.1",
                name="System Monitoring",
                description="Detect anomalous activities through monitoring",
                framework=ComplianceFramework.SOC2,
                requirement="Detection of Anomalous Activities",
                category="logging_monitoring",
                severity="high",
                remediation_steps=[
                    "Implement SIEM solution",
                    "Monitor system logs",
                    "Set up alerting for anomalies"
                ]
            ),
            
            # Availability
            ComplianceControl(
                control_id="A1.1",
                name="Availability Commitments",
                description="Meet availability commitments through system design",
                framework=ComplianceFramework.SOC2,
                requirement="Availability",
                category="availability",
                severity="high",
                remediation_steps=[
                    "Implement redundancy",
                    "Document RTO and RPO",
                    "Test disaster recovery procedures"
                ]
            ),
            ComplianceControl(
                control_id="A1.2",
                name="System Performance",
                description="Monitor system performance and availability",
                framework=ComplianceFramework.SOC2,
                requirement="System Availability",
                category="availability",
                severity="medium"
            ),
            
            # Confidentiality
            ComplianceControl(
                control_id="C1.1",
                name="Confidentiality Commitments",
                description="Protect confidential information meeting commitments",
                framework=ComplianceFramework.SOC2,
                requirement="Confidentiality",
                category="data_protection",
                severity="critical",
                remediation_steps=[
                    "Classify data based on sensitivity",
                    "Implement encryption",
                    "Control data access"
                ]
            ),
            
            # Processing Integrity
            ComplianceControl(
                control_id="PI1.1",
                name="Processing Integrity",
                description="System processing is complete, valid, accurate, timely, and authorized",
                framework=ComplianceFramework.SOC2,
                requirement="Processing Integrity",
                category="data_integrity",
                severity="high"
            ),
        ]


class ISO27001Template:
    """ISO/IEC 27001:2022 Information Security Management System"""
    
    @staticmethod
    def get_controls() -> List[ComplianceControl]:
        """Get ISO 27001 control set"""
        return [
            # A.5 Organizational Controls
            ComplianceControl(
                control_id="ISO-5.1",
                name="Policies for Information Security",
                description="Information security policy defined, approved, communicated",
                framework=ComplianceFramework.ISO_27001,
                requirement="Information security policies",
                category="governance",
                severity="high",
                remediation_steps=[
                    "Develop information security policy",
                    "Get management approval",
                    "Communicate to all personnel"
                ]
            ),
            ComplianceControl(
                control_id="ISO-5.7",
                name="Threat Intelligence",
                description="Information relating to information security threats collected and analyzed",
                framework=ComplianceFramework.ISO_27001,
                requirement="Threat intelligence",
                category="threat_management",
                severity="medium"
            ),
            
            # A.6 People Controls
            ComplianceControl(
                control_id="ISO-6.2",
                name="Terms and Conditions of Employment",
                description="Personnel and organization's security responsibilities defined",
                framework=ComplianceFramework.ISO_27001,
                requirement="Terms and conditions of employment",
                category="administrative",
                severity="medium"
            ),
            ComplianceControl(
                control_id="ISO-6.3",
                name="Information Security Awareness",
                description="Personnel receive appropriate security awareness training",
                framework=ComplianceFramework.ISO_27001,
                requirement="Information security awareness, education and training",
                category="training",
                severity="medium"
            ),
            
            # A.7 Physical Controls
            ComplianceControl(
                control_id="ISO-7.1",
                name="Physical Security Perimeters",
                description="Secure areas protected by perimeters",
                framework=ComplianceFramework.ISO_27001,
                requirement="Physical security perimeters",
                category="physical_security",
                severity="high"
            ),
            ComplianceControl(
                control_id="ISO-7.4",
                name="Physical Security Monitoring",
                description="Premises continuously monitored for unauthorized access",
                framework=ComplianceFramework.ISO_27001,
                requirement="Physical security monitoring",
                category="physical_security",
                severity="medium"
            ),
            
            # A.8 Technological Controls
            ComplianceControl(
                control_id="ISO-8.1",
                name="User Endpoint Devices",
                description="Information on user endpoint devices protected",
                framework=ComplianceFramework.ISO_27001,
                requirement="User endpoint devices",
                category="endpoint_security",
                severity="high",
                remediation_steps=[
                    "Implement endpoint protection",
                    "Enforce device encryption",
                    "Control removable media"
                ]
            ),
            ComplianceControl(
                control_id="ISO-8.2",
                name="Privileged Access Rights",
                description="Allocation and use of privileged access rights restricted and managed",
                framework=ComplianceFramework.ISO_27001,
                requirement="Privileged access rights",
                category="access_control",
                severity="critical",
                remediation_steps=[
                    "Implement PAM solution",
                    "Review privileged accounts regularly",
                    "Monitor privileged access"
                ]
            ),
            ComplianceControl(
                control_id="ISO-8.3",
                name="Information Access Restriction",
                description="Access to information and other associated assets restricted",
                framework=ComplianceFramework.ISO_27001,
                requirement="Information access restriction",
                category="access_control",
                severity="critical"
            ),
            ComplianceControl(
                control_id="ISO-8.5",
                name="Secure Authentication",
                description="Secure authentication technologies and procedures implemented",
                framework=ComplianceFramework.ISO_27001,
                requirement="Secure authentication",
                category="access_control",
                severity="critical",
                remediation_steps=[
                    "Implement multi-factor authentication",
                    "Enforce password complexity",
                    "Use secure authentication protocols"
                ]
            ),
            ComplianceControl(
                control_id="ISO-8.8",
                name="Management of Technical Vulnerabilities",
                description="Information about technical vulnerabilities acquired, exposed to evaluated",
                framework=ComplianceFramework.ISO_27001,
                requirement="Management of technical vulnerabilities",
                category="vulnerability_management",
                severity="critical",
                remediation_steps=[
                    "Establish vulnerability management process",
                    "Conduct regular vulnerability assessments",
                    "Remediate vulnerabilities based on risk"
                ]
            ),
            ComplianceControl(
                control_id="ISO-8.9",
                name="Configuration Management",
                description="Configurations including security configurations recorded and managed",
                framework=ComplianceFramework.ISO_27001,
                requirement="Configuration management",
                category="configuration_management",
                severity="high"
            ),
            ComplianceControl(
                control_id="ISO-8.10",
                name="Information Deletion",
                description="Information stored in information systems deleted when no longer required",
                framework=ComplianceFramework.ISO_27001,
                requirement="Information deletion",
                category="data_protection",
                severity="medium"
            ),
            ComplianceControl(
                control_id="ISO-8.16",
                name="Monitoring Activities",
                description="Networks, systems and applications monitored for anomalous behaviour",
                framework=ComplianceFramework.ISO_27001,
                requirement="Monitoring activities",
                category="logging_monitoring",
                severity="high",
                remediation_steps=[
                    "Implement security monitoring",
                    "Review logs regularly",
                    "Set up automated alerting"
                ]
            ),
            ComplianceControl(
                control_id="ISO-8.23",
                name="Web Filtering",
                description="Access to external websites managed to reduce exposure",
                framework=ComplianceFramework.ISO_27001,
                requirement="Web filtering",
                category="network_security",
                severity="medium"
            ),
            ComplianceControl(
                control_id="ISO-8.24",
                name="Use of Cryptography",
                description="Rules for effective use of cryptography defined and implemented",
                framework=ComplianceFramework.ISO_27001,
                requirement="Use of cryptography",
                category="cryptography",
                severity="high",
                remediation_steps=[
                    "Implement encryption for data at rest",
                    "Use TLS for data in transit",
                    "Manage cryptographic keys securely"
                ]
            ),
            ComplianceControl(
                control_id="ISO-8.28",
                name="Secure Coding",
                description="Secure coding principles applied to software development",
                framework=ComplianceFramework.ISO_27001,
                requirement="Secure coding",
                category="application_security",
                severity="high"
            ),
        ]

