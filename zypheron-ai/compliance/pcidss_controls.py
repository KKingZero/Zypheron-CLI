"""
PCI-DSS v4.0 Controls

Comprehensive control set for PCI-DSS (Payment Card Industry Data Security Standard) v4.0 compliance.
Organized by 12 Requirements across 6 categories:
- Requirements 1-2: Build and Maintain a Secure Network and Systems
- Requirements 3-4: Protect Cardholder Data
- Requirements 5-6: Maintain a Vulnerability Management Program
- Requirements 7-9: Implement Strong Access Control Measures
- Requirements 10-11: Regularly Monitor and Test Networks
- Requirement 12: Maintain an Information Security Policy

Each control includes:
- Full enterprise depth with testing procedures, evidence requirements, common gaps
- Remediation guidance and testing frequency
- Mapped to specific PCI-DSS requirement groups
"""

from typing import List
from .compliance_reporter import ComplianceControl, ComplianceFramework


class PCIDSSv4Controls:
    """PCI-DSS v4.0 control library with 50+ enterprise-grade controls"""

    @staticmethod
    def get_controls() -> List[ComplianceControl]:
        """Get comprehensive PCI-DSS v4.0 control set"""
        return [
            # ============================================================
            # Requirement 1: Install and Maintain Network Security Controls
            # ============================================================
            ComplianceControl(
                control_id="PCI-1.1.1",
                name="Network Security Controls Processes",
                description="Processes and mechanisms for installing and maintaining network security controls are defined and documented",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 1: Install and maintain network security controls",
                category="network_security",
                severity="critical",
                pci_requirement_group="Requirements 1-2: Network Security",
                testing_procedures=[
                    "Review network security policies and procedures",
                    "Examine network security control documentation",
                    "Interview personnel about network security processes",
                    "Assess network security roles and responsibilities",
                    "Review network security training materials"
                ],
                evidence_requirements=[
                    "Network security policy",
                    "Network security procedures",
                    "Network diagrams and documentation",
                    "Role and responsibility matrix",
                    "Training materials and completion records"
                ],
                common_gaps=[
                    "Network security processes not documented",
                    "Roles and responsibilities unclear",
                    "Procedures don't match actual implementation",
                    "No training on network security requirements"
                ],
                remediation_guidance="Document comprehensive network security policies and procedures. Define clear roles and "
                                    "responsibilities. Ensure procedures reflect current implementation. Provide regular training to staff.",
                testing_frequency="Annual review and attestation"
            ),

            ComplianceControl(
                control_id="PCI-1.2.1",
                name="Network Security Controls Configuration",
                description="Network security controls (NSCs) are configured and maintained to restrict connections between untrusted networks and system components in the CDE",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 1.2: Network security controls restrict connections between untrusted and cardholder data environment networks",
                category="network_security",
                severity="critical",
                pci_requirement_group="Requirements 1-2: Network Security",
                testing_procedures=[
                    "Review firewall and router configurations",
                    "Examine network segmentation implementation",
                    "Test restrictions between untrusted networks and CDE",
                    "Assess DMZ configuration",
                    "Review inbound and outbound traffic restrictions"
                ],
                evidence_requirements=[
                    "Firewall rule sets and configurations",
                    "Network segmentation diagrams",
                    "Traffic flow documentation",
                    "DMZ configuration evidence",
                    "Network security control test results"
                ],
                common_gaps=[
                    "Insufficient network segmentation",
                    "Overly permissive firewall rules",
                    "No DMZ for internet-facing systems",
                    "Direct connectivity between untrusted networks and CDE"
                ],
                remediation_guidance="Implement network segmentation to isolate CDE from untrusted networks. Configure firewalls with "
                                    "least-privilege rules. Deploy DMZ for internet-facing systems. Deny all traffic by default.",
                testing_frequency="Quarterly firewall rule review"
            ),

            ComplianceControl(
                control_id="PCI-1.2.7",
                name="Quarterly Firewall Rule Review",
                description="All NSC rulesets are reviewed at least once every six months",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 1.2: Review network security controls",
                category="network_security",
                severity="high",
                pci_requirement_group="Requirements 1-2: Network Security",
                testing_procedures=[
                    "Review firewall rule review procedures",
                    "Examine recent rule review evidence (last 6 months)",
                    "Assess review thoroughness and documentation",
                    "Test remediation of unnecessary rules",
                    "Validate review frequency compliance"
                ],
                evidence_requirements=[
                    "Firewall rule review procedure",
                    "Rule review reports (semi-annual)",
                    "Identified and removed rule documentation",
                    "Review completion sign-offs",
                    "Remediation tracking records"
                ],
                common_gaps=[
                    "Reviews not conducted semi-annually",
                    "Reviews not documented",
                    "Unnecessary rules not removed",
                    "No formal review process"
                ],
                remediation_guidance="Establish formal firewall rule review process. Conduct reviews every 6 months minimum. Document "
                                    "all reviews and findings. Remove unnecessary or overly permissive rules. Track remediation.",
                testing_frequency="Semi-annual firewall rule review"
            ),

            ComplianceControl(
                control_id="PCI-1.3.1",
                name="Inbound Traffic Restriction",
                description="Inbound traffic to the CDE is restricted to only authorized traffic",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 1.3: Network access to and from the cardholder data environment is restricted",
                category="network_security",
                severity="critical",
                pci_requirement_group="Requirements 1-2: Network Security",
                testing_procedures=[
                    "Review inbound traffic restrictions",
                    "Test firewall rules for inbound traffic",
                    "Examine default-deny configuration",
                    "Assess business justification for allowed traffic",
                    "Validate only necessary ports/protocols allowed"
                ],
                evidence_requirements=[
                    "Inbound traffic policy",
                    "Firewall rules for inbound traffic",
                    "Business justification documentation",
                    "Allowed ports/protocols list",
                    "Default-deny configuration evidence"
                ],
                common_gaps=[
                    "Default-allow instead of default-deny",
                    "Excessive inbound traffic allowed",
                    "No business justification for rules",
                    "Unnecessary ports/services accessible"
                ],
                remediation_guidance="Configure default-deny for all inbound traffic. Only allow necessary traffic with documented "
                                    "business justification. Restrict to minimum required ports/protocols. Review and validate regularly.",
                testing_frequency="Quarterly review with firewall rules"
            ),

            ComplianceControl(
                control_id="PCI-1.4.1",
                name="Wireless Network Security",
                description="Network security controls are implemented for all wireless networks connected to the CDE or transmitting account data",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 1.4: Network connections between trusted and untrusted networks are controlled",
                category="network_security",
                severity="critical",
                pci_requirement_group="Requirements 1-2: Network Security",
                testing_procedures=[
                    "Review wireless network security controls",
                    "Test wireless encryption (WPA2/WPA3)",
                    "Assess wireless network segmentation",
                    "Examine wireless authentication",
                    "Review rogue wireless detection"
                ],
                evidence_requirements=[
                    "Wireless security policy",
                    "Wireless network configurations (encryption, auth)",
                    "Wireless network segmentation evidence",
                    "Rogue access point detection logs",
                    "Wireless security assessment results"
                ],
                common_gaps=[
                    "Weak wireless encryption (WEP, WPA)",
                    "Wireless networks not segmented from CDE",
                    "No rogue AP detection",
                    "Shared wireless credentials"
                ],
                remediation_guidance="Require WPA2 or WPA3 encryption for all wireless networks. Segment wireless from CDE with "
                                    "firewall. Implement 802.1X authentication. Deploy rogue wireless detection. Use unique credentials.",
                testing_frequency="Quarterly wireless security assessment"
            ),

            # ============================================================
            # Requirement 2: Apply Secure Configurations
            # ============================================================
            ComplianceControl(
                control_id="PCI-2.1.1",
                name="Vendor Default Removal",
                description="All vendor-supplied default passwords are changed before system components are placed into production",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 2.1: Processes and mechanisms for applying secure configurations are defined",
                category="configuration_management",
                severity="critical",
                pci_requirement_group="Requirements 1-2: Network Security",
                testing_procedures=[
                    "Review system hardening procedures",
                    "Test for vendor default passwords",
                    "Examine new system deployment checklist",
                    "Assess password change documentation",
                    "Validate no defaults in production"
                ],
                evidence_requirements=[
                    "System hardening standards",
                    "Deployment checklist with default removal",
                    "Password change documentation",
                    "Vulnerability scan results (no default passwords)",
                    "Configuration verification records"
                ],
                common_gaps=[
                    "Vendor defaults not changed",
                    "No systematic removal process",
                    "Defaults discovered in production",
                    "Incomplete hardening checklist"
                ],
                remediation_guidance="Change all vendor default passwords before production deployment. Create hardening checklist "
                                    "including default removal. Scan for defaults regularly. Document all password changes.",
                testing_frequency="During deployment; quarterly vulnerability scans"
            ),

            ComplianceControl(
                control_id="PCI-2.2.1",
                name="Secure Configuration Standards",
                description="Configuration standards are defined and implemented for all system components",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 2.2: System components are configured and managed securely",
                category="configuration_management",
                severity="critical",
                pci_requirement_group="Requirements 1-2: Network Security",
                testing_procedures=[
                    "Review configuration standards documentation",
                    "Examine hardening guides for each system type",
                    "Test implementation of standards",
                    "Assess configuration management process",
                    "Review configuration drift detection"
                ],
                evidence_requirements=[
                    "Configuration standards for all system types",
                    "Hardening guides (OS, database, application)",
                    "Configuration baseline documentation",
                    "Configuration compliance reports",
                    "Configuration management procedures"
                ],
                common_gaps=[
                    "No documented configuration standards",
                    "Standards not based on industry best practices",
                    "Inconsistent implementation across systems",
                    "No configuration drift monitoring"
                ],
                remediation_guidance="Develop configuration standards based on industry benchmarks (CIS, DISA STIG). Create hardening "
                                    "guides for all system types. Implement configuration management. Monitor for drift from baseline.",
                testing_frequency="Annual standard review; continuous drift monitoring"
            ),

            ComplianceControl(
                control_id="PCI-2.2.4",
                name="Unnecessary Services Disabled",
                description="Only necessary services, protocols, daemons, and functions are enabled, and all unnecessary functionality is disabled or removed",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 2.2.4: Only necessary services and protocols are enabled",
                category="configuration_management",
                severity="high",
                pci_requirement_group="Requirements 1-2: Network Security",
                testing_procedures=[
                    "Review enabled services and protocols",
                    "Test for unnecessary services",
                    "Examine business justification for enabled services",
                    "Assess service hardening",
                    "Review service inventory"
                ],
                evidence_requirements=[
                    "Authorized services and protocols list",
                    "Business justification documentation",
                    "Service inventory",
                    "Unnecessary service removal records",
                    "Port scan results"
                ],
                common_gaps=[
                    "Excessive services enabled",
                    "No inventory of enabled services",
                    "No business justification",
                    "Insecure protocols enabled (Telnet, FTP)"
                ],
                remediation_guidance="Inventory all enabled services and protocols. Disable or remove unnecessary services. Document "
                                    "business justification for required services. Replace insecure protocols with secure alternatives.",
                testing_frequency="Quarterly service review; annual assessment"
            ),

            # ============================================================
            # Requirement 3: Protect Stored Account Data
            # ============================================================
            ComplianceControl(
                control_id="PCI-3.1.1",
                name="Data Retention and Disposal",
                description="A data retention and disposal policy is documented and implemented",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 3.1: Account data storage is kept to a minimum",
                category="data_protection",
                severity="critical",
                pci_requirement_group="Requirements 3-4: Data Protection",
                testing_procedures=[
                    "Review data retention policy",
                    "Examine data disposal procedures",
                    "Test automated data deletion",
                    "Assess retention period compliance",
                    "Review disposal verification"
                ],
                evidence_requirements=[
                    "Data retention and disposal policy",
                    "Retention period definitions",
                    "Automated deletion job configurations",
                    "Disposal verification records",
                    "Data storage inventory"
                ],
                common_gaps=[
                    "No data retention policy",
                    "Data retained longer than necessary",
                    "No automated disposal",
                    "Disposal not verified"
                ],
                remediation_guidance="Document data retention policy with specific retention periods. Implement automated data disposal "
                                    "processes. Verify disposal completion. Limit retention to business necessity and legal requirements.",
                testing_frequency="Quarterly data retention review"
            ),

            ComplianceControl(
                control_id="PCI-3.2.1",
                name="No Storage of Sensitive Authentication Data After Authorization",
                description="Sensitive authentication data (SAD) is not retained after authorization, even if encrypted",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 3.2: Storage of sensitive authentication data is restricted",
                category="data_protection",
                severity="critical",
                pci_requirement_group="Requirements 3-4: Data Protection",
                testing_procedures=[
                    "Review data storage practices",
                    "Test for SAD storage (CAV2/CVC2/CVV2, full track, PIN)",
                    "Examine application code and databases",
                    "Assess log file contents",
                    "Review SAD purge procedures"
                ],
                evidence_requirements=[
                    "SAD storage prohibition policy",
                    "Application code review results",
                    "Database schema and sample data",
                    "Log file samples",
                    "Data discovery scan results"
                ],
                common_gaps=[
                    "SAD stored in databases or logs",
                    "Full track data retained",
                    "CVV2/CVC2 stored",
                    "PIN blocks stored improperly"
                ],
                remediation_guidance="Immediately purge all sensitive authentication data after authorization. Review and remediate "
                                    "application code storing SAD. Implement automated SAD detection and purging. Never store full track, CVV2, or PIN.",
                testing_frequency="Quarterly data discovery scans"
            ),

            ComplianceControl(
                control_id="PCI-3.3.1",
                name="PAN Masking",
                description="PAN is masked when displayed (the BIN and last four digits are the maximum number of digits to be displayed)",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 3.3: Sensitive authentication data is secured",
                category="data_protection",
                severity="high",
                pci_requirement_group="Requirements 3-4: Data Protection",
                testing_procedures=[
                    "Review PAN display requirements",
                    "Test PAN masking in applications",
                    "Examine screen displays and reports",
                    "Assess masking exceptions and justifications",
                    "Review unmasked PAN access controls"
                ],
                evidence_requirements=[
                    "PAN display policy",
                    "Application masking configuration",
                    "Screen and report samples",
                    "Business justification for full PAN display",
                    "Access controls for unmasked PAN"
                ],
                common_gaps=[
                    "PAN displayed in clear text",
                    "More than BIN+last 4 displayed",
                    "No business justification for full PAN",
                    "Insufficient access controls for unmasked PAN"
                ],
                remediation_guidance="Implement PAN masking showing only BIN and last 4 digits. Restrict full PAN display to legitimate "
                                    "business need with documented justification. Implement strict access controls for unmasked PAN viewing.",
                testing_frequency="Annual application review"
            ),

            ComplianceControl(
                control_id="PCI-3.5.1",
                name="Encryption of Stored PAN",
                description="PAN is rendered unreadable anywhere it is stored using strong cryptography",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 3.5: Primary account number is secured wherever stored",
                category="cryptography",
                severity="critical",
                pci_requirement_group="Requirements 3-4: Data Protection",
                testing_procedures=[
                    "Review PAN encryption implementation",
                    "Assess encryption strength (AES-256 minimum)",
                    "Examine encryption coverage (databases, files, backups)",
                    "Test encryption key management",
                    "Validate disk/database-level encryption"
                ],
                evidence_requirements=[
                    "PAN encryption policy",
                    "Encryption implementation documentation",
                    "Encryption algorithm configuration",
                    "Key management procedures",
                    "Encryption verification reports"
                ],
                common_gaps=[
                    "PAN stored in clear text",
                    "Weak encryption algorithms",
                    "Insufficient encryption coverage",
                    "Poor key management"
                ],
                remediation_guidance="Encrypt all stored PAN using strong cryptography (AES-256 minimum). Implement encryption at "
                                    "application or database level. Encrypt backups and archives. Use secure key management (HSM or KMS).",
                testing_frequency="Annual encryption review; continuous for new storage"
            ),

            ComplianceControl(
                control_id="PCI-3.6.1",
                name="Cryptographic Key Management",
                description="Cryptographic keys used to protect stored account data are managed securely",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 3.6: Cryptographic keys are managed securely",
                category="cryptography",
                severity="critical",
                pci_requirement_group="Requirements 3-4: Data Protection",
                testing_procedures=[
                    "Review key management procedures",
                    "Assess key generation and strength",
                    "Test key storage security (HSM/KMS)",
                    "Examine key rotation procedures",
                    "Review key access controls"
                ],
                evidence_requirements=[
                    "Key management policy and procedures",
                    "Key generation documentation",
                    "HSM/KMS configuration",
                    "Key rotation records",
                    "Key custodian access logs"
                ],
                common_gaps=[
                    "Keys stored with encrypted data",
                    "No key rotation",
                    "Keys in clear text or weak protection",
                    "Insufficient key access controls"
                ],
                remediation_guidance="Store keys separately from encrypted data using HSM or KMS. Implement cryptographic key rotation "
                                    "annually. Generate keys using industry-accepted methods. Restrict key access to minimum personnel.",
                testing_frequency="Annual key management review; continuous access monitoring"
            ),

            # ============================================================
            # Requirement 4: Protect Cardholder Data with Strong Cryptography During Transmission
            # ============================================================
            ComplianceControl(
                control_id="PCI-4.1.1",
                name="PAN Encryption During Transmission",
                description="Strong cryptography and security protocols are implemented to safeguard PAN during transmission over open, public networks",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 4.1: Processes and mechanisms for protecting cardholder data with strong cryptography during transmission are defined",
                category="cryptography",
                severity="critical",
                pci_requirement_group="Requirements 3-4: Data Protection",
                testing_procedures=[
                    "Review encryption in transit policy",
                    "Test TLS implementation and configuration",
                    "Assess encryption protocol versions (TLS 1.2+)",
                    "Examine certificate management",
                    "Review encryption coverage for all transmission paths"
                ],
                evidence_requirements=[
                    "Encryption in transit policy",
                    "TLS configuration documentation",
                    "SSL Labs or similar scan results",
                    "Certificate inventory and management",
                    "Network encryption architecture"
                ],
                common_gaps=[
                    "Weak TLS versions allowed (TLS 1.0/1.1)",
                    "Weak cipher suites enabled",
                    "PAN transmitted unencrypted",
                    "Self-signed or expired certificates"
                ],
                remediation_guidance="Require TLS 1.2 or higher for all PAN transmission. Disable weak ciphers and protocols. Use "
                                    "trusted certificates from recognized CAs. Implement automated certificate renewal. Never send PAN via email or chat.",
                testing_frequency="Quarterly TLS configuration review"
            ),

            ComplianceControl(
                control_id="PCI-4.2.1",
                name="End-User Messaging Technologies",
                description="PAN is not sent via end-user messaging technologies (e.g., email, chat, SMS, instant messaging)",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 4.2: PAN is protected with strong cryptography whenever it is sent over end-user messaging technologies",
                category="data_protection",
                severity="critical",
                pci_requirement_group="Requirements 3-4: Data Protection",
                testing_procedures=[
                    "Review end-user messaging policy",
                    "Test data loss prevention (DLP) controls",
                    "Examine email/messaging monitoring",
                    "Assess PAN transmission detection",
                    "Review user awareness training"
                ],
                evidence_requirements=[
                    "Policy prohibiting PAN via messaging",
                    "DLP configuration and alerts",
                    "Email/messaging monitoring logs",
                    "Security awareness training on PAN handling",
                    "Incident records of policy violations"
                ],
                common_gaps=[
                    "No policy against PAN in email/messaging",
                    "No DLP to detect PAN transmission",
                    "Users unaware of prohibition",
                    "No monitoring or enforcement"
                ],
                remediation_guidance="Implement policy prohibiting PAN transmission via email, chat, SMS. Deploy DLP to detect and "
                                    "block PAN in messaging. Train users on secure PAN handling. Monitor for violations and enforce policy.",
                testing_frequency="Continuous DLP monitoring; annual policy review"
            ),

            # ============================================================
            # Requirement 5: Protect All Systems and Networks from Malicious Software
            # ============================================================
            ComplianceControl(
                control_id="PCI-5.1.1",
                name="Anti-Malware Solution Deployment",
                description="Anti-malware solutions are deployed on all system components, except those identified as not at risk from malware",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 5.1: Processes and mechanisms for protecting all systems and networks from malicious software are defined",
                category="endpoint_security",
                severity="critical",
                pci_requirement_group="Requirements 5-6: Vulnerability Management",
                testing_procedures=[
                    "Review anti-malware deployment coverage",
                    "Assess malware risk evaluation for exceptions",
                    "Test anti-malware functionality",
                    "Examine signature update frequency",
                    "Review endpoint protection monitoring"
                ],
                evidence_requirements=[
                    "Anti-malware policy",
                    "Deployment coverage reports",
                    "Risk assessment for exceptions",
                    "Signature update logs",
                    "Malware detection and remediation records"
                ],
                common_gaps=[
                    "Incomplete anti-malware deployment",
                    "No risk assessment for exceptions",
                    "Signatures not updated regularly",
                    "Anti-malware disabled or not functioning"
                ],
                remediation_guidance="Deploy anti-malware on all systems commonly affected by malware. Document risk assessment for "
                                    "any exceptions. Ensure automatic signature updates. Monitor for disabled or malfunctioning protection.",
                testing_frequency="Weekly deployment compliance review"
            ),

            ComplianceControl(
                control_id="PCI-5.2.1",
                name="Anti-Malware Current and Active",
                description="All anti-malware solutions are kept current, performing periodic scans, and generating audit logs",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 5.2: Malicious software is prevented, detected, and addressed",
                category="endpoint_security",
                severity="critical",
                pci_requirement_group="Requirements 5-6: Vulnerability Management",
                testing_procedures=[
                    "Test anti-malware signature currency",
                    "Review periodic scan configuration",
                    "Examine malware detection logs",
                    "Assess real-time protection status",
                    "Review malware remediation procedures"
                ],
                evidence_requirements=[
                    "Anti-malware configuration (real-time, periodic scans)",
                    "Signature update status reports",
                    "Scan logs and schedules",
                    "Malware detection and remediation logs",
                    "Audit log retention evidence"
                ],
                common_gaps=[
                    "Outdated malware signatures",
                    "Periodic scans not configured",
                    "Real-time protection disabled",
                    "Logs not retained or reviewed"
                ],
                remediation_guidance="Configure automatic signature updates (at least daily). Enable real-time protection and periodic "
                                    "full scans (weekly minimum). Retain and review anti-malware logs. Investigate and remediate all detections.",
                testing_frequency="Weekly signature currency check; monthly log review"
            ),

            ComplianceControl(
                control_id="PCI-5.3.1",
                name="Anti-Malware Not Alterable by Users",
                description="Anti-malware solutions cannot be disabled or altered by users unless specifically documented and authorized",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 5.3: Anti-malware solutions are actively running and cannot be disabled or altered",
                category="endpoint_security",
                severity="high",
                pci_requirement_group="Requirements 5-6: Vulnerability Management",
                testing_procedures=[
                    "Test user ability to disable anti-malware",
                    "Review administrative controls",
                    "Examine exception approval process",
                    "Assess tamper protection configuration",
                    "Review monitoring for disabled protection"
                ],
                evidence_requirements=[
                    "Anti-malware tamper protection configuration",
                    "User permission restrictions",
                    "Exception approval documentation",
                    "Monitoring alerts for disabled protection",
                    "Remediation records for unauthorized changes"
                ],
                common_gaps=[
                    "Users can disable anti-malware",
                    "No tamper protection enabled",
                    "Exceptions not properly authorized",
                    "No monitoring for disabled protection"
                ],
                remediation_guidance="Enable anti-malware tamper protection. Remove user ability to disable or alter protection. "
                                    "Require documented authorization for any exceptions. Monitor and alert on disabled protection.",
                testing_frequency="Quarterly configuration review"
            ),

            ComplianceControl(
                control_id="PCI-5.4.1",
                name="Phishing Attack Awareness",
                description="Personnel are made aware of the threats posed by phishing attacks and are trained on how to detect and report phishing attempts",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 5.4: Phishing attacks are detected and addressed",
                category="security_awareness",
                severity="high",
                pci_requirement_group="Requirements 5-6: Vulnerability Management",
                testing_procedures=[
                    "Review phishing awareness training content",
                    "Assess training frequency and completion",
                    "Examine phishing simulation testing",
                    "Review phishing incident reporting process",
                    "Test email filtering and protection"
                ],
                evidence_requirements=[
                    "Phishing awareness training materials",
                    "Training completion records",
                    "Phishing simulation results",
                    "Incident reporting procedures",
                    "Email security gateway configuration"
                ],
                common_gaps=[
                    "No phishing awareness training",
                    "Training not conducted regularly",
                    "No phishing simulations",
                    "Unclear reporting process"
                ],
                remediation_guidance="Provide annual phishing awareness training to all personnel. Conduct periodic phishing simulations. "
                                    "Establish clear reporting process for suspicious emails. Implement email filtering and anti-phishing controls.",
                testing_frequency="Annual training; quarterly simulations"
            ),

            # ============================================================
            # Requirement 6: Develop and Maintain Secure Systems and Software
            # ============================================================
            ComplianceControl(
                control_id="PCI-6.1.1",
                name="Security Vulnerability Identification",
                description="Processes are defined and maintained for identifying and managing security vulnerabilities",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 6.1: Processes and mechanisms for developing and maintaining secure systems are defined",
                category="vulnerability_management",
                severity="critical",
                pci_requirement_group="Requirements 5-6: Vulnerability Management",
                testing_procedures=[
                    "Review vulnerability management policy",
                    "Assess vulnerability information sources",
                    "Examine vulnerability tracking process",
                    "Test vulnerability prioritization methodology",
                    "Review vulnerability remediation SLAs"
                ],
                evidence_requirements=[
                    "Vulnerability management policy and procedures",
                    "Vulnerability information sources (CVE, vendor bulletins)",
                    "Vulnerability tracking system",
                    "Risk prioritization methodology",
                    "Remediation SLAs and metrics"
                ],
                common_gaps=[
                    "No formal vulnerability management process",
                    "Vulnerabilities not tracked systematically",
                    "No risk-based prioritization",
                    "Remediation timelines not defined"
                ],
                remediation_guidance="Implement vulnerability management program with defined processes. Subscribe to vulnerability "
                                    "information sources. Track vulnerabilities in centralized system. Prioritize based on risk. Define remediation SLAs.",
                testing_frequency="Continuous vulnerability identification"
            ),

            ComplianceControl(
                control_id="PCI-6.2.1",
                name="Bespoke Software Security",
                description="Bespoke and custom software are developed securely based on industry standards and best practices",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 6.2: Bespoke and custom software are developed securely",
                category="application_security",
                severity="critical",
                pci_requirement_group="Requirements 5-6: Vulnerability Management",
                testing_procedures=[
                    "Review secure development lifecycle (SDLC)",
                    "Assess secure coding standards",
                    "Examine developer security training",
                    "Test code review processes",
                    "Review security testing integration"
                ],
                evidence_requirements=[
                    "Secure SDLC documentation",
                    "Secure coding standards (OWASP, SANS)",
                    "Developer training records",
                    "Code review procedures and samples",
                    "Security testing tools and results"
                ],
                common_gaps=[
                    "No secure SDLC implemented",
                    "Developers not trained in secure coding",
                    "No code reviews or security testing",
                    "Security not integrated into development"
                ],
                remediation_guidance="Implement secure SDLC with security integrated throughout. Adopt secure coding standards (OWASP). "
                                    "Train developers annually on secure coding. Conduct code reviews and security testing for all changes.",
                testing_frequency="Annual SDLC review; per-release security testing"
            ),

            ComplianceControl(
                control_id="PCI-6.3.1",
                name="Security Vulnerabilities Identified and Addressed",
                description="Security vulnerabilities are identified and addressed throughout the SDLC",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 6.3: Security vulnerabilities are identified and addressed",
                category="vulnerability_management",
                severity="critical",
                pci_requirement_group="Requirements 5-6: Vulnerability Management",
                testing_procedures=[
                    "Review vulnerability remediation timelines",
                    "Assess patch deployment process",
                    "Test critical patch deployment (within 30 days)",
                    "Examine compensating controls for unpatched systems",
                    "Review patch testing procedures"
                ],
                evidence_requirements=[
                    "Vulnerability remediation policy (risk-based timelines)",
                    "Patch deployment records",
                    "Critical vulnerability remediation tracking",
                    "Compensating control documentation",
                    "Patch testing procedures"
                ],
                common_gaps=[
                    "Patches not applied within required timeframes",
                    "No risk-based remediation prioritization",
                    "Patches not tested before deployment",
                    "No compensating controls for delayed patches"
                ],
                remediation_guidance="Define risk-based remediation timelines (critical: 30 days maximum). Implement patch management "
                                    "process with testing. Track and report remediation status. Document compensating controls if patching delayed.",
                testing_frequency="Monthly patch compliance review"
            ),

            ComplianceControl(
                control_id="PCI-6.4.1",
                name="Public-Facing Web Application Protection",
                description="Public-facing web applications are protected against attacks via manual and automated application security testing",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 6.4: Public-facing web applications are protected against attacks",
                category="application_security",
                severity="critical",
                pci_requirement_group="Requirements 5-6: Vulnerability Management",
                testing_procedures=[
                    "Review web application security testing",
                    "Assess manual penetration testing frequency (annual)",
                    "Examine automated vulnerability scanning",
                    "Test WAF deployment and configuration",
                    "Review application security assessments"
                ],
                evidence_requirements=[
                    "Web application security policy",
                    "Annual penetration test reports",
                    "Automated vulnerability scan results",
                    "Web application firewall (WAF) configuration",
                    "Application security assessment schedule"
                ],
                common_gaps=[
                    "No regular web application security testing",
                    "WAF not deployed or misconfigured",
                    "Penetration tests not conducted annually",
                    "Vulnerabilities not remediated"
                ],
                remediation_guidance="Conduct annual manual penetration testing of public-facing web applications. Perform automated "
                                    "vulnerability scanning quarterly. Deploy and properly configure WAF. Remediate identified vulnerabilities promptly.",
                testing_frequency="Annual penetration test; quarterly automated scans"
            ),

            # ============================================================
            # Requirement 7: Restrict Access to System Components and Cardholder Data
            # ============================================================
            ComplianceControl(
                control_id="PCI-7.1.1",
                name="Access Control System and Processes",
                description="Processes and mechanisms for restricting access to system components and cardholder data by business need-to-know are defined",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 7.1: Processes and mechanisms for restricting access are defined",
                category="access_control",
                severity="critical",
                pci_requirement_group="Requirements 7-9: Access Control",
                testing_procedures=[
                    "Review access control policy",
                    "Assess need-to-know and least privilege principles",
                    "Examine role definition process",
                    "Test access request and approval workflow",
                    "Review access control system documentation"
                ],
                evidence_requirements=[
                    "Access control policy",
                    "Role definitions and descriptions",
                    "Access request procedures",
                    "Approval workflow documentation",
                    "Access control system configuration"
                ],
                common_gaps=[
                    "No formal access control policy",
                    "Need-to-know not enforced",
                    "Roles not formally defined",
                    "No approval process for access requests"
                ],
                remediation_guidance="Implement comprehensive access control policy based on need-to-know and least privilege. "
                                    "Define roles with specific access requirements. Require approval for all access requests. Document access control system.",
                testing_frequency="Annual policy review"
            ),

            ComplianceControl(
                control_id="PCI-7.2.1",
                name="User Access Based on Need-to-Know",
                description="Access to system components and data is limited to only those individuals whose job requires such access",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 7.2: Access to system components and data is appropriately defined and assigned",
                category="access_control",
                severity="critical",
                pci_requirement_group="Requirements 7-9: Access Control",
                testing_procedures=[
                    "Review user access assignments",
                    "Test least privilege implementation",
                    "Assess role-based access control (RBAC)",
                    "Examine access justifications",
                    "Review excessive access identification"
                ],
                evidence_requirements=[
                    "User access listings by system/role",
                    "Access justification documentation",
                    "RBAC configuration",
                    "Access review results showing need-to-know",
                    "Excessive access remediation records"
                ],
                common_gaps=[
                    "Excessive user access (more than needed)",
                    "No role-based access control",
                    "Access not justified by job function",
                    "Default 'All Access' permissions"
                ],
                remediation_guidance="Implement role-based access control aligned with job functions. Grant minimum access required. "
                                    "Require and document business justification for access. Review and remove excessive access regularly.",
                testing_frequency="Quarterly access reviews"
            ),

            ComplianceControl(
                control_id="PCI-7.3.1",
                name="User Access Review and Recertification",
                description="Access rights are reviewed and recertified at least once every six months",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 7.3: Access is reviewed and recertified periodically",
                category="access_control",
                severity="critical",
                pci_requirement_group="Requirements 7-9: Access Control",
                testing_procedures=[
                    "Review access review procedures",
                    "Examine recent access reviews (last 6 months)",
                    "Assess review completeness and documentation",
                    "Test remediation of unauthorized access",
                    "Validate management participation in reviews"
                ],
                evidence_requirements=[
                    "Access review procedures",
                    "Completed access review reports (semi-annual)",
                    "Management certifications/approvals",
                    "Access removal/modification records",
                    "Review completion tracking"
                ],
                common_gaps=[
                    "Access reviews not conducted semi-annually",
                    "Reviews incomplete or not documented",
                    "Unauthorized access not removed",
                    "Managers don't participate in reviews"
                ],
                remediation_guidance="Conduct comprehensive access reviews every 6 months minimum. Require manager certification of "
                                    "their team's access. Remove unauthorized or excessive access within 7 days. Document all reviews and remediation.",
                testing_frequency="Semi-annual access review"
            ),

            # ============================================================
            # Requirement 8: Identify Users and Authenticate Access
            # ============================================================
            ComplianceControl(
                control_id="PCI-8.1.1",
                name="User Identification for All Access",
                description="All users are assigned a unique ID before access to system components is allowed",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 8.1: Processes and mechanisms for identifying users and authenticating access are defined",
                category="access_control",
                severity="critical",
                pci_requirement_group="Requirements 7-9: Access Control",
                testing_procedures=[
                    "Review user identification policy",
                    "Test for shared or generic accounts",
                    "Assess unique ID enforcement",
                    "Examine service account management",
                    "Review application authentication"
                ],
                evidence_requirements=[
                    "User identification policy",
                    "User account listings",
                    "Service account inventory and justifications",
                    "Evidence of unique IDs",
                    "Shared account risk assessments (if any)"
                ],
                common_gaps=[
                    "Shared accounts in use",
                    "Generic accounts not properly managed",
                    "No unique IDs for all users",
                    "Service accounts used interactively"
                ],
                remediation_guidance="Assign unique ID to every user. Eliminate shared user accounts. Manage service accounts separately "
                                    "with restrictions. Enforce unique ID requirement for all system access.",
                testing_frequency="Quarterly user account review"
            ),

            ComplianceControl(
                control_id="PCI-8.2.1",
                name="Strong Authentication for Users",
                description="Strong authentication is implemented for all users through multi-factor authentication or strong cryptographic mechanisms",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 8.2: User identification and authentication are managed",
                category="access_control",
                severity="critical",
                pci_requirement_group="Requirements 7-9: Access Control",
                testing_procedures=[
                    "Review authentication requirements",
                    "Test MFA implementation for CDE access",
                    "Assess MFA for remote access",
                    "Examine MFA for administrative access",
                    "Review authentication strength"
                ],
                evidence_requirements=[
                    "Authentication policy and standards",
                    "MFA configuration and enrollment",
                    "Remote access authentication settings",
                    "Administrative access MFA evidence",
                    "MFA compliance reports"
                ],
                common_gaps=[
                    "MFA not required for CDE access",
                    "Weak MFA methods (SMS OTP)",
                    "MFA not enforced for administrators",
                    "Remote access without MFA"
                ],
                remediation_guidance="Require MFA for all access to CDE and all remote access. Use strong MFA methods (authenticator "
                                    "app, hardware token). Enforce MFA for all administrative and privileged access. Monitor MFA compliance.",
                testing_frequency="Monthly MFA compliance review"
            ),

            ComplianceControl(
                control_id="PCI-8.3.1",
                name="Password Complexity and Strength",
                description="Strong passwords/passphrases are required for all system components",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 8.3: Strong authentication is established and managed",
                category="access_control",
                severity="high",
                pci_requirement_group="Requirements 7-9: Access Control",
                testing_procedures=[
                    "Review password policy requirements",
                    "Test password complexity enforcement",
                    "Assess password length requirements (12+ characters)",
                    "Examine password history and reuse",
                    "Review password expiration (90 days maximum)"
                ],
                evidence_requirements=[
                    "Password policy documentation",
                    "System password configuration settings",
                    "Password complexity requirements",
                    "Password age and history settings",
                    "Password compliance reports"
                ],
                common_gaps=[
                    "Weak password requirements (<12 characters)",
                    "No complexity requirements enforced",
                    "Passwords don't expire or too long (>90 days)",
                    "Password reuse allowed"
                ],
                remediation_guidance="Require passwords minimum 12 characters (or 8 with complexity). Enforce complexity (upper, lower, "
                                    "numeric, special). Set maximum password age of 90 days. Prevent password reuse (remember last 4 minimum).",
                testing_frequency="Annual password policy review; continuous enforcement"
            ),

            ComplianceControl(
                control_id="PCI-8.4.1",
                name="User Account Management",
                description="User accounts are added, deleted, and managed according to defined procedures",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 8.4: Multi-factor authentication is implemented",
                category="access_control",
                severity="critical",
                pci_requirement_group="Requirements 7-9: Access Control",
                testing_procedures=[
                    "Review account provisioning procedures",
                    "Test new account approval process",
                    "Assess account deactivation/termination",
                    "Examine inactive account suspension (90 days)",
                    "Review account modification processes"
                ],
                evidence_requirements=[
                    "Account management procedures",
                    "Account request approvals",
                    "Termination checklists and evidence",
                    "Inactive account suspension reports",
                    "Account modification approvals"
                ],
                common_gaps=[
                    "Accounts created without approval",
                    "Terminated user accounts not disabled",
                    "Inactive accounts not suspended",
                    "No formal account management process"
                ],
                remediation_guidance="Require approval for all new account requests. Disable accounts immediately upon termination. "
                                    "Suspend inactive accounts after 90 days. Require approval for account modifications. Document all account changes.",
                testing_frequency="Monthly account management review"
            ),

            # ============================================================
            # Requirement 9: Restrict Physical Access to Cardholder Data
            # ============================================================
            ComplianceControl(
                control_id="PCI-9.1.1",
                name="Physical Access Controls",
                description="Physical access to systems in the CDE is controlled through appropriate entry controls",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 9.1: Processes and mechanisms for restricting physical access are defined",
                category="physical_security",
                severity="high",
                pci_requirement_group="Requirements 7-9: Access Control",
                testing_procedures=[
                    "Review physical security policies",
                    "Inspect data center and office access controls",
                    "Test badge access system",
                    "Assess physical access restrictions to CDE",
                    "Review security guard or monitoring"
                ],
                evidence_requirements=[
                    "Physical security policy",
                    "Badge access system configuration",
                    "Physical access control photos/documentation",
                    "Access control lists for sensitive areas",
                    "Security monitoring records"
                ],
                common_gaps=[
                    "Inadequate physical access controls",
                    "No badge access or access logging",
                    "CDE systems in unsecured areas",
                    "No monitoring or security guards"
                ],
                remediation_guidance="Implement badge access controls for all CDE areas. Install cameras or monitoring. Restrict "
                                    "physical access to business-necessary personnel. Log all access events. Regularly review access logs.",
                testing_frequency="Quarterly physical security review"
            ),

            ComplianceControl(
                control_id="PCI-9.2.1",
                name="Visitor Management",
                description="Visitors to facilities where the CDE is located are authorized and escorted at all times",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 9.2: Physical access to the CDE is controlled and monitored",
                category="physical_security",
                severity="high",
                pci_requirement_group="Requirements 7-9: Access Control",
                testing_procedures=[
                    "Review visitor management procedures",
                    "Test visitor sign-in and badge process",
                    "Assess visitor escort requirements",
                    "Examine visitor access logs",
                    "Review visitor badge return process"
                ],
                evidence_requirements=[
                    "Visitor management policy",
                    "Visitor logs with sign-in/out",
                    "Visitor badge issuance records",
                    "Escort assignment documentation",
                    "Badge return tracking"
                ],
                common_gaps=[
                    "No visitor sign-in or badges",
                    "Visitors not escorted",
                    "Visitor access not logged",
                    "No visitor badge retrieval"
                ],
                remediation_guidance="Require visitor sign-in with ID verification. Issue visible visitor badges. Assign escorts for "
                                    "all visitors in CDE areas. Log all visitor access. Retrieve badges upon departure.",
                testing_frequency="Monthly visitor log review"
            ),

            ComplianceControl(
                control_id="PCI-9.3.1",
                name="Physical Media Handling",
                description="Physical media containing cardholder data is securely stored, accessed, distributed, and destroyed",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 9.3: Physical access for personnel and visitors is authorized and managed",
                category="physical_security",
                severity="high",
                pci_requirement_group="Requirements 7-9: Access Control",
                testing_procedures=[
                    "Review media handling procedures",
                    "Assess media storage security",
                    "Test media destruction methods",
                    "Examine media tracking and inventory",
                    "Review media distribution controls"
                ],
                evidence_requirements=[
                    "Media handling policy and procedures",
                    "Secure media storage configuration",
                    "Media destruction certificates",
                    "Media inventory and tracking logs",
                    "Media distribution approvals"
                ],
                common_gaps=[
                    "Media not securely stored",
                    "No media destruction procedures",
                    "Media not tracked or inventoried",
                    "Insecure media disposal"
                ],
                remediation_guidance="Store media containing cardholder data in secure location. Track media inventory. Require "
                                    "approval for media distribution. Destroy media securely (shred, degauss) with certificates. Encrypt media.",
                testing_frequency="Annual media handling review"
            ),

            # ============================================================
            # Requirement 10: Log and Monitor All Access
            # ============================================================
            ComplianceControl(
                control_id="PCI-10.1.1",
                name="Logging and Monitoring Processes",
                description="Processes and mechanisms for logging and monitoring all access to system components and cardholder data are defined",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 10.1: Processes and mechanisms for logging and monitoring are defined",
                category="logging_monitoring",
                severity="critical",
                pci_requirement_group="Requirements 10-11: Monitoring & Testing",
                testing_procedures=[
                    "Review logging and monitoring policy",
                    "Assess audit log requirements definition",
                    "Examine log retention requirements (1 year)",
                    "Test log centralization and correlation",
                    "Review log monitoring procedures"
                ],
                evidence_requirements=[
                    "Logging and monitoring policy",
                    "Audit log requirements documentation",
                    "Log retention configuration (1 year minimum)",
                    "SIEM or log management system evidence",
                    "Log review procedures and schedules"
                ],
                common_gaps=[
                    "Incomplete logging of security events",
                    "Logs not retained for 1 year",
                    "No centralized log management",
                    "Logs not reviewed regularly"
                ],
                remediation_guidance="Define comprehensive audit logging requirements. Implement centralized log management (SIEM). "
                                    "Retain logs for minimum 1 year (3 months online). Review logs at least daily. Protect log integrity.",
                testing_frequency="Continuous logging; daily log review"
            ),

            ComplianceControl(
                control_id="PCI-10.2.1",
                name="Audit Log Events",
                description="Audit logs capture all individual user access to cardholder data, actions by privileged users, access to audit logs, and security events",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 10.2: Audit logs are implemented to support anomaly detection",
                category="logging_monitoring",
                severity="critical",
                pci_requirement_group="Requirements 10-11: Monitoring & Testing",
                testing_procedures=[
                    "Review logged event types",
                    "Test logging of user access to cardholder data",
                    "Assess privileged action logging",
                    "Examine audit log access logging",
                    "Review security event logging"
                ],
                evidence_requirements=[
                    "Logged event types documentation",
                    "Sample logs showing required events",
                    "Privileged access logs",
                    "Audit log access records",
                    "Security event logs (authentication, authorization failures)"
                ],
                common_gaps=[
                    "Insufficient event logging",
                    "Privileged actions not logged",
                    "No logging of audit log access",
                    "Authentication failures not logged"
                ],
                remediation_guidance="Configure logging for all required events per PCI-DSS 10.2. Log individual user access to CHD, "
                                    "all privileged actions, audit log access, authentication/authorization attempts, security policy changes.",
                testing_frequency="Annual logging configuration review"
            ),

            ComplianceControl(
                control_id="PCI-10.3.1",
                name="Audit Log Details",
                description="Audit log entries include user identification, event type, date/time, success/failure, origination, identity of affected resources",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 10.3: Audit logs are protected from destruction and unauthorized modifications",
                category="logging_monitoring",
                severity="critical",
                pci_requirement_group="Requirements 10-11: Monitoring & Testing",
                testing_procedures=[
                    "Review audit log detail requirements",
                    "Examine sample logs for completeness",
                    "Assess log field capture (user, timestamp, event, etc.)",
                    "Test log detail adequacy for investigation",
                    "Review log standardization"
                ],
                evidence_requirements=[
                    "Audit log format and field requirements",
                    "Sample audit logs with all required fields",
                    "Log detail mapping to PCI requirements",
                    "Investigation examples using logs",
                    "Time synchronization evidence"
                ],
                common_gaps=[
                    "Logs missing required fields",
                    "No user identification in logs",
                    "Timestamps inaccurate or missing",
                    "Insufficient detail for investigation"
                ],
                remediation_guidance="Configure logging to capture all required fields: user ID, event type, date/time, success/failure, "
                                    "origination, affected resource. Synchronize time across all systems. Standardize log formats.",
                testing_frequency="Annual log format review"
            ),

            ComplianceControl(
                control_id="PCI-10.4.1",
                name="Audit Log Review",
                description="Audit logs are reviewed to identify anomalies or suspicious activity at least once per day",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 10.4: Audit logs are reviewed to identify anomalies and suspicious activity",
                category="logging_monitoring",
                severity="critical",
                pci_requirement_group="Requirements 10-11: Monitoring & Testing",
                testing_procedures=[
                    "Review log review procedures and frequency",
                    "Examine daily log review evidence",
                    "Assess automated log analysis and alerting",
                    "Test incident escalation from log review",
                    "Review log review coverage (all CDE systems)"
                ],
                evidence_requirements=[
                    "Log review procedures",
                    "Daily log review records/sign-offs",
                    "SIEM rules and alerts configuration",
                    "Incident escalation examples from logs",
                    "Log review coverage documentation"
                ],
                common_gaps=[
                    "Logs not reviewed daily",
                    "Manual review only, no automation",
                    "Anomalies not investigated",
                    "Incomplete log review coverage"
                ],
                remediation_guidance="Review logs from all CDE systems at least daily. Implement automated log analysis and alerting "
                                    "(SIEM). Investigate all anomalies and security events. Document reviews and findings. Escalate incidents.",
                testing_frequency="Daily log review; monthly process review"
            ),

            ComplianceControl(
                control_id="PCI-10.5.1",
                name="Audit Log Integrity and Protection",
                description="Audit logs are protected from unauthorized modifications and destruction",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 10.5: Audit log history is retained and available for analysis",
                category="logging_monitoring",
                severity="critical",
                pci_requirement_group="Requirements 10-11: Monitoring & Testing",
                testing_procedures=[
                    "Review audit log protection controls",
                    "Test log file access restrictions",
                    "Assess log integrity monitoring",
                    "Examine log backup and archival",
                    "Review log encryption or hashing"
                ],
                evidence_requirements=[
                    "Audit log protection policy",
                    "Log file access control configuration",
                    "Log integrity monitoring tools",
                    "Log backup and archival procedures",
                    "Log encryption or hash verification"
                ],
                common_gaps=[
                    "Logs accessible to unauthorized users",
                    "No log integrity monitoring",
                    "Logs not backed up",
                    "Log tampering not detected"
                ],
                remediation_guidance="Restrict audit log access to authorized personnel only. Implement log integrity monitoring "
                                    "(file integrity monitoring, write-once media, log hashing). Back up logs to secure location. Alert on log modifications.",
                testing_frequency="Continuous log integrity monitoring"
            ),

            # ============================================================
            # Requirement 11: Test Security of Systems and Networks Regularly
            # ============================================================
            ComplianceControl(
                control_id="PCI-11.1.1",
                name="Wireless Access Point Inventory and Detection",
                description="Authorized and unauthorized wireless access points are managed and detected",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 11.1: Processes and mechanisms for regularly testing security are defined",
                category="network_security",
                severity="high",
                pci_requirement_group="Requirements 10-11: Monitoring & Testing",
                testing_procedures=[
                    "Review wireless access point inventory",
                    "Test rogue wireless detection tools",
                    "Assess wireless scanning frequency (quarterly)",
                    "Examine wireless access point authorization",
                    "Review wireless incident response"
                ],
                evidence_requirements=[
                    "Authorized wireless access point inventory",
                    "Rogue wireless detection tool configuration",
                    "Quarterly wireless scan results",
                    "Wireless authorization approvals",
                    "Rogue AP incident records"
                ],
                common_gaps=[
                    "No wireless access point inventory",
                    "No rogue wireless detection",
                    "Wireless scans not conducted quarterly",
                    "Unauthorized APs not addressed"
                ],
                remediation_guidance="Inventory all authorized wireless access points. Deploy automated rogue wireless detection. "
                                    "Conduct quarterly wireless scans. Investigate and remove unauthorized access points immediately.",
                testing_frequency="Quarterly wireless scanning"
            ),

            ComplianceControl(
                control_id="PCI-11.3.1",
                name="Internal Vulnerability Scanning",
                description="Internal vulnerability scans are performed at least once every three months and after significant infrastructure or application changes",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 11.3: External and internal vulnerabilities are regularly identified, prioritized, and addressed",
                category="vulnerability_management",
                severity="critical",
                pci_requirement_group="Requirements 10-11: Monitoring & Testing",
                testing_procedures=[
                    "Review internal vulnerability scan schedule",
                    "Examine quarterly scan results",
                    "Assess scan coverage (all CDE systems)",
                    "Test post-change scanning process",
                    "Review vulnerability remediation and rescans"
                ],
                evidence_requirements=[
                    "Internal vulnerability scan policy",
                    "Quarterly scan reports (last 4 quarters)",
                    "Scan coverage evidence (all CDE IPs)",
                    "Post-change scan results",
                    "Rescan evidence showing vulnerabilities resolved"
                ],
                common_gaps=[
                    "Scans not conducted quarterly",
                    "Incomplete scan coverage",
                    "No scanning after changes",
                    "Vulnerabilities not remediated and rescanned"
                ],
                remediation_guidance="Conduct authenticated internal vulnerability scans quarterly and after significant changes. "
                                    "Scan all CDE system components. Remediate vulnerabilities based on risk ranking. Rescan to verify remediation.",
                testing_frequency="Quarterly internal vulnerability scans"
            ),

            ComplianceControl(
                control_id="PCI-11.3.2",
                name="External Vulnerability Scanning",
                description="External vulnerability scans are performed by PCI SSC Approved Scanning Vendor (ASV) at least once every three months",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 11.3: External and internal vulnerabilities are regularly identified",
                category="vulnerability_management",
                severity="critical",
                pci_requirement_group="Requirements 10-11: Monitoring & Testing",
                testing_procedures=[
                    "Review ASV scan schedule and results",
                    "Verify ASV approval status",
                    "Examine quarterly passing ASV scans",
                    "Assess scan coverage (all external IPs)",
                    "Review post-change ASV scanning"
                ],
                evidence_requirements=[
                    "ASV scan reports (last 4 quarters)",
                    "ASV approval/qualification documentation",
                    "Passing scan evidence (CVSS <4.0)",
                    "External IP inventory and scan coverage",
                    "Post-change ASV scan results"
                ],
                common_gaps=[
                    "ASV scans not quarterly",
                    "Scans not by approved ASV",
                    "Vulnerabilities not remediated to passing",
                    "Incomplete external IP coverage"
                ],
                remediation_guidance="Engage PCI SSC approved scanning vendor. Conduct quarterly ASV scans of all external IPs. "
                                    "Remediate vulnerabilities to achieve passing scan (no vulnerabilities ≥4.0 CVSS). Scan after infrastructure changes.",
                testing_frequency="Quarterly external ASV scans"
            ),

            ComplianceControl(
                control_id="PCI-11.4.1",
                name="Penetration Testing",
                description="External and internal penetration testing is performed at least once every 12 months and after significant changes",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 11.4: External and internal penetration testing is regularly performed",
                category="vulnerability_management",
                severity="critical",
                pci_requirement_group="Requirements 10-11: Monitoring & Testing",
                testing_procedures=[
                    "Review penetration testing scope and methodology",
                    "Examine annual penetration test reports",
                    "Assess tester qualifications and independence",
                    "Test post-change penetration testing",
                    "Review remediation of findings and retesting"
                ],
                evidence_requirements=[
                    "Annual penetration test reports (network and application layer)",
                    "Tester qualifications and certifications",
                    "Penetration testing methodology",
                    "Remediation tracking for findings",
                    "Retest evidence showing issues resolved"
                ],
                common_gaps=[
                    "Penetration tests not conducted annually",
                    "Testers not qualified or independent",
                    "Application layer testing not performed",
                    "Findings not remediated and retested"
                ],
                remediation_guidance="Conduct annual penetration testing by qualified and independent testers. Include both network "
                                    "and application layer testing. Test after significant changes. Remediate findings and retest to verify.",
                testing_frequency="Annual penetration testing; post-significant change"
            ),

            ComplianceControl(
                control_id="PCI-11.5.1",
                name="File Integrity Monitoring",
                description="Mechanisms are deployed to detect and alert on unauthorized modification of critical system and content files",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 11.5: Network intrusions and unexpected file changes are detected and responded to",
                category="monitoring",
                severity="high",
                pci_requirement_group="Requirements 10-11: Monitoring & Testing",
                testing_procedures=[
                    "Review file integrity monitoring (FIM) implementation",
                    "Assess FIM coverage (critical files and systems)",
                    "Test FIM alert generation and response",
                    "Examine FIM baseline and update process",
                    "Review FIM alert investigation and resolution"
                ],
                evidence_requirements=[
                    "File integrity monitoring policy and procedures",
                    "FIM tool configuration and coverage",
                    "FIM alerts and investigation records",
                    "FIM baseline documentation",
                    "Change correlation process (FIM vs change management)"
                ],
                common_gaps=[
                    "No file integrity monitoring deployed",
                    "Incomplete FIM coverage",
                    "FIM alerts not investigated",
                    "Changes not correlated with change management"
                ],
                remediation_guidance="Deploy file integrity monitoring for all critical system files, configuration files, and content. "
                                    "Alert on unauthorized changes. Investigate all FIM alerts. Correlate with change management. Update baseline after approved changes.",
                testing_frequency="Continuous FIM monitoring; weekly alert review"
            ),

            # ============================================================
            # Requirement 12: Support Information Security with Organizational Policies and Programs
            # ============================================================
            ComplianceControl(
                control_id="PCI-12.1.1",
                name="Information Security Policy",
                description="An overall information security policy is established, published, maintained, and disseminated to all relevant personnel",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 12.1: A comprehensive information security policy is established and published",
                category="governance",
                severity="high",
                pci_requirement_group="Requirement 12: Security Policy",
                testing_procedures=[
                    "Review information security policy",
                    "Assess policy completeness and scope",
                    "Examine policy approval and publication",
                    "Test policy distribution to personnel",
                    "Review annual policy review process"
                ],
                evidence_requirements=[
                    "Information security policy document",
                    "Policy approval and sign-off",
                    "Policy distribution and acknowledgment records",
                    "Annual policy review documentation",
                    "Policy version control"
                ],
                common_gaps=[
                    "No comprehensive security policy",
                    "Policy not approved by management",
                    "Policy not distributed to all personnel",
                    "Policy not reviewed annually"
                ],
                remediation_guidance="Develop comprehensive information security policy covering all PCI-DSS requirements. Obtain "
                                    "executive/board approval. Distribute to all personnel and require acknowledgment. Review and update annually.",
                testing_frequency="Annual policy review and attestation"
            ),

            ComplianceControl(
                control_id="PCI-12.2.1",
                name="Acceptable Use Policy",
                description="An acceptable use policy is documented and implemented for end-user technologies",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 12.2: Acceptable use policies are defined and implemented",
                category="governance",
                severity="medium",
                pci_requirement_group="Requirement 12: Security Policy",
                testing_procedures=[
                    "Review acceptable use policy",
                    "Assess policy coverage (laptops, mobile, remote access)",
                    "Examine user acknowledgment process",
                    "Test policy enforcement mechanisms",
                    "Review acceptable use violations and enforcement"
                ],
                evidence_requirements=[
                    "Acceptable use policy document",
                    "User signed acknowledgments",
                    "Policy enforcement tools (DLP, web filtering)",
                    "Violation tracking and disciplinary actions",
                    "Policy training materials"
                ],
                common_gaps=[
                    "No acceptable use policy",
                    "Policy doesn't cover all technologies",
                    "Users haven't acknowledged policy",
                    "No enforcement of policy violations"
                ],
                remediation_guidance="Develop acceptable use policy for all end-user technologies. Require user acknowledgment upon "
                                    "hire and annually. Implement technical controls to enforce policy. Address violations with disciplinary action.",
                testing_frequency="Annual policy review; continuous enforcement"
            ),

            ComplianceControl(
                control_id="PCI-12.3.1",
                name="Risk Assessment Process",
                description="A targeted risk analysis is performed at least once every 12 months to identify threats and vulnerabilities",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 12.3: Risks to the cardholder data environment are formally identified, evaluated, and managed",
                category="risk_management",
                severity="critical",
                pci_requirement_group="Requirement 12: Security Policy",
                testing_procedures=[
                    "Review risk assessment methodology",
                    "Examine annual risk assessment results",
                    "Assess threat and vulnerability identification",
                    "Test risk treatment and mitigation planning",
                    "Review risk assessment updates for changes"
                ],
                evidence_requirements=[
                    "Risk assessment methodology",
                    "Annual risk assessment reports",
                    "Identified threats and vulnerabilities",
                    "Risk treatment plans",
                    "Risk assessment updates for significant changes"
                ],
                common_gaps=[
                    "Risk assessments not conducted annually",
                    "Informal or incomplete risk analysis",
                    "Risks not properly documented",
                    "No risk treatment or mitigation plans"
                ],
                remediation_guidance="Conduct formal risk assessment at least annually using documented methodology. Identify threats, "
                                    "vulnerabilities, and likelihood/impact. Develop risk treatment plans. Update assessment after significant changes.",
                testing_frequency="Annual risk assessment; post-significant change"
            ),

            ComplianceControl(
                control_id="PCI-12.5.1",
                name="Security Responsibilities Assignment",
                description="Information security responsibilities are explicitly assigned to individuals or teams",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 12.5: PCI DSS scope is documented and validated",
                category="governance",
                severity="high",
                pci_requirement_group="Requirement 12: Security Policy",
                testing_procedures=[
                    "Review security roles and responsibilities",
                    "Examine organizational charts",
                    "Assess job descriptions for security personnel",
                    "Test awareness of security responsibilities",
                    "Review accountability mechanisms"
                ],
                evidence_requirements=[
                    "Security roles and responsibilities documentation",
                    "Organizational chart showing security functions",
                    "Job descriptions with security duties",
                    "Security team roster and qualifications",
                    "Performance metrics tied to security"
                ],
                common_gaps=[
                    "Security responsibilities not formally assigned",
                    "No dedicated security personnel",
                    "Job descriptions don't include security",
                    "Unclear accountability for security"
                ],
                remediation_guidance="Formally assign security responsibilities to specific individuals or teams. Document in job "
                                    "descriptions and organizational chart. Ensure adequate staffing for security functions. Establish accountability.",
                testing_frequency="Annual review with organizational changes"
            ),

            ComplianceControl(
                control_id="PCI-12.6.1",
                name="Security Awareness Program",
                description="A formal security awareness program is implemented to make all personnel aware of the importance of cardholder data security",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 12.6: Security awareness education is an ongoing activity",
                category="security_awareness",
                severity="high",
                pci_requirement_group="Requirement 12: Security Policy",
                testing_procedures=[
                    "Review security awareness program",
                    "Assess training content and frequency (upon hire and annual)",
                    "Examine training completion records",
                    "Test employee knowledge of security policies",
                    "Review awareness campaign effectiveness"
                ],
                evidence_requirements=[
                    "Security awareness program documentation",
                    "Training materials and curriculum",
                    "Training completion records (all personnel)",
                    "Training attendance and test scores",
                    "Ongoing awareness campaign materials"
                ],
                common_gaps=[
                    "No formal security awareness program",
                    "Training not provided annually",
                    "Incomplete training records",
                    "Training not relevant or effective"
                ],
                remediation_guidance="Develop comprehensive security awareness program. Provide training upon hire and at least annually. "
                                    "Cover PCI-DSS requirements, data handling, incident reporting. Track completion. Conduct ongoing awareness campaigns.",
                testing_frequency="Annual training; continuous awareness activities"
            ),

            ComplianceControl(
                control_id="PCI-12.8.1",
                name="Third-Party Service Provider Management",
                description="Service providers are managed to ensure they protect cardholder data",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 12.8: Risk to information assets associated with third-party service provider relationships is managed",
                category="vendor_management",
                severity="critical",
                pci_requirement_group="Requirement 12: Security Policy",
                testing_procedures=[
                    "Review third-party service provider inventory",
                    "Assess provider PCI-DSS compliance status",
                    "Examine contracts with security requirements",
                    "Test annual provider compliance confirmation",
                    "Review provider due diligence and monitoring"
                ],
                evidence_requirements=[
                    "Third-party service provider inventory",
                    "Provider PCI-DSS compliance documentation (AOC)",
                    "Contracts with security and PCI requirements",
                    "Annual compliance confirmations",
                    "Provider monitoring and review records"
                ],
                common_gaps=[
                    "No inventory of service providers",
                    "Providers not PCI-DSS compliant",
                    "Contracts lack security requirements",
                    "No annual compliance verification"
                ],
                remediation_guidance="Inventory all third-party service providers with access to CHD or CDE. Require PCI-DSS compliance "
                                    "with annual AOC. Include security requirements in contracts. Verify compliance annually. Monitor provider security.",
                testing_frequency="Annual provider compliance verification"
            ),

            ComplianceControl(
                control_id="PCI-12.10.1",
                name="Incident Response Plan",
                description="A documented incident response plan is created, tested, and implemented to respond to system breaches",
                framework=ComplianceFramework.PCI_DSS,
                requirement="Requirement 12.10: Suspected and confirmed security incidents are responded to immediately",
                category="incident_response",
                severity="critical",
                pci_requirement_group="Requirement 12: Security Policy",
                testing_procedures=[
                    "Review incident response plan",
                    "Assess plan comprehensiveness and currency",
                    "Examine incident response team and roles",
                    "Test annual IR plan testing and drills",
                    "Review actual incident handling and lessons learned"
                ],
                evidence_requirements=[
                    "Incident response plan document",
                    "Incident response team roster and contact info",
                    "Annual IR plan testing/drill results",
                    "Actual incident records and post-mortems",
                    "IR plan updates based on lessons learned"
                ],
                common_gaps=[
                    "No documented incident response plan",
                    "Plan not tested annually",
                    "IR team not identified or trained",
                    "Incidents not handled per plan"
                ],
                remediation_guidance="Develop comprehensive incident response plan addressing detection, containment, eradication, "
                                    "recovery. Identify and train IR team. Test plan annually through drills. Update plan based on tests and real incidents.",
                testing_frequency="Annual IR plan testing; continuous incident handling"
            ),
        ]
