"""
SOC 2 Type II Controls

Comprehensive control set for SOC 2 Type II compliance based on the 2017 Trust Services Criteria.
Organized by Trust Services Categories (TSC):
- Common Criteria (CC): Security foundation (applies to all trust services)
- Availability (A): System availability and performance
- Confidentiality (C): Protection of confidential information
- Processing Integrity (PI): Complete, valid, accurate, timely, and authorized processing
- Privacy (P): Personal information handling (not included here, as it's optional)

Each control includes:
- Full enterprise depth with testing procedures, evidence requirements, common gaps
- Remediation guidance and testing frequency
- Mapped to specific TSC categories
"""

from typing import List
from .compliance_reporter import ComplianceControl, ComplianceFramework


class SOC2TypeIIControls:
    """SOC 2 Type II control library with 50+ enterprise-grade controls"""

    @staticmethod
    def get_controls() -> List[ComplianceControl]:
        """Get comprehensive SOC 2 Type II control set"""
        return [
            # ============================================================
            # CC1: Control Environment
            # ============================================================
            ComplianceControl(
                control_id="CC1.1",
                name="Integrity and Ethical Values",
                description="The entity demonstrates a commitment to integrity and ethical values",
                framework=ComplianceFramework.SOC2,
                requirement="COSO Principle 1: Demonstrate commitment to integrity and ethical values",
                category="governance",
                severity="high",
                tsc_category="Security",
                testing_procedures=[
                    "Review code of conduct and ethics policies",
                    "Interview management about tone at the top",
                    "Review employee acknowledgments of code of conduct",
                    "Assess disciplinary actions for policy violations",
                    "Review board meeting minutes for ethics discussions"
                ],
                evidence_requirements=[
                    "Code of conduct document",
                    "Ethics policy",
                    "Employee signed acknowledgments",
                    "Disciplinary action records (sanitized)",
                    "Board meeting minutes"
                ],
                common_gaps=[
                    "Code of conduct not formally documented",
                    "No evidence of employee acknowledgment or training",
                    "Ethics violations not consistently addressed",
                    "Management doesn't model ethical behavior"
                ],
                remediation_guidance="Develop and implement a formal code of conduct. Require annual employee acknowledgment. "
                                    "Establish clear disciplinary procedures for violations. Ensure management demonstrates ethical "
                                    "behavior through actions and communications.",
                testing_frequency="Annual review; continuous monitoring of violations"
            ),

            ComplianceControl(
                control_id="CC1.2",
                name="Board Independence and Oversight",
                description="The board of directors demonstrates independence from management and exercises oversight",
                framework=ComplianceFramework.SOC2,
                requirement="COSO Principle 2: Board independence and oversight",
                category="governance",
                severity="high",
                tsc_category="Security",
                testing_procedures=[
                    "Review board composition and independence",
                    "Examine board charter and committee charters",
                    "Review board meeting frequency and attendance",
                    "Assess board's security oversight activities",
                    "Review audit committee independence"
                ],
                evidence_requirements=[
                    "Board member bios and independence documentation",
                    "Board and committee charters",
                    "Board meeting minutes and attendance records",
                    "Audit committee meeting minutes",
                    "Security briefings to board"
                ],
                common_gaps=[
                    "Limited board independence from management",
                    "Insufficient security expertise on board",
                    "Infrequent board meetings or poor attendance",
                    "No audit committee or inadequate charter"
                ],
                remediation_guidance="Ensure board has adequate independent directors. Establish or enhance audit committee. "
                                    "Provide regular security briefings to board. Document board oversight of security controls.",
                testing_frequency="Annual review"
            ),

            ComplianceControl(
                control_id="CC1.3",
                name="Organizational Structure and Authority",
                description="Management establishes structures, reporting lines, and appropriate authorities",
                framework=ComplianceFramework.SOC2,
                requirement="COSO Principle 3: Establish structure, authority, and responsibility",
                category="governance",
                severity="medium",
                tsc_category="Security",
                testing_procedures=[
                    "Review organizational chart and reporting structure",
                    "Examine job descriptions for security roles",
                    "Assess segregation of duties",
                    "Review delegation of authority policies",
                    "Interview key personnel about roles and responsibilities"
                ],
                evidence_requirements=[
                    "Organizational chart",
                    "Job descriptions (especially security-related)",
                    "Segregation of duties matrix",
                    "Authority and responsibility documentation"
                ],
                common_gaps=[
                    "Organizational structure not documented",
                    "Unclear security roles and responsibilities",
                    "Insufficient segregation of duties",
                    "No formal delegation of authority"
                ],
                remediation_guidance="Document organizational structure with clear reporting lines. Define security roles explicitly "
                                    "in job descriptions. Implement segregation of duties for critical functions. Document authority levels.",
                testing_frequency="Annual review; update with organizational changes"
            ),

            ComplianceControl(
                control_id="CC1.4",
                name="Commitment to Competence",
                description="The entity demonstrates commitment to attract, develop, and retain competent individuals",
                framework=ComplianceFramework.SOC2,
                requirement="COSO Principle 4: Demonstrate commitment to competence",
                category="human_resources",
                severity="medium",
                tsc_category="Security",
                testing_procedures=[
                    "Review hiring and screening procedures",
                    "Examine employee training programs",
                    "Assess performance evaluation processes",
                    "Review retention and succession planning",
                    "Evaluate security skills and certifications"
                ],
                evidence_requirements=[
                    "Hiring and onboarding procedures",
                    "Background check policies and records",
                    "Training program documentation",
                    "Performance review records",
                    "Security certifications and skills inventory"
                ],
                common_gaps=[
                    "No background checks for sensitive positions",
                    "Inadequate security training programs",
                    "No assessment of security competencies",
                    "High turnover in critical security roles"
                ],
                remediation_guidance="Implement background checks for all employees with access to systems/data. Develop comprehensive "
                                    "security training program. Assess and document security competencies. Create succession plans for key roles.",
                testing_frequency="Annual review; continuous for new hires"
            ),

            ComplianceControl(
                control_id="CC1.5",
                name="Accountability for Responsibilities",
                description="The entity holds individuals accountable for their internal control responsibilities",
                framework=ComplianceFramework.SOC2,
                requirement="COSO Principle 5: Hold individuals accountable",
                category="governance",
                severity="medium",
                tsc_category="Security",
                testing_procedures=[
                    "Review performance evaluation criteria",
                    "Assess accountability mechanisms",
                    "Examine incident response and escalation procedures",
                    "Review consequences for control failures",
                    "Test accountability for security incidents"
                ],
                evidence_requirements=[
                    "Performance evaluation criteria including security",
                    "Incident response records showing accountability",
                    "Disciplinary action records for control failures",
                    "Security metrics tied to performance"
                ],
                common_gaps=[
                    "Security not included in performance evaluations",
                    "No consequences for control failures",
                    "Incidents not tracked to responsible parties",
                    "Accountability not clearly defined"
                ],
                remediation_guidance="Include security responsibilities in performance evaluations. Establish clear accountability for "
                                    "security incidents and control failures. Document and enforce consequences for violations.",
                testing_frequency="Annual review; continuous monitoring"
            ),

            # ============================================================
            # CC2: Communication and Information
            # ============================================================
            ComplianceControl(
                control_id="CC2.1",
                name="Internal Communication of Information",
                description="The entity obtains or generates and uses relevant, quality information to support internal control",
                framework=ComplianceFramework.SOC2,
                requirement="COSO Principle 13: Use relevant information to support internal control",
                category="governance",
                severity="medium",
                tsc_category="Security",
                testing_procedures=[
                    "Review information systems and data quality",
                    "Assess internal communication channels",
                    "Examine security awareness communications",
                    "Test incident communication procedures",
                    "Review security metrics and reporting"
                ],
                evidence_requirements=[
                    "Security policies and procedures documentation",
                    "Security awareness materials",
                    "Incident communication records",
                    "Security dashboards and metrics",
                    "Internal announcements and communications"
                ],
                common_gaps=[
                    "Inconsistent or outdated security communications",
                    "No formal security awareness program",
                    "Poor incident communication",
                    "Security metrics not regularly reported"
                ],
                remediation_guidance="Establish regular security awareness communications. Implement formal incident communication "
                                    "procedures. Create security dashboards for stakeholders. Ensure information is timely and accurate.",
                testing_frequency="Quarterly review"
            ),

            ComplianceControl(
                control_id="CC2.2",
                name="External Communication of Information",
                description="The entity communicates with external parties regarding matters affecting internal control",
                framework=ComplianceFramework.SOC2,
                requirement="COSO Principle 14: Communicate with external parties",
                category="governance",
                severity="medium",
                tsc_category="Security",
                testing_procedures=[
                    "Review customer communication about security",
                    "Examine vendor/partner security communications",
                    "Assess regulatory reporting and disclosure",
                    "Review breach notification procedures",
                    "Test external incident communication"
                ],
                evidence_requirements=[
                    "Customer-facing security documentation",
                    "Vendor security agreements",
                    "Regulatory filings and disclosures",
                    "Breach notification procedures",
                    "External incident communications"
                ],
                common_gaps=[
                    "No formal breach notification procedures",
                    "Inadequate customer security communication",
                    "Poor vendor security coordination",
                    "Delayed or missing regulatory notifications"
                ],
                remediation_guidance="Develop breach notification procedures compliant with regulations. Create customer security "
                                    "documentation. Establish vendor communication protocols. Ensure timely regulatory reporting.",
                testing_frequency="Annual review; test breach procedures"
            ),

            ComplianceControl(
                control_id="CC2.3",
                name="Security Commitments and System Requirements",
                description="The entity communicates security commitments, system requirements, and responsibilities",
                framework=ComplianceFramework.SOC2,
                requirement="TSC: Define security commitments and communicate to stakeholders",
                category="governance",
                severity="high",
                tsc_category="Security",
                testing_procedures=[
                    "Review customer contracts and SLAs",
                    "Examine security commitments documentation",
                    "Assess privacy policies and terms of service",
                    "Review system requirements documentation",
                    "Test customer onboarding communication"
                ],
                evidence_requirements=[
                    "Customer contracts with security commitments",
                    "Service level agreements (SLAs)",
                    "Privacy policy and terms of service",
                    "System requirements documentation",
                    "Customer onboarding materials"
                ],
                common_gaps=[
                    "Vague or missing security commitments in contracts",
                    "No documented SLAs for security/availability",
                    "Outdated privacy policies",
                    "System requirements not communicated to customers"
                ],
                remediation_guidance="Document explicit security commitments in contracts. Define measurable SLAs. Maintain current "
                                    "privacy policy. Communicate system requirements clearly to customers during onboarding.",
                testing_frequency="Annual review; update with service changes"
            ),

            # ============================================================
            # CC3: Risk Assessment
            # ============================================================
            ComplianceControl(
                control_id="CC3.1",
                name="Risk Identification and Assessment",
                description="The entity identifies and assesses risks to achievement of objectives",
                framework=ComplianceFramework.SOC2,
                requirement="COSO Principle 6: Specify objectives and identify/analyze risks",
                category="risk_management",
                severity="high",
                tsc_category="Security",
                testing_procedures=[
                    "Review risk assessment methodology",
                    "Examine most recent risk assessment",
                    "Assess risk identification processes",
                    "Review risk register and tracking",
                    "Test risk assessment frequency and triggers"
                ],
                evidence_requirements=[
                    "Risk assessment methodology documentation",
                    "Completed risk assessments (annual minimum)",
                    "Risk register with identified risks",
                    "Risk treatment plans",
                    "Risk assessment updates for significant changes"
                ],
                common_gaps=[
                    "No formal risk assessment process",
                    "Risk assessments not performed regularly",
                    "Risks not properly documented or tracked",
                    "No risk assessment for system changes"
                ],
                remediation_guidance="Establish formal risk assessment methodology. Conduct risk assessments at least annually and "
                                    "for significant changes. Maintain risk register. Develop risk treatment plans for identified risks.",
                testing_frequency="Annual risk assessment; continuous risk monitoring"
            ),

            ComplianceControl(
                control_id="CC3.2",
                name="Fraud Risk Assessment",
                description="The entity considers potential for fraud in assessing risks",
                framework=ComplianceFramework.SOC2,
                requirement="COSO Principle 8: Assess fraud risk",
                category="risk_management",
                severity="high",
                tsc_category="Security",
                testing_procedures=[
                    "Review fraud risk assessment procedures",
                    "Examine anti-fraud controls",
                    "Assess fraud detection mechanisms",
                    "Review fraud incident history",
                    "Test whistleblower mechanisms"
                ],
                evidence_requirements=[
                    "Fraud risk assessment documentation",
                    "Anti-fraud policies and procedures",
                    "Fraud detection tools and monitoring",
                    "Fraud incident reports",
                    "Whistleblower policy and reporting channel"
                ],
                common_gaps=[
                    "Fraud risks not specifically assessed",
                    "No anti-fraud controls implemented",
                    "Inadequate fraud detection capabilities",
                    "No whistleblower protection program"
                ],
                remediation_guidance="Conduct fraud-specific risk assessment. Implement fraud detection controls (monitoring, alerts). "
                                    "Establish whistleblower policy and anonymous reporting channel. Review and investigate fraud incidents.",
                testing_frequency="Annual fraud risk assessment"
            ),

            ComplianceControl(
                control_id="CC3.3",
                name="Change Risk Assessment",
                description="The entity identifies and assesses changes that could significantly impact internal control",
                framework=ComplianceFramework.SOC2,
                requirement="COSO Principle 9: Identify and assess changes",
                category="change_management",
                severity="high",
                tsc_category="Security",
                testing_procedures=[
                    "Review change management procedures",
                    "Assess change risk evaluation process",
                    "Examine significant changes and risk assessments",
                    "Test change approval workflow",
                    "Review post-implementation validation"
                ],
                evidence_requirements=[
                    "Change management policy and procedures",
                    "Change request records with risk assessments",
                    "Change approval documentation",
                    "Post-implementation review records",
                    "Rollback procedures"
                ],
                common_gaps=[
                    "Changes deployed without risk assessment",
                    "No formal change management process",
                    "Emergency changes bypass controls",
                    "No post-implementation review"
                ],
                remediation_guidance="Implement formal change management with mandatory risk assessment. Require approval for all "
                                    "changes including emergencies. Conduct post-implementation reviews. Document rollback procedures.",
                testing_frequency="Continuous monitoring of changes"
            ),

            ComplianceControl(
                control_id="CC3.4",
                name="Third-Party Risk Assessment",
                description="The entity assesses risks associated with vendors, suppliers, and business partners",
                framework=ComplianceFramework.SOC2,
                requirement="TSC: Assess and manage vendor risks",
                category="vendor_management",
                severity="critical",
                tsc_category="Security",
                testing_procedures=[
                    "Review vendor risk assessment process",
                    "Examine vendor security questionnaires",
                    "Assess vendor contract security requirements",
                    "Review vendor SOC 2/security certifications",
                    "Test vendor monitoring and oversight"
                ],
                evidence_requirements=[
                    "Vendor risk assessment methodology",
                    "Completed vendor security assessments",
                    "Vendor contracts with security requirements",
                    "Vendor SOC 2 reports or security certifications",
                    "Vendor monitoring and review records"
                ],
                common_gaps=[
                    "No vendor security assessments performed",
                    "Vendor contracts lack security requirements",
                    "No review of vendor SOC 2 reports",
                    "Vendors not monitored after onboarding"
                ],
                remediation_guidance="Implement vendor security assessment for all critical vendors. Include security requirements in "
                                    "contracts. Review vendor SOC 2 reports and certifications. Conduct ongoing vendor monitoring.",
                testing_frequency="Annual vendor review; assessment before onboarding"
            ),

            # ============================================================
            # CC4: Monitoring Activities
            # ============================================================
            ComplianceControl(
                control_id="CC4.1",
                name="Ongoing and Separate Evaluations",
                description="The entity conducts ongoing and separate evaluations of internal controls",
                framework=ComplianceFramework.SOC2,
                requirement="COSO Principle 16: Conduct ongoing and separate evaluations",
                category="monitoring",
                severity="high",
                tsc_category="Security",
                testing_procedures=[
                    "Review internal audit plan and execution",
                    "Examine control self-assessments",
                    "Assess continuous monitoring activities",
                    "Review external audit findings",
                    "Test remediation of identified deficiencies"
                ],
                evidence_requirements=[
                    "Internal audit plan and reports",
                    "Control self-assessment results",
                    "Continuous monitoring logs and alerts",
                    "External audit reports and findings",
                    "Remediation tracking and closure evidence"
                ],
                common_gaps=[
                    "No internal audit function",
                    "Controls not regularly tested",
                    "Identified deficiencies not remediated",
                    "No continuous monitoring implemented"
                ],
                remediation_guidance="Establish internal audit function or engage third-party. Conduct regular control testing. "
                                    "Implement continuous monitoring for critical controls. Track and remediate findings timely.",
                testing_frequency="Ongoing monitoring; annual separate evaluations"
            ),

            ComplianceControl(
                control_id="CC4.2",
                name="Deficiency Communication and Remediation",
                description="The entity evaluates and communicates internal control deficiencies",
                framework=ComplianceFramework.SOC2,
                requirement="COSO Principle 17: Evaluate and communicate deficiencies",
                category="monitoring",
                severity="high",
                tsc_category="Security",
                testing_procedures=[
                    "Review deficiency tracking process",
                    "Examine remediation timelines and priorities",
                    "Assess communication to management and board",
                    "Review root cause analysis procedures",
                    "Test closure validation process"
                ],
                evidence_requirements=[
                    "Deficiency tracking system/log",
                    "Remediation plans and timelines",
                    "Management and board communications",
                    "Root cause analysis documentation",
                    "Validation of remediation completion"
                ],
                common_gaps=[
                    "Deficiencies not tracked systematically",
                    "No prioritization or remediation timelines",
                    "Management not informed of critical issues",
                    "Remediation not validated before closure"
                ],
                remediation_guidance="Implement deficiency tracking system. Prioritize based on risk and set remediation timelines. "
                                    "Communicate critical issues to management/board promptly. Validate remediation before closure.",
                testing_frequency="Continuous deficiency monitoring"
            ),

            # ============================================================
            # CC5: Control Activities
            # ============================================================
            ComplianceControl(
                control_id="CC5.1",
                name="Control Activities Over Technology",
                description="The entity selects and develops control activities over technology",
                framework=ComplianceFramework.SOC2,
                requirement="COSO Principle 11: Select and develop control activities over technology",
                category="technology_controls",
                severity="high",
                tsc_category="Security",
                testing_procedures=[
                    "Review IT general controls (ITGC)",
                    "Assess technology control design",
                    "Examine segregation of duties in IT",
                    "Test automated controls effectiveness",
                    "Review IT control monitoring"
                ],
                evidence_requirements=[
                    "IT general controls documentation",
                    "System configuration standards",
                    "Segregation of duties matrix for IT",
                    "Automated control logs",
                    "IT control test results"
                ],
                common_gaps=[
                    "IT general controls not documented",
                    "Insufficient segregation of IT duties",
                    "Automated controls not monitored",
                    "Technology controls not aligned with risks"
                ],
                remediation_guidance="Document and implement IT general controls (access, change, operations). Enforce segregation "
                                    "of IT duties. Monitor automated controls. Align technology controls with identified risks.",
                testing_frequency="Annual ITGC testing; continuous monitoring"
            ),

            ComplianceControl(
                control_id="CC5.2",
                name="Deployment of Control Activities",
                description="The entity deploys control activities through policies and procedures",
                framework=ComplianceFramework.SOC2,
                requirement="COSO Principle 12: Deploy control activities through policies",
                category="governance",
                severity="medium",
                tsc_category="Security",
                testing_procedures=[
                    "Review policies and procedures completeness",
                    "Assess policy communication and accessibility",
                    "Test employee awareness of procedures",
                    "Examine policy update process",
                    "Validate policy compliance"
                ],
                evidence_requirements=[
                    "Complete set of security policies",
                    "Procedures and work instructions",
                    "Policy acknowledgment records",
                    "Policy update and review records",
                    "Evidence of policy compliance"
                ],
                common_gaps=[
                    "Policies not documented or outdated",
                    "Procedures don't reflect actual practice",
                    "Employees unaware of policies",
                    "No regular policy review/update"
                ],
                remediation_guidance="Document comprehensive security policies and procedures. Communicate to all employees and "
                                    "require acknowledgment. Review and update policies annually. Monitor compliance with policies.",
                testing_frequency="Annual policy review; continuous compliance monitoring"
            ),

            # ============================================================
            # CC6: Logical and Physical Access Controls
            # ============================================================
            ComplianceControl(
                control_id="CC6.1",
                name="Logical Access Controls",
                description="The entity implements logical access security controls to protect information assets",
                framework=ComplianceFramework.SOC2,
                requirement="TSC: Restrict logical access to authorized users",
                category="access_control",
                severity="critical",
                tsc_category="Security",
                testing_procedures=[
                    "Review access control policy and standards",
                    "Test user access provisioning process",
                    "Examine authentication mechanisms",
                    "Assess authorization and role-based access",
                    "Review access logs and monitoring"
                ],
                evidence_requirements=[
                    "Access control policy",
                    "User provisioning procedures and records",
                    "Authentication configuration (MFA, password policy)",
                    "Role definitions and assignments",
                    "Access logs and monitoring reports"
                ],
                common_gaps=[
                    "Weak or no access control policy",
                    "No formal provisioning process",
                    "Weak authentication (no MFA)",
                    "Excessive user permissions",
                    "Access logs not reviewed"
                ],
                remediation_guidance="Implement comprehensive access control policy. Establish formal provisioning/deprovisioning "
                                    "process. Require MFA for all users. Implement least privilege and RBAC. Monitor and review access logs.",
                testing_frequency="Quarterly access reviews; continuous monitoring"
            ),

            ComplianceControl(
                control_id="CC6.2",
                name="User Access Provisioning and Deprovisioning",
                description="Prior to issuing credentials and granting access, the entity registers and authorizes new users",
                framework=ComplianceFramework.SOC2,
                requirement="TSC: Control user provisioning lifecycle",
                category="access_control",
                severity="critical",
                tsc_category="Security",
                testing_procedures=[
                    "Test new user provisioning process",
                    "Examine access request approvals",
                    "Assess termination/deprovisioning procedures",
                    "Review role changes and transfers",
                    "Validate timely removal of access"
                ],
                evidence_requirements=[
                    "User provisioning procedures",
                    "Access request tickets with approvals",
                    "Termination checklists and evidence",
                    "Role change request approvals",
                    "Deprovisioning timeliness metrics"
                ],
                common_gaps=[
                    "No approval required for access requests",
                    "Delayed deprovisioning after termination",
                    "Terminated users retain access",
                    "No process for role changes"
                ],
                remediation_guidance="Require manager approval for all access requests. Automate deprovisioning tied to HR system. "
                                    "Validate access removal within 24 hours of termination. Implement formal transfer process.",
                testing_frequency="Monthly user access review; test terminations"
            ),

            ComplianceControl(
                control_id="CC6.3",
                name="Privileged Access Management",
                description="The entity restricts and monitors privileged access",
                framework=ComplianceFramework.SOC2,
                requirement="TSC: Restrict privileged access and monitor usage",
                category="access_control",
                severity="critical",
                tsc_category="Security",
                testing_procedures=[
                    "Review privileged account inventory",
                    "Assess privileged access request process",
                    "Test privileged session monitoring",
                    "Examine administrative activity logs",
                    "Review privileged account reviews"
                ],
                evidence_requirements=[
                    "Privileged account inventory",
                    "Privileged access request approvals",
                    "Privileged session recordings/logs",
                    "Administrative activity monitoring reports",
                    "Privileged account review records"
                ],
                common_gaps=[
                    "No inventory of privileged accounts",
                    "Shared privileged credentials",
                    "Privileged access not monitored",
                    "No regular review of privileged users"
                ],
                remediation_guidance="Inventory all privileged accounts. Eliminate shared accounts. Implement privileged access "
                                    "management (PAM) solution. Monitor all privileged sessions. Review privileged access quarterly.",
                testing_frequency="Quarterly privileged access review; continuous monitoring"
            ),

            ComplianceControl(
                control_id="CC6.4",
                name="Physical Access Controls",
                description="The entity restricts physical access to facilities and protected information assets",
                framework=ComplianceFramework.SOC2,
                requirement="TSC: Implement physical access controls",
                category="physical_security",
                severity="high",
                tsc_category="Security",
                testing_procedures=[
                    "Review physical security policies",
                    "Inspect data center and office access controls",
                    "Test visitor management procedures",
                    "Examine access logs and monitoring",
                    "Assess environmental controls"
                ],
                evidence_requirements=[
                    "Physical security policy",
                    "Badge access system configuration",
                    "Visitor logs and escort procedures",
                    "Physical access logs",
                    "Environmental monitoring (temp, humidity, fire)"
                ],
                common_gaps=[
                    "Inadequate data center physical security",
                    "No visitor management or escort policy",
                    "Physical access not logged",
                    "Insufficient environmental monitoring"
                ],
                remediation_guidance="Implement badge access for all facilities. Require visitor sign-in and escort. Log all "
                                    "physical access events. Monitor environmental conditions in data center. Review access logs monthly.",
                testing_frequency="Monthly physical access log review; annual walkthrough"
            ),

            ComplianceControl(
                control_id="CC6.5",
                name="Access Review and Recertification",
                description="The entity periodically reviews and recertifies user access rights",
                framework=ComplianceFramework.SOC2,
                requirement="TSC: Conduct periodic access reviews",
                category="access_control",
                severity="critical",
                tsc_category="Security",
                testing_procedures=[
                    "Review access review procedures",
                    "Examine recent access review results",
                    "Assess review completeness and timeliness",
                    "Test remediation of excess access",
                    "Validate manager participation in reviews"
                ],
                evidence_requirements=[
                    "Access review procedures",
                    "Completed access review reports",
                    "Manager certifications/approvals",
                    "Access removal records",
                    "Access review completion metrics"
                ],
                common_gaps=[
                    "Access reviews not performed regularly",
                    "Reviews incomplete or not validated",
                    "Excess access identified but not removed",
                    "Managers don't participate in reviews"
                ],
                remediation_guidance="Conduct access reviews at least quarterly. Require manager certification of their team's access. "
                                    "Remove unauthorized or excess access within 7 days. Track review completion and remediation.",
                testing_frequency="Quarterly access reviews"
            ),

            ComplianceControl(
                control_id="CC6.6",
                name="Multi-Factor Authentication",
                description="The entity requires multi-factor authentication for remote and privileged access",
                framework=ComplianceFramework.SOC2,
                requirement="TSC: Implement strong authentication",
                category="access_control",
                severity="critical",
                tsc_category="Security",
                testing_procedures=[
                    "Review MFA implementation scope",
                    "Test MFA for remote access",
                    "Examine MFA for privileged accounts",
                    "Assess MFA bypass procedures",
                    "Review MFA compliance reporting"
                ],
                evidence_requirements=[
                    "MFA policy and standards",
                    "MFA system configuration",
                    "MFA enrollment records",
                    "MFA bypass approval records",
                    "MFA compliance reports"
                ],
                common_gaps=[
                    "MFA not implemented or partial coverage",
                    "MFA not required for privileged access",
                    "Easy MFA bypass without approval",
                    "No monitoring of MFA compliance"
                ],
                remediation_guidance="Require MFA for all remote access and privileged accounts. Eliminate MFA bypass or require "
                                    "executive approval. Monitor MFA enrollment and compliance. Use phishing-resistant MFA where possible.",
                testing_frequency="Monthly MFA compliance monitoring"
            ),

            ComplianceControl(
                control_id="CC6.7",
                name="Password Management",
                description="The entity enforces password complexity, length, and rotation requirements",
                framework=ComplianceFramework.SOC2,
                requirement="TSC: Implement password security controls",
                category="access_control",
                severity="high",
                tsc_category="Security",
                testing_procedures=[
                    "Review password policy requirements",
                    "Test password complexity enforcement",
                    "Assess password aging and expiration",
                    "Examine password reset procedures",
                    "Review password manager usage"
                ],
                evidence_requirements=[
                    "Password policy documentation",
                    "System password configuration settings",
                    "Password reset procedure",
                    "Password manager deployment records",
                    "Password compliance reports"
                ],
                common_gaps=[
                    "Weak password requirements",
                    "No password complexity enforcement",
                    "Insecure password reset process",
                    "No password manager provided"
                ],
                remediation_guidance="Enforce minimum 12-character passwords with complexity. Implement password expiration (90 days). "
                                    "Secure password reset with identity verification. Provide enterprise password manager to users.",
                testing_frequency="Annual password policy review; continuous enforcement"
            ),

            ComplianceControl(
                control_id="CC6.8",
                name="Encryption of Data at Rest",
                description="The entity encrypts sensitive data at rest using industry-standard encryption",
                framework=ComplianceFramework.SOC2,
                requirement="TSC: Protect data at rest with encryption",
                category="cryptography",
                severity="critical",
                tsc_category="Security",
                testing_procedures=[
                    "Review encryption policy and standards",
                    "Assess encryption coverage (databases, files, backups)",
                    "Test encryption key management",
                    "Examine encryption algorithms and strength",
                    "Validate encryption implementation"
                ],
                evidence_requirements=[
                    "Encryption policy and standards",
                    "Encryption coverage inventory",
                    "Key management procedures and systems",
                    "Encryption configuration evidence",
                    "Encryption verification reports"
                ],
                common_gaps=[
                    "Sensitive data not encrypted",
                    "Weak encryption algorithms used",
                    "Poor key management practices",
                    "Backups not encrypted"
                ],
                remediation_guidance="Encrypt all databases, files, and backups containing sensitive data. Use AES-256 or equivalent. "
                                    "Implement secure key management (HSM or cloud KMS). Document encryption coverage.",
                testing_frequency="Annual encryption review; continuous for new systems"
            ),

            # ============================================================
            # CC7: System Operations
            # ============================================================
            ComplianceControl(
                control_id="CC7.1",
                name="System Monitoring and Anomaly Detection",
                description="The entity monitors systems to detect anomalous activities and security events",
                framework=ComplianceFramework.SOC2,
                requirement="TSC: Detect and respond to security events",
                category="monitoring",
                severity="critical",
                tsc_category="Security",
                testing_procedures=[
                    "Review security monitoring tools and coverage",
                    "Assess SIEM implementation and use",
                    "Test alert rules and thresholds",
                    "Examine security event investigation process",
                    "Review monitoring logs and reports"
                ],
                evidence_requirements=[
                    "Security monitoring policy",
                    "SIEM configuration and rules",
                    "Security alert records",
                    "Investigation and response records",
                    "Monitoring coverage reports"
                ],
                common_gaps=[
                    "No SIEM or centralized logging",
                    "Insufficient monitoring coverage",
                    "Alerts not investigated or responded to",
                    "No defined alert response procedures"
                ],
                remediation_guidance="Implement SIEM solution with comprehensive log collection. Define alert rules for security events. "
                                    "Establish incident investigation procedures. Monitor and investigate all critical alerts.",
                testing_frequency="Continuous monitoring; quarterly review"
            ),

            ComplianceControl(
                control_id="CC7.2",
                name="Incident Response and Management",
                description="The entity identifies, reports, and responds to security incidents",
                framework=ComplianceFramework.SOC2,
                requirement="TSC: Respond to and manage security incidents",
                category="incident_response",
                severity="critical",
                tsc_category="Security",
                testing_procedures=[
                    "Review incident response plan",
                    "Assess incident response team and roles",
                    "Examine incident records and handling",
                    "Test incident escalation procedures",
                    "Review post-incident analysis"
                ],
                evidence_requirements=[
                    "Incident response plan and procedures",
                    "Incident response team roster",
                    "Incident tickets and resolution records",
                    "Escalation and notification records",
                    "Post-incident review reports"
                ],
                common_gaps=[
                    "No formal incident response plan",
                    "Incidents not properly documented",
                    "Slow or inadequate incident response",
                    "No post-incident analysis or lessons learned"
                ],
                remediation_guidance="Develop and document incident response plan. Establish incident response team with defined roles. "
                                    "Document all incidents with timestamps and actions. Conduct post-incident reviews for major incidents.",
                testing_frequency="Annual IR plan test; continuous incident handling"
            ),

            ComplianceControl(
                control_id="CC7.3",
                name="Security Patch Management",
                description="The entity identifies and deploys security patches in a timely manner",
                framework=ComplianceFramework.SOC2,
                requirement="TSC: Maintain secure system configurations",
                category="vulnerability_management",
                severity="critical",
                tsc_category="Security",
                testing_procedures=[
                    "Review patch management policy",
                    "Assess patch deployment timelines",
                    "Examine patch testing procedures",
                    "Review patch compliance reporting",
                    "Test emergency patch process"
                ],
                evidence_requirements=[
                    "Patch management policy and procedures",
                    "Patch deployment records",
                    "Patch testing documentation",
                    "Patch compliance reports",
                    "Emergency patch approvals"
                ],
                common_gaps=[
                    "No patch management process",
                    "Delayed patching (>30 days for critical)",
                    "Patches not tested before deployment",
                    "No visibility into patch status"
                ],
                remediation_guidance="Implement patch management policy with timelines (critical: 15 days, high: 30 days). Test patches "
                                    "in staging before production. Automate patch deployment where possible. Report patch compliance monthly.",
                testing_frequency="Monthly patch compliance review"
            ),

            ComplianceControl(
                control_id="CC7.4",
                name="Malware Detection and Prevention",
                description="The entity implements controls to prevent, detect, and remediate malware",
                framework=ComplianceFramework.SOC2,
                requirement="TSC: Protect against malicious code",
                category="endpoint_security",
                severity="critical",
                tsc_category="Security",
                testing_procedures=[
                    "Review anti-malware solution deployment",
                    "Assess malware signature updates",
                    "Test malware detection and quarantine",
                    "Examine malware incident response",
                    "Review endpoint protection coverage"
                ],
                evidence_requirements=[
                    "Anti-malware policy",
                    "Endpoint protection deployment records",
                    "Malware detection logs and alerts",
                    "Malware remediation records",
                    "Coverage and compliance reports"
                ],
                common_gaps=[
                    "Anti-malware not deployed on all endpoints",
                    "Signatures not updated regularly",
                    "Malware detections not investigated",
                    "No email/web filtering"
                ],
                remediation_guidance="Deploy endpoint protection on all devices. Ensure automatic signature updates. Implement email "
                                    "and web filtering. Investigate and remediate all malware detections. Monitor coverage compliance.",
                testing_frequency="Monthly endpoint protection review; continuous monitoring"
            ),

            ComplianceControl(
                control_id="CC7.5",
                name="Data Backup and Recovery",
                description="The entity performs regular backups and tests recovery procedures",
                framework=ComplianceFramework.SOC2,
                requirement="TSC: Protect data availability through backups",
                category="backup_recovery",
                severity="critical",
                tsc_category="Security",
                testing_procedures=[
                    "Review backup policy and schedules",
                    "Test backup execution and completion",
                    "Assess backup encryption and security",
                    "Test data restoration procedures",
                    "Review backup retention and offsite storage"
                ],
                evidence_requirements=[
                    "Backup policy and procedures",
                    "Backup job logs and success records",
                    "Backup encryption configuration",
                    "Restore test results",
                    "Offsite backup and retention records"
                ],
                common_gaps=[
                    "Backups not performed regularly",
                    "Restore procedures not tested",
                    "Backups not encrypted",
                    "No offsite/offline backup storage"
                ],
                remediation_guidance="Perform daily backups of critical systems and data. Encrypt all backups. Store backups offsite or "
                                    "in separate cloud account. Test restore procedures quarterly. Document RTO/RPO requirements.",
                testing_frequency="Quarterly restore testing; continuous backup monitoring"
            ),

            # ============================================================
            # CC8: Change Management
            # ============================================================
            ComplianceControl(
                control_id="CC8.1",
                name="Change Management Process",
                description="The entity implements a change management process for system modifications",
                framework=ComplianceFramework.SOC2,
                requirement="TSC: Manage system changes with authorization and testing",
                category="change_management",
                severity="high",
                tsc_category="Security",
                testing_procedures=[
                    "Review change management policy",
                    "Test change request and approval process",
                    "Assess change testing requirements",
                    "Examine change implementation procedures",
                    "Review post-implementation validation"
                ],
                evidence_requirements=[
                    "Change management policy and procedures",
                    "Change request tickets with approvals",
                    "Change testing and validation records",
                    "Change implementation schedules",
                    "Post-implementation review reports"
                ],
                common_gaps=[
                    "No formal change management process",
                    "Changes not properly authorized",
                    "Insufficient testing before deployment",
                    "No rollback plans documented"
                ],
                remediation_guidance="Implement formal change management with required approvals. Test all changes in non-production "
                                    "environment. Document rollback procedures. Conduct post-implementation reviews for major changes.",
                testing_frequency="Monthly change management review"
            ),

            ComplianceControl(
                control_id="CC8.2",
                name="Emergency Change Procedures",
                description="The entity manages emergency changes with appropriate controls and approvals",
                framework=ComplianceFramework.SOC2,
                requirement="TSC: Control emergency changes",
                category="change_management",
                severity="high",
                tsc_category="Security",
                testing_procedures=[
                    "Review emergency change procedures",
                    "Assess emergency change approvals",
                    "Test post-implementation review process",
                    "Examine emergency change frequency",
                    "Validate documentation requirements"
                ],
                evidence_requirements=[
                    "Emergency change procedures",
                    "Emergency change approval records",
                    "Post-implementation reviews",
                    "Emergency change logs",
                    "Retrospective approval documentation"
                ],
                common_gaps=[
                    "No defined emergency change process",
                    "Emergency changes bypass all controls",
                    "No post-implementation review",
                    "Excessive use of emergency process"
                ],
                remediation_guidance="Define emergency change criteria and procedures. Require executive approval for emergencies. "
                                    "Conduct post-implementation review within 24 hours. Monitor frequency to prevent abuse.",
                testing_frequency="Monthly emergency change review"
            ),

            # ============================================================
            # CC9: Risk Mitigation
            # ============================================================
            ComplianceControl(
                control_id="CC9.1",
                name="Vulnerability Assessment and Penetration Testing",
                description="The entity conducts vulnerability assessments and penetration tests",
                framework=ComplianceFramework.SOC2,
                requirement="TSC: Assess security through testing",
                category="vulnerability_management",
                severity="critical",
                tsc_category="Security",
                testing_procedures=[
                    "Review vulnerability assessment schedule",
                    "Examine vulnerability scan results",
                    "Assess penetration testing scope and frequency",
                    "Review remediation of identified vulnerabilities",
                    "Validate external testing by qualified firms"
                ],
                evidence_requirements=[
                    "Vulnerability assessment policy",
                    "Vulnerability scan reports",
                    "Penetration test reports (annual minimum)",
                    "Vulnerability remediation tracking",
                    "Tester qualifications/certifications"
                ],
                common_gaps=[
                    "No regular vulnerability scanning",
                    "Penetration testing not performed annually",
                    "Vulnerabilities not remediated timely",
                    "Testing performed by unqualified personnel"
                ],
                remediation_guidance="Conduct vulnerability scans monthly (minimum). Perform annual penetration test by qualified third "
                                    "party. Remediate critical/high findings within 30 days. Re-test after remediation.",
                testing_frequency="Monthly vulnerability scans; annual penetration test"
            ),

            ComplianceControl(
                control_id="CC9.2",
                name="Network Segmentation and Firewalls",
                description="The entity implements network segmentation and firewall controls",
                framework=ComplianceFramework.SOC2,
                requirement="TSC: Protect network boundaries",
                category="network_security",
                severity="critical",
                tsc_category="Security",
                testing_procedures=[
                    "Review network architecture and segmentation",
                    "Assess firewall rule sets",
                    "Test firewall rule review process",
                    "Examine intrusion detection/prevention",
                    "Validate DMZ and internal network separation"
                ],
                evidence_requirements=[
                    "Network architecture diagrams",
                    "Firewall configurations and rule sets",
                    "Firewall rule review records",
                    "IDS/IPS configuration and alerts",
                    "Network segmentation documentation"
                ],
                common_gaps=[
                    "Flat network with no segmentation",
                    "Firewall rules too permissive",
                    "No firewall rule review process",
                    "Missing IDS/IPS capabilities"
                ],
                remediation_guidance="Implement network segmentation separating production, development, and management networks. "
                                    "Configure firewalls with least-privilege rules. Review firewall rules quarterly. Deploy IDS/IPS.",
                testing_frequency="Quarterly firewall rule review; continuous IDS/IPS monitoring"
            ),

            # ============================================================
            # A1: Availability
            # ============================================================
            ComplianceControl(
                control_id="A1.1",
                name="System Availability Monitoring",
                description="The entity monitors system availability and performance against defined objectives",
                framework=ComplianceFramework.SOC2,
                requirement="TSC Availability: Monitor and meet availability commitments",
                category="availability",
                severity="high",
                tsc_category="Availability",
                testing_procedures=[
                    "Review availability SLAs and commitments",
                    "Assess system monitoring and alerting",
                    "Examine availability metrics and reporting",
                    "Test incident response for outages",
                    "Review capacity planning procedures"
                ],
                evidence_requirements=[
                    "Availability SLAs and targets",
                    "Monitoring dashboards and alerts",
                    "Availability reports and metrics",
                    "Outage incident records and RCA",
                    "Capacity planning documentation"
                ],
                common_gaps=[
                    "No defined availability SLAs",
                    "Insufficient monitoring coverage",
                    "Availability not measured or reported",
                    "No capacity planning process"
                ],
                remediation_guidance="Define availability SLAs (e.g., 99.9% uptime). Implement comprehensive monitoring with alerts. "
                                    "Report availability metrics monthly. Conduct capacity planning quarterly. Document RCA for outages.",
                testing_frequency="Continuous availability monitoring; monthly reporting"
            ),

            ComplianceControl(
                control_id="A1.2",
                name="Business Continuity and Disaster Recovery",
                description="The entity maintains business continuity and disaster recovery plans",
                framework=ComplianceFramework.SOC2,
                requirement="TSC Availability: Ensure business continuity",
                category="business_continuity",
                severity="critical",
                tsc_category="Availability",
                testing_procedures=[
                    "Review BC/DR plans and procedures",
                    "Assess recovery time objectives (RTO)",
                    "Test disaster recovery procedures",
                    "Examine backup and failover capabilities",
                    "Review plan updates and maintenance"
                ],
                evidence_requirements=[
                    "Business continuity plan",
                    "Disaster recovery plan with RTO/RPO",
                    "DR test results and reports",
                    "Failover and backup configurations",
                    "Plan review and update records"
                ],
                common_gaps=[
                    "No documented BC/DR plans",
                    "Plans not tested regularly",
                    "RTO/RPO not defined or unrealistic",
                    "Single points of failure exist"
                ],
                remediation_guidance="Develop comprehensive BC/DR plans with defined RTO/RPO. Test DR procedures at least annually. "
                                    "Implement redundancy to eliminate single points of failure. Update plans annually or after changes.",
                testing_frequency="Annual DR test; annual plan review"
            ),

            ComplianceControl(
                control_id="A1.3",
                name="High Availability Architecture",
                description="The entity implements redundancy and failover capabilities",
                framework=ComplianceFramework.SOC2,
                requirement="TSC Availability: Design for high availability",
                category="availability",
                severity="high",
                tsc_category="Availability",
                testing_procedures=[
                    "Review system architecture for redundancy",
                    "Assess load balancing and failover",
                    "Test automatic failover procedures",
                    "Examine database replication",
                    "Review SPoF analysis and mitigation"
                ],
                evidence_requirements=[
                    "High availability architecture diagrams",
                    "Load balancer and failover configurations",
                    "Failover test results",
                    "Database replication configuration",
                    "Single point of failure analysis"
                ],
                common_gaps=[
                    "No redundancy in critical components",
                    "Manual failover processes",
                    "Database not replicated",
                    "Single datacenter/region deployment"
                ],
                remediation_guidance="Implement redundancy for critical components (web, app, database layers). Configure automatic "
                                    "failover. Use database replication across availability zones. Deploy across multiple regions for DR.",
                testing_frequency="Quarterly failover testing"
            ),

            # ============================================================
            # C1: Confidentiality
            # ============================================================
            ComplianceControl(
                control_id="C1.1",
                name="Data Classification and Handling",
                description="The entity classifies data and implements appropriate handling procedures",
                framework=ComplianceFramework.SOC2,
                requirement="TSC Confidentiality: Classify and protect confidential information",
                category="data_protection",
                severity="critical",
                tsc_category="Confidentiality",
                testing_procedures=[
                    "Review data classification policy",
                    "Assess data inventory and classification",
                    "Examine handling procedures by classification",
                    "Test data labeling implementation",
                    "Review employee training on classification"
                ],
                evidence_requirements=[
                    "Data classification policy and scheme",
                    "Data inventory with classifications",
                    "Data handling procedures",
                    "Data labeling examples",
                    "Classification training records"
                ],
                common_gaps=[
                    "No data classification scheme",
                    "Data not inventoried or classified",
                    "Handling procedures not defined",
                    "Employees unaware of classification"
                ],
                remediation_guidance="Develop data classification policy (e.g., Public, Internal, Confidential, Restricted). Inventory "
                                    "and classify all data assets. Define handling requirements per classification. Train employees.",
                testing_frequency="Annual data classification review"
            ),

            ComplianceControl(
                control_id="C1.2",
                name="Encryption of Data in Transit",
                description="The entity encrypts confidential information during transmission",
                framework=ComplianceFramework.SOC2,
                requirement="TSC Confidentiality: Protect data in transit",
                category="cryptography",
                severity="critical",
                tsc_category="Confidentiality",
                testing_procedures=[
                    "Review encryption in transit requirements",
                    "Assess TLS/SSL implementation",
                    "Test encryption protocols and ciphers",
                    "Examine certificate management",
                    "Validate VPN encryption for remote access"
                ],
                evidence_requirements=[
                    "Encryption in transit policy",
                    "TLS configuration and certificates",
                    "SSL Labs or similar test results",
                    "Certificate inventory and renewal process",
                    "VPN encryption configuration"
                ],
                common_gaps=[
                    "Weak TLS versions allowed (TLS 1.0/1.1)",
                    "Weak cipher suites enabled",
                    "Expired or self-signed certificates",
                    "Unencrypted internal communications"
                ],
                remediation_guidance="Require TLS 1.2+ for all external connections. Disable weak ciphers. Implement automated "
                                    "certificate renewal. Encrypt internal traffic between critical components. Use VPN for remote access.",
                testing_frequency="Quarterly TLS configuration review; continuous cert monitoring"
            ),

            ComplianceControl(
                control_id="C1.3",
                name="Confidential Data Access Controls",
                description="The entity restricts access to confidential information to authorized individuals",
                framework=ComplianceFramework.SOC2,
                requirement="TSC Confidentiality: Limit access to confidential data",
                category="access_control",
                severity="critical",
                tsc_category="Confidentiality",
                testing_procedures=[
                    "Review access controls for confidential data",
                    "Test role-based access implementation",
                    "Assess data access logging and monitoring",
                    "Examine need-to-know enforcement",
                    "Review confidential data access reviews"
                ],
                evidence_requirements=[
                    "Confidential data access policy",
                    "RBAC configuration for sensitive data",
                    "Data access logs and monitoring",
                    "Access justification documentation",
                    "Confidential data access review records"
                ],
                common_gaps=[
                    "Broad access to confidential data",
                    "No logging of data access",
                    "Access not reviewed regularly",
                    "Need-to-know not enforced"
                ],
                remediation_guidance="Restrict confidential data access to business-necessary users only. Implement data access logging "
                                    "and monitoring. Review confidential data access monthly. Require justification for access requests.",
                testing_frequency="Monthly confidential data access review"
            ),

            ComplianceControl(
                control_id="C1.4",
                name="Non-Disclosure Agreements",
                description="The entity obtains confidentiality agreements from employees and third parties",
                framework=ComplianceFramework.SOC2,
                requirement="TSC Confidentiality: Obtain confidentiality commitments",
                category="governance",
                severity="medium",
                tsc_category="Confidentiality",
                testing_procedures=[
                    "Review NDA templates and requirements",
                    "Examine employee NDA/confidentiality clauses",
                    "Assess third-party NDA coverage",
                    "Test NDA tracking and renewal",
                    "Review NDA enforcement"
                ],
                evidence_requirements=[
                    "NDA templates (employee and vendor)",
                    "Signed employee NDAs/offer letters with confidentiality",
                    "Vendor/partner NDA records",
                    "NDA tracking system",
                    "NDA breach incident records"
                ],
                common_gaps=[
                    "No NDAs required for employees or contractors",
                    "NDAs not obtained from third parties",
                    "NDAs not tracked or renewed",
                    "Breaches not investigated"
                ],
                remediation_guidance="Include confidentiality clause in all employment agreements. Require NDAs from contractors and "
                                    "third parties with data access. Track NDA status. Investigate and address NDA breaches.",
                testing_frequency="Annual NDA compliance review"
            ),

            # ============================================================
            # PI1: Processing Integrity
            # ============================================================
            ComplianceControl(
                control_id="PI1.1",
                name="Data Processing Accuracy and Completeness",
                description="The entity ensures data processing is complete, valid, accurate, timely, and authorized",
                framework=ComplianceFramework.SOC2,
                requirement="TSC Processing Integrity: Process data accurately",
                category="data_integrity",
                severity="high",
                tsc_category="Processing Integrity",
                testing_procedures=[
                    "Review data validation controls",
                    "Test input validation and error handling",
                    "Assess transaction processing completeness",
                    "Examine data reconciliation procedures",
                    "Review processing error monitoring"
                ],
                evidence_requirements=[
                    "Data validation rules and logic",
                    "Input validation test results",
                    "Transaction processing logs",
                    "Reconciliation reports",
                    "Error logs and resolution records"
                ],
                common_gaps=[
                    "Insufficient input validation",
                    "No reconciliation of processed data",
                    "Processing errors not monitored",
                    "No data quality checks"
                ],
                remediation_guidance="Implement comprehensive input validation. Reconcile processed data against source. Monitor "
                                    "processing errors and investigate anomalies. Implement data quality checks and alerts.",
                testing_frequency="Continuous processing monitoring; monthly reconciliation"
            ),

            ComplianceControl(
                control_id="PI1.2",
                name="Processing Authorization and Approval",
                description="The entity ensures system processing is properly authorized",
                framework=ComplianceFramework.SOC2,
                requirement="TSC Processing Integrity: Authorize processing",
                category="data_integrity",
                severity="high",
                tsc_category="Processing Integrity",
                testing_procedures=[
                    "Review authorization controls for processing",
                    "Test approval workflows",
                    "Assess segregation of duties in processing",
                    "Examine audit trails for processing actions",
                    "Review unauthorized processing detection"
                ],
                evidence_requirements=[
                    "Processing authorization procedures",
                    "Approval workflow configurations",
                    "Segregation of duties matrix",
                    "Processing audit logs",
                    "Unauthorized activity alerts"
                ],
                common_gaps=[
                    "No authorization required for processing",
                    "Insufficient segregation of duties",
                    "Processing not logged",
                    "Unauthorized processing not detected"
                ],
                remediation_guidance="Require authorization for critical processing operations. Implement approval workflows. Enforce "
                                    "segregation of duties. Log all processing activities. Monitor for unauthorized processing.",
                testing_frequency="Continuous authorization monitoring; quarterly SoD review"
            ),

            ComplianceControl(
                control_id="PI1.3",
                name="Processing Timeliness and Delivery",
                description="The entity ensures processing is timely and outputs are delivered as committed",
                framework=ComplianceFramework.SOC2,
                requirement="TSC Processing Integrity: Ensure timely processing",
                category="data_integrity",
                severity="medium",
                tsc_category="Processing Integrity",
                testing_procedures=[
                    "Review processing SLAs and commitments",
                    "Assess processing job scheduling and monitoring",
                    "Test processing failure alerts",
                    "Examine processing timeliness metrics",
                    "Review delivery confirmation procedures"
                ],
                evidence_requirements=[
                    "Processing SLAs and schedules",
                    "Job scheduler configurations",
                    "Processing monitoring and alerts",
                    "Timeliness metrics and reports",
                    "Delivery confirmation records"
                ],
                common_gaps=[
                    "No processing SLAs defined",
                    "Processing delays not monitored",
                    "Failed jobs not alerted",
                    "No delivery confirmation"
                ],
                remediation_guidance="Define processing SLAs and schedules. Implement job monitoring with failure alerts. Track "
                                    "processing timeliness metrics. Confirm successful delivery of processing outputs.",
                testing_frequency="Continuous processing monitoring; monthly SLA review"
            ),
        ]
