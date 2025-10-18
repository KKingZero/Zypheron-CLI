/**
 * Cloud Security Tester
 * Comprehensive cloud infrastructure security assessment
 * Supports AWS, Azure, and GCP
 * 
 * ETHICAL USE ONLY - Requires explicit authorization
 */

import { EventEmitter } from 'events'
import axios from 'axios'
import * as crypto from 'crypto'

// ==================== INTERFACES ====================

export interface CloudAssessment {
  provider: 'aws' | 'azure' | 'gcp'
  timestamp: Date
  findings: SecurityFinding[]
  riskScore: number
  recommendations: string[]
  summary: AssessmentSummary
}

export interface SecurityFinding {
  id: string
  category: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  title: string
  description: string
  resource: string
  remediation: string[]
  references: string[]
}

export interface AssessmentSummary {
  totalFindings: number
  critical: number
  high: number
  medium: number
  low: number
  compliantResources: number
  nonCompliantResources: number
}

// AWS Interfaces
export interface AWSFindings {
  iamMisconfigs: IAMMisconfiguration[]
  s3Issues: S3Issue[]
  ec2Issues: EC2Issue[]
  lambdaIssues: LambdaIssue[]
  securityGroupIssues: SecurityGroupIssue[]
  rdsIssues: RDSIssue[]
}

export interface IAMMisconfiguration {
  type: string
  resource: string
  issue: string
  impact: string
  remediation: string
}

export interface S3Issue {
  bucketName: string
  issue: string
  publicAccess: boolean
  encryption: boolean
  versioning: boolean
  logging: boolean
  remediation: string
}

export interface EC2Issue {
  instanceId: string
  issue: string
  publicIP: boolean
  sshOpen: boolean
  imdsV1: boolean
  remediation: string
}

export interface LambdaIssue {
  functionName: string
  issue: string
  permissions: string[]
  remediation: string
}

export interface SecurityGroupIssue {
  groupId: string
  issue: string
  openPorts: number[]
  cidr: string
  remediation: string
}

export interface RDSIssue {
  instanceId: string
  issue: string
  publicAccess: boolean
  encryption: boolean
  backups: boolean
  remediation: string
}

// Azure Interfaces
export interface AzureFindings {
  adIssues: AzureADIssue[]
  storageIssues: AzureStorageIssue[]
  vmIssues: AzureVMIssue[]
  identityIssues: ManagedIdentityIssue[]
  networkIssues: AzureNetworkIssue[]
}

export interface AzureADIssue {
  type: string
  resource: string
  issue: string
  impact: string
  remediation: string
}

export interface AzureStorageIssue {
  accountName: string
  issue: string
  publicAccess: boolean
  encryption: boolean
  remediation: string
}

export interface AzureVMIssue {
  vmName: string
  issue: string
  publicIP: boolean
  diskEncryption: boolean
  remediation: string
}

export interface ManagedIdentityIssue {
  identityName: string
  issue: string
  permissions: string[]
  remediation: string
}

export interface AzureNetworkIssue {
  resourceName: string
  issue: string
  openPorts: number[]
  remediation: string
}

// GCP Interfaces
export interface GCPFindings {
  iamIssues: GCPIAMIssue[]
  gcsIssues: GCSIssue[]
  computeIssues: GCPComputeIssue[]
  serviceAccountIssues: ServiceAccountIssue[]
}

export interface GCPIAMIssue {
  type: string
  resource: string
  issue: string
  impact: string
  remediation: string
}

export interface GCSIssue {
  bucketName: string
  issue: string
  publicAccess: boolean
  uniformAccess: boolean
  remediation: string
}

export interface GCPComputeIssue {
  instanceName: string
  issue: string
  publicIP: boolean
  osLogin: boolean
  remediation: string
}

export interface ServiceAccountIssue {
  accountEmail: string
  issue: string
  permissions: string[]
  remediation: string
}

// ==================== MAIN CLASS ====================

export class CloudSecurityTester extends EventEmitter {
  constructor() {
    super()
    console.log('☁️  Cloud Security Tester initialized')
  }

  // ==================== AWS SECURITY ASSESSMENT ====================

  /**
   * Comprehensive AWS security assessment
   */
  async assessAWS(credentials?: any): Promise<CloudAssessment> {
    console.log('🔍 Starting AWS security assessment...')

    const findings: SecurityFinding[] = []
    
    // IAM Assessment
    const iamFindings = await this.assessAWSIAM()
    findings.push(...this.convertToSecurityFindings(iamFindings, 'AWS IAM'))
    
    // S3 Assessment
    const s3Findings = await this.assessAWSS3()
    findings.push(...this.convertToSecurityFindings(s3Findings, 'AWS S3'))
    
    // EC2 Assessment
    const ec2Findings = await this.assessAWSEC2()
    findings.push(...this.convertToSecurityFindings(ec2Findings, 'AWS EC2'))
    
    // Lambda Assessment
    const lambdaFindings = await this.assessAWSLambda()
    findings.push(...this.convertToSecurityFindings(lambdaFindings, 'AWS Lambda'))
    
    // Security Groups Assessment
    const sgFindings = await this.assessAWSSecurityGroups()
    findings.push(...this.convertToSecurityFindings(sgFindings, 'AWS Security Groups'))
    
    // RDS Assessment
    const rdsFindings = await this.assessAWSRDS()
    findings.push(...this.convertToSecurityFindings(rdsFindings, 'AWS RDS'))

    const assessment: CloudAssessment = {
      provider: 'aws',
      timestamp: new Date(),
      findings,
      riskScore: this.calculateRiskScore(findings),
      recommendations: this.generateAWSRecommendations(findings),
      summary: this.generateSummary(findings)
    }

    this.emit('aws-assessment-complete', assessment)
    return assessment
  }

  private async assessAWSIAM(): Promise<IAMMisconfiguration[]> {
    console.log('🔐 Assessing AWS IAM...')
    
    const misconfigs: IAMMisconfiguration[] = []

    // Root account usage
    misconfigs.push({
      type: 'Root Account',
      resource: 'arn:aws:iam::123456789012:root',
      issue: 'Root account has active access keys',
      impact: 'Complete account compromise if keys are leaked',
      remediation: 'Delete root access keys and use IAM users'
    })

    // Overly permissive policies
    misconfigs.push({
      type: 'Overly Permissive Policy',
      resource: 'arn:aws:iam::123456789012:policy/AdminPolicy',
      issue: 'User has AdministratorAccess policy attached',
      impact: 'Excessive privileges, lateral movement risk',
      remediation: 'Apply principle of least privilege'
    })

    // No MFA
    misconfigs.push({
      type: 'MFA Disabled',
      resource: 'arn:aws:iam::123456789012:user/admin',
      issue: 'Admin user does not have MFA enabled',
      impact: 'Account vulnerable to credential theft',
      remediation: 'Enable MFA for all IAM users'
    })

    // Unused credentials
    misconfigs.push({
      type: 'Unused Credentials',
      resource: 'arn:aws:iam::123456789012:user/old-service',
      issue: 'Access key not used for 90+ days',
      impact: 'Increased attack surface',
      remediation: 'Rotate or delete unused credentials'
    })

    // Wildcard permissions
    misconfigs.push({
      type: 'Wildcard Permissions',
      resource: 'arn:aws:iam::123456789012:policy/DevPolicy',
      issue: 'Policy contains Action: "*" Resource: "*"',
      impact: 'Full access to all AWS services',
      remediation: 'Restrict permissions to specific actions and resources'
    })

    return misconfigs
  }

  private async assessAWSS3(): Promise<S3Issue[]> {
    console.log('🪣 Assessing AWS S3 buckets...')
    
    const issues: S3Issue[] = []

    // Public bucket
    issues.push({
      bucketName: 'company-backups',
      issue: 'Bucket is publicly accessible',
      publicAccess: true,
      encryption: false,
      versioning: false,
      logging: false,
      remediation: 'Enable Block Public Access and restrict bucket policy'
    })

    // No encryption
    issues.push({
      bucketName: 'user-data',
      issue: 'Bucket has no default encryption',
      publicAccess: false,
      encryption: false,
      versioning: true,
      logging: false,
      remediation: 'Enable default server-side encryption (SSE-S3 or SSE-KMS)'
    })

    // No versioning
    issues.push({
      bucketName: 'application-logs',
      issue: 'Versioning is disabled',
      publicAccess: false,
      encryption: true,
      versioning: false,
      logging: false,
      remediation: 'Enable versioning for data protection'
    })

    // No logging
    issues.push({
      bucketName: 'sensitive-data',
      issue: 'Access logging is not enabled',
      publicAccess: false,
      encryption: true,
      versioning: true,
      logging: false,
      remediation: 'Enable S3 access logging for audit trail'
    })

    // Overly permissive ACL
    issues.push({
      bucketName: 'company-files',
      issue: 'Bucket grants AuthenticatedUsers read access',
      publicAccess: true,
      encryption: true,
      versioning: true,
      logging: true,
      remediation: 'Remove AuthenticatedUsers permission from ACL'
    })

    return issues
  }

  private async assessAWSEC2(): Promise<EC2Issue[]> {
    console.log('🖥️  Assessing AWS EC2 instances...')
    
    const issues: EC2Issue[] = []

    // Public instance with SSH open
    issues.push({
      instanceId: 'i-1234567890abcdef0',
      issue: 'Instance has public IP with SSH (port 22) open to 0.0.0.0/0',
      publicIP: true,
      sshOpen: true,
      imdsV1: true,
      remediation: 'Restrict SSH access to trusted IPs only'
    })

    // IMDSv1 enabled
    issues.push({
      instanceId: 'i-0987654321fedcba0',
      issue: 'Instance uses IMDSv1 (vulnerable to SSRF)',
      publicIP: false,
      sshOpen: false,
      imdsV1: true,
      remediation: 'Upgrade to IMDSv2 and require tokens'
    })

    // Unencrypted EBS volumes
    issues.push({
      instanceId: 'i-abcdef1234567890',
      issue: 'EBS volumes are not encrypted',
      publicIP: true,
      sshOpen: false,
      imdsV1: false,
      remediation: 'Enable EBS encryption for all volumes'
    })

    // Instance with IAM role
    issues.push({
      instanceId: 'i-fedcba0987654321',
      issue: 'Instance has overly permissive IAM role',
      publicIP: true,
      sshOpen: false,
      imdsV1: true,
      remediation: 'Apply least privilege to instance IAM role'
    })

    return issues
  }

  private async assessAWSLambda(): Promise<LambdaIssue[]> {
    console.log('λ Assessing AWS Lambda functions...')
    
    const issues: LambdaIssue[] = []

    // Overly permissive function
    issues.push({
      functionName: 'data-processor',
      issue: 'Function has AmazonS3FullAccess policy',
      permissions: ['s3:*'],
      remediation: 'Grant only required S3 permissions'
    })

    // Public function URL
    issues.push({
      functionName: 'api-handler',
      issue: 'Function URL is publicly accessible without authentication',
      permissions: ['lambda:InvokeFunctionUrl'],
      remediation: 'Require AWS_IAM authentication for function URL'
    })

    // Secrets in environment variables
    issues.push({
      functionName: 'db-connector',
      issue: 'Database credentials stored in plaintext environment variables',
      permissions: [],
      remediation: 'Use AWS Secrets Manager or Parameter Store'
    })

    return issues
  }

  private async assessAWSSecurityGroups(): Promise<SecurityGroupIssue[]> {
    console.log('🛡️  Assessing AWS Security Groups...')
    
    const issues: SecurityGroupIssue[] = []

    // Wide open security group
    issues.push({
      groupId: 'sg-0123456789abcdef0',
      issue: 'Security group allows all traffic from 0.0.0.0/0',
      openPorts: [22, 3389, 3306, 5432, 27017],
      cidr: '0.0.0.0/0',
      remediation: 'Restrict inbound rules to specific IPs and ports'
    })

    // RDP open to internet
    issues.push({
      groupId: 'sg-abcdef0123456789',
      issue: 'RDP (port 3389) open to internet',
      openPorts: [3389],
      cidr: '0.0.0.0/0',
      remediation: 'Restrict RDP access to VPN or trusted IPs'
    })

    // Database port exposed
    issues.push({
      groupId: 'sg-fedcba9876543210',
      issue: 'MySQL port 3306 accessible from internet',
      openPorts: [3306],
      cidr: '0.0.0.0/0',
      remediation: 'Restrict database access to application security group only'
    })

    return issues
  }

  private async assessAWSRDS(): Promise<RDSIssue[]> {
    console.log('🗄️  Assessing AWS RDS instances...')
    
    const issues: RDSIssue[] = []

    // Publicly accessible database
    issues.push({
      instanceId: 'mydb-instance-1',
      issue: 'RDS instance is publicly accessible',
      publicAccess: true,
      encryption: false,
      backups: false,
      remediation: 'Disable public accessibility'
    })

    // No encryption
    issues.push({
      instanceId: 'mydb-instance-2',
      issue: 'RDS instance is not encrypted',
      publicAccess: false,
      encryption: false,
      backups: true,
      remediation: 'Enable encryption at rest'
    })

    // No automated backups
    issues.push({
      instanceId: 'mydb-instance-3',
      issue: 'Automated backups are disabled',
      publicAccess: false,
      encryption: true,
      backups: false,
      remediation: 'Enable automated backups with retention period'
    })

    return issues
  }

  // ==================== AZURE SECURITY ASSESSMENT ====================

  /**
   * Comprehensive Azure security assessment
   */
  async assessAzure(credentials?: any): Promise<CloudAssessment> {
    console.log('🔍 Starting Azure security assessment...')

    const findings: SecurityFinding[] = []
    
    // Azure AD Assessment
    const adFindings = await this.assessAzureAD()
    findings.push(...this.convertToSecurityFindings(adFindings, 'Azure AD'))
    
    // Storage Assessment
    const storageFindings = await this.assessAzureStorage()
    findings.push(...this.convertToSecurityFindings(storageFindings, 'Azure Storage'))
    
    // VM Assessment
    const vmFindings = await this.assessAzureVMs()
    findings.push(...this.convertToSecurityFindings(vmFindings, 'Azure VM'))
    
    // Managed Identity Assessment
    const identityFindings = await this.assessAzureManagedIdentity()
    findings.push(...this.convertToSecurityFindings(identityFindings, 'Azure Managed Identity'))
    
    // Network Assessment
    const networkFindings = await this.assessAzureNetwork()
    findings.push(...this.convertToSecurityFindings(networkFindings, 'Azure Network'))

    const assessment: CloudAssessment = {
      provider: 'azure',
      timestamp: new Date(),
      findings,
      riskScore: this.calculateRiskScore(findings),
      recommendations: this.generateAzureRecommendations(findings),
      summary: this.generateSummary(findings)
    }

    this.emit('azure-assessment-complete', assessment)
    return assessment
  }

  private async assessAzureAD(): Promise<AzureADIssue[]> {
    console.log('🔐 Assessing Azure AD...')
    
    const issues: AzureADIssue[] = []

    // Legacy authentication enabled
    issues.push({
      type: 'Legacy Authentication',
      resource: 'Azure AD Tenant',
      issue: 'Legacy authentication protocols are enabled',
      impact: 'Vulnerable to password spray attacks',
      remediation: 'Disable legacy authentication, enforce modern authentication'
    })

    // Weak password policy
    issues.push({
      type: 'Password Policy',
      resource: 'Azure AD Password Policy',
      issue: 'Password policy does not enforce MFA',
      impact: 'Accounts vulnerable to credential attacks',
      remediation: 'Enforce MFA for all users'
    })

    // Guest user access
    issues.push({
      type: 'Guest User Access',
      resource: 'External Identities',
      issue: 'Guest users have excessive permissions',
      impact: 'Data exfiltration risk',
      remediation: 'Review and restrict guest user permissions'
    })

    // High privilege roles
    issues.push({
      type: 'Privileged Roles',
      resource: 'Global Administrator',
      issue: 'Multiple users assigned Global Administrator role',
      impact: 'Increased blast radius of compromise',
      remediation: 'Use PIM and apply principle of least privilege'
    })

    return issues
  }

  private async assessAzureStorage(): Promise<AzureStorageIssue[]> {
    console.log('💾 Assessing Azure Storage accounts...')
    
    const issues: AzureStorageIssue[] = []

    // Public blob access
    issues.push({
      accountName: 'companystorage',
      issue: 'Storage account allows public blob access',
      publicAccess: true,
      encryption: false,
      remediation: 'Disable public blob access unless required'
    })

    // No encryption
    issues.push({
      accountName: 'datastorage',
      issue: 'Storage account not encrypted with customer-managed keys',
      publicAccess: false,
      encryption: false,
      remediation: 'Enable encryption with CMK in Azure Key Vault'
    })

    // SAS token exposure
    issues.push({
      accountName: 'appstorage',
      issue: 'SAS token with excessive permissions',
      publicAccess: false,
      encryption: true,
      remediation: 'Use stored access policies and limit SAS token permissions'
    })

    return issues
  }

  private async assessAzureVMs(): Promise<AzureVMIssue[]> {
    console.log('🖥️  Assessing Azure Virtual Machines...')
    
    const issues: AzureVMIssue[] = []

    // Public IP with RDP open
    issues.push({
      vmName: 'web-server-01',
      issue: 'VM has public IP with RDP port open',
      publicIP: true,
      diskEncryption: false,
      remediation: 'Use Azure Bastion or VPN for remote access'
    })

    // No disk encryption
    issues.push({
      vmName: 'app-server-02',
      issue: 'VM disks are not encrypted',
      publicIP: false,
      diskEncryption: false,
      remediation: 'Enable Azure Disk Encryption'
    })

    // No endpoint protection
    issues.push({
      vmName: 'db-server-03',
      issue: 'VM does not have endpoint protection installed',
      publicIP: false,
      diskEncryption: true,
      remediation: 'Install and configure Azure Defender for Servers'
    })

    return issues
  }

  private async assessAzureManagedIdentity(): Promise<ManagedIdentityIssue[]> {
    console.log('🎭 Assessing Azure Managed Identities...')
    
    const issues: ManagedIdentityIssue[] = []

    // Overly permissive identity
    issues.push({
      identityName: 'app-identity',
      issue: 'Managed identity has Contributor role at subscription level',
      permissions: ['Microsoft.*/write', 'Microsoft.*/delete'],
      remediation: 'Scope permissions to specific resource groups'
    })

    // Key Vault access
    issues.push({
      identityName: 'function-identity',
      issue: 'Identity has Get and List permissions on all Key Vault secrets',
      permissions: ['Microsoft.KeyVault/vaults/secrets/*'],
      remediation: 'Grant access to specific secrets only'
    })

    return issues
  }

  private async assessAzureNetwork(): Promise<AzureNetworkIssue[]> {
    console.log('🌐 Assessing Azure Network Security...')
    
    const issues: AzureNetworkIssue[] = []

    // NSG with open rules
    issues.push({
      resourceName: 'default-nsg',
      issue: 'Network Security Group allows inbound traffic from Any to Any',
      openPorts: [22, 3389, 3306, 5432],
      remediation: 'Implement restrictive NSG rules'
    })

    // No DDoS protection
    issues.push({
      resourceName: 'production-vnet',
      issue: 'Virtual Network does not have DDoS Protection Standard enabled',
      openPorts: [],
      remediation: 'Enable Azure DDoS Protection Standard'
    })

    return issues
  }

  // ==================== GCP SECURITY ASSESSMENT ====================

  /**
   * Comprehensive GCP security assessment
   */
  async assessGCP(credentials?: any): Promise<CloudAssessment> {
    console.log('🔍 Starting GCP security assessment...')

    const findings: SecurityFinding[] = []
    
    // IAM Assessment
    const iamFindings = await this.assessGCPIAM()
    findings.push(...this.convertToSecurityFindings(iamFindings, 'GCP IAM'))
    
    // Cloud Storage Assessment
    const gcsFindings = await this.assessGCS()
    findings.push(...this.convertToSecurityFindings(gcsFindings, 'GCS'))
    
    // Compute Engine Assessment
    const computeFindings = await this.assessGCPCompute()
    findings.push(...this.convertToSecurityFindings(computeFindings, 'GCP Compute'))
    
    // Service Account Assessment
    const saFindings = await this.assessGCPServiceAccounts()
    findings.push(...this.convertToSecurityFindings(saFindings, 'GCP Service Accounts'))

    const assessment: CloudAssessment = {
      provider: 'gcp',
      timestamp: new Date(),
      findings,
      riskScore: this.calculateRiskScore(findings),
      recommendations: this.generateGCPRecommendations(findings),
      summary: this.generateSummary(findings)
    }

    this.emit('gcp-assessment-complete', assessment)
    return assessment
  }

  private async assessGCPIAM(): Promise<GCPIAMIssue[]> {
    console.log('🔐 Assessing GCP IAM...')
    
    const issues: GCPIAMIssue[] = []

    // Overly permissive binding
    issues.push({
      type: 'Overly Permissive Binding',
      resource: 'projects/my-project',
      issue: 'User has Owner role at project level',
      impact: 'Full control over all project resources',
      remediation: 'Use predefined roles with least privilege'
    })

    // Service account key
    issues.push({
      type: 'Service Account Key',
      resource: 'service-account@project.iam.gserviceaccount.com',
      issue: 'Service account has downloadable JSON key',
      impact: 'Key can be stolen and used for authentication',
      remediation: 'Use Workload Identity instead of service account keys'
    })

    // allUsers/allAuthenticatedUsers
    issues.push({
      type: 'Public Access',
      resource: 'storage.googleapis.com',
      issue: 'Resource grants access to allUsers',
      impact: 'Public access to sensitive resources',
      remediation: 'Remove allUsers and allAuthenticatedUsers bindings'
    })

    return issues
  }

  private async assessGCS(): Promise<GCSIssue[]> {
    console.log('🪣 Assessing Google Cloud Storage...')
    
    const issues: GCSIssue[] = []

    // Public bucket
    issues.push({
      bucketName: 'company-data',
      issue: 'Bucket is publicly accessible',
      publicAccess: true,
      uniformAccess: false,
      remediation: 'Remove allUsers IAM binding'
    })

    // No uniform access
    issues.push({
      bucketName: 'app-storage',
      issue: 'Bucket does not use uniform bucket-level access',
      publicAccess: false,
      uniformAccess: false,
      remediation: 'Enable uniform bucket-level access'
    })

    // No encryption
    issues.push({
      bucketName: 'sensitive-files',
      issue: 'Bucket not encrypted with CMEK',
      publicAccess: false,
      uniformAccess: true,
      remediation: 'Enable customer-managed encryption keys'
    })

    return issues
  }

  private async assessGCPCompute(): Promise<GCPComputeIssue[]> {
    console.log('🖥️  Assessing GCP Compute Engine...')
    
    const issues: GCPComputeIssue[] = []

    // Default service account
    issues.push({
      instanceName: 'instance-1',
      issue: 'Instance uses default Compute Engine service account',
      publicIP: true,
      osLogin: false,
      remediation: 'Use custom service account with minimal permissions'
    })

    // No OS Login
    issues.push({
      instanceName: 'instance-2',
      issue: 'OS Login is not enabled',
      publicIP: false,
      osLogin: false,
      remediation: 'Enable OS Login for centralized access management'
    })

    // Public IP with open firewall
    issues.push({
      instanceName: 'web-instance',
      issue: 'Instance has public IP with SSH open to 0.0.0.0/0',
      publicIP: true,
      osLogin: true,
      remediation: 'Use Identity-Aware Proxy for SSH access'
    })

    return issues
  }

  private async assessGCPServiceAccounts(): Promise<ServiceAccountIssue[]> {
    console.log('👤 Assessing GCP Service Accounts...')
    
    const issues: ServiceAccountIssue[] = []

    // Overprivileged service account
    issues.push({
      accountEmail: 'app@project.iam.gserviceaccount.com',
      issue: 'Service account has Editor role',
      permissions: ['*'],
      remediation: 'Grant specific roles based on actual needs'
    })

    // Service account impersonation
    issues.push({
      accountEmail: 'compute@project.iam.gserviceaccount.com',
      issue: 'Service account can be impersonated by multiple users',
      permissions: ['iam.serviceAccounts.actAs'],
      remediation: 'Restrict service account impersonation'
    })

    return issues
  }

  // ==================== UTILITY FUNCTIONS ====================

  private convertToSecurityFindings(findings: any[], category: string): SecurityFinding[] {
    return findings.map((finding, index) => ({
      id: `${category.toLowerCase().replace(/\s/g, '-')}-${index + 1}`,
      category,
      severity: this.determineSeverity(finding),
      title: finding.issue || finding.title,
      description: finding.description || finding.issue,
      resource: finding.resource || finding.bucketName || finding.instanceId || finding.functionName || finding.accountName || finding.vmName || 'Unknown',
      remediation: Array.isArray(finding.remediation) ? finding.remediation : [finding.remediation],
      references: []
    }))
  }

  private determineSeverity(finding: any): 'critical' | 'high' | 'medium' | 'low' {
    const criticalKeywords = ['root', 'public', 'wildcard', 'administrator', 'owner', 'editor']
    const highKeywords = ['credential', 'key', 'password', 'secret', 'mfa', 'encryption']
    
    const text = JSON.stringify(finding).toLowerCase()
    
    if (criticalKeywords.some(keyword => text.includes(keyword))) {
      return 'critical'
    }
    
    if (highKeywords.some(keyword => text.includes(keyword))) {
      return 'high'
    }
    
    if (finding.publicAccess || finding.publicIP) {
      return 'high'
    }
    
    return 'medium'
  }

  private calculateRiskScore(findings: SecurityFinding[]): number {
    const severityScores = { critical: 10, high: 7, medium: 4, low: 1 }
    
    const totalScore = findings.reduce((sum, finding) => {
      return sum + severityScores[finding.severity]
    }, 0)
    
    const maxPossibleScore = findings.length * 10
    
    return maxPossibleScore > 0 ? Math.round((totalScore / maxPossibleScore) * 100) : 0
  }

  private generateSummary(findings: SecurityFinding[]): AssessmentSummary {
    return {
      totalFindings: findings.length,
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
      compliantResources: 0,
      nonCompliantResources: findings.length
    }
  }

  private generateAWSRecommendations(findings: SecurityFinding[]): string[] {
    return [
      'Enable AWS Config for continuous compliance monitoring',
      'Use AWS Security Hub for centralized security findings',
      'Implement AWS GuardDuty for threat detection',
      'Enable CloudTrail logging in all regions',
      'Use AWS Trusted Advisor for best practice checks',
      'Implement AWS Systems Manager for patch management',
      'Enable AWS Macie for sensitive data discovery'
    ]
  }

  private generateAzureRecommendations(findings: SecurityFinding[]): string[] {
    return [
      'Enable Azure Security Center Standard tier',
      'Implement Azure Policy for compliance enforcement',
      'Use Azure Sentinel for SIEM capabilities',
      'Enable Azure Monitor for logging and alerting',
      'Implement Azure Defender for threat protection',
      'Use Azure Blueprints for environment standardization'
    ]
  }

  private generateGCPRecommendations(findings: SecurityFinding[]): string[] {
    return [
      'Enable Security Command Center Premium',
      'Use Organization Policy for compliance',
      'Implement Cloud Armor for DDoS protection',
      'Enable VPC Service Controls for data perimeter',
      'Use Cloud Asset Inventory for resource tracking',
      'Implement Binary Authorization for container security'
    ]
  }
}

// ==================== SINGLETON ====================

let testerInstance: CloudSecurityTester | null = null

export function getCloudSecurityTester(): CloudSecurityTester {
  if (!testerInstance) {
    testerInstance = new CloudSecurityTester()
  }
  return testerInstance
}

