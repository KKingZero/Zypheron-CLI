import React from 'react';
import { Shield, Zap, Eye, Network, Key, Users, Code, Bug, Fingerprint, Server, Radio, Smartphone, AlertTriangle, Cloud, Lock, Anchor, MessageSquare, Shuffle } from 'lucide-react';

export interface AttackVector {
  id: string;
  name: string;
  description: string;
  icon: React.ReactNode;
  riskLevel: 'high' | 'medium' | 'low' | 'critical';
  category: string;
  osint?: boolean;
}

export const attackCategories = {
  social: 'Social Engineering & Phishing',
  malware: 'Malware & Malicious Software',
  web: 'Web & Database Attacks',
  network: 'Network & Service Attacks',
  access: 'Credential & Session Attacks',
  system: 'System & Device Exploits',
  mobile: 'Wireless & Mobile Attacks',
};

export const allAttackVectors: AttackVector[] = [
  // Existing
  { id: 'botnet', name: 'Botnet Attack', description: 'Simulate distributed botnet attack patterns and C&C comms.', icon: <Network />, riskLevel: 'high', category: 'network' },
  { id: 'dos', name: 'Denial-of-Service (DoS)', description: 'Generate high-volume traffic patterns to test server resilience.', icon: <Zap />, riskLevel: 'high', category: 'network' },
  { id: 'mitm', name: 'Man-in-the-Middle', description: 'Create intercepted network traffic patterns and certificate manipulation vectors.', icon: <Eye />, riskLevel: 'high', category: 'network' },
  { id: 'session_hijacking', name: 'Session Hijacking', description: 'Take over a user session after they\'ve logged into a secure system.', icon: <Key />, riskLevel: 'medium', category: 'access' },
  { id: 'credential_reuse', name: 'Credential Stuffing', description: 'Use stolen usernames and passwords from one site to try logging into others.', icon: <Shield />, riskLevel: 'medium', category: 'access', osint: true },
  { id: 'insider_threat', name: 'Insider Threat Simulation', description: 'Model privileged user abuse and internal system compromise scenarios.', icon: <Users />, riskLevel: 'high', category: 'social' },
  
  // Social Engineering & Phishing
  { id: 'phishing', name: 'Phishing', description: 'Trick users into giving up personal information by impersonating a trusted entity.', icon: <MessageSquare />, riskLevel: 'medium', category: 'social' },
  { id: 'spear_phishing', name: 'Spear Phishing', description: 'A targeted version of phishing aimed at specific individuals or companies.', icon: <Fingerprint />, riskLevel: 'high', category: 'social', osint: true },
  { id: 'whaling', name: 'Whaling', description: 'Phishing for high-profile targets like CEOs with highly personalized messages.', icon: <Anchor />, riskLevel: 'critical', category: 'social', osint: true },
  { id: 'social_engineering', name: 'Social Engineering', description: 'Trick people into giving away personal info or performing unauthorized actions.', icon: <Users />, riskLevel: 'high', category: 'social' },
  { id: 'shoulder_surfing', name: 'Shoulder Surfing', description: 'Looking over someone\'s shoulder to see what they\'re typing or viewing.', icon: <Eye />, riskLevel: 'low', category: 'social' },

  // Malware & Malicious Software
  { id: 'malware', name: 'Malware', description: 'Bad software designed to harm your computer or steal your information.', icon: <Bug />, riskLevel: 'high', category: 'malware' },
  { id: 'ransomware', name: 'Ransomware', description: 'Lock up files or systems and demand a ransom payment to unlock them.', icon: <Lock />, riskLevel: 'critical', category: 'malware' },
  { id: 'spyware', name: 'Spyware', description: 'Secretly monitors computer activity and sends the info to a hacker.', icon: <Eye />, riskLevel: 'high', category: 'malware' },
  { id: 'trojan_horse', name: 'Trojan Horse', description: 'Software that looks useful but hides harmful code.', icon: <Shield />, riskLevel: 'high', category: 'malware' },
  { id: 'worms', name: 'Worms', description: 'Programs that copy themselves and spread across networks without user interaction.', icon: <Shuffle />, riskLevel: 'high', category: 'malware' },
  { id: 'key_logging', name: 'Keylogging', description: 'Record everything typed on a keyboard to steal credentials or sensitive data.', icon: <Key />, riskLevel: 'high', category: 'malware' },
  { id: 'drive_by_download', name: 'Drive-by Download', description: 'A compromised website downloads malicious software without the user\'s knowledge.', icon: <Cloud />, riskLevel: 'medium', category: 'malware' },
  { id: 'rootkits', name: 'Rootkits', description: 'Programs that give hackers admin control while hiding their presence.', icon: <Server />, riskLevel: 'critical', category: 'malware' },
  { id: 'backdoor', name: 'Backdoor', description: 'A hidden way into a system that bypasses normal security checks.', icon: <Code />, riskLevel: 'critical', category: 'malware' },
  { id: 'botnets', name: 'Botnets', description: 'Networks of infected computers used to launch large-scale attacks or send spam.', icon: <Network />, riskLevel: 'high', category: 'malware' },
  { id: 'cryptojacking', name: 'Cryptojacking', description: 'Secretly uses a victim\'s computer resources to mine cryptocurrency.', icon: <Zap />, riskLevel: 'medium', category: 'malware' },
  { id: 'rogue_software', name: 'Rogue Software', description: 'Pretends to be helpful security software but is actually harmful.', icon: <AlertTriangle />, riskLevel: 'medium', category: 'malware' },
  { id: 'exploit_kits', name: 'Exploit Kits', description: 'Toolkits that automate the process of finding and exploiting vulnerabilities.', icon: <Zap />, riskLevel: 'high', category: 'malware' },

  // Web & Database Attacks
  { id: 'sql_injection', name: 'SQL Injection', description: 'Insert malicious SQL code into a website\'s database queries to gain access.', icon: <Code />, riskLevel: 'critical', category: 'web' },
  { id: 'xss', name: 'Cross-site Scripting (XSS)', description: 'Inject harmful code into a website which then runs in a victim\'s browser.', icon: <Code />, riskLevel: 'high', category: 'web' },
  { id: 'csrf', name: 'Cross-Site Request Forgery (CSRF)', description: 'Trick a logged-in user into performing actions on a website without their knowledge.', icon: <Shuffle />, riskLevel: 'medium', category: 'web' },
  { id: 'command_injection', name: 'Command Injection', description: 'Run dangerous commands on a server by exploiting poorly coded applications.', icon: <Code />, riskLevel: 'critical', category: 'web' },
  { id: 'clickjacking', name: 'Clickjacking', description: 'Hide malicious actions under legitimate buttons or links on a website.', icon: <Zap />, riskLevel: 'medium', category: 'web' },

  // Network & Service Attacks
  { id: 'ddos', name: 'DDoS', description: 'Flood a website or network with so much traffic from multiple sources that it crashes.', icon: <Zap />, riskLevel: 'high', category: 'network' },
  { id: 'dns_spoofing', name: 'DNS Spoofing', description: 'Trick a computer into connecting to a fake website instead of the real one.', icon: <Shuffle />, riskLevel: 'high', category: 'network' },
  { id: 'watering_hole', name: 'Watering Hole Attack', description: 'Infect a website that a particular group of people often visit.', icon: <Cloud />, riskLevel: 'high', category: 'network', osint: true },
  { id: 'eavesdropping', name: 'Eavesdropping Attack', description: 'Listen in on private communications over a network.', icon: <Eye />, riskLevel: 'medium', category: 'network' },

  // Credential, Session & Access Attacks
  { id: 'brute_force', name: 'Brute Force Attack', description: 'Guess passwords or keys by trying every possible combination.', icon: <Key />, riskLevel: 'medium', category: 'access' },
  { id: 'password_spraying', name: 'Password Spraying', description: 'Try a few common passwords on many different accounts.', icon: <Key />, riskLevel: 'medium', category: 'access' },
  { id: 'privilege_escalation', name: 'Privilege Escalation', description: 'Gain higher access levels on a system than originally intended.', icon: <Shield />, riskLevel: 'high', category: 'access' },
  { id: 'session_fixation', name: 'Session Fixation', description: 'Force a user to use a specific session ID that a hacker can then hijack.', icon: <Key />, riskLevel: 'medium', category: 'access' },

  // System, Hardware & Zero-Day Exploits
  { id: 'zero_day', name: 'Zero-Day Exploit', description: 'Take advantage of a security flaw that is unknown to the software vendor.', icon: <AlertTriangle />, riskLevel: 'critical', category: 'system' },
  { id: 'firmware_hacking', name: 'Firmware Hacking', description: 'Target the low-level software that controls hardware components.', icon: <Server />, riskLevel: 'critical', category: 'system' },
  { id: 'jailbreaking_rooting', name: 'Jailbreaking / Rooting', description: 'Remove software restrictions on a device to gain full control over the OS.', icon: <Smartphone />, riskLevel: 'high', category: 'system' },
  
  // Wireless & Mobile Attacks
  { id: 'bluesnarfing', name: 'Bluesnarfing', description: 'Unauthorized access of information from a Bluetooth-enabled device.', icon: <Radio />, riskLevel: 'medium', category: 'mobile' },
  { id: 'bluejacking', name: 'Bluejacking', description: 'Send unsolicited messages to Bluetooth-enabled devices.', icon: <Radio />, riskLevel: 'low', category: 'mobile' },
  { id: 'sim_swapping', name: 'SIM Swapping', description: 'Trick a phone provider into transferring a phone number to a hacker\'s SIM card.', icon: <Smartphone />, riskLevel: 'critical', category: 'mobile', osint: true },
]; 