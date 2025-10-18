/**
 * Kali Linux Inspired Color Theme
 * Signature cyan/green aesthetic with dark backgrounds
 */

export const KaliTheme = {
  // Primary colors (Kali signature)
  primary: '#00FF00',      // Kali green
  secondary: '#00FFFF',    // Cyan
  accent: '#00D9FF',       // Light cyan
  
  // Status colors
  danger: '#FF0000',       // Red
  warning: '#FFFF00',      // Yellow
  info: '#00BFFF',         // Sky blue
  success: '#00FF00',      // Green
  muted: '#808080',        // Gray
  
  // Background & foreground
  background: '#0A0E14',   // Very dark blue-gray
  backgroundAlt: '#1A1E24', // Slightly lighter
  foreground: '#B3B1AD',   // Light gray text
  foregroundBright: '#FFFFFF', // White
  
  // Prompt colors
  prompt: '#00FF00',       // Green prompt
  command: '#00FFFF',      // Cyan commands
  output: '#B3B1AD',       // Gray output
  error: '#FF0000',        // Red errors
  
  // Threat levels (matching security standards)
  critical: '#FF0000',     // Red (CVSS 9.0-10.0)
  high: '#FF6600',         // Orange (CVSS 7.0-8.9)
  medium: '#FFFF00',       // Yellow (CVSS 4.0-6.9)
  low: '#00BFFF',          // Blue (CVSS 0.1-3.9)
  informational: '#808080', // Gray (CVSS 0.0)
  
  // UI Elements
  border: '#00FFFF',       // Cyan borders
  separator: '#404040',    // Dark gray
  highlight: '#00FF00',    // Green highlight
  selection: '#00FFFF',    // Cyan selection
  
  // Syntax highlighting
  syntax: {
    keyword: '#FF6600',    // Orange
    string: '#00FF00',     // Green
    number: '#00BFFF',     // Blue
    comment: '#808080',    // Gray
    function: '#00FFFF',   // Cyan
    variable: '#FFFF00',   // Yellow
    operator: '#FF0000',   // Red
  },
  
  // Tool status
  toolInstalled: '#00FF00',   // Green check
  toolMissing: '#FF0000',     // Red X
  toolOptional: '#FFFF00',    // Yellow warning
  
  // Progress indicators
  progressComplete: '#00FF00',
  progressIncomplete: '#404040',
  
  // Claude-inspired elements
  claudeAccent: '#8B5CF6',    // Purple (Claude brand color)
  claudeHighlight: '#A78BFA', // Light purple
} as const;

/**
 * Status indicator prefixes (Kali-style)
 */
export const StatusIndicators = {
  SUCCESS: '[+]',
  INFO: '[*]',
  WARNING: '[!]',
  ERROR: '[-]',
  QUESTION: '[?]',
  ARROW: '└──╼',
  BRANCH: '├─',
  LAST_BRANCH: '└─',
  VERTICAL: '│',
} as const;

/**
 * Box drawing characters
 */
export const BoxChars = {
  topLeft: '┌',
  topRight: '┐',
  bottomLeft: '└',
  bottomRight: '┘',
  horizontal: '─',
  vertical: '│',
  cross: '┼',
  tTop: '┬',
  tBottom: '┴',
  tLeft: '├',
  tRight: '┤',
} as const;

/**
 * Emoji/Icons for modern terminals
 */
export const Icons = {
  // Status
  success: '✓',
  error: '✗',
  warning: '⚠',
  info: 'ℹ',
  question: '?',
  
  // Tools
  tool: '🔧',
  scan: '🔍',
  exploit: '💥',
  shield: '🛡️',
  target: '🎯',
  lightning: '⚡',
  robot: '🤖',
  lock: '🔒',
  unlock: '🔓',
  key: '🔑',
  
  // Threat levels
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵',
  info: '⚪',
  
  // Progress
  loading: '⣾⣽⣻⢿⡿⣟⣯⣷', // Spinner frames
  check: '✓',
  cross: '✗',
  
  // Network
  network: '🌐',
  server: '🖥️',
  database: '💾',
  cloud: '☁️',
} as const;

/**
 * ASCII Art Banners
 */
export const ASCIIArt = {
  logo: `
╔════════════════════════════════════════════════════════════════════╗
║  ███████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗  ██████╗ ███╗   ██╗║
║  ╚══███╔╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗██╔═══██╗████╗  ██║║
║    ███╔╝  ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝██║   ██║██╔██╗ ██║║
║   ███╔╝    ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██║   ██║██║╚██╗██║║
║  ███████╗   ██║   ██║     ██║  ██║███████╗██║  ██║╚██████╔╝██║ ╚████║║
║  ╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝║
║                                                                        ║
║              AI-Powered Penetration Testing Platform                  ║
║                       v1.0.0 | CLI Edition                            ║
╚════════════════════════════════════════════════════════════════════╝
`,
  
  logoCompact: `
  ╔══════════════════════════════════════════╗
  ║  ⚡ ZYPHERON - CLI Edition            ║
  ║  AI-Powered Pentest Platform            ║
  ╚══════════════════════════════════════════╝
`,
  
  snake: `
      /^\/^\\
    _|__|  O|
\\/     /~     \\_/ \\
 \\____|__________/  \\
        \\_______      \\
                \`\\     \\                 \\
                  |     |                  \\
                 /      /                    \\
                /     /                       \\
              /      /                         \\ \\
             /     /                            \\  \\
           /     /             _----_            \\   \\
          /     /           _-~      ~-_         |   |
         (      (        _-~    _--_    ~-_     _/   |
          \\      ~-____-~    _-~    ~-_    ~-_-~    /
            ~-_           _-~          ~-_       _-~
               ~--______-~                ~-___-~
`,
};

export type ThemeColor = keyof typeof KaliTheme;

