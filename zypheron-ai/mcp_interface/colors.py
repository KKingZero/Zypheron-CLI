"""
Zypheron Color Palette for MCP Output

Enhanced color scheme for terminal output with Zypheron branding.
Maintains visual consistency with Zypheron's cyan/purple theme.
"""

import logging


class ZypheronColors:
    """Zypheron-branded color palette for terminal output"""

    # Basic colors (for backward compatibility)
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'

    # Zypheron core brand colors - Dark crimson theme
    ZYPHERON_RED = '\033[38;5;124m'        # Primary brand color - Dark red
    ZYPHERON_CRIMSON = '\033[38;5;88m'     # Secondary brand color - Deep crimson
    BLOOD_RED = '\033[38;5;52m'            # Tertiary - Blood red
    DARK_MAROON = '\033[38;5;89m'          # Maroon accent
    EMBER_RED = '\033[38;5;160m'           # Brighter ember
    RUST_ORANGE = '\033[38;5;130m'         # Rust/orange
    TERMINAL_GRAY = '\033[38;5;240m'       # Gray for subdued text
    BRIGHT_WHITE = '\033[97m'              # White for contrast
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    # Enhanced red/crimson tones for Zypheron theme
    DEEP_BURGUNDY = '\033[38;5;53m'        # Deep burgundy
    WINE_RED = '\033[38;5;95m'             # Wine red
    BRICK_RED = '\033[38;5;131m'           # Brick red
    COPPER = '\033[38;5;166m'              # Copper accent
    BURNT_ORANGE = '\033[38;5;172m'        # Burnt orange
    CHARCOAL = '\033[38;5;235m'            # Charcoal gray

    # Highlighting colors - crimson theme
    HIGHLIGHT_RED = '\033[48;5;124m\033[38;5;15m'      # Dark red bg, white text
    HIGHLIGHT_CRIMSON = '\033[48;5;88m\033[38;5;15m'   # Crimson bg, white text
    HIGHLIGHT_ORANGE = '\033[48;5;130m\033[38;5;16m'   # Rust bg, black text
    HIGHLIGHT_YELLOW = '\033[48;5;226m\033[38;5;16m'   # Yellow bg, black text
    HIGHLIGHT_GRAY = '\033[48;5;240m\033[38;5;15m'     # Gray bg, white text

    # Status colors with Zypheron crimson theme
    SUCCESS = '\033[38;5;46m'                          # Bright green (kept for success)
    WARNING = '\033[38;5;166m'                         # Copper/orange
    ERROR = '\033[38;5;160m'                           # Ember red
    CRITICAL = '\033[48;5;88m\033[38;5;15m\033[1m'     # Crimson bg, white bold text
    INFO = '\033[38;5;124m'                            # Dark red (Zypheron primary)
    DEBUG = '\033[38;5;235m'                           # Charcoal

    # Vulnerability severity colors
    VULN_CRITICAL = '\033[48;5;124m\033[38;5;15m\033[1m'  # Dark red background
    VULN_HIGH = '\033[38;5;196m\033[1m'     # Bright red bold
    VULN_MEDIUM = '\033[38;5;208m\033[1m'   # Orange bold
    VULN_LOW = '\033[38;5;226m'             # Yellow
    VULN_INFO = '\033[38;5;51m'             # Cyan

    # Tool status colors
    TOOL_RUNNING = '\033[38;5;124m\033[5m'  # Blinking dark red
    TOOL_SUCCESS = '\033[38;5;46m\033[1m'   # Bold green
    TOOL_FAILED = '\033[38;5;160m\033[1m'   # Bold ember red
    TOOL_TIMEOUT = '\033[38;5;166m\033[1m'  # Bold copper
    TOOL_RECOVERY = '\033[38;5;89m\033[1m'  # Bold maroon


class ColoredFormatter(logging.Formatter):
    """Enhanced formatter with Zypheron colors and emojis for MCP client"""

    COLORS = {
        'DEBUG': ZypheronColors.DEBUG,
        'INFO': ZypheronColors.INFO,
        'WARNING': ZypheronColors.WARNING,
        'ERROR': ZypheronColors.ERROR,
        'CRITICAL': ZypheronColors.CRITICAL
    }

    EMOJIS = {
        'DEBUG': '🔍',
        'INFO': '💡',
        'WARNING': '⚠️',
        'ERROR': '❌',
        'CRITICAL': '🚨'
    }

    def format(self, record):
        """Format log record with colors and emojis"""
        log_color = self.COLORS.get(record.levelname, '')
        emoji = self.EMOJIS.get(record.levelname, '')
        reset = ZypheronColors.RESET

        # Format: [EMOJI] [TIME] [LEVEL] - Message
        record.levelname = f"{log_color}{emoji} {record.levelname}{reset}"
        
        # Add crimson color to logger name for Zypheron branding
        record.name = f"{ZypheronColors.ZYPHERON_RED}{record.name}{reset}"
        
        return super().format(record)


def colorize(text: str, color: str) -> str:
    """
    Apply color to text with automatic reset.
    
    Args:
        text: Text to colorize
        color: Color code from ZypheronColors
        
    Returns:
        Colorized text string
    """
    return f"{color}{text}{ZypheronColors.RESET}"


def print_banner():
    """Print Zypheron MCP banner with branding"""
    banner = f"""
{ZypheronColors.ZYPHERON_RED}╔═══════════════════════════════════════════════════════════╗
║  ███████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗  ██████╗ ██╗   ██╗
║  ╚══███╔╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗██╔═══██╗████╗ ██║
║    ███╔╝  ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝██║   ██║██╔██╗██║
║   ███╔╝    ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██║   ██║██║╚████║
║  ███████╗   ██║   ██║     ██║  ██║███████╗██║  ██║╚██████╔╝██║ ╚███║
║  ╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚══╝
╚═══════════════════════════════════════════════════════════╝{ZypheronColors.RESET}
{ZypheronColors.EMBER_RED}    MCP Interface - Advanced Security Testing Framework{ZypheronColors.RESET}
{ZypheronColors.TERMINAL_GRAY}    v1.0.0 | 30+ Professional Security Tools{ZypheronColors.RESET}
"""
    print(banner)


def format_tool_output(tool_name: str, status: str, message: str) -> str:
    """
    Format tool execution output with Zypheron colors.
    
    Args:
        tool_name: Name of the security tool
        status: Execution status (success, error, running, etc.)
        message: Output message
        
    Returns:
        Formatted colored string
    """
    status_colors = {
        'running': ZypheronColors.TOOL_RUNNING,
        'success': ZypheronColors.TOOL_SUCCESS,
        'error': ZypheronColors.TOOL_FAILED,
        'timeout': ZypheronColors.TOOL_TIMEOUT,
        'recovery': ZypheronColors.TOOL_RECOVERY,
    }
    
    color = status_colors.get(status.lower(), ZypheronColors.INFO)
    tool_colored = colorize(tool_name, ZypheronColors.ZYPHERON_RED)
    status_colored = colorize(status.upper(), color)
    
    return f"[{tool_colored}] {status_colored}: {message}"

