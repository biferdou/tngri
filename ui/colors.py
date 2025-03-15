"""
Terminal color and formatting utilities.
"""

import os
import sys
import platform


class Colors:
    """ANSI color codes for terminal output."""
    RESET = "\033[0m"
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    
    # Background colors
    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"


# Flag to track if colors are enabled
_colors_enabled = True


def disable_colors() -> None:
    """Disable colored output."""
    global _colors_enabled
    _colors_enabled = False
    
    # Replace all color codes with empty strings
    for attr_name in dir(Colors):
        if not attr_name.startswith('_'):
            setattr(Colors, attr_name, "")


def enable_colors() -> None:
    """Enable colored output."""
    global _colors_enabled
    _colors_enabled = True
    
    # Restore original color codes
    for attr_name, value in _original_colors.items():
        setattr(Colors, attr_name, value)


def are_colors_enabled() -> bool:
    """
    Check if colors are enabled.
    
    Returns:
        bool: True if colors are enabled
    """
    return _colors_enabled


def auto_configure_colors() -> None:
    """
    Automatically configure colors based on terminal capabilities.
    Disables colors if not supported by the terminal.
    """
    # Check if output is redirected to a file
    if not sys.stdout.isatty():
        disable_colors()
        return
    
    # Check platform-specific terminal support
    if platform.system() == "Windows":
        # Enable ANSI colors on Windows 10+
        if hasattr(os, 'system'):
            try:
                # Try to enable virtual terminal processing
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except:
                disable_colors()
    
    # Check for NO_COLOR environment variable
    if os.environ.get('NO_COLOR', '') != '':
        disable_colors()
        return
    
    # Check for TERM environment variable
    term = os.environ.get('TERM', '')
    if term in ('dumb', 'unknown'):
        disable_colors()
        return


def colorize(text: str, color: str) -> str:
    """
    Apply a color to text if colors are enabled.
    
    Args:
        text: Text to colorize
        color: Color to apply
        
    Returns:
        str: Colorized text
    """
    if _colors_enabled:
        return f"{color}{text}{Colors.RESET}"
    return text


# Create a backup of the original colors for enable/disable functionality
_original_colors = {attr: getattr(Colors, attr) for attr in dir(Colors) 
                    if not attr.startswith('_') and isinstance(getattr(Colors, attr), str)}

# Auto-configure colors on module import
auto_configure_colors()