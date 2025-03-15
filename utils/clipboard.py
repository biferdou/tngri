"""
Secure clipboard handling for the Tngri Password Manager.
"""

import threading
import logging
from typing import Optional

logger = logging.getLogger("tngri.clipboard")

# Global flag to keep track of pyperclip availability
_pyperclip_available = None


def check_pyperclip_available() -> bool:
    """
    Check if the pyperclip module is available.
    
    Returns:
        bool: True if pyperclip is available
    """
    global _pyperclip_available
    
    if _pyperclip_available is None:
        try:
            import pyperclip
            _pyperclip_available = True
        except ImportError:
            _pyperclip_available = False
            logger.warning("pyperclip module not available, clipboard functions disabled")
    
    return _pyperclip_available


class SecureClipboard:
    """
    Manages secure copying to clipboard with auto-clearing.
    """
    
    _clear_timer = None
    
    @classmethod
    def copy(cls, text: str, clear_after: int = 30) -> bool:
        """
        Copy text to clipboard and clear after specified seconds.
        
        Args:
            text: Text to copy to clipboard
            clear_after: Seconds until clipboard is cleared (0 to disable)
            
        Returns:
            bool: True if copy was successful
        """
        if not check_pyperclip_available():
            logger.error("Cannot copy to clipboard: pyperclip not available")
            return False
            
        try:
            import pyperclip
            
            # Cancel any pending clear operation
            if cls._clear_timer:
                cls._clear_timer.cancel()
                cls._clear_timer = None
                
            # Copy the text
            pyperclip.copy(text)
            
            if clear_after > 0:
                logger.debug(f"Text copied to clipboard, will clear in {clear_after} seconds")
                
                # Schedule clearing
                cls._clear_timer = threading.Timer(clear_after, cls.clear)
                cls._clear_timer.daemon = True
                cls._clear_timer.start()
            else:
                logger.debug("Text copied to clipboard")
                
            return True
            
        except Exception as e:
            logger.error(f"Error copying to clipboard: {e}")
            return False
    
    @classmethod
    def clear(cls) -> bool:
        """
        Clear the clipboard contents.
        
        Returns:
            bool: True if clearing was successful
        """
        if not check_pyperclip_available():
            logger.error("Cannot clear clipboard: pyperclip not available")
            return False
            
        try:
            import pyperclip
            pyperclip.copy("")
            cls._clear_timer = None
            logger.debug("Clipboard cleared")
            return True
        except Exception as e:
            logger.error(f"Error clearing clipboard: {e}")
            return False
    
    @classmethod
    def cancel_timers(cls) -> None:
        """Cancel any pending clipboard clear operations."""
        if cls._clear_timer:
            cls._clear_timer.cancel()
            cls._clear_timer = None
            logger.debug("Clipboard timer cancelled")


def get_clipboard_contents() -> Optional[str]:
    """
    Get the current clipboard contents.
    
    Returns:
        Optional[str]: Clipboard contents or None if unavailable
    """
    if not check_pyperclip_available():
        return None
        
    try:
        import pyperclip
        return pyperclip.paste()
    except Exception as e:
        logger.error(f"Error getting clipboard contents: {e}")
        return None