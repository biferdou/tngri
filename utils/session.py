"""
Session management for the Tngri Password Manager.
"""

import threading
import logging
from datetime import datetime, timedelta

logger = logging.getLogger("tngri.session")


class VaultSession:
    """
    Manages user session with auto-timeout.
    """
    
    def __init__(self, timeout_minutes: int = 5):
        """
        Initialize session with timeout.
        
        Args:
            timeout_minutes: Minutes until session automatically locks
        """
        self.timeout_minutes = timeout_minutes
        self.last_activity = datetime.now()
        self._lock_timer = None
        self.locked = True
        
        logger.debug(f"Session initialized with {timeout_minutes} minute timeout")
    
    def activity(self) -> None:
        """Register user activity to reset timeout."""
        self.last_activity = datetime.now()
        
        # Reset timer if exists
        if self._lock_timer:
            self._lock_timer.cancel()
            
        # Set new timer
        if self.timeout_minutes > 0:
            self._lock_timer = threading.Timer(self.timeout_minutes * 60, self.lock)
            self._lock_timer.daemon = True
            self._lock_timer.start()
            
            logger.debug(f"Session timeout reset to {self.timeout_minutes} minutes")
    
    def lock(self) -> None:
        """Lock the vault session."""
        self.locked = True
        logger.info("Session timed out, vault locked")
    
    def unlock(self) -> None:
        """Unlock the vault session."""
        self.locked = False
        self.activity()
        logger.info("Session unlocked")
    
    def is_locked(self) -> bool:
        """
        Check if the session is locked.
        
        Returns:
            bool: True if session is locked
        """
        return self.locked
    
    def time_remaining(self) -> int:
        """
        Get the time remaining until session lock in seconds.
        
        Returns:
            int: Seconds until lock (0 if already locked or timeout disabled)
        """
        if self.locked or self.timeout_minutes <= 0:
            return 0
            
        expire_time = self.last_activity + timedelta(minutes=self.timeout_minutes)
        remaining = (expire_time - datetime.now()).total_seconds()
        
        return max(0, int(remaining))
    
    def cancel_timers(self) -> None:
        """Cancel any pending timers."""
        if self._lock_timer:
            self._lock_timer.cancel()
            self._lock_timer = None
            logger.debug("Session timer cancelled")