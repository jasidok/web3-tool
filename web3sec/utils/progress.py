
"""
Progress tracking utilities for Web3Sec Framework.
"""

import sys
import time
from typing import Optional

from .logger import get_logger


class ProgressTracker:
    """
    Progress tracker with optional visual progress bar.
    
    Provides progress tracking capabilities with console output
    and integration with the logging system.
    """
    
    def __init__(self, enabled: bool = True, show_bar: bool = True):
        """
        Initialize progress tracker.
        
        Args:
            enabled: Whether progress tracking is enabled
            show_bar: Whether to show visual progress bar
        """
        self.enabled = enabled
        self.show_bar = show_bar and enabled
        self.logger = get_logger(__name__)
        
        self.total = 0
        self.current = 0
        self.start_time = None
        self.last_update_time = 0
        self.update_interval = 0.1  # Update every 100ms
        
        self.current_message = ""
    
    def set_total(self, total: int):
        """
        Set total number of items to process.
        
        Args:
            total: Total number of items
        """
        self.total = total
        self.current = 0
        self.start_time = time.time()
        
        if self.enabled:
            self.logger.info(f"Starting processing of {total} items")
    
    def update(self, message: str = ""):
        """
        Update progress with optional message.
        
        Args:
            message: Optional progress message
        """
        if not self.enabled:
            return
        
        self.current_message = message
        current_time = time.time()
        
        # Throttle updates to avoid spam
        if current_time - self.last_update_time < self.update_interval:
            return
        
        self.last_update_time = current_time
        
        if self.show_bar:
            self._show_progress_bar()
        elif message:
            self.logger.debug(f"Progress: {message}")
    
    def increment(self, message: str = ""):
        """
        Increment progress counter and update display.
        
        Args:
            message: Optional progress message
        """
        if not self.enabled:
            return
        
        self.current += 1
        self.update(message)
    
    def finish(self, message: str = "Complete"):
        """
        Mark progress as finished.
        
        Args:
            message: Completion message
        """
        if not self.enabled:
            return
        
        if self.show_bar:
            self._show_progress_bar(force=True)
            print()  # New line after progress bar
        
        if self.start_time:
            elapsed = time.time() - self.start_time
            self.logger.info(f"{message}: {self.current}/{self.total} items in {elapsed:.2f}s")
        else:
            self.logger.info(f"{message}: {self.current} items processed")
    
    def _show_progress_bar(self, force: bool = False):
        """Show visual progress bar."""
        if not self.show_bar and not force:
            return
        
        if self.total == 0:
            return
        
        # Calculate progress
        percentage = min(100, (self.current / self.total) * 100)
        filled_length = int(50 * self.current // self.total)
        
        # Create progress bar
        bar = '█' * filled_length + '-' * (50 - filled_length)
        
        # Calculate ETA
        eta_str = ""
        if self.start_time and self.current > 0:
            elapsed = time.time() - self.start_time
            if self.current < self.total:
                eta = (elapsed / self.current) * (self.total - self.current)
                eta_str = f" ETA: {eta:.0f}s"
        
        # Format message
        message_part = f" - {self.current_message}" if self.current_message else ""
        
        # Print progress bar
        progress_line = f'\rProgress: |{bar}| {percentage:.1f}% ({self.current}/{self.total}){eta_str}{message_part}'
        
        # Truncate if too long
        if len(progress_line) > 120:
            progress_line = progress_line[:117] + "..."
        
        sys.stdout.write(progress_line)
        sys.stdout.flush()
    
    def get_progress_info(self) -> dict:
        """
        Get current progress information.
        
        Returns:
            Dictionary with progress information
        """
        info = {
            'total': self.total,
            'current': self.current,
            'percentage': (self.current / self.total * 100) if self.total > 0 else 0,
            'enabled': self.enabled
        }
        
        if self.start_time:
            elapsed = time.time() - self.start_time
            info['elapsed_seconds'] = elapsed
            
            if self.current > 0:
                info['items_per_second'] = self.current / elapsed
                
                if self.current < self.total:
                    eta = (elapsed / self.current) * (self.total - self.current)
                    info['eta_seconds'] = eta
        
        return info


class SimpleProgressTracker:
    """
    Simplified progress tracker for basic use cases.
    """
    
    def __init__(self, total: int, description: str = "Processing"):
        """
        Initialize simple progress tracker.
        
        Args:
            total: Total number of items
            description: Description of the process
        """
        self.total = total
        self.current = 0
        self.description = description
        self.logger = get_logger(__name__)
        
        self.logger.info(f"{description}: 0/{total}")
    
    def update(self, increment: int = 1):
        """
        Update progress.
        
        Args:
            increment: Number to increment by
        """
        self.current += increment
        
        # Log every 10% or at completion
        percentage = (self.current / self.total) * 100
        
        if self.current == self.total or percentage % 10 == 0:
            self.logger.info(f"{self.description}: {self.current}/{self.total} ({percentage:.0f}%)")
    
    def finish(self):
        """Mark as finished."""
        self.logger.info(f"{self.description}: Complete ({self.current}/{self.total})")
