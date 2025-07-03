
"""
Logging utilities for Web3Sec Framework.
"""

import logging
import sys
from pathlib import Path
from typing import Optional


def setup_logger(
    name: str = "web3sec",
    level: str = "INFO",
    log_file: Optional[str] = None,
    console_format: Optional[str] = None
) -> logging.Logger:
    """
    Set up logger with console and optional file output.
    
    Args:
        name: Logger name
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for log output
        console_format: Optional console log format
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Set level
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    
    # Console format
    if console_format is None:
        if level.upper() == "DEBUG":
            console_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        else:
            console_format = "%(levelname)s: %(message)s"
    
    console_formatter = logging.Formatter(console_format)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        try:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(log_path)
            file_handler.setLevel(logging.DEBUG)  # Always log everything to file
            
            file_format = "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s"
            file_formatter = logging.Formatter(file_format)
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
            
        except Exception as e:
            logger.warning(f"Could not set up file logging: {e}")
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get logger instance.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)


class ProgressLogger:
    """Logger with progress tracking capabilities."""
    
    def __init__(self, logger: logging.Logger, total_items: int = 0):
        """
        Initialize progress logger.
        
        Args:
            logger: Base logger instance
            total_items: Total number of items to process
        """
        self.logger = logger
        self.total_items = total_items
        self.current_item = 0
        self.last_percentage = -1
    
    def update(self, message: str = ""):
        """
        Update progress and log if percentage changed.
        
        Args:
            message: Optional progress message
        """
        self.current_item += 1
        
        if self.total_items > 0:
            percentage = int((self.current_item / self.total_items) * 100)
            
            if percentage != self.last_percentage and percentage % 10 == 0:
                progress_msg = f"Progress: {percentage}% ({self.current_item}/{self.total_items})"
                if message:
                    progress_msg += f" - {message}"
                
                self.logger.info(progress_msg)
                self.last_percentage = percentage
    
    def finish(self, message: str = "Complete"):
        """
        Log completion message.
        
        Args:
            message: Completion message
        """
        if self.total_items > 0:
            self.logger.info(f"{message}: {self.current_item}/{self.total_items} items processed")
        else:
            self.logger.info(f"{message}: {self.current_item} items processed")
