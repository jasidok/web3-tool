
"""
Base formatter class for output formatting.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any


class BaseFormatter(ABC):
    """
    Abstract base class for output formatters.
    
    All output formatters must implement the format method
    to convert scan results into their specific format.
    """
    
    def __init__(self):
        """Initialize base formatter."""
        self.format_name = "base"
        self.file_extension = ".txt"
    
    @abstractmethod
    def format(self, results: Dict[str, Any]) -> str:
        """
        Format scan results into output string.
        
        Args:
            results: Dictionary containing scan results and metadata
            
        Returns:
            Formatted output string
        """
        pass
    
    def get_format_name(self) -> str:
        """Get formatter name."""
        return self.format_name
    
    def get_file_extension(self) -> str:
        """Get recommended file extension for this format."""
        return self.file_extension
    
    def supports_format(self, format_name: str) -> bool:
        """Check if this formatter supports the given format name."""
        return format_name.lower() == self.format_name.lower()
