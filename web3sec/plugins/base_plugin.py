
"""
Base plugin class for Web3Sec Framework plugins.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

from ..core.scanner_base import Finding


class BasePlugin(ABC):
    """
    Abstract base class for all Web3Sec Framework plugins.
    
    This class defines the interface that all plugins must implement,
    whether they are built-in scanners, external tool integrations,
    or template-based plugins.
    """
    
    def __init__(self):
        """Initialize base plugin."""
        self.name = "base_plugin"
        self.plugin_type = "unknown"
        self.version = "1.0.0"
        self.description = "Base plugin class"
        self.supported_extensions = []
    
    @abstractmethod
    def get_name(self) -> str:
        """
        Get the plugin name.
        
        Returns:
            Plugin name as string
        """
        pass
    
    @abstractmethod
    def supports_file(self, file_path: str) -> bool:
        """
        Check if this plugin supports the given file type.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            True if plugin supports this file type
        """
        pass
    
    @abstractmethod
    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """
        Scan a file for vulnerabilities.
        
        Args:
            file_path: Path to the file being scanned
            content: File content as string
            
        Returns:
            List of Finding objects
        """
        pass
    
    def get_supported_extensions(self) -> List[str]:
        """Get list of supported file extensions."""
        return self.supported_extensions.copy()
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get plugin metadata."""
        return {
            'name': self.name,
            'type': self.plugin_type,
            'version': self.version,
            'description': self.description,
            'supported_extensions': self.supported_extensions
        }
    
    def scan_file_with_timeout(self, file_path: str, content: str, timeout: int) -> List[Finding]:
        """
        Scan file with timeout support.
        
        Default implementation just calls scan_file.
        Plugins can override this for timeout-aware scanning.
        
        Args:
            file_path: Path to the file being scanned
            content: File content as string
            timeout: Timeout in seconds
            
        Returns:
            List of Finding objects
        """
        return self.scan_file(file_path, content)
    
    def get_config(self) -> Dict[str, Any]:
        """
        Get current plugin configuration.
        
        Returns:
            Dictionary with plugin configuration
        """
        return {}
    
    def validate(self) -> Dict[str, Any]:
        """
        Validate plugin configuration and availability.
        
        Returns:
            Dictionary with validation results
        """
        return {
            'valid': True,
            'errors': [],
            'warnings': []
        }
