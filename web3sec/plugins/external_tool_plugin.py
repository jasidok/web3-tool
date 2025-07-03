
"""
Base class for external tool integration plugins.
"""

import subprocess
from abc import abstractmethod
from typing import List, Dict, Any

from .base_plugin import BasePlugin
from ..core.scanner_base import Finding
from ..utils.logger import get_logger


class ExternalToolPlugin(BasePlugin):
    """
    Base class for plugins that integrate external security tools.
    
    This class provides common functionality for running external tools
    and parsing their output.
    """
    
    def __init__(self):
        """Initialize external tool plugin."""
        super().__init__()
        self.plugin_type = "external_tool"
        self.logger = get_logger(__name__)
        
        # Tool configuration
        self.tool_path = None
        self.timeout = 60
        self.enabled = False
    
    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if the external tool is available on the system.
        
        Returns:
            True if tool is available and executable
        """
        pass
    
    def check_tool_version(self) -> str:
        """
        Get the version of the external tool.
        
        Returns:
            Version string or 'unknown' if cannot be determined
        """
        try:
            result = subprocess.run(
                [self.tool_path, '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        
        return 'unknown'
    
    def run_tool(self, command: List[str], timeout: int = None) -> subprocess.CompletedProcess:
        """
        Run external tool with given command.
        
        Args:
            command: Command list to execute
            timeout: Timeout in seconds (uses self.timeout if None)
            
        Returns:
            CompletedProcess result
        """
        if timeout is None:
            timeout = self.timeout
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Tool {self.tool_path} timed out after {timeout}s")
            raise
        except Exception as e:
            self.logger.error(f"Error running tool {self.tool_path}: {e}")
            raise
    
    def validate(self) -> Dict[str, Any]:
        """Validate external tool availability."""
        validation = super().validate()
        
        if not self.tool_path:
            validation['errors'].append("Tool path not configured")
            validation['valid'] = False
        elif not self.is_available():
            validation['warnings'].append(f"External tool not found: {self.tool_path}")
        
        return validation
    
    def get_config(self) -> Dict[str, Any]:
        """Get external tool configuration."""
        config = super().get_config()
        config.update({
            'tool_path': self.tool_path,
            'timeout': self.timeout,
            'enabled': self.enabled,
            'available': self.is_available(),
            'version': self.check_tool_version()
        })
        return config
