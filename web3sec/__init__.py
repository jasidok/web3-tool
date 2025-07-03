
"""
Web3Sec Framework - Professional-grade Web3 vulnerability scanning framework.
"""

__version__ = "2.0.0"
__author__ = "Web3Sec Team"
__description__ = "Professional Web3 vulnerability scanning framework"

from .core.framework import Web3SecFramework
from .core.scanner_manager import ScannerManager
from .core.plugin_loader import PluginLoader
from .core.config_manager import ConfigManager

__all__ = [
    "Web3SecFramework",
    "ScannerManager", 
    "PluginLoader",
    "ConfigManager"
]
