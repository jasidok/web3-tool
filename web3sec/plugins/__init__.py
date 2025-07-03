
"""
Plugin system for Web3Sec framework.
"""

from .base_plugin import BasePlugin
from .external_tool_plugin import ExternalToolPlugin
from .template_plugin import TemplatePlugin

__all__ = [
    "BasePlugin",
    "ExternalToolPlugin", 
    "TemplatePlugin"
]
