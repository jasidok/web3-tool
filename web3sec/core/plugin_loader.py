"""
Plugin loader for discovering and loading various types of plugins.
"""

import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional

from .config_manager import ConfigManager
from ..utils.logger import get_logger


class PluginLoader:
    """
    Handles discovery and loading of all plugin types.
    
    Supports loading:
    1. Built-in scanner plugins
    2. External tool integration plugins
    3. Template-based plugins
    4. Custom user plugins
    """
    
    def __init__(self, config: ConfigManager):
        """
        Initialize plugin loader.
        
        Args:
            config: Configuration manager instance
        """
        self.logger = get_logger(__name__)
        self.config = config
        self.loaded_plugins = {}
        
        # Get framework root directory
        self.framework_root = Path(__file__).parent.parent
        
        self.logger.debug("Plugin loader initialized")
    
    def load_builtin_plugins(self) -> Dict[str, Any]:
        """
        Load built-in scanner plugins.
        
        Returns:
            Dictionary of plugin name -> plugin instance
        """
        plugins = {}
        builtin_path = self.framework_root / "plugins" / "builtin"
        
        try:
            # Import built-in plugin modules
            from ..plugins.builtin.solidity_scanner import SolidityScanner
            from ..plugins.builtin.web3js_scanner import Web3JSScanner
            from ..plugins.builtin.typescript_scanner import TypeScriptScanner
            
            # Instantiate plugins
            plugin_classes = [SolidityScanner, Web3JSScanner, TypeScriptScanner]
            
            for plugin_class in plugin_classes:
                try:
                    plugin_instance = plugin_class()
                    plugin_name = plugin_instance.get_name()
                    plugins[plugin_name] = plugin_instance
                    self.logger.debug(f"Loaded built-in plugin: {plugin_name}")
                except Exception as e:
                    self.logger.warning(f"Failed to load built-in plugin {plugin_class.__name__}: {e}")
            
        except ImportError as e:
            self.logger.warning(f"Failed to import built-in plugins: {e}")
        
        self.logger.info(f"Loaded {len(plugins)} built-in plugins")
        return plugins
    
    def load_external_plugins(self) -> Dict[str, Any]:
        """
        Load external tool integration plugins.
        
        Returns:
            Dictionary of plugin name -> plugin instance
        """
        plugins = {}
        
        try:
            from ..plugins.external.slither_plugin import SlitherPlugin
            from ..plugins.external.mythril_plugin import MythrilPlugin
            from ..plugins.external.solhint_plugin import SolhintPlugin
            from ..plugins.external.ethlint_plugin import EthlintPlugin
            
            # Get external tool configurations
            external_tools = self.config.get('external_tools', {})
            
            plugin_classes = [
                ('slither', SlitherPlugin),
                ('mythril', MythrilPlugin),
                ('solhint', SolhintPlugin),
                ('ethlint', EthlintPlugin)
            ]
            
            for tool_name, plugin_class in plugin_classes:
                tool_config = external_tools.get(tool_name, {})
                
                # Only load if enabled in configuration
                if tool_config.get('enabled', False):
                    try:
                        plugin_instance = plugin_class(tool_config)
                        plugin_name = plugin_instance.get_name()
                        plugins[plugin_name] = plugin_instance
                        self.logger.debug(f"Loaded external plugin: {plugin_name}")
                    except Exception as e:
                        self.logger.warning(f"Failed to load external plugin {tool_name}: {e}")
                else:
                    self.logger.debug(f"External tool {tool_name} disabled in configuration")
            
        except ImportError as e:
            self.logger.warning(f"Failed to import external plugins: {e}")
        
        self.logger.info(f"Loaded {len(plugins)} external tool plugins")
        return plugins
    
    def load_template_plugins(self) -> Dict[str, Any]:
        """
        Load template-based plugins.
        
        Returns:
            Dictionary of plugin name -> plugin instance
        """
        plugins = {}
        
        try:
            from ..plugins.template_plugin import TemplatePlugin
            from ..templates.template_loader import TemplateLoader
            
            # Load templates
            template_loader = TemplateLoader(self.config)
            templates = template_loader.load_all_templates()
            
            # Create template plugins
            for template_name, template_data in templates.items():
                try:
                    plugin_instance = TemplatePlugin(template_name, template_data)
                    plugin_name = f"template_{template_name}"
                    plugins[plugin_name] = plugin_instance
                    self.logger.debug(f"Loaded template plugin: {plugin_name}")
                except Exception as e:
                    self.logger.warning(f"Failed to load template plugin {template_name}: {e}")
            
        except ImportError as e:
            self.logger.warning(f"Failed to import template plugins: {e}")
        
        self.logger.info(f"Loaded {len(plugins)} template plugins")
        return plugins
    
    def load_custom_plugins(self) -> Dict[str, Any]:
        """
        Load custom user plugins from configured directories.
        
        Returns:
            Dictionary of plugin name -> plugin instance
        """
        plugins = {}
        custom_dirs = self.config.get('plugins.custom_plugin_dirs', [])
        
        for plugin_dir in custom_dirs:
            plugin_path = Path(plugin_dir)
            if not plugin_path.exists():
                self.logger.warning(f"Custom plugin directory not found: {plugin_path}")
                continue
            
            # Discover Python files in the directory
            for py_file in plugin_path.glob("*.py"):
                if py_file.name.startswith("_"):
                    continue  # Skip private files
                
                try:
                    plugin_instance = self._load_plugin_from_file(py_file)
                    if plugin_instance:
                        plugin_name = plugin_instance.get_name()
                        plugins[plugin_name] = plugin_instance
                        self.logger.debug(f"Loaded custom plugin: {plugin_name}")
                except Exception as e:
                    self.logger.warning(f"Failed to load custom plugin {py_file}: {e}")
        
        self.logger.info(f"Loaded {len(plugins)} custom plugins")
        return plugins
    
    def _load_plugin_from_file(self, file_path: Path) -> Optional[Any]:
        """
        Load a plugin from a Python file.
        
        Args:
            file_path: Path to the Python file
            
        Returns:
            Plugin instance or None if loading failed
        """
        try:
            # Load module from file
            spec = importlib.util.spec_from_file_location(file_path.stem, file_path)
            if not spec or not spec.loader:
                return None
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find plugin classes in the module
            from ..plugins.base_plugin import BasePlugin
            
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and 
                    issubclass(attr, BasePlugin) and 
                    attr != BasePlugin):
                    # Found a plugin class, instantiate it
                    return attr()
            
            self.logger.warning(f"No plugin class found in {file_path}")
            return None
            
        except Exception as e:
            self.logger.error(f"Error loading plugin from {file_path}: {e}")
            return None
    
    def discover_plugins(self, directory: Path) -> List[Path]:
        """
        Discover plugin files in a directory.
        
        Args:
            directory: Directory to search for plugins
            
        Returns:
            List of plugin file paths
        """
        plugin_files = []
        
        if not directory.exists():
            return plugin_files
        
        # Look for Python files
        for py_file in directory.rglob("*.py"):
            if py_file.name.startswith("_"):
                continue  # Skip private files
            
            # Check if file contains plugin classes
            if self._is_plugin_file(py_file):
                plugin_files.append(py_file)
        
        return plugin_files
    
    def _is_plugin_file(self, file_path: Path) -> bool:
        """
        Check if a file contains plugin classes.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            True if file contains plugin classes
        """
        try:
            content = file_path.read_text(encoding='utf-8')
            
            # Simple heuristic: look for plugin-related imports and classes
            plugin_indicators = [
                'BasePlugin',
                'ScannerBase',
                'class.*Plugin',
                'class.*Scanner',
                'def scan_file',
                'def get_name'
            ]
            
            for indicator in plugin_indicators:
                if indicator in content:
                    return True
            
            return False
            
        except Exception:
            return False
    
    def validate_plugin(self, plugin: Any) -> Dict[str, Any]:
        """
        Validate a plugin instance.
        
        Args:
            plugin: Plugin instance to validate
            
        Returns:
            Dictionary with validation results
        """
        validation = {
            'valid': True,
            'errors': [],
            'warnings': []
        }
        
        # Check required methods
        required_methods = ['get_name', 'scan_file', 'supports_file']
        for method in required_methods:
            if not hasattr(plugin, method):
                validation['errors'].append(f"Missing required method: {method}")
                validation['valid'] = False
        
        # Check plugin name
        try:
            name = plugin.get_name()
            if not name or not isinstance(name, str):
                validation['errors'].append("Invalid plugin name")
                validation['valid'] = False
        except Exception as e:
            validation['errors'].append(f"Error getting plugin name: {e}")
            validation['valid'] = False
        
        # Check supported extensions
        try:
            if hasattr(plugin, 'supported_extensions'):
                extensions = plugin.supported_extensions
                if not isinstance(extensions, list):
                    validation['warnings'].append("supported_extensions should be a list")
        except Exception as e:
            validation['warnings'].append(f"Error checking supported extensions: {e}")
        
        return validation
    
    def get_plugin_metadata(self, plugin: Any) -> Dict[str, Any]:
        """
        Extract metadata from a plugin.
        
        Args:
            plugin: Plugin instance
            
        Returns:
            Dictionary with plugin metadata
        """
        metadata = {
            'name': 'unknown',
            'version': 'unknown',
            'description': 'No description available',
            'author': 'unknown',
            'plugin_type': 'unknown',
            'supported_extensions': []
        }
        
        # Extract available metadata
        metadata_attrs = [
            'name', 'version', 'description', 'author', 
            'plugin_type', 'supported_extensions'
        ]
        
        for attr in metadata_attrs:
            if hasattr(plugin, attr):
                metadata[attr] = getattr(plugin, attr)
        
        # Try to get name from get_name method
        try:
            if hasattr(plugin, 'get_name'):
                metadata['name'] = plugin.get_name()
        except Exception:
            pass
        
        return metadata
    
    def reload_plugin(self, plugin_name: str) -> Optional[Any]:
        """
        Reload a specific plugin.
        
        Args:
            plugin_name: Name of the plugin to reload
            
        Returns:
            Reloaded plugin instance or None
        """
        # This is a simplified implementation
        # In a full implementation, you'd track plugin sources and reload appropriately
        self.logger.info(f"Reloading plugin: {plugin_name}")
        
        # For now, just reload all plugins
        all_plugins = {}
        all_plugins.update(self.load_builtin_plugins())
        all_plugins.update(self.load_external_plugins())
        all_plugins.update(self.load_template_plugins())
        all_plugins.update(self.load_custom_plugins())
        
        return all_plugins.get(plugin_name)
