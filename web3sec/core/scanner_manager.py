"""
Scanner manager for orchestrating plugin execution and result aggregation.
"""

import concurrent.futures
import time
from typing import List, Dict, Any, Optional
from pathlib import Path

from .plugin_loader import PluginLoader
from .config_manager import ConfigManager
from ..utils.logger import get_logger


class ScannerManager:
    """
    Manages plugin discovery, execution, and result aggregation.
    
    This class coordinates between different types of plugins (built-in scanners,
    external tools, template-based scanners) and provides a unified interface
    for scanning operations.
    """
    
    def __init__(self, plugin_loader: PluginLoader, config: ConfigManager):
        """
        Initialize scanner manager.
        
        Args:
            plugin_loader: Plugin loader instance
            config: Configuration manager instance
        """
        self.logger = get_logger(__name__)
        self.plugin_loader = plugin_loader
        self.config = config
        self.plugins = {}
        
        # Load all available plugins
        self._load_plugins()
        
        self.logger.info(f"Scanner manager initialized with {len(self.plugins)} plugins")
    
    def _load_plugins(self):
        """Load all available plugins."""
        try:
            # Load built-in plugins
            builtin_plugins = self.plugin_loader.load_builtin_plugins()
            self.plugins.update(builtin_plugins)
            
            # Load external tool plugins
            external_plugins = self.plugin_loader.load_external_plugins()
            self.plugins.update(external_plugins)
            
            # Load template-based plugins
            template_plugins = self.plugin_loader.load_template_plugins()
            self.plugins.update(template_plugins)
            
            # Load custom plugins if enabled
            if self.config.get('plugins.enable_external_plugins', True):
                custom_plugins = self.plugin_loader.load_custom_plugins()
                self.plugins.update(custom_plugins)
            
            self.logger.debug(f"Loaded plugins: {list(self.plugins.keys())}")
            
        except Exception as e:
            self.logger.error(f"Error loading plugins: {e}")
            raise
    
    def get_available_plugins(self) -> List[str]:
        """
        Get list of available plugin names.
        
        Returns:
            List of plugin names
        """
        return list(self.plugins.keys())
    
    def get_plugin_info(self, plugin_name: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific plugin.
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            Dictionary with plugin information
        """
        plugin = self.plugins.get(plugin_name)
        if not plugin:
            raise ValueError(f"Plugin not found: {plugin_name}")
        
        info = {
            'name': plugin_name,
            'type': getattr(plugin, 'plugin_type', 'unknown'),
            'version': getattr(plugin, 'version', 'unknown'),
            'description': getattr(plugin, 'description', 'No description available'),
            'supported_extensions': getattr(plugin, 'supported_extensions', []),
            'enabled': True,
            'configuration': getattr(plugin, 'get_config', lambda: {})()
        }
        
        # Add external tool specific information
        if hasattr(plugin, 'tool_path'):
            info['tool_path'] = plugin.tool_path
            info['tool_available'] = plugin.is_available()
        
        return info
    
    def get_plugins_for_file(self, file_path: str) -> List[str]:
        """
        Get list of plugin names that support the given file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            List of plugin names that can scan this file
        """
        supported_plugins = []
        
        for plugin_name, plugin in self.plugins.items():
            try:
                if hasattr(plugin, 'supports_file') and plugin.supports_file(file_path):
                    supported_plugins.append(plugin_name)
            except Exception as e:
                self.logger.warning(f"Error checking file support for plugin {plugin_name}: {e}")
        
        return supported_plugins
    
    def scan_file(
        self,
        file_path: str,
        content: str,
        plugin_names: List[str],
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Scan a file with specified plugins.
        
        Args:
            file_path: Path to the file
            content: File content
            plugin_names: List of plugin names to use
            **kwargs: Additional scanning options
            
        Returns:
            List of findings as dictionaries
        """
        all_findings = []
        max_threads = self.config.get('scanning.max_threads', 4)
        timeout_per_plugin = self.config.get('plugins.plugin_timeout', 60)
        
        # Filter to only plugins that support this file
        applicable_plugins = []
        for plugin_name in plugin_names:
            plugin = self.plugins.get(plugin_name)
            if plugin and hasattr(plugin, 'supports_file') and plugin.supports_file(file_path):
                applicable_plugins.append((plugin_name, plugin))
        
        if not applicable_plugins:
            self.logger.debug(f"No applicable plugins for file: {file_path}")
            return all_findings
        
        # Scan with plugins (concurrent execution)
        if len(applicable_plugins) > 1 and max_threads > 1:
            all_findings = self._scan_concurrent(
                file_path, content, applicable_plugins, timeout_per_plugin
            )
        else:
            all_findings = self._scan_sequential(
                file_path, content, applicable_plugins, timeout_per_plugin
            )
        
        # Post-process findings
        all_findings = self._post_process_findings(all_findings, file_path)
        
        return all_findings
    
    def _scan_concurrent(
        self,
        file_path: str,
        content: str,
        plugins: List[tuple],
        timeout: int
    ) -> List[Dict[str, Any]]:
        """Scan file with multiple plugins concurrently."""
        all_findings = []
        max_workers = min(len(plugins), self.config.get('scanning.max_threads', 4))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all plugin scan tasks
            future_to_plugin = {}
            for plugin_name, plugin in plugins:
                future = executor.submit(
                    self._scan_with_plugin,
                    plugin_name, plugin, file_path, content, timeout
                )
                future_to_plugin[future] = plugin_name
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_plugin, timeout=timeout * 2):
                plugin_name = future_to_plugin[future]
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                except Exception as e:
                    self.logger.warning(f"Plugin {plugin_name} failed on {file_path}: {e}")
        
        return all_findings
    
    def _scan_sequential(
        self,
        file_path: str,
        content: str,
        plugins: List[tuple],
        timeout: int
    ) -> List[Dict[str, Any]]:
        """Scan file with plugins sequentially."""
        all_findings = []
        
        for plugin_name, plugin in plugins:
            try:
                findings = self._scan_with_plugin(
                    plugin_name, plugin, file_path, content, timeout
                )
                all_findings.extend(findings)
            except Exception as e:
                self.logger.warning(f"Plugin {plugin_name} failed on {file_path}: {e}")
        
        return all_findings
    
    def _scan_with_plugin(
        self,
        plugin_name: str,
        plugin: Any,
        file_path: str,
        content: str,
        timeout: int
    ) -> List[Dict[str, Any]]:
        """Scan file with a single plugin."""
        start_time = time.time()
        
        try:
            # Check if plugin has scan_file method
            if not hasattr(plugin, 'scan_file'):
                self.logger.warning(f"Plugin {plugin_name} missing scan_file method")
                return []
            
            # Execute scan with timeout
            findings = []
            if hasattr(plugin, 'scan_file_with_timeout'):
                findings = plugin.scan_file_with_timeout(file_path, content, timeout)
            else:
                # Use basic scan_file method
                findings = plugin.scan_file(file_path, content)
            
            # Convert findings to dictionaries if needed
            dict_findings = []
            for finding in findings:
                if hasattr(finding, 'to_dict'):
                    dict_findings.append(finding.to_dict())
                elif isinstance(finding, dict):
                    dict_findings.append(finding)
                else:
                    self.logger.warning(f"Invalid finding format from {plugin_name}")
            
            # Add plugin metadata to findings
            for finding in dict_findings:
                finding['plugin'] = plugin_name
                finding['scan_time'] = time.time() - start_time
            
            self.logger.debug(
                f"Plugin {plugin_name} found {len(dict_findings)} issues in "
                f"{file_path} ({time.time() - start_time:.2f}s)"
            )
            
            return dict_findings
            
        except Exception as e:
            self.logger.error(f"Error in plugin {plugin_name} scanning {file_path}: {e}")
            return []
    
    def _post_process_findings(
        self,
        findings: List[Dict[str, Any]],
        file_path: str
    ) -> List[Dict[str, Any]]:
        """Post-process findings to deduplicate and enhance."""
        if not findings:
            return findings
        
        # Deduplicate similar findings
        deduplicated = self._deduplicate_findings(findings)
        
        # Sort by severity and line number
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        deduplicated.sort(key=lambda x: (
            severity_order.get(x.get('severity', '').lower(), 5),
            x.get('line', 0)
        ))
        
        return deduplicated
    
    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate findings based on file, line, and vulnerability type."""
        seen = set()
        deduplicated = []
        
        for finding in findings:
            # Create a key for deduplication
            key = (
                finding.get('filename', ''),
                finding.get('line', 0),
                finding.get('vuln_type', ''),
                finding.get('severity', '')
            )
            
            if key not in seen:
                seen.add(key)
                deduplicated.append(finding)
            else:
                # If duplicate, merge plugin information
                for existing in deduplicated:
                    existing_key = (
                        existing.get('filename', ''),
                        existing.get('line', 0),
                        existing.get('vuln_type', ''),
                        existing.get('severity', '')
                    )
                    if existing_key == key:
                        # Add plugin to list if not already present
                        existing_plugin = existing.get('plugin', '')
                        new_plugin = finding.get('plugin', '')
                        if new_plugin and new_plugin not in existing_plugin:
                            existing['plugin'] = f"{existing_plugin}, {new_plugin}"
                        break
        
        return deduplicated
    
    def scan_directory(
        self,
        directory_path: str,
        plugin_names: List[str],
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Scan all supported files in a directory.
        
        Args:
            directory_path: Path to directory to scan
            plugin_names: List of plugin names to use
            **kwargs: Additional scanning options
            
        Returns:
            List of all findings from directory scan
        """
        from ..utils.file_utils import FileUtils
        
        file_utils = FileUtils(self.config)
        files_to_scan = file_utils.discover_files(Path(directory_path))
        
        all_findings = []
        for file_path in files_to_scan:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                findings = self.scan_file(str(file_path), content, plugin_names, **kwargs)
                all_findings.extend(findings)
            except Exception as e:
                self.logger.warning(f"Error scanning {file_path}: {e}")
        
        return all_findings
    
    def reload_plugins(self):
        """Reload all plugins."""
        self.logger.info("Reloading plugins...")
        self.plugins.clear()
        self._load_plugins()
        self.logger.info(f"Reloaded {len(self.plugins)} plugins")
    
    def get_plugin_statistics(self) -> Dict[str, Any]:
        """Get statistics about loaded plugins."""
        stats = {
            'total_plugins': len(self.plugins),
            'by_type': {},
            'external_tools_available': 0,
            'external_tools_total': 0
        }
        
        for plugin_name, plugin in self.plugins.items():
            plugin_type = getattr(plugin, 'plugin_type', 'unknown')
            stats['by_type'][plugin_type] = stats['by_type'].get(plugin_type, 0) + 1
            
            # Check external tool availability
            if plugin_type == 'external_tool':
                stats['external_tools_total'] += 1
                if hasattr(plugin, 'is_available') and plugin.is_available():
                    stats['external_tools_available'] += 1
        
        return stats
