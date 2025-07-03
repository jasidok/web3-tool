"""
Web3Sec Framework - Main orchestration class.
"""

import logging
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Union

from .scanner_manager import ScannerManager
from .plugin_loader import PluginLoader
from .config_manager import ConfigManager
from ..formatters.json_formatter import JSONFormatter
from ..formatters.csv_formatter import CSVFormatter
from ..formatters.html_formatter import HTMLFormatter
from ..utils.logger import get_logger
from ..utils.file_utils import FileUtils
from ..utils.progress import ProgressTracker


class Web3SecFramework:
    """
    Main Web3Sec Framework class that orchestrates all scanning operations.
    
    This class provides the primary interface for the framework, coordinating
    between plugins, scanners, formatters, and configuration management.
    """
    
    def __init__(self, config: Optional[ConfigManager] = None):
        """
        Initialize the Web3Sec Framework.
        
        Args:
            config: Optional ConfigManager instance. If None, creates default config.
        """
        self.logger = get_logger(__name__)
        self.config = config or ConfigManager()
        
        # Initialize core components
        self.plugin_loader = PluginLoader(self.config)
        self.scanner_manager = ScannerManager(self.plugin_loader, self.config)
        self.file_utils = FileUtils(self.config)
        
        # Initialize formatters
        self.formatters = {
            'json': JSONFormatter(),
            'csv': CSVFormatter(),
            'html': HTMLFormatter()
        }
        
        # Scan statistics
        self.stats = {
            'files_processed': 0,
            'files_skipped': 0,
            'vulnerabilities_found': 0,
            'scan_time': 0.0,
            'plugins_used': []
        }
        
        self.logger.info("Web3Sec Framework initialized")
    
    def scan_target(
        self,
        target: Union[str, Path],
        plugins: Optional[List[str]] = None,
        output_format: str = 'json',
        output_file: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Scan a target file or directory for vulnerabilities.
        
        Args:
            target: Path to file or directory to scan
            plugins: List of plugin names to use. If None, uses default plugins
            output_format: Output format ('json', 'csv', 'html')
            output_file: Optional output file path
            **kwargs: Additional scanning options
            
        Returns:
            Dictionary containing scan results and metadata
        """
        start_time = time.time()
        target_path = Path(target)
        
        self.logger.info(f"Starting scan of target: {target_path}")
        
        # Validate target
        if not target_path.exists():
            raise FileNotFoundError(f"Target path does not exist: {target_path}")
        
        # Get plugins to use
        if plugins is None:
            plugins = self.config.get('default_plugins', ['solidity', 'web3js', 'typescript'])
        
        # Validate plugins
        available_plugins = self.list_plugins()
        invalid_plugins = set(plugins) - set(available_plugins)
        if invalid_plugins:
            raise ValueError(f"Invalid plugins: {', '.join(invalid_plugins)}")
        
        self.stats['plugins_used'] = plugins
        
        # Initialize progress tracking
        progress = ProgressTracker(enabled=kwargs.get('show_progress', True))
        
        try:
            # Discover files to scan
            files_to_scan = self.file_utils.discover_files(target_path)
            progress.set_total(len(files_to_scan))
            
            self.logger.info(f"Found {len(files_to_scan)} files to scan")
            
            # Scan files
            all_findings = []
            for file_path in files_to_scan:
                try:
                    progress.update(f"Scanning {file_path.name}")
                    
                    # Read file content
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    
                    # Get applicable plugins for this file
                    file_plugins = self.scanner_manager.get_plugins_for_file(str(file_path))
                    active_plugins = [p for p in plugins if p in file_plugins]
                    
                    if active_plugins:
                        # Scan with applicable plugins
                        findings = self.scanner_manager.scan_file(
                            str(file_path), 
                            content, 
                            active_plugins
                        )
                        all_findings.extend(findings)
                        self.stats['files_processed'] += 1
                    else:
                        self.stats['files_skipped'] += 1
                        
                except Exception as e:
                    self.logger.warning(f"Error scanning {file_path}: {e}")
                    self.stats['files_skipped'] += 1
                
                progress.increment()
            
            progress.finish()
            
            # Calculate final statistics
            self.stats['scan_time'] = time.time() - start_time
            self.stats['vulnerabilities_found'] = len(all_findings)
            
            # Prepare results
            results = {
                'scan_info': {
                    'target': str(target_path),
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'framework_version': '2.0.0',
                    'plugins_used': plugins,
                    'total_files': len(files_to_scan),
                    'files_processed': self.stats['files_processed'],
                    'files_skipped': self.stats['files_skipped'],
                    'scan_time_seconds': round(self.stats['scan_time'], 2)
                },
                'summary': self._generate_summary(all_findings),
                'findings': all_findings
            }
            
            # Format and output results
            if output_file:
                self._write_results(results, output_format, output_file)
            
            self.logger.info(f"Scan completed in {self.stats['scan_time']:.2f}s")
            self.logger.info(f"Found {len(all_findings)} vulnerabilities")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            raise
    
    def list_plugins(self) -> List[str]:
        """
        Get list of available plugin names.
        
        Returns:
            List of plugin names
        """
        return self.scanner_manager.get_available_plugins()
    
    def get_plugin_info(self, plugin_name: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific plugin.
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            Dictionary with plugin information
        """
        return self.scanner_manager.get_plugin_info(plugin_name)
    
    def validate_config(self) -> Dict[str, Any]:
        """
        Validate the current configuration.
        
        Returns:
            Dictionary with validation results
        """
        validation_results = {
            'valid': True,
            'errors': [],
            'warnings': []
        }
        
        # Check external tools
        external_tools = self.config.get('external_tools', {})
        for tool_name, tool_config in external_tools.items():
            if tool_config.get('enabled', False):
                # Check if tool is available
                tool_path = tool_config.get('path', tool_name)
                if not self.file_utils.is_tool_available(tool_path):
                    validation_results['warnings'].append(
                        f"External tool '{tool_name}' not found at path: {tool_path}"
                    )
        
        # Check template directories
        template_dirs = self.config.get('templates', {}).get('custom_template_dirs', [])
        for template_dir in template_dirs:
            if not Path(template_dir).exists():
                validation_results['warnings'].append(
                    f"Custom template directory not found: {template_dir}"
                )
        
        return validation_results
    
    def _generate_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics for findings."""
        summary = {
            'total_findings': len(findings),
            'by_severity': {},
            'by_category': {},
            'by_file': {}
        }
        
        for finding in findings:
            # Count by severity
            severity = finding.get('severity', 'unknown')
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            # Count by category
            category = finding.get('category', 'unknown')
            summary['by_category'][category] = summary['by_category'].get(category, 0) + 1
            
            # Count by file
            filename = finding.get('filename', 'unknown')
            summary['by_file'][filename] = summary['by_file'].get(filename, 0) + 1
        
        return summary
    
    def _write_results(self, results: Dict[str, Any], format_type: str, output_file: str):
        """Write results to file in specified format."""
        formatter = self.formatters.get(format_type)
        if not formatter:
            raise ValueError(f"Unsupported output format: {format_type}")
        
        formatted_output = formatter.format(results)
        
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(formatted_output, encoding='utf-8')
        
        self.logger.info(f"Results written to: {output_path}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current scan statistics."""
        return self.stats.copy()
