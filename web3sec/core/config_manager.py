"""
Configuration management for Web3Sec Framework.
"""

import json
import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, Union

from ..utils.logger import get_logger


class ConfigManager:
    """
    Manages configuration for the Web3Sec Framework.
    
    Supports loading configuration from:
    1. Default built-in configuration
    2. .web3scanrc file (JSON or YAML)
    3. Environment variables
    4. Command-line overrides
    """
    
    DEFAULT_CONFIG = {
        "default_plugins": ["solidity", "web3js", "typescript"],
        "external_tools": {
            "slither": {
                "enabled": False,
                "path": "slither",
                "timeout": 300
            },
            "mythril": {
                "enabled": False,
                "path": "myth",
                "timeout": 600
            },
            "solhint": {
                "enabled": True,
                "path": "solhint",
                "timeout": 60
            },
            "ethlint": {
                "enabled": False,
                "path": "ethlint",
                "timeout": 60
            }
        },
        "output": {
            "default_format": "json",
            "include_code_snippets": True,
            "max_snippet_lines": 5,
            "show_progress": True
        },
        "scanning": {
            "max_file_size_mb": 10,
            "exclude_patterns": [
                "node_modules/*",
                "*.test.js",
                "*.spec.js",
                "test/*",
                "tests/*",
                "*.min.js",
                "dist/*",
                "build/*"
            ],
            "max_threads": 4,
            "timeout_per_file": 30
        },
        "logging": {
            "level": "INFO",
            "file": None,
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            "console_format": "%(levelname)s: %(message)s"
        },
        "templates": {
            "custom_template_dirs": [],
            "builtin_templates": True,
            "template_timeout": 10
        },
        "plugins": {
            "custom_plugin_dirs": [],
            "plugin_timeout": 60,
            "enable_external_plugins": True
        }
    }
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_file: Optional path to configuration file
        """
        self.logger = get_logger(__name__)
        self.config = self.DEFAULT_CONFIG.copy()
        self.config_file = config_file
        
        # Load configuration in order of precedence
        self._load_default_config()
        self._load_config_file()
        self._load_environment_variables()
        
        self.logger.debug("Configuration loaded successfully")
    
    def _load_default_config(self):
        """Load default configuration."""
        self.config = self.DEFAULT_CONFIG.copy()
    
    def _load_config_file(self):
        """Load configuration from file."""
        config_paths = []
        
        # Add explicitly specified config file
        if self.config_file:
            config_paths.append(Path(self.config_file))
        
        # Add standard config file locations
        config_paths.extend([
            Path.cwd() / ".web3scanrc",
            Path.cwd() / ".web3scanrc.json",
            Path.cwd() / ".web3scanrc.yaml",
            Path.cwd() / ".web3scanrc.yml",
            Path.home() / ".web3scanrc",
            Path.home() / ".web3scanrc.json",
            Path.home() / ".web3scanrc.yaml",
            Path.home() / ".web3scanrc.yml"
        ])
        
        for config_path in config_paths:
            if config_path.exists():
                try:
                    self._load_config_from_file(config_path)
                    self.logger.info(f"Loaded configuration from: {config_path}")
                    break
                except Exception as e:
                    self.logger.warning(f"Failed to load config from {config_path}: {e}")
    
    def _load_config_from_file(self, config_path: Path):
        """Load configuration from a specific file."""
        content = config_path.read_text(encoding='utf-8')
        
        # Try to parse as JSON first, then YAML
        try:
            file_config = json.loads(content)
        except json.JSONDecodeError:
            try:
                file_config = yaml.safe_load(content)
            except yaml.YAMLError as e:
                raise ValueError(f"Invalid configuration file format: {e}")
        
        # Merge with existing configuration
        self._deep_merge(self.config, file_config)
    
    def _load_environment_variables(self):
        """Load configuration from environment variables."""
        env_mappings = {
            'WEB3SEC_LOG_LEVEL': ('logging', 'level'),
            'WEB3SEC_MAX_THREADS': ('scanning', 'max_threads'),
            'WEB3SEC_MAX_FILE_SIZE': ('scanning', 'max_file_size_mb'),
            'WEB3SEC_OUTPUT_FORMAT': ('output', 'default_format'),
            'WEB3SEC_SLITHER_PATH': ('external_tools', 'slither', 'path'),
            'WEB3SEC_MYTHRIL_PATH': ('external_tools', 'mythril', 'path'),
            'WEB3SEC_SOLHINT_PATH': ('external_tools', 'solhint', 'path'),
        }
        
        for env_var, config_path in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                self._set_nested_value(self.config, config_path, self._convert_env_value(value))
                self.logger.debug(f"Set config from env var {env_var}: {config_path}")
    
    def _convert_env_value(self, value: str) -> Union[str, int, bool]:
        """Convert environment variable string to appropriate type."""
        # Try boolean
        if value.lower() in ('true', 'false'):
            return value.lower() == 'true'
        
        # Try integer
        try:
            return int(value)
        except ValueError:
            pass
        
        # Return as string
        return value
    
    def _deep_merge(self, target: Dict[str, Any], source: Dict[str, Any]):
        """Deep merge source dictionary into target dictionary."""
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._deep_merge(target[key], value)
            else:
                target[key] = value
    
    def _set_nested_value(self, config: Dict[str, Any], path: tuple, value: Any):
        """Set a nested configuration value using a path tuple."""
        current = config
        for key in path[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        current[path[-1]] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by key.
        
        Args:
            key: Configuration key (supports dot notation for nested keys)
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        keys = key.split('.')
        current = self.config
        
        try:
            for k in keys:
                current = current[k]
            return current
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any):
        """
        Set configuration value by key.
        
        Args:
            key: Configuration key (supports dot notation for nested keys)
            value: Value to set
        """
        keys = key.split('.')
        current = self.config
        
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        
        current[keys[-1]] = value
    
    def update(self, updates: Dict[str, Any]):
        """
        Update configuration with dictionary of values.
        
        Args:
            updates: Dictionary of configuration updates
        """
        self._deep_merge(self.config, updates)
    
    def override_from_cli(self, cli_args: Dict[str, Any]):
        """
        Override configuration with command-line arguments.
        
        Args:
            cli_args: Dictionary of CLI arguments
        """
        # Map CLI arguments to configuration keys
        cli_mappings = {
            'verbose': ('logging', 'level', 'DEBUG'),
            'debug': ('logging', 'level', 'DEBUG'),
            'silent': ('logging', 'level', 'ERROR'),
            'threads': ('scanning', 'max_threads'),
            'output_format': ('output', 'default_format'),
            'exclude_patterns': ('scanning', 'exclude_patterns'),
            'max_file_size': ('scanning', 'max_file_size_mb'),
            'template_dir': ('templates', 'custom_template_dirs'),
        }
        
        for cli_key, config_mapping in cli_mappings.items():
            if cli_key in cli_args and cli_args[cli_key] is not None:
                if len(config_mapping) == 3:
                    # Special case with conditional value
                    if cli_args[cli_key]:
                        self._set_nested_value(self.config, config_mapping[:2], config_mapping[2])
                else:
                    # Direct mapping
                    value = cli_args[cli_key]
                    
                    # Handle special cases
                    if cli_key == 'exclude_patterns' and isinstance(value, str):
                        value = [p.strip() for p in value.split(',')]
                    elif cli_key == 'template_dir':
                        # Add to existing list
                        existing = self.get('templates.custom_template_dirs', [])
                        if isinstance(value, str):
                            value = existing + [value]
                        else:
                            value = existing + value
                    
                    self._set_nested_value(self.config, config_mapping, value)
    
    def get_all(self) -> Dict[str, Any]:
        """Get complete configuration dictionary."""
        return self.config.copy()
    
    def save_to_file(self, file_path: str, format_type: str = 'json'):
        """
        Save current configuration to file.
        
        Args:
            file_path: Path to save configuration
            format_type: Format to save ('json' or 'yaml')
        """
        config_path = Path(file_path)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        if format_type.lower() == 'json':
            content = json.dumps(self.config, indent=2, ensure_ascii=False)
        elif format_type.lower() in ('yaml', 'yml'):
            content = yaml.dump(self.config, default_flow_style=False, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format_type}")
        
        config_path.write_text(content, encoding='utf-8')
        self.logger.info(f"Configuration saved to: {config_path}")
    
    def validate(self) -> Dict[str, Any]:
        """
        Validate current configuration.
        
        Returns:
            Dictionary with validation results
        """
        validation = {
            'valid': True,
            'errors': [],
            'warnings': []
        }
        
        # Validate required sections
        required_sections = ['default_plugins', 'external_tools', 'output', 'scanning', 'logging']
        for section in required_sections:
            if section not in self.config:
                validation['errors'].append(f"Missing required configuration section: {section}")
                validation['valid'] = False
        
        # Validate numeric values
        numeric_configs = [
            ('scanning.max_threads', 1, 32),
            ('scanning.max_file_size_mb', 1, 1000),
            ('output.max_snippet_lines', 1, 20),
        ]
        
        for config_key, min_val, max_val in numeric_configs:
            value = self.get(config_key)
            if value is not None:
                if not isinstance(value, int) or value < min_val or value > max_val:
                    validation['warnings'].append(
                        f"Invalid value for {config_key}: {value} (should be {min_val}-{max_val})"
                    )
        
        # Validate log level
        log_level = self.get('logging.level')
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if log_level and log_level not in valid_levels:
            validation['warnings'].append(
                f"Invalid log level: {log_level} (should be one of {valid_levels})"
            )
        
        return validation
