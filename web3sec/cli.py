"""
Advanced CLI interface for Web3Sec Framework.
"""

import argparse
import sys
import time
from pathlib import Path
from typing import List, Optional

from core.framework import Web3SecFramework
from core.config_manager import ConfigManager
from utils.logger import setup_logger, get_logger


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the comprehensive argument parser."""
    parser = argparse.ArgumentParser(
        prog="web3sec",
        description="Web3Sec Framework - Professional-grade Web3 vulnerability scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan of a Solidity contract
  web3sec --target contract.sol --output results.json

  # Scan entire project with specific plugins
  web3sec --target /path/to/project --plugins solidity,mythril,slither --output scan.html

  # Scan with custom templates and verbose output
  web3sec --target dapp/ --template-dir ./custom-templates --verbose --output report.csv

  # List available plugins
  web3sec --list-plugins

  # Scan with configuration file
  web3sec --target project/ --config .web3scanrc --threads 8 --silent

  # Exclude test files and use external tools
  web3sec --target src/ --exclude "*.test.js,test/*" --plugins all --debug

Configuration:
  The framework looks for configuration files in the following order:
  1. File specified with --config
  2. .web3scanrc in current directory
  3. .web3scanrc in home directory
  
  Configuration files can be JSON or YAML format.

Plugin Types:
  - Built-in: solidity, web3js, typescript
  - External: slither, mythril, solhint, ethlint
  - Template: Custom YAML-based vulnerability templates
  - Custom: User-defined plugins in specified directories

For more information, visit: https://github.com/web3sec/web3sec-framework
        """
    )
    
    # Target specification
    target_group = parser.add_argument_group('Target Options')
    target_group.add_argument(
        "--target", "-t",
        required=True,
        help="Target file or directory to scan"
    )
    
    target_group.add_argument(
        "--exclude",
        help="Comma-separated list of file patterns to exclude (e.g., '*.test.js,node_modules/*')"
    )
    
    # Plugin selection
    plugin_group = parser.add_argument_group('Plugin Options')
    plugin_group.add_argument(
        "--plugins", "-p",
        help="Comma-separated list of plugins to use (default: solidity,web3js,typescript). Use 'all' for all available plugins"
    )
    
    plugin_group.add_argument(
        "--list-plugins",
        action="store_true",
        help="List all available plugins and exit"
    )
    
    plugin_group.add_argument(
        "--plugin-info",
        help="Show detailed information about a specific plugin"
    )
    
    # Template options
    template_group = parser.add_argument_group('Template Options')
    template_group.add_argument(
        "--template-dir",
        action="append",
        help="Additional directory to search for custom templates (can be used multiple times)"
    )
    
    template_group.add_argument(
        "--list-templates",
        action="store_true",
        help="List all available templates and exit"
    )
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        "--output", "-o",
        help="Output file path (default: stdout)"
    )
    
    output_group.add_argument(
        "--format", "-f",
        choices=["json", "csv", "html"],
        default="json",
        help="Output format (default: json)"
    )
    
    output_group.add_argument(
        "--no-code-snippets",
        action="store_true",
        help="Exclude code snippets from output"
    )
    
    # Filtering options
    filter_group = parser.add_argument_group('Filtering Options')
    filter_group.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Minimum severity level to report"
    )
    
    filter_group.add_argument(
        "--category",
        help="Filter by vulnerability category"
    )
    
    filter_group.add_argument(
        "--confidence",
        choices=["high", "medium", "low"],
        help="Minimum confidence level to report"
    )
    
    # Performance options
    perf_group = parser.add_argument_group('Performance Options')
    perf_group.add_argument(
        "--threads",
        type=int,
        help="Number of threads for concurrent scanning (default: 4)"
    )
    
    perf_group.add_argument(
        "--max-file-size",
        type=int,
        help="Maximum file size to scan in MB (default: 10)"
    )
    
    perf_group.add_argument(
        "--timeout",
        type=int,
        help="Timeout per file in seconds (default: 30)"
    )
    
    # Logging and verbosity
    log_group = parser.add_argument_group('Logging Options')
    log_group.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output (INFO level)"
    )
    
    log_group.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output (DEBUG level)"
    )
    
    log_group.add_argument(
        "--silent", "-s",
        action="store_true",
        help="Suppress all output except errors"
    )
    
    log_group.add_argument(
        "--log-file",
        help="Write logs to specified file"
    )
    
    # Configuration options
    config_group = parser.add_argument_group('Configuration Options')
    config_group.add_argument(
        "--config", "-c",
        help="Path to configuration file (.web3scanrc)"
    )
    
    config_group.add_argument(
        "--save-config",
        help="Save current configuration to specified file"
    )
    
    config_group.add_argument(
        "--validate-config",
        action="store_true",
        help="Validate configuration and exit"
    )
    
    # Utility options
    util_group = parser.add_argument_group('Utility Options')
    util_group.add_argument(
        "--version",
        action="version",
        version="Web3Sec Framework 2.0.0"
    )
    
    util_group.add_argument(
        "--stats",
        action="store_true",
        help="Show detailed scanning statistics"
    )
    
    util_group.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress indicators"
    )
    
    return parser


def handle_list_plugins(framework: Web3SecFramework):
    """Handle --list-plugins command."""
    plugins = framework.list_plugins()
    
    if not plugins:
        print("No plugins available.")
        return
    
    print("Available Plugins:")
    print("=" * 50)
    
    # Group plugins by type
    plugin_groups = {}
    for plugin_name in plugins:
        try:
            info = framework.get_plugin_info(plugin_name)
            plugin_type = info.get('type', 'unknown')
            if plugin_type not in plugin_groups:
                plugin_groups[plugin_type] = []
            plugin_groups[plugin_type].append((plugin_name, info))
        except Exception as e:
            print(f"Error getting info for plugin {plugin_name}: {e}")
    
    # Display plugins by type
    for plugin_type, plugin_list in plugin_groups.items():
        print(f"\n{plugin_type.title()} Plugins:")
        print("-" * 30)
        
        for plugin_name, info in plugin_list:
            status = "✓" if info.get('enabled', True) else "✗"
            description = info.get('description', 'No description')
            extensions = ', '.join(info.get('supported_extensions', []))
            
            print(f"  {status} {plugin_name}")
            print(f"    Description: {description}")
            if extensions:
                print(f"    File types: {extensions}")
            
            # Show external tool status
            if plugin_type == 'external_tool':
                available = info.get('tool_available', False)
                tool_path = info.get('tool_path', 'unknown')
                status_text = "Available" if available else "Not found"
                print(f"    Tool status: {status_text} ({tool_path})")
            
            print()


def handle_plugin_info(framework: Web3SecFramework, plugin_name: str):
    """Handle --plugin-info command."""
    try:
        info = framework.get_plugin_info(plugin_name)
        
        print(f"Plugin Information: {plugin_name}")
        print("=" * 50)
        
        for key, value in info.items():
            if key == 'configuration' and isinstance(value, dict):
                print(f"{key.title()}:")
                for config_key, config_value in value.items():
                    print(f"  {config_key}: {config_value}")
            else:
                print(f"{key.title()}: {value}")
        
    except Exception as e:
        print(f"Error getting plugin information: {e}")
        sys.exit(1)


def handle_validate_config(config: ConfigManager):
    """Handle --validate-config command."""
    validation = config.validate()
    
    print("Configuration Validation Results:")
    print("=" * 40)
    
    if validation['valid']:
        print("✓ Configuration is valid")
    else:
        print("✗ Configuration has errors")
    
    if validation['errors']:
        print("\nErrors:")
        for error in validation['errors']:
            print(f"  ✗ {error}")
    
    if validation['warnings']:
        print("\nWarnings:")
        for warning in validation['warnings']:
            print(f"  ⚠ {warning}")
    
    if not validation['valid']:
        sys.exit(1)


def main():
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    try:
        # Initialize configuration
        config = ConfigManager(config_file=args.config)
        
        # Override configuration with CLI arguments
        cli_overrides = {
            'verbose': args.verbose,
            'debug': args.debug,
            'silent': args.silent,
            'threads': args.threads,
            'output_format': args.format,
            'exclude_patterns': args.exclude,
            'max_file_size': args.max_file_size,
            'template_dir': args.template_dir,
            'log_file': args.log_file,
            'timeout': args.timeout,
            'show_progress': not args.no_progress,
            'include_code_snippets': not args.no_code_snippets
        }
        
        # Remove None values
        cli_overrides = {k: v for k, v in cli_overrides.items() if v is not None}
        config.override_from_cli(cli_overrides)
        
        # Setup logging
        log_level = 'ERROR' if args.silent else ('DEBUG' if args.debug else ('INFO' if args.verbose else 'WARNING'))
        logger = setup_logger(
            level=log_level,
            log_file=args.log_file,
            console_format=config.get('logging.console_format')
        )
        
        # Handle utility commands
        if args.validate_config:
            handle_validate_config(config)
            return
        
        if args.save_config:
            config.save_to_file(args.save_config)
            print(f"Configuration saved to: {args.save_config}")
            return
        
        # Initialize framework
        framework = Web3SecFramework(config)
        
        # Handle list commands
        if args.list_plugins:
            handle_list_plugins(framework)
            return
        
        if args.plugin_info:
            handle_plugin_info(framework, args.plugin_info)
            return
        
        # Validate target
        target_path = Path(args.target)
        if not target_path.exists():
            logger.error(f"Target path does not exist: {target_path}")
            sys.exit(1)
        
        # Determine plugins to use
        if args.plugins:
            if args.plugins.lower() == 'all':
                plugins = framework.list_plugins()
            else:
                plugins = [p.strip() for p in args.plugins.split(',')]
        else:
            plugins = config.get('default_plugins', ['solidity', 'web3js', 'typescript'])
        
        # Validate plugins
        available_plugins = framework.list_plugins()
        invalid_plugins = set(plugins) - set(available_plugins)
        if invalid_plugins:
            logger.error(f"Invalid plugins: {', '.join(invalid_plugins)}")
            logger.info(f"Available plugins: {', '.join(available_plugins)}")
            sys.exit(1)
        
        logger.info(f"Starting scan with plugins: {', '.join(plugins)}")
        logger.info(f"Target: {target_path}")
        
        # Perform scan
        start_time = time.time()
        
        scan_options = {
            'show_progress': not args.no_progress,
            'severity_filter': args.severity,
            'category_filter': args.category,
            'confidence_filter': args.confidence
        }
        
        results = framework.scan_target(
            target=target_path,
            plugins=plugins,
            output_format=args.format,
            output_file=args.output,
            **scan_options
        )
        
        scan_time = time.time() - start_time
        
        # Display results summary
        if not args.silent:
            summary = results['summary']
            print(f"\nScan completed in {scan_time:.2f}s")
            print(f"Files processed: {results['scan_info']['files_processed']}")
            print(f"Total vulnerabilities: {summary['total_findings']}")
            
            if summary['by_severity']:
                print("\nFindings by severity:")
                severity_order = ['critical', 'high', 'medium', 'low', 'info']
                for severity in severity_order:
                    count = summary['by_severity'].get(severity, 0)
                    if count > 0:
                        emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵', 'info': '⚪'}.get(severity, '⚫')
                        print(f"  {emoji} {severity.title()}: {count}")
        
        # Show detailed statistics if requested
        if args.stats:
            stats = framework.get_stats()
            print(f"\nDetailed Statistics:")
            print(f"  Scan time: {stats['scan_time']:.2f}s")
            print(f"  Files processed: {stats['files_processed']}")
            print(f"  Files skipped: {stats['files_skipped']}")
            print(f"  Plugins used: {', '.join(stats['plugins_used'])}")
        
        # Output results if no output file specified
        if not args.output and not args.silent:
            from .formatters.json_formatter import JSONFormatter
            formatter = JSONFormatter()
            print("\n" + formatter.format(results))
    
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        if args.debug if 'args' in locals() else False:
            import traceback
            traceback.print_exc()
        else:
            print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
