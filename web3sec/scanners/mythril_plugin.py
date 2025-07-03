
"""
Mythril integration plugin for Web3Sec Framework.
"""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..base_plugin import BasePlugin
from ...core.scanner_base import Finding, Severity
from ...utils.logger import get_logger


class MythrilPlugin(BasePlugin):
    """
    Plugin for integrating Mythril security analyzer.
    
    Mythril is a security analysis tool for Ethereum Virtual Machine (EVM) bytecode
    that uses symbolic execution, SMT solving, and taint analysis.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Mythril plugin.
        
        Args:
            config: Plugin configuration dictionary
        """
        super().__init__()
        self.name = "mythril"
        self.plugin_type = "external_tool"
        self.version = "1.0.0"
        self.description = "Mythril security analyzer integration for EVM bytecode analysis"
        self.supported_extensions = ['.sol']
        
        self.logger = get_logger(__name__)
        
        # Configuration
        self.tool_path = config.get('path', 'myth')
        self.timeout = config.get('timeout', 600)
        self.enabled = config.get('enabled', False)
        
        # Mythril-specific options
        self.execution_timeout = config.get('execution_timeout', 300)
        self.max_depth = config.get('max_depth', 22)
        self.strategy = config.get('strategy', 'dfs')
        self.solc_version = config.get('solc_version', None)
        
        self.logger.debug(f"Mythril plugin initialized with path: {self.tool_path}")
    
    def is_available(self) -> bool:
        """Check if Mythril is available on the system."""
        try:
            result = subprocess.run(
                [self.tool_path, 'version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False
    
    def supports_file(self, file_path: str) -> bool:
        """Check if this plugin supports the given file type."""
        return any(file_path.lower().endswith(ext) for ext in self.supported_extensions)
    
    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """
        Scan a Solidity file using Mythril.
        
        Args:
            file_path: Path to the file being scanned
            content: File content as string
            
        Returns:
            List of Finding objects
        """
        if not self.is_available():
            self.logger.warning("Mythril is not available, skipping scan")
            return []
        
        findings = []
        
        try:
            # Create temporary file for Mythril analysis
            with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as temp_file:
                temp_file.write(content)
                temp_file_path = temp_file.name
            
            try:
                # Run Mythril analysis
                findings = self._run_mythril_analysis(temp_file_path, file_path)
            finally:
                # Clean up temporary file
                Path(temp_file_path).unlink(missing_ok=True)
        
        except Exception as e:
            self.logger.error(f"Error running Mythril on {file_path}: {e}")
        
        return findings
    
    def _run_mythril_analysis(self, temp_file_path: str, original_file_path: str) -> List[Finding]:
        """Run Mythril analysis and parse results."""
        findings = []
        
        # Build Mythril command
        cmd = [
            self.tool_path, 'analyze',
            temp_file_path,
            '--outform', 'jsonv2',
            '--execution-timeout', str(self.execution_timeout),
            '--max-depth', str(self.max_depth),
            '--strategy', self.strategy
        ]
        
        # Add Solidity compiler version if specified
        if self.solc_version:
            cmd.extend(['--solv', self.solc_version])
        
        try:
            # Execute Mythril
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # Mythril may return non-zero exit code even with successful analysis
            if result.stdout:
                mythril_data = json.loads(result.stdout)
                findings = self._parse_mythril_results(mythril_data, original_file_path)
            elif result.stderr:
                self.logger.warning(f"Mythril analysis completed with warnings: {result.stderr}")
        
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Mythril analysis timed out after {self.timeout}s")
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Mythril JSON output: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error during Mythril analysis: {e}")
        
        return findings
    
    def _parse_mythril_results(self, mythril_data: List[Dict[str, Any]], file_path: str) -> List[Finding]:
        """Parse Mythril JSONv2 results into Finding objects."""
        findings = []
        
        # Mythril JSONv2 format returns a list of analysis results
        for result in mythril_data:
            issues = result.get('issues', [])
            
            for issue in issues:
                try:
                    finding = self._create_finding_from_issue(issue, file_path)
                    if finding:
                        findings.append(finding)
                except Exception as e:
                    self.logger.warning(f"Error parsing Mythril issue: {e}")
        
        return findings
    
    def _create_finding_from_issue(self, issue: Dict[str, Any], file_path: str) -> Optional[Finding]:
        """Create a Finding object from a Mythril issue."""
        try:
            # Extract basic information
            swc_id = issue.get('swcID', 'Unknown')
            swc_title = issue.get('swcTitle', 'Unknown Issue')
            severity = issue.get('severity', 'Medium')
            
            # Extract description
            description_obj = issue.get('description', {})
            if isinstance(description_obj, dict):
                description = f"{description_obj.get('head', '')} {description_obj.get('tail', '')}".strip()
            else:
                description = str(description_obj)
            
            # Map Mythril severity to our severity levels
            severity_mapping = {
                'High': Severity.HIGH,
                'Medium': Severity.MEDIUM,
                'Low': Severity.LOW
            }
            mapped_severity = severity_mapping.get(severity, Severity.MEDIUM)
            
            # Extract location information
            locations = issue.get('locations', [])
            line_number = 1
            code_snippet = "No code snippet available"
            
            if locations:
                # Use first location
                first_location = locations[0]
                source_map = first_location.get('sourceMap', '')
                
                # Parse source map to extract line number (simplified)
                if ':' in source_map:
                    try:
                        parts = source_map.split(':')
                        if len(parts) >= 2:
                            line_number = int(parts[1]) if parts[1].isdigit() else 1
                    except (ValueError, IndexError):
                        line_number = 1
            
            # Extract test cases for code snippet
            extra = issue.get('extra', {})
            test_cases = extra.get('testCases', [])
            if test_cases:
                # Use the first test case input as code context
                first_test = test_cases[0]
                if 'steps' in first_test and first_test['steps']:
                    first_step = first_test['steps'][0]
                    code_snippet = first_step.get('input', code_snippet)[:200] + "..."
            
            # Create recommendation based on SWC ID
            recommendation = self._get_recommendation_for_swc(swc_id)
            
            # Assess bounty potential
            bounty_potential = self._assess_bounty_potential(mapped_severity, swc_id)
            
            finding = Finding(
                filename=file_path,
                line=line_number,
                vuln_type=swc_title,
                severity=mapped_severity.value,
                description=description,
                code_snippet=code_snippet,
                impact=f"SWC-{swc_id}: {swc_title}",
                recommendation=recommendation,
                bounty_potential=bounty_potential,
                category="Symbolic Execution",
                confidence="high"  # Mythril generally has high confidence
            )
            
            return finding
            
        except Exception as e:
            self.logger.error(f"Error creating finding from Mythril issue: {e}")
            return None
    
    def _get_recommendation_for_swc(self, swc_id: str) -> str:
        """Get recommendation based on SWC ID."""
        recommendations = {
            '101': 'Use SafeMath library or Solidity 0.8+ for arithmetic operations',
            '103': 'Implement proper access controls and input validation',
            '104': 'Check return values of external calls and handle failures',
            '105': 'Avoid using tx.origin for authorization, use msg.sender instead',
            '106': 'Remove or properly protect selfdestruct functionality',
            '107': 'Use checks-effects-interactions pattern to prevent reentrancy',
            '108': 'Validate state changes and use proper error handling',
            '109': 'Initialize state variables properly in constructor',
            '110': 'Use require() for input validation instead of assert()',
            '111': 'Implement proper access controls for sensitive functions',
            '112': 'Use call() instead of delegatecall() when possible',
            '113': 'Implement proper access controls for critical functions',
            '114': 'Avoid using block.timestamp for critical logic',
            '115': 'Validate external contract calls and handle failures',
            '116': 'Avoid using blockhash for randomness',
            '120': 'Implement proper input validation and bounds checking',
            '124': 'Implement proper access controls and ownership patterns'
        }
        
        return recommendations.get(swc_id, 'Review the identified issue and implement appropriate security measures')
    
    def _assess_bounty_potential(self, severity: Severity, swc_id: str) -> str:
        """Assess bounty potential based on severity and SWC ID."""
        critical_swcs = ['106', '107', '112']  # Selfdestruct, Reentrancy, Delegatecall
        high_value_swcs = ['101', '103', '104', '111', '113']  # Overflow, DoS, Unchecked calls, Access control
        
        if severity == Severity.HIGH and swc_id in critical_swcs:
            return "CRITICAL - Critical vulnerabilities often pay $25k-$100k+"
        elif severity == Severity.HIGH or swc_id in high_value_swcs:
            return "HIGH - High severity issues typically $5k-$50k"
        elif severity == Severity.MEDIUM:
            return "MEDIUM - Medium severity issues usually $1k-$10k"
        else:
            return "LOW - Low severity issues typically $100-$2k"
    
    def get_config(self) -> Dict[str, Any]:
        """Get current plugin configuration."""
        return {
            'tool_path': self.tool_path,
            'timeout': self.timeout,
            'enabled': self.enabled,
            'execution_timeout': self.execution_timeout,
            'max_depth': self.max_depth,
            'strategy': self.strategy,
            'solc_version': self.solc_version,
            'available': self.is_available()
        }
