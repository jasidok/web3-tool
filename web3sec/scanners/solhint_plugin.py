
"""
Solhint integration plugin for Web3Sec Framework.
"""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..base_plugin import BasePlugin
from ...core.scanner_base import Finding, Severity
from ...utils.logger import get_logger


class SolhintPlugin(BasePlugin):
    """
    Plugin for integrating Solhint linter.
    
    Solhint is an open-source linting tool for Solidity that provides
    security and style guide validations.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Solhint plugin.
        
        Args:
            config: Plugin configuration dictionary
        """
        super().__init__()
        self.name = "solhint"
        self.plugin_type = "external_tool"
        self.version = "1.0.0"
        self.description = "Solhint linter integration for Solidity style and security checks"
        self.supported_extensions = ['.sol']
        
        self.logger = get_logger(__name__)
        
        # Configuration
        self.tool_path = config.get('path', 'solhint')
        self.timeout = config.get('timeout', 60)
        self.enabled = config.get('enabled', True)
        
        # Solhint-specific options
        self.config_file = config.get('config_file', None)
        self.rules = config.get('rules', {})
        
        self.logger.debug(f"Solhint plugin initialized with path: {self.tool_path}")
    
    def is_available(self) -> bool:
        """Check if Solhint is available on the system."""
        try:
            result = subprocess.run(
                [self.tool_path, '--version'],
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
        Scan a Solidity file using Solhint.
        
        Args:
            file_path: Path to the file being scanned
            content: File content as string
            
        Returns:
            List of Finding objects
        """
        if not self.is_available():
            self.logger.warning("Solhint is not available, skipping scan")
            return []
        
        findings = []
        
        try:
            # Create temporary file for Solhint analysis
            with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as temp_file:
                temp_file.write(content)
                temp_file_path = temp_file.name
            
            try:
                # Run Solhint analysis
                findings = self._run_solhint_analysis(temp_file_path, file_path)
            finally:
                # Clean up temporary file
                Path(temp_file_path).unlink(missing_ok=True)
        
        except Exception as e:
            self.logger.error(f"Error running Solhint on {file_path}: {e}")
        
        return findings
    
    def _run_solhint_analysis(self, temp_file_path: str, original_file_path: str) -> List[Finding]:
        """Run Solhint analysis and parse results."""
        findings = []
        
        # Build Solhint command
        cmd = [self.tool_path, temp_file_path, '--formatter', 'json']
        
        # Add config file if specified
        if self.config_file:
            cmd.extend(['--config', self.config_file])
        
        try:
            # Execute Solhint
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # Solhint returns non-zero exit code when issues are found
            if result.stdout:
                solhint_data = json.loads(result.stdout)
                findings = self._parse_solhint_results(solhint_data, original_file_path)
            elif result.returncode != 0 and result.stderr:
                self.logger.warning(f"Solhint analysis failed: {result.stderr}")
        
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Solhint analysis timed out after {self.timeout}s")
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Solhint JSON output: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error during Solhint analysis: {e}")
        
        return findings
    
    def _parse_solhint_results(self, solhint_data: List[Dict[str, Any]], file_path: str) -> List[Finding]:
        """Parse Solhint JSON results into Finding objects."""
        findings = []
        
        # Solhint JSON format is an array of file objects
        for file_result in solhint_data:
            messages = file_result.get('messages', [])
            
            for message in messages:
                try:
                    finding = self._create_finding_from_message(message, file_path)
                    if finding:
                        findings.append(finding)
                except Exception as e:
                    self.logger.warning(f"Error parsing Solhint message: {e}")
        
        return findings
    
    def _create_finding_from_message(self, message: Dict[str, Any], file_path: str) -> Optional[Finding]:
        """Create a Finding object from a Solhint message."""
        try:
            # Extract basic information
            rule_id = message.get('ruleId', 'unknown')
            severity_level = message.get('severity', 1)  # 1 = warning, 2 = error
            description = message.get('message', 'No description available')
            line_number = message.get('line', 1)
            column = message.get('column', 1)
            
            # Map Solhint severity to our severity levels
            if severity_level == 2:  # Error
                severity = Severity.HIGH
            else:  # Warning
                severity = Severity.MEDIUM
            
            # Determine if it's a security or style issue
            security_rules = [
                'avoid-suicide', 'avoid-sha3', 'avoid-tx-origin', 'check-send-result',
                'compiler-version', 'func-visibility', 'not-rely-on-time',
                'not-rely-on-block-hash', 'reentrancy', 'state-visibility',
                'avoid-call-value', 'avoid-low-level-calls', 'avoid-throw'
            ]
            
            category = "Security" if rule_id in security_rules else "Style Guide"
            
            # Adjust severity for security issues
            if category == "Security" and rule_id in ['avoid-suicide', 'reentrancy', 'avoid-call-value']:
                severity = Severity.CRITICAL
            elif category == "Security":
                severity = Severity.HIGH
            
            # Create code snippet placeholder
            code_snippet = f"Line {line_number}, Column {column}: {description}"
            
            # Get recommendation based on rule
            recommendation = self._get_recommendation_for_rule(rule_id)
            
            # Assess bounty potential
            bounty_potential = self._assess_bounty_potential(severity, rule_id, category)
            
            finding = Finding(
                filename=file_path,
                line=line_number,
                vuln_type=rule_id.replace('-', ' ').title(),
                severity=severity.value,
                description=description,
                code_snippet=code_snippet,
                impact=f"Rule: {rule_id}, Category: {category}",
                recommendation=recommendation,
                bounty_potential=bounty_potential,
                category=category,
                confidence="high" if category == "Security" else "medium"
            )
            
            return finding
            
        except Exception as e:
            self.logger.error(f"Error creating finding from Solhint message: {e}")
            return None
    
    def _get_recommendation_for_rule(self, rule_id: str) -> str:
        """Get recommendation based on Solhint rule ID."""
        recommendations = {
            'avoid-suicide': 'Remove selfdestruct or add proper access controls',
            'avoid-sha3': 'Use keccak256 instead of sha3',
            'avoid-tx-origin': 'Use msg.sender instead of tx.origin for authorization',
            'check-send-result': 'Check the return value of send() calls',
            'compiler-version': 'Use a specific and recent Solidity compiler version',
            'func-visibility': 'Explicitly specify function visibility',
            'not-rely-on-time': 'Avoid using block.timestamp for critical logic',
            'not-rely-on-block-hash': 'Avoid using blockhash for randomness',
            'reentrancy': 'Use checks-effects-interactions pattern',
            'state-visibility': 'Explicitly specify state variable visibility',
            'avoid-call-value': 'Use transfer() or send() instead of call.value()',
            'avoid-low-level-calls': 'Avoid low-level calls when possible',
            'avoid-throw': 'Use require() or revert() instead of throw',
            'bracket-align': 'Align brackets according to style guide',
            'code-complexity': 'Reduce function complexity',
            'const-name-snakecase': 'Use SNAKE_CASE for constants',
            'contract-name-camelcase': 'Use CamelCase for contract names',
            'event-name-camelcase': 'Use CamelCase for event names',
            'func-name-mixedcase': 'Use mixedCase for function names',
            'func-param-name-mixedcase': 'Use mixedCase for function parameters',
            'indent': 'Use consistent indentation',
            'max-line-length': 'Keep lines under the maximum length limit',
            'modifier-name-mixedcase': 'Use mixedCase for modifier names',
            'no-console': 'Remove console.log statements',
            'no-empty-blocks': 'Remove empty code blocks',
            'no-unused-vars': 'Remove unused variables',
            'quotes': 'Use consistent quote style',
            'semicolon': 'Use semicolons consistently',
            'space-after-comma': 'Add space after commas',
            'var-name-mixedcase': 'Use mixedCase for variable names'
        }
        
        return recommendations.get(rule_id, f'Follow best practices for {rule_id.replace("-", " ")}')
    
    def _assess_bounty_potential(self, severity: Severity, rule_id: str, category: str) -> str:
        """Assess bounty potential based on severity, rule, and category."""
        critical_security_rules = ['avoid-suicide', 'reentrancy', 'avoid-call-value']
        high_security_rules = [
            'avoid-tx-origin', 'check-send-result', 'not-rely-on-time',
            'avoid-low-level-calls', 'func-visibility', 'state-visibility'
        ]
        
        if category == "Security":
            if rule_id in critical_security_rules:
                return "HIGH - Critical security issues often pay $5k-$50k+"
            elif rule_id in high_security_rules:
                return "MEDIUM - Security issues typically $1k-$10k"
            else:
                return "LOW-MEDIUM - Minor security issues usually $100-$2k"
        else:
            return "LOW - Style guide violations rarely qualify for bounties"
    
    def get_config(self) -> Dict[str, Any]:
        """Get current plugin configuration."""
        return {
            'tool_path': self.tool_path,
            'timeout': self.timeout,
            'enabled': self.enabled,
            'config_file': self.config_file,
            'rules': self.rules,
            'available': self.is_available()
        }
