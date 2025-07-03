
"""
Ethlint integration plugin for Web3Sec Framework.
"""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..base_plugin import BasePlugin
from ...core.scanner_base import Finding, Severity
from ...utils.logger import get_logger


class EthlintPlugin(BasePlugin):
    """
    Plugin for integrating Ethlint (formerly Solium) linter.
    
    Ethlint is a static code analysis tool for Solidity that identifies
    and reports on potential style and security issues.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Ethlint plugin.
        
        Args:
            config: Plugin configuration dictionary
        """
        super().__init__()
        self.name = "ethlint"
        self.plugin_type = "external_tool"
        self.version = "1.0.0"
        self.description = "Ethlint (Solium) linter integration for Solidity analysis"
        self.supported_extensions = ['.sol']
        
        self.logger = get_logger(__name__)
        
        # Configuration
        self.tool_path = config.get('path', 'ethlint')
        self.timeout = config.get('timeout', 60)
        self.enabled = config.get('enabled', False)
        
        # Ethlint-specific options
        self.config_file = config.get('config_file', None)
        self.fix = config.get('fix', False)
        
        self.logger.debug(f"Ethlint plugin initialized with path: {self.tool_path}")
    
    def is_available(self) -> bool:
        """Check if Ethlint is available on the system."""
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
        Scan a Solidity file using Ethlint.
        
        Args:
            file_path: Path to the file being scanned
            content: File content as string
            
        Returns:
            List of Finding objects
        """
        if not self.is_available():
            self.logger.warning("Ethlint is not available, skipping scan")
            return []
        
        findings = []
        
        try:
            # Create temporary file for Ethlint analysis
            with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as temp_file:
                temp_file.write(content)
                temp_file_path = temp_file.name
            
            try:
                # Run Ethlint analysis
                findings = self._run_ethlint_analysis(temp_file_path, file_path)
            finally:
                # Clean up temporary file
                Path(temp_file_path).unlink(missing_ok=True)
        
        except Exception as e:
            self.logger.error(f"Error running Ethlint on {file_path}: {e}")
        
        return findings
    
    def _run_ethlint_analysis(self, temp_file_path: str, original_file_path: str) -> List[Finding]:
        """Run Ethlint analysis and parse results."""
        findings = []
        
        # Build Ethlint command
        cmd = [self.tool_path, temp_file_path, '--reporter', 'json']
        
        # Add config file if specified
        if self.config_file:
            cmd.extend(['--config', self.config_file])
        
        try:
            # Execute Ethlint
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # Parse output - Ethlint may output to stderr for some versions
            output = result.stdout or result.stderr
            
            if output:
                try:
                    ethlint_data = json.loads(output)
                    findings = self._parse_ethlint_results(ethlint_data, original_file_path)
                except json.JSONDecodeError:
                    # Fallback to parsing text output if JSON parsing fails
                    findings = self._parse_text_output(output, original_file_path)
            elif result.returncode != 0:
                self.logger.warning(f"Ethlint analysis failed with return code {result.returncode}")
        
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Ethlint analysis timed out after {self.timeout}s")
        except Exception as e:
            self.logger.error(f"Unexpected error during Ethlint analysis: {e}")
        
        return findings
    
    def _parse_ethlint_results(self, ethlint_data: List[Dict[str, Any]], file_path: str) -> List[Finding]:
        """Parse Ethlint JSON results into Finding objects."""
        findings = []
        
        # Handle different possible JSON structures
        if isinstance(ethlint_data, list):
            # Array of file results
            for file_result in ethlint_data:
                if isinstance(file_result, dict):
                    messages = file_result.get('messages', [])
                    for message in messages:
                        finding = self._create_finding_from_message(message, file_path)
                        if finding:
                            findings.append(finding)
        elif isinstance(ethlint_data, dict):
            # Single file result or different structure
            messages = ethlint_data.get('messages', [])
            for message in messages:
                finding = self._create_finding_from_message(message, file_path)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _parse_text_output(self, output: str, file_path: str) -> List[Finding]:
        """Parse text output as fallback when JSON parsing fails."""
        findings = []
        lines = output.strip().split('\n')
        
        for line in lines:
            if not line.strip():
                continue
            
            try:
                # Try to parse common Ethlint text format
                # Example: "1:1  error  'pragma' is not defined  no-undef"
                parts = line.split()
                if len(parts) >= 4:
                    location = parts[0]
                    severity = parts[1]
                    message = ' '.join(parts[2:-1])
                    rule_id = parts[-1] if parts[-1] != message.split()[-1] else 'unknown'
                    
                    # Parse line:column
                    line_num = 1
                    if ':' in location:
                        try:
                            line_num = int(location.split(':')[0])
                        except ValueError:
                            pass
                    
                    # Map severity
                    mapped_severity = Severity.HIGH if severity == 'error' else Severity.MEDIUM
                    
                    finding = Finding(
                        filename=file_path,
                        line=line_num,
                        vuln_type=rule_id.replace('-', ' ').title(),
                        severity=mapped_severity.value,
                        description=message,
                        code_snippet=f"Line {line_num}: {message}",
                        impact=f"Rule: {rule_id}",
                        recommendation=self._get_recommendation_for_rule(rule_id),
                        bounty_potential=self._assess_bounty_potential(mapped_severity, rule_id),
                        category="Linting",
                        confidence="medium"
                    )
                    findings.append(finding)
            except Exception as e:
                self.logger.debug(f"Could not parse line: {line} - {e}")
        
        return findings
    
    def _create_finding_from_message(self, message: Dict[str, Any], file_path: str) -> Optional[Finding]:
        """Create a Finding object from an Ethlint message."""
        try:
            # Extract basic information
            rule_id = message.get('ruleId', message.get('rule', 'unknown'))
            severity_level = message.get('severity', 1)
            description = message.get('message', 'No description available')
            line_number = message.get('line', 1)
            column = message.get('column', 1)
            
            # Map Ethlint severity to our severity levels
            if severity_level == 2:  # Error
                severity = Severity.HIGH
            else:  # Warning
                severity = Severity.MEDIUM
            
            # Determine category based on rule type
            security_rules = [
                'no-unused-vars', 'no-empty', 'quotes', 'semi',
                'pragma-on-top', 'no-experimental', 'imports-on-top'
            ]
            
            category = "Security" if rule_id not in security_rules else "Style"
            
            # Create code snippet
            code_snippet = f"Line {line_number}, Column {column}: {description}"
            
            # Get recommendation
            recommendation = self._get_recommendation_for_rule(rule_id)
            
            # Assess bounty potential
            bounty_potential = self._assess_bounty_potential(severity, rule_id)
            
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
                confidence="medium"
            )
            
            return finding
            
        except Exception as e:
            self.logger.error(f"Error creating finding from Ethlint message: {e}")
            return None
    
    def _get_recommendation_for_rule(self, rule_id: str) -> str:
        """Get recommendation based on Ethlint rule ID."""
        recommendations = {
            'quotes': 'Use consistent quote style (single or double quotes)',
            'semi': 'Use semicolons consistently',
            'no-unused-vars': 'Remove unused variables',
            'no-empty': 'Remove empty code blocks or add comments',
            'pragma-on-top': 'Place pragma directive at the top of the file',
            'no-experimental': 'Avoid using experimental features in production',
            'imports-on-top': 'Place import statements at the top of the file',
            'indentation': 'Use consistent indentation (tabs or spaces)',
            'bracket-align': 'Align brackets according to style guide',
            'operator-whitespace': 'Use consistent whitespace around operators',
            'comma-hanging': 'Use consistent comma placement',
            'array-declarations': 'Use consistent array declaration style',
            'variable-declarations': 'Use consistent variable declaration style',
            'function-whitespace': 'Use consistent whitespace in function declarations',
            'lbrace': 'Place opening braces consistently',
            'mixedcase': 'Use mixedCase for function and variable names',
            'camelcase': 'Use camelCase for identifiers',
            'uppercase': 'Use UPPERCASE for constants',
            'no-constant': 'Avoid using constant keyword for functions',
            'max-len': 'Keep lines under the maximum length limit'
        }
        
        return recommendations.get(rule_id, f'Follow best practices for {rule_id.replace("-", " ")}')
    
    def _assess_bounty_potential(self, severity: Severity, rule_id: str) -> str:
        """Assess bounty potential based on severity and rule."""
        # Ethlint is primarily a style linter, so bounty potential is generally low
        if severity == Severity.HIGH:
            return "LOW - Style and linting issues rarely qualify for bounties"
        else:
            return "VERY LOW - Minor style issues do not typically qualify for bounties"
    
    def get_config(self) -> Dict[str, Any]:
        """Get current plugin configuration."""
        return {
            'tool_path': self.tool_path,
            'timeout': self.timeout,
            'enabled': self.enabled,
            'config_file': self.config_file,
            'fix': self.fix,
            'available': self.is_available()
        }
