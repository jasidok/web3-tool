
"""
Template-based plugin for YAML vulnerability templates.
"""

import re
import yaml
from typing import List, Dict, Any, Optional

from .base_plugin import BasePlugin
from ..core.scanner_base import Finding, Severity
from ..utils.logger import get_logger


class TemplatePlugin(BasePlugin):
    """
    Plugin that executes YAML-based vulnerability templates.
    
    This plugin implements a Nuclei-style template system for
    defining custom vulnerability checks using YAML templates.
    """
    
    def __init__(self, template_name: str, template_data: Dict[str, Any]):
        """
        Initialize template plugin.
        
        Args:
            template_name: Name of the template
            template_data: Parsed YAML template data
        """
        super().__init__()
        self.template_name = template_name
        self.template_data = template_data
        
        self.name = f"template_{template_name}"
        self.plugin_type = "template"
        self.version = "1.0.0"
        
        self.logger = get_logger(__name__)
        
        # Parse template metadata
        self._parse_template_info()
        
        self.logger.debug(f"Template plugin initialized: {self.name}")
    
    def _parse_template_info(self):
        """Parse template information section."""
        info = self.template_data.get('info', {})
        
        self.description = info.get('description', f'Template-based scan: {self.template_name}')
        self.template_severity = info.get('severity', 'medium')
        self.template_author = info.get('author', 'unknown')
        self.template_tags = info.get('tags', [])
        
        # Determine supported file extensions from template
        file_matchers = self.template_data.get('file', {})
        if file_matchers:
            extensions = file_matchers.get('extensions', [])
            self.supported_extensions = [ext if ext.startswith('.') else f'.{ext}' for ext in extensions]
        else:
            # Default to common web3 file types
            self.supported_extensions = ['.sol', '.js', '.ts', '.json']
    
    def get_name(self) -> str:
        """Get plugin name."""
        return self.name
    
    def supports_file(self, file_path: str) -> bool:
        """Check if template supports the given file type."""
        if not self.supported_extensions:
            return True  # Template applies to all files if no extensions specified
        
        return any(file_path.lower().endswith(ext) for ext in self.supported_extensions)
    
    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """
        Scan file using template rules.
        
        Args:
            file_path: Path to the file being scanned
            content: File content as string
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        try:
            # Execute template matchers
            if self._execute_matchers(content, file_path):
                finding = self._create_finding(file_path, content)
                if finding:
                    findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Error executing template {self.template_name}: {e}")
        
        return findings
    
    def _execute_matchers(self, content: str, file_path: str) -> bool:
        """
        Execute template matchers against file content.
        
        Args:
            content: File content
            file_path: File path
            
        Returns:
            True if all matchers pass
        """
        matchers = self.template_data.get('matchers', [])
        if not matchers:
            return False
        
        matcher_condition = self.template_data.get('matchers-condition', 'or')
        
        results = []
        for matcher in matchers:
            result = self._execute_single_matcher(matcher, content, file_path)
            results.append(result)
        
        # Apply matcher condition
        if matcher_condition.lower() == 'and':
            return all(results)
        else:  # 'or'
            return any(results)
    
    def _execute_single_matcher(self, matcher: Dict[str, Any], content: str, file_path: str) -> bool:
        """Execute a single matcher."""
        matcher_type = matcher.get('type', 'word')
        negative = matcher.get('negative', False)
        
        result = False
        
        try:
            if matcher_type == 'word':
                result = self._match_words(matcher, content)
            elif matcher_type == 'regex':
                result = self._match_regex(matcher, content)
            elif matcher_type == 'size':
                result = self._match_size(matcher, content)
            elif matcher_type == 'dsl':
                result = self._match_dsl(matcher, content, file_path)
            elif matcher_type == 'binary':
                result = self._match_binary(matcher, content)
            else:
                self.logger.warning(f"Unknown matcher type: {matcher_type}")
                return False
        
        except Exception as e:
            self.logger.error(f"Error executing matcher {matcher_type}: {e}")
            return False
        
        # Apply negative condition
        return not result if negative else result
    
    def _match_words(self, matcher: Dict[str, Any], content: str) -> bool:
        """Match words in content."""
        words = matcher.get('words', [])
        condition = matcher.get('condition', 'or')
        case_insensitive = matcher.get('case-insensitive', False)
        
        if case_insensitive:
            content = content.lower()
            words = [word.lower() for word in words]
        
        matches = [word in content for word in words]
        
        if condition == 'and':
            return all(matches)
        else:  # 'or'
            return any(matches)
    
    def _match_regex(self, matcher: Dict[str, Any], content: str) -> bool:
        """Match regex patterns in content."""
        patterns = matcher.get('regex', [])
        
        for pattern in patterns:
            try:
                if re.search(pattern, content, re.MULTILINE | re.IGNORECASE):
                    return True
            except re.error as e:
                self.logger.warning(f"Invalid regex pattern '{pattern}': {e}")
        
        return False
    
    def _match_size(self, matcher: Dict[str, Any], content: str) -> bool:
        """Match content size."""
        size_conditions = matcher.get('size', [])
        content_size = len(content)
        
        for condition in size_conditions:
            if isinstance(condition, int):
                if content_size == condition:
                    return True
            elif isinstance(condition, str):
                # Parse size conditions like ">1000", "<500", ">=100"
                if condition.startswith('>='):
                    if content_size >= int(condition[2:]):
                        return True
                elif condition.startswith('<='):
                    if content_size <= int(condition[2:]):
                        return True
                elif condition.startswith('>'):
                    if content_size > int(condition[1:]):
                        return True
                elif condition.startswith('<'):
                    if content_size < int(condition[1:]):
                        return True
        
        return False
    
    def _match_dsl(self, matcher: Dict[str, Any], content: str, file_path: str) -> bool:
        """Match using DSL expressions."""
        dsl_expressions = matcher.get('dsl', [])
        
        # Create context for DSL evaluation
        context = {
            'len': len,
            'body': content,
            'content': content,
            'file_path': file_path,
            'file_name': file_path.split('/')[-1] if '/' in file_path else file_path,
            'file_size': len(content)
        }
        
        for expression in dsl_expressions:
            try:
                # Simple DSL evaluation (limited for security)
                # This is a simplified implementation
                if self._evaluate_dsl_expression(expression, context):
                    return True
            except Exception as e:
                self.logger.warning(f"Error evaluating DSL expression '{expression}': {e}")
        
        return False
    
    def _evaluate_dsl_expression(self, expression: str, context: Dict[str, Any]) -> bool:
        """Evaluate a DSL expression safely."""
        # Replace context variables
        for key, value in context.items():
            if isinstance(value, str):
                expression = expression.replace(key, f'"{value}"')
            else:
                expression = expression.replace(key, str(value))
        
        # Simple expression evaluation (very limited for security)
        try:
            # Only allow basic comparisons and arithmetic
            allowed_chars = set('0123456789+-*/<>=!&|() "\'')
            if not all(c in allowed_chars for c in expression.replace(' ', '')):
                return False
            
            # Evaluate the expression
            return eval(expression)
        except:
            return False
    
    def _match_binary(self, matcher: Dict[str, Any], content: str) -> bool:
        """Match binary patterns in content."""
        binary_patterns = matcher.get('binary', [])
        
        # Convert content to bytes for binary matching
        try:
            content_bytes = content.encode('utf-8', errors='ignore')
        except:
            return False
        
        for pattern in binary_patterns:
            try:
                # Convert hex pattern to bytes
                if isinstance(pattern, str):
                    pattern_bytes = bytes.fromhex(pattern.replace(' ', ''))
                    if pattern_bytes in content_bytes:
                        return True
            except ValueError:
                self.logger.warning(f"Invalid binary pattern: {pattern}")
        
        return False
    
    def _create_finding(self, file_path: str, content: str) -> Optional[Finding]:
        """Create a Finding object from template match."""
        try:
            info = self.template_data.get('info', {})
            
            # Map template severity to our severity levels
            severity_mapping = {
                'critical': Severity.CRITICAL,
                'high': Severity.HIGH,
                'medium': Severity.MEDIUM,
                'low': Severity.LOW,
                'info': Severity.INFO
            }
            
            severity = severity_mapping.get(self.template_severity.lower(), Severity.MEDIUM)
            
            # Extract line number if possible (simplified)
            line_number = 1
            
            # Create code snippet
            lines = content.split('\n')
            snippet_lines = lines[:3] if len(lines) >= 3 else lines
            code_snippet = '\n'.join(f"{i+1:4d}: {line}" for i, line in enumerate(snippet_lines))
            
            # Get template metadata
            vuln_type = info.get('name', self.template_name)
            description = info.get('description', f'Template {self.template_name} matched')
            
            # Create recommendation
            recommendation = info.get('remediation', 'Review the identified issue and apply appropriate fixes')
            
            # Assess bounty potential based on severity and tags
            bounty_potential = self._assess_bounty_potential(severity, self.template_tags)
            
            finding = Finding(
                filename=file_path,
                line=line_number,
                vuln_type=vuln_type,
                severity=severity.value,
                description=description,
                code_snippet=code_snippet,
                impact=info.get('impact', 'See template description'),
                recommendation=recommendation,
                bounty_potential=bounty_potential,
                category="Template Match",
                confidence="medium"
            )
            
            return finding
            
        except Exception as e:
            self.logger.error(f"Error creating finding from template: {e}")
            return None
    
    def _assess_bounty_potential(self, severity: Severity, tags: List[str]) -> str:
        """Assess bounty potential based on severity and tags."""
        high_value_tags = ['rce', 'sqli', 'xss', 'idor', 'auth-bypass', 'privilege-escalation']
        medium_value_tags = ['disclosure', 'dos', 'csrf', 'redirect']
        
        has_high_value = any(tag in high_value_tags for tag in tags)
        has_medium_value = any(tag in medium_value_tags for tag in tags)
        
        if severity == Severity.CRITICAL and has_high_value:
            return "CRITICAL - High-impact vulnerabilities often pay $25k-$100k+"
        elif severity == Severity.HIGH or has_high_value:
            return "HIGH - High severity issues typically $5k-$50k"
        elif severity == Severity.MEDIUM or has_medium_value:
            return "MEDIUM - Medium severity issues usually $1k-$10k"
        else:
            return "LOW - Low severity issues typically $100-$2k"
    
    def get_config(self) -> Dict[str, Any]:
        """Get template configuration."""
        return {
            'template_name': self.template_name,
            'template_data': self.template_data,
            'supported_extensions': self.supported_extensions,
            'severity': self.template_severity,
            'author': self.template_author,
            'tags': self.template_tags
        }
