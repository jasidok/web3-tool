
"""
TypeScript vulnerability scanner for Web3Sec Framework.
"""

import re
from typing import List, Dict, Any

from ..base_plugin import BasePlugin
from ...core.scanner_base import Finding, Severity
from ...utils.logger import get_logger


class TypeScriptScanner(BasePlugin):
    """Scanner for TypeScript vulnerabilities in Web3 applications."""
    
    def __init__(self):
        super().__init__()
        self.name = "typescript"
        self.plugin_type = "builtin"
        self.version = "2.0.0"
        self.description = "TypeScript vulnerability scanner for Web3 dApp development"
        self.supported_extensions = ['.ts', '.tsx']
        
        self.logger = get_logger(__name__)
        self.patterns = self._load_vulnerability_patterns()
    
    def get_name(self) -> str:
        return self.name
    
    def supports_file(self, file_path: str) -> bool:
        return any(file_path.lower().endswith(ext) for ext in self.supported_extensions)
    
    def _load_vulnerability_patterns(self) -> Dict[str, Dict]:
        """Load TypeScript vulnerability patterns."""
        return {
            "any_type_usage": {
                "patterns": [
                    r":\s*any\b",
                    r"as\s+any\b",
                    r"<any>",
                    r"Array<any>"
                ],
                "severity": Severity.LOW,
                "description": "Usage of 'any' type defeats TypeScript's type safety",
                "impact": "Loss of type safety and potential runtime errors",
                "recommendation": "Use specific types or unknown/object instead of any",
                "bounty_potential": "LOW - $100-$500 for type safety issues",
                "category": "Type Safety"
            },
            "unsafe_type_assertion": {
                "patterns": [
                    r"as\s+\w+(?!\s*\|\s*undefined)",
                    r"<\w+>(?!\s*null)",
                    r"!\s*as\s+\w+"
                ],
                "severity": Severity.MEDIUM,
                "description": "Unsafe type assertion without null checks",
                "impact": "Runtime errors due to incorrect type assumptions",
                "recommendation": "Add proper null/undefined checks before type assertions",
                "bounty_potential": "MEDIUM - $500-$3k for type assertion issues",
                "category": "Type Safety"
            },
            "missing_error_types": {
                "patterns": [
                    r"catch\s*\(\s*\w+\s*\)(?![^}]*instanceof)",
                    r"catch\s*\(\s*error\s*\)(?![^}]*Error)",
                    r"\.catch\(\s*\w+\s*=>"
                ],
                "severity": Severity.LOW,
                "description": "Error handling without proper type checking",
                "impact": "Improper error handling and potential application crashes",
                "recommendation": "Use proper error type checking in catch blocks",
                "bounty_potential": "LOW - $200-$1k for error handling",
                "category": "Error Handling"
            },
            "weak_web3_types": {
                "patterns": [
                    r"web3:\s*any",
                    r"contract:\s*any",
                    r"provider:\s*any",
                    r"signer:\s*any"
                ],
                "severity": Severity.MEDIUM,
                "description": "Weak typing for Web3 objects",
                "impact": "Loss of type safety for critical Web3 operations",
                "recommendation": "Use proper Web3 TypeScript types from @types/web3",
                "bounty_potential": "MEDIUM - $1k-$5k for Web3 type safety",
                "category": "Web3 Security"
            },
            "unsafe_environment_access": {
                "patterns": [
                    r"process\.env\.\w+(?!\s*\|\|)",
                    r"process\.env\[\s*['\"][^'\"]+['\"]\s*\](?!\s*\|\|)",
                    r"import\.meta\.env\.\w+(?!\s*\|\|)"
                ],
                "severity": Severity.MEDIUM,
                "description": "Unsafe environment variable access without fallbacks",
                "impact": "Application crashes when environment variables are missing",
                "recommendation": "Provide default values or proper validation for env vars",
                "bounty_potential": "MEDIUM - $500-$2k for env handling",
                "category": "Configuration"
            },
            "missing_async_error_handling": {
                "patterns": [
                    r"async\s+function[^{]*\{(?![^}]*try)",
                    r"async\s+\([^)]*\)\s*=>[^{]*\{(?![^}]*try)",
                    r"await\s+[^;]+;(?![^}]*catch)"
                ],
                "severity": Severity.MEDIUM,
                "description": "Async function without proper error handling",
                "impact": "Unhandled promise rejections and application instability",
                "recommendation": "Wrap async operations in try-catch blocks",
                "bounty_potential": "MEDIUM - $1k-$5k for async error handling",
                "category": "Error Handling"
            },
            "hardcoded_contract_addresses": {
                "patterns": [
                    r"0x[a-fA-F0-9]{40}",
                    r"contractAddress\s*[:=]\s*['\"]0x[a-fA-F0-9]{40}['\"]",
                    r"address\s*[:=]\s*['\"]0x[a-fA-F0-9]{40}['\"]"
                ],
                "severity": Severity.MEDIUM,
                "description": "Hardcoded contract addresses in source code",
                "impact": "Difficulty in deployment across different networks",
                "recommendation": "Use configuration files or environment variables",
                "bounty_potential": "LOW - $500-$2k for hardcoded addresses",
                "category": "Configuration"
            },
            "unsafe_json_parsing": {
                "patterns": [
                    r"JSON\.parse\([^)]+\)(?!\s*catch)",
                    r"JSON\.parse\([^)]+\)(?![^;]*try)"
                ],
                "severity": Severity.MEDIUM,
                "description": "Unsafe JSON parsing without error handling",
                "impact": "Application crashes on malformed JSON",
                "recommendation": "Wrap JSON.parse in try-catch blocks",
                "bounty_potential": "MEDIUM - $500-$3k for JSON parsing issues",
                "category": "Error Handling"
            },
            "missing_input_validation": {
                "patterns": [
                    r"function\s+\w+\([^)]*:\s*string[^)]*\)(?![^{]*if)",
                    r"function\s+\w+\([^)]*:\s*number[^)]*\)(?![^{]*if)",
                    r"=>\s*\{(?![^}]*if)[^}]*return"
                ],
                "severity": Severity.HIGH,
                "description": "Function missing input validation",
                "impact": "Potential for invalid data processing and security issues",
                "recommendation": "Add proper input validation for all function parameters",
                "bounty_potential": "HIGH - $2k-$10k for input validation bypass",
                "category": "Input Validation"
            },
            "weak_random_generation": {
                "patterns": [
                    r"Math\.random\(\)",
                    r"Date\.now\(\)\s*%",
                    r"new\s+Date\(\)\.getTime\(\)\s*%"
                ],
                "severity": Severity.MEDIUM,
                "description": "Weak random number generation",
                "impact": "Predictable randomness in security-sensitive operations",
                "recommendation": "Use crypto.getRandomValues() for cryptographic randomness",
                "bounty_potential": "MEDIUM - $1k-$8k for weak randomness",
                "category": "Cryptography"
            },
            "console_statements": {
                "patterns": [
                    r"console\.log\(",
                    r"console\.warn\(",
                    r"console\.error\(",
                    r"console\.debug\("
                ],
                "severity": Severity.LOW,
                "description": "Console statements in production code",
                "impact": "Information disclosure and performance impact",
                "recommendation": "Remove console statements or use proper logging",
                "bounty_potential": "LOW - $100-$500 for info disclosure",
                "category": "Information Disclosure"
            },
            "unsafe_dom_manipulation": {
                "patterns": [
                    r"innerHTML\s*=",
                    r"outerHTML\s*=",
                    r"document\.write\(",
                    r"eval\("
                ],
                "severity": Severity.HIGH,
                "description": "Unsafe DOM manipulation that could lead to XSS",
                "impact": "Cross-site scripting vulnerabilities",
                "recommendation": "Use safe DOM manipulation methods like textContent",
                "bounty_potential": "HIGH - $5k-$25k for XSS vulnerabilities",
                "category": "Web Security"
            }
        }
    
    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """Scan TypeScript file for vulnerabilities."""
        findings = []
        lines = content.split('\n')
        
        for vuln_name, vuln_data in self.patterns.items():
            patterns = vuln_data["patterns"]
            
            for pattern in patterns:
                for line_num, line in enumerate(lines, 1):
                    matches = re.finditer(pattern, line, re.IGNORECASE | re.MULTILINE)
                    
                    for match in matches:
                        # Skip if it's in a comment
                        if self._is_in_comment(line, match.start()):
                            continue
                        
                        # Extract code snippet
                        code_snippet = self._extract_code_snippet(content, line_num, context_lines=2)
                        confidence = self._calculate_confidence(match.group(), line)
                        
                        finding = Finding(
                            filename=file_path,
                            line=line_num,
                            vuln_type=vuln_name.replace("_", " ").title(),
                            severity=vuln_data["severity"].value,
                            description=vuln_data["description"],
                            code_snippet=code_snippet,
                            impact=vuln_data["impact"],
                            recommendation=vuln_data["recommendation"],
                            bounty_potential=vuln_data["bounty_potential"],
                            category=vuln_data["category"],
                            confidence=confidence
                        )
                        findings.append(finding)
        
        return findings
    
    def _is_in_comment(self, line: str, position: int) -> bool:
        """Check if position is within a comment."""
        # Check for single-line comment
        comment_pos = line.find('//')
        if comment_pos != -1 and position > comment_pos:
            return True
        
        # Check for JSDoc comment
        if line.strip().startswith('*') or line.strip().startswith('/*'):
            return True
        
        return False
    
    def _extract_code_snippet(self, content: str, line_number: int, context_lines: int = 2) -> str:
        """Extract code snippet around the vulnerable line."""
        lines = content.split('\n')
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        
        snippet_lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line_number - 1 else "    "
            snippet_lines.append(f"{prefix}{i + 1:4d}: {lines[i]}")
        
        return '\n'.join(snippet_lines)
    
    def _calculate_confidence(self, pattern_match: str, context: str) -> str:
        """Calculate confidence level for a finding."""
        # Enhanced confidence calculation for TypeScript
        if any(keyword in context.lower() for keyword in ['private', 'secret', 'password', 'token']):
            return "high"
        elif len(pattern_match) > 15:
            return "medium"
        else:
            return "low"
