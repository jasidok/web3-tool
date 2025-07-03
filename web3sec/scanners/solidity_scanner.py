
"""
Enhanced Solidity vulnerability scanner for Web3Sec Framework.
"""

import re
from typing import List, Dict, Any

from ..base_plugin import BasePlugin
from ...core.scanner_base import Finding, Severity
from ...utils.logger import get_logger
from ...analyzers.reentrancy_analyzer import ReentrancyAnalyzer, extract_functions_from_solidity


class SolidityScanner(BasePlugin):
    """Enhanced scanner for Solidity smart contract vulnerabilities."""
    
    def __init__(self):
        super().__init__()
        self.name = "solidity"
        self.plugin_type = "builtin"
        self.version = "2.1.0"
        self.description = "Enhanced Solidity vulnerability scanner with comprehensive reentrancy analysis"
        self.supported_extensions = ['.sol']
        
        self.logger = get_logger(__name__)
        self.patterns = self._load_vulnerability_patterns()
        self.reentrancy_analyzer = ReentrancyAnalyzer()
        
        # Configuration for reentrancy analysis depth
        self.reentrancy_analysis_depth = "standard"  # quick, standard, deep
    
    def get_name(self) -> str:
        return self.name
    
    def supports_file(self, file_path: str) -> bool:
        return any(file_path.lower().endswith(ext) for ext in self.supported_extensions)
    
    def set_reentrancy_analysis_depth(self, depth: str):
        """Set the depth of reentrancy analysis: quick, standard, or deep."""
        if depth in ["quick", "standard", "deep"]:
            self.reentrancy_analysis_depth = depth
        else:
            self.logger.warning(f"Invalid reentrancy analysis depth: {depth}. Using 'standard'.")
            self.reentrancy_analysis_depth = "standard"
    
    def _load_vulnerability_patterns(self) -> Dict[str, Dict]:
        """Load enhanced Solidity vulnerability patterns."""
        return {
            "unchecked_call": {
                "patterns": [
                    r"\.call\([^)]*\)(?!\s*(?:require|assert|\|\||&&))",
                    r"\.delegatecall\([^)]*\)(?!\s*(?:require|assert|\|\||&&))",
                    r"\.staticcall\([^)]*\)(?!\s*(?:require|assert|\|\||&&))"
                ],
                "severity": Severity.HIGH,
                "description": "Unchecked external call - return value not verified",
                "impact": "Silent failures can lead to inconsistent state and loss of funds",
                "recommendation": "Always check return values of external calls using require() or assert()",
                "bounty_potential": "HIGH - $5k-$25k typically",
                "category": "Error Handling"
            },
            "integer_overflow": {
                "patterns": [
                    r"(?<!SafeMath\.)(\+|\-|\*|\/)\s*(?!SafeMath)",
                    r"uint256\s+\w+\s*=\s*\w+\s*[\+\-\*\/]\s*\w+(?!\s*(?:require|assert))"
                ],
                "severity": Severity.HIGH,
                "description": "Potential integer overflow/underflow - arithmetic without SafeMath",
                "impact": "Can cause unexpected behavior, token minting, or fund loss",
                "recommendation": "Use SafeMath library or Solidity 0.8+ built-in overflow checks",
                "bounty_potential": "HIGH - Often $5k-$50k depending on impact",
                "category": "Arithmetic"
            },
            "tx_origin_auth": {
                "patterns": [
                    r"require\s*\(\s*tx\.origin\s*==",
                    r"if\s*\(\s*tx\.origin\s*==",
                    r"modifier\s+\w+\s*\([^)]*\)\s*\{[^}]*tx\.origin"
                ],
                "severity": Severity.MEDIUM,
                "description": "Use of tx.origin for authorization",
                "impact": "Vulnerable to phishing attacks through malicious contracts",
                "recommendation": "Use msg.sender instead of tx.origin for authorization",
                "bounty_potential": "MEDIUM - $1k-$10k usually",
                "category": "Access Control"
            },
            "delegatecall_injection": {
                "patterns": [
                    r"\.delegatecall\(\s*abi\.encodeWithSignature",
                    r"\.delegatecall\(\s*\w+\s*\)",
                    r"assembly\s*\{[^}]*delegatecall"
                ],
                "severity": Severity.CRITICAL,
                "description": "Delegatecall usage - potential for malicious code execution",
                "impact": "Can allow attacker to execute arbitrary code in contract context",
                "recommendation": "Carefully validate delegatecall targets, use libraries, or avoid delegatecall",
                "bounty_potential": "CRITICAL - $25k-$100k+ for exploitable cases",
                "category": "Code Injection"
            },
            "selfdestruct_access": {
                "patterns": [
                    r"selfdestruct\s*\(",
                    r"suicide\s*\("
                ],
                "severity": Severity.CRITICAL,
                "description": "Contract can be destroyed via selfdestruct",
                "impact": "Contract and funds can be permanently destroyed",
                "recommendation": "Remove selfdestruct or add proper access controls with multi-sig",
                "bounty_potential": "CRITICAL - $25k-$100k+ if exploitable",
                "category": "Access Control"
            },
            "weak_randomness": {
                "patterns": [
                    r"block\.timestamp\s*%",
                    r"block\.number\s*%",
                    r"block\.difficulty\s*%",
                    r"blockhash\([^)]*\)\s*%",
                    r"keccak256\(abi\.encodePacked\(block\."
                ],
                "severity": Severity.MEDIUM,
                "description": "Weak randomness source using predictable block properties",
                "impact": "Randomness can be manipulated by miners or predicted",
                "recommendation": "Use commit-reveal schemes, external oracles, or VRF",
                "bounty_potential": "MEDIUM - $2k-$15k for gambling/lottery contracts",
                "category": "Randomness"
            },
            "unprotected_function": {
                "patterns": [
                    r"function\s+\w+\([^)]*\)\s+(?:public|external)(?!\s+(?:view|pure))(?![^{]*(?:onlyOwner|require\(msg\.sender|modifier))",
                    r"function\s+\w+\([^)]*\)\s+(?:public|external)\s+(?:payable\s+)?(?![^{]*(?:onlyOwner|require\(msg\.sender|modifier))"
                ],
                "severity": Severity.HIGH,
                "description": "Public/external function without access control",
                "impact": "Anyone can call sensitive functions",
                "recommendation": "Add proper access control modifiers (onlyOwner, etc.)",
                "bounty_potential": "HIGH - $10k-$75k+ depending on function impact",
                "category": "Access Control"
            },
            "timestamp_dependence": {
                "patterns": [
                    r"block\.timestamp\s*[<>=!]+",
                    r"now\s*[<>=!]+",
                    r"require\([^)]*block\.timestamp"
                ],
                "severity": Severity.LOW,
                "description": "Timestamp dependence detected",
                "impact": "Miners can manipulate timestamps within ~15 second window",
                "recommendation": "Avoid strict timestamp comparisons, use block numbers instead",
                "bounty_potential": "LOW - $500-$3k for timing-sensitive logic",
                "category": "Timing"
            },
            "dos_gas_limit": {
                "patterns": [
                    r"for\s*\([^)]*;\s*\w+\s*<\s*\w+\.length\s*;[^)]*\)\s*\{[^}]*(?:transfer|send|call)",
                    r"while\s*\([^)]*\.length[^)]*\)\s*\{[^}]*(?:transfer|send|call)"
                ],
                "severity": Severity.MEDIUM,
                "description": "Potential DoS via gas limit in loops with external calls",
                "impact": "Function can become uncallable due to gas limit",
                "recommendation": "Implement pull payment pattern or limit loop iterations",
                "bounty_potential": "MEDIUM - $2k-$10k for DoS vulnerabilities",
                "category": "Denial of Service"
            },
            "unsafe_cast": {
                "patterns": [
                    r"uint8\s*\(\s*\w+\s*\)",
                    r"uint16\s*\(\s*\w+\s*\)",
                    r"uint32\s*\(\s*\w+\s*\)",
                    r"int8\s*\(\s*\w+\s*\)"
                ],
                "severity": Severity.MEDIUM,
                "description": "Unsafe type casting detected",
                "impact": "Data truncation can lead to unexpected behavior",
                "recommendation": "Add bounds checking before casting to smaller types",
                "bounty_potential": "MEDIUM - $1k-$8k for casting issues",
                "category": "Type Safety"
            },
            "missing_zero_check": {
                "patterns": [
                    r"function\s+\w+\([^)]*address\s+\w+[^)]*\)\s+[^{]*\{(?![^}]*require\([^)]*!=\s*address\(0\))",
                    r"=\s*\w+\s*;(?![^;]*require\([^)]*!=\s*address\(0\))"
                ],
                "severity": Severity.LOW,
                "description": "Missing zero address check",
                "impact": "Functions may accept zero address leading to locked funds",
                "recommendation": "Add require(address != address(0)) checks",
                "bounty_potential": "LOW - $500-$2k for zero address issues",
                "category": "Input Validation"
            },
            "floating_pragma": {
                "patterns": [
                    r"pragma\s+solidity\s*\^",
                    r"pragma\s+solidity\s*>=.*<"
                ],
                "severity": Severity.LOW,
                "description": "Floating pragma version",
                "impact": "Contract may be compiled with different compiler versions",
                "recommendation": "Use specific pragma version for production contracts",
                "bounty_potential": "LOW - $100-$1k for version issues",
                "category": "Best Practices"
            }
        }
    
    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """Scan Solidity file for vulnerabilities."""
        findings = []
        
        # First, run the comprehensive reentrancy analysis
        reentrancy_findings = self._scan_reentrancy_comprehensive(file_path, content)
        findings.extend(reentrancy_findings)
        
        # Then run other vulnerability pattern scans
        other_findings = self._scan_other_vulnerabilities(file_path, content)
        findings.extend(other_findings)
        
        return findings
    
    def _scan_reentrancy_comprehensive(self, file_path: str, content: str) -> List[Finding]:
        """Perform comprehensive reentrancy analysis."""
        findings = []
        
        try:
            # Extract functions from the Solidity code
            functions = extract_functions_from_solidity(content)
            
            for func_name, func_code, start_line, end_line in functions:
                # Skip view/pure functions for reentrancy analysis
                if re.search(r'\b(view|pure)\b', func_code, re.IGNORECASE):
                    continue
                
                # Analyze the function for reentrancy
                analysis = self.reentrancy_analyzer.analyze_function(
                    func_code, func_name, file_path, start_line
                )
                
                if analysis:
                    # Convert analysis to Finding
                    finding = self._create_reentrancy_finding(
                        file_path, func_name, start_line, analysis, func_code
                    )
                    findings.append(finding)
                    
                    # Log detailed analysis for debugging
                    self.logger.debug(f"Reentrancy analysis for {func_name}: {analysis.reasoning}")
        
        except Exception as e:
            self.logger.error(f"Error in comprehensive reentrancy analysis: {e}")
            # Fall back to basic pattern matching if advanced analysis fails
            findings.extend(self._scan_basic_reentrancy(file_path, content))
        
        return findings
    
    def _create_reentrancy_finding(self, file_path: str, func_name: str, 
                                 start_line: int, analysis, func_code: str) -> Finding:
        """Create a Finding object from reentrancy analysis."""
        
        # Determine severity based on confidence
        if analysis.confidence == "HIGH":
            severity = Severity.CRITICAL.value
        elif analysis.confidence == "MEDIUM":
            severity = Severity.HIGH.value
        else:
            severity = Severity.MEDIUM.value
        
        # Create detailed description
        description = f"Reentrancy vulnerability detected in function '{func_name}'"
        
        # Create enhanced code snippet
        code_snippet = self._extract_code_snippet(func_code, 1, context_lines=5)
        
        # Create detailed impact description
        impact = f"Function allows potential reentrancy attack. {analysis.reasoning}"
        
        # Create comprehensive recommendations
        recommendations = "\n".join([f"• {rec}" for rec in analysis.recommendations])
        
        # Determine bounty potential based on confidence and pattern
        if analysis.confidence == "HIGH" and analysis.pattern_type == "risky":
            bounty_potential = "CRITICAL - $25k-$100k+ for exploitable reentrancy"
        elif analysis.confidence == "MEDIUM":
            bounty_potential = "HIGH - $10k-$50k for reentrancy vulnerabilities"
        else:
            bounty_potential = "MEDIUM - $5k-$25k depending on exploitability"
        
        # Create structured analysis data for JSON output
        analysis_data = {
            "state_updated_before_call": analysis.state_updated_before_call,
            "external_call_type": analysis.external_call_type,
            "gas_forwarded": analysis.gas_forwarded,
            "access_control": analysis.access_control,
            "reasoning": analysis.reasoning,
            "external_calls_count": len(analysis.external_calls),
            "state_changes_count": len(analysis.state_changes)
        }
        
        finding = Finding(
            filename=file_path,
            line=start_line,
            vuln_type="Reentrancy",
            severity=severity,
            description=description,
            code_snippet=code_snippet,
            impact=impact,
            recommendation=recommendations,
            bounty_potential=bounty_potential,
            category="Access Control",
            confidence=analysis.confidence.lower()
        )
        
        # Add analysis data as additional attribute
        finding.analysis = analysis_data
        
        return finding
    
    def _scan_basic_reentrancy(self, file_path: str, content: str) -> List[Finding]:
        """Fallback basic reentrancy pattern matching."""
        findings = []
        lines = content.split('\n')
        
        basic_patterns = [
            r"\.call\{value:\s*\w+\}\(\s*\"\"\s*\)",
            r"\.call\.value\(\w+\)\(\)",
            r"\.send\(\w+\)",
            r"\.transfer\(\w+\)",
            r"payable\([^)]+\)\.call\{value:",
            r"address\([^)]+\)\.call\{value:",
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in basic_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    if not self._is_in_comment(line, 0):
                        code_snippet = self._extract_code_snippet(content, line_num, context_lines=3)
                        
                        finding = Finding(
                            filename=file_path,
                            line=line_num,
                            vuln_type="Reentrancy (Basic Detection)",
                            severity=Severity.HIGH.value,
                            description="Potential reentrancy vulnerability - external call detected",
                            code_snippet=code_snippet,
                            impact="Attacker may be able to drain contract funds through recursive calls",
                            recommendation="Use checks-effects-interactions pattern, reentrancy guard, or pull payment pattern",
                            bounty_potential="HIGH - Reentrancy bugs often pay $10k-$75k+",
                            category="Access Control",
                            confidence="medium"
                        )
                        findings.append(finding)
        
        return findings
    
    def _scan_other_vulnerabilities(self, file_path: str, content: str) -> List[Finding]:
        """Scan for other vulnerability patterns (non-reentrancy)."""
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
                        
                        # Extract more context for better snippet
                        code_snippet = self._extract_code_snippet(content, line_num, context_lines=3)
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
        
        # TODO: Add multi-line comment detection
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
        # Enhanced confidence calculation
        if len(pattern_match) > 30 and any(keyword in context.lower() for keyword in ['require', 'assert', 'check']):
            return "high"
        elif len(pattern_match) > 15:
            return "medium"
        else:
            return "low"
