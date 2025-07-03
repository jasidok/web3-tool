
"""
Web3.js vulnerability scanner for Web3Sec Framework.
"""

import re
from typing import List, Dict, Any

from ..base_plugin import BasePlugin
from ...core.scanner_base import Finding, Severity
from ...utils.logger import get_logger


class Web3JSScanner(BasePlugin):
    """Scanner for Web3.js and JavaScript vulnerabilities in Web3 applications."""
    
    def __init__(self):
        super().__init__()
        self.name = "web3js"
        self.plugin_type = "builtin"
        self.version = "2.0.0"
        self.description = "Web3.js and JavaScript vulnerability scanner for dApp frontends"
        self.supported_extensions = ['.js', '.jsx']
        
        self.logger = get_logger(__name__)
        self.patterns = self._load_vulnerability_patterns()
    
    def get_name(self) -> str:
        return self.name
    
    def supports_file(self, file_path: str) -> bool:
        return any(file_path.lower().endswith(ext) for ext in self.supported_extensions)
    
    def _load_vulnerability_patterns(self) -> Dict[str, Dict]:
        """Load Web3.js vulnerability patterns."""
        return {
            "private_key_exposure": {
                "patterns": [
                    r"privateKey\s*[:=]\s*['\"][0-9a-fA-F]{64}['\"]",
                    r"private_key\s*[:=]\s*['\"][0-9a-fA-F]{64}['\"]",
                    r"PRIVATE_KEY\s*[:=]\s*['\"][0-9a-fA-F]{64}['\"]",
                    r"\.privateKey\s*=\s*['\"][0-9a-fA-F]{64}['\"]"
                ],
                "severity": Severity.CRITICAL,
                "description": "Private key exposed in source code",
                "impact": "Complete compromise of associated wallet and funds",
                "recommendation": "Use environment variables or secure key management systems",
                "bounty_potential": "CRITICAL - Private key exposure can pay $50k-$500k+",
                "category": "Credential Exposure"
            },
            "hardcoded_mnemonic": {
                "patterns": [
                    r"mnemonic\s*[:=]\s*['\"][^'\"]{50,}['\"]",
                    r"seed\s*[:=]\s*['\"][^'\"]{50,}['\"]",
                    r"seedPhrase\s*[:=]\s*['\"][^'\"]{50,}['\"]"
                ],
                "severity": Severity.CRITICAL,
                "description": "Hardcoded mnemonic phrase in source code",
                "impact": "Complete wallet compromise and fund theft",
                "recommendation": "Never hardcode mnemonics, use secure storage",
                "bounty_potential": "CRITICAL - Mnemonic exposure extremely valuable",
                "category": "Credential Exposure"
            },
            "insecure_rpc_endpoint": {
                "patterns": [
                    r"http://[^'\"\s]+",
                    r"ws://[^'\"\s]+",
                    r"new\s+Web3\s*\(\s*['\"]http://",
                    r"provider\s*[:=]\s*['\"]http://"
                ],
                "severity": Severity.MEDIUM,
                "description": "Insecure HTTP RPC endpoint usage",
                "impact": "Man-in-the-middle attacks and data interception",
                "recommendation": "Use HTTPS/WSS endpoints for production",
                "bounty_potential": "MEDIUM - $1k-$5k for insecure connections",
                "category": "Network Security"
            },
            "missing_gas_estimation": {
                "patterns": [
                    r"\.send\(\s*\{[^}]*\}\s*\)(?![^}]*gas)",
                    r"\.call\(\s*\{[^}]*\}\s*\)(?![^}]*gas)",
                    r"contract\.methods\.[^.]+\.send\(\s*\{[^}]*\}\s*\)(?![^}]*gas)"
                ],
                "severity": Severity.MEDIUM,
                "description": "Transaction sent without gas estimation",
                "impact": "Transaction may fail due to insufficient gas",
                "recommendation": "Use estimateGas() before sending transactions",
                "bounty_potential": "LOW - $500-$2k for UX issues",
                "category": "Transaction Handling"
            },
            "insufficient_error_handling": {
                "patterns": [
                    r"\.send\([^)]*\)(?!\s*\.catch)",
                    r"\.call\([^)]*\)(?!\s*\.catch)",
                    r"web3\.eth\.[^(]+\([^)]*\)(?!\s*\.catch)"
                ],
                "severity": Severity.LOW,
                "description": "Missing error handling for Web3 operations",
                "impact": "Poor user experience and potential application crashes",
                "recommendation": "Add proper error handling with .catch() or try-catch",
                "bounty_potential": "LOW - $200-$1k for error handling",
                "category": "Error Handling"
            },
            "unsafe_user_input": {
                "patterns": [
                    r"web3\.utils\.toWei\(\s*userInput",
                    r"web3\.utils\.toWei\(\s*input",
                    r"contract\.methods\.[^(]+\(\s*userInput",
                    r"\.send\(\s*\{\s*value:\s*userInput"
                ],
                "severity": Severity.HIGH,
                "description": "Unsafe user input used in Web3 operations",
                "impact": "Input validation bypass and potential fund loss",
                "recommendation": "Validate and sanitize all user inputs",
                "bounty_potential": "HIGH - $5k-$25k for input validation issues",
                "category": "Input Validation"
            },
            "missing_network_check": {
                "patterns": [
                    r"new\s+Web3\([^)]+\)(?![^;]*getChainId)",
                    r"web3\.eth\.getAccounts\(\)(?![^;]*getChainId)",
                    r"contract\.methods\.[^.]+\.send\([^)]*\)(?![^;]*chainId)"
                ],
                "severity": Severity.MEDIUM,
                "description": "Missing network/chain ID verification",
                "impact": "Transactions may be sent to wrong network",
                "recommendation": "Always verify chain ID before transactions",
                "bounty_potential": "MEDIUM - $2k-$10k for network confusion",
                "category": "Network Security"
            },
            "exposed_api_keys": {
                "patterns": [
                    r"apiKey\s*[:=]\s*['\"][^'\"]{20,}['\"]",
                    r"API_KEY\s*[:=]\s*['\"][^'\"]{20,}['\"]",
                    r"infura\s*[:=]\s*['\"][^'\"]{20,}['\"]",
                    r"alchemy\s*[:=]\s*['\"][^'\"]{20,}['\"]"
                ],
                "severity": Severity.HIGH,
                "description": "API key exposed in source code",
                "impact": "Unauthorized API usage and potential service abuse",
                "recommendation": "Use environment variables for API keys",
                "bounty_potential": "HIGH - $3k-$15k for API key exposure",
                "category": "Credential Exposure"
            },
            "weak_signature_verification": {
                "patterns": [
                    r"web3\.eth\.accounts\.recover\([^)]*\)(?!\s*===)",
                    r"ecrecover\([^)]*\)(?!\s*===)",
                    r"\.recover\([^)]*\)(?![^;]*require)"
                ],
                "severity": Severity.HIGH,
                "description": "Weak signature verification implementation",
                "impact": "Signature forgery and authentication bypass",
                "recommendation": "Properly verify recovered addresses against expected signers",
                "bounty_potential": "HIGH - $10k-$50k for auth bypass",
                "category": "Authentication"
            },
            "console_log_in_production": {
                "patterns": [
                    r"console\.log\(",
                    r"console\.warn\(",
                    r"console\.error\(",
                    r"console\.debug\("
                ],
                "severity": Severity.LOW,
                "description": "Console logging statements in production code",
                "impact": "Information disclosure and performance impact",
                "recommendation": "Remove console statements or use proper logging",
                "bounty_potential": "LOW - $100-$500 for info disclosure",
                "category": "Information Disclosure"
            },
            "missing_slippage_protection": {
                "patterns": [
                    r"swapExactTokensForTokens\([^)]*\)(?![^)]*deadline)",
                    r"swapTokensForExactTokens\([^)]*\)(?![^)]*deadline)",
                    r"addLiquidity\([^)]*\)(?![^)]*deadline)"
                ],
                "severity": Severity.MEDIUM,
                "description": "Missing slippage protection in DeFi operations",
                "impact": "MEV attacks and unfavorable trade execution",
                "recommendation": "Add deadline and slippage parameters",
                "bounty_potential": "MEDIUM - $2k-$8k for MEV vulnerabilities",
                "category": "DeFi Security"
            },
            "unsafe_allowance": {
                "patterns": [
                    r"approve\([^,]+,\s*MAX_UINT256",
                    r"approve\([^,]+,\s*2\*\*256",
                    r"approve\([^,]+,\s*ethers\.constants\.MaxUint256"
                ],
                "severity": Severity.MEDIUM,
                "description": "Unlimited token allowance approval",
                "impact": "Risk of unlimited token spending by approved contract",
                "recommendation": "Use specific allowance amounts when possible",
                "bounty_potential": "MEDIUM - $1k-$5k for allowance issues",
                "category": "Token Security"
            }
        }
    
    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """Scan Web3.js file for vulnerabilities."""
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
        # Enhanced confidence calculation for Web3.js
        if any(keyword in context.lower() for keyword in ['private', 'secret', 'key', 'mnemonic']):
            return "high"
        elif len(pattern_match) > 20:
            return "medium"
        else:
            return "low"
