
"""
Base scanner classes and data structures for Web3Sec Framework.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Represents a vulnerability finding."""
    filename: str
    line: int
    vuln_type: str
    severity: str
    description: str
    code_snippet: str
    impact: Optional[str] = None
    recommendation: Optional[str] = None
    bounty_potential: Optional[str] = None
    category: Optional[str] = None
    confidence: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary format."""
        return {
            "filename": self.filename,
            "line": self.line,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "description": self.description,
            "code_snippet": self.code_snippet,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "bounty_potential": self.bounty_potential,
            "category": self.category,
            "confidence": self.confidence
        }


class ScannerBase(ABC):
    """Abstract base class for all vulnerability scanners."""
    
    def __init__(self, name: str):
        self.name = name
        self.supported_extensions = []
        self.patterns = {}
    
    @abstractmethod
    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """
        Scan a file for vulnerabilities.
        
        Args:
            file_path: Path to the file being scanned
            content: File content as string
            
        Returns:
            List of Finding objects
        """
        pass
    
    def supports_file(self, file_path: str) -> bool:
        """Check if this scanner supports the given file type."""
        return any(file_path.lower().endswith(ext) for ext in self.supported_extensions)
    
    def get_name(self) -> str:
        """Get scanner name."""
        return self.name
    
    def get_supported_extensions(self) -> List[str]:
        """Get list of supported file extensions."""
        return self.supported_extensions.copy()
    
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
        # Simple heuristic - can be enhanced
        if len(pattern_match) > 20 and any(keyword in context.lower() for keyword in ['require', 'assert', 'check']):
            return "high"
        elif len(pattern_match) > 10:
            return "medium"
        else:
            return "low"
