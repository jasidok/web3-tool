
"""
Slither integration plugin for Web3Sec Framework.
"""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..base_plugin import BasePlugin
from ...core.scanner_base import Finding, Severity
from ...utils.logger import get_logger


class SlitherPlugin(BasePlugin):
    """
    Plugin for integrating Slither static analyzer.
    
    Slither is a static analysis framework for Solidity that identifies vulnerabilities,
    enhances code comprehension, and facilitates custom analyses.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Slither plugin.
        
        Args:
            config: Plugin configuration dictionary
        """
        super().__init__()
        self.name = "slither"
        self.plugin_type = "external_tool"
        self.version = "1.0.0"
        self.description = "Slither static analyzer integration for Solidity contracts"
        self.supported_extensions = ['.sol']
        
        self.logger = get_logger(__name__)
        
        # Configuration
        self.tool_path = config.get('path', 'slither')
        self.timeout = config.get('timeout', 300)
        self.enabled = config.get('enabled', False)
        
        # Slither-specific options
        self.exclude_detectors = config.get('exclude_detectors', [])
        self.include_detectors = config.get('include_detectors', [])
        self.solc_version = config.get('solc_version', None)
        
        self.logger.debug(f"Slither plugin initialized with path: {self.tool_path}")
    
    def is_available(self) -> bool:
        """Check if Slither is available on the system."""
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
        Scan a Solidity file using Slither.
        
        Args:
            file_path: Path to the file being scanned
            content: File content as string
            
        Returns:
            List of Finding objects
        """
        if not self.is_available():
            self.logger.warning("Slither is not available, skipping scan")
            return []
        
        findings = []
        
        try:
            # Create temporary file for Slither analysis
            with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as temp_file:
                temp_file.write(content)
                temp_file_path = temp_file.name
            
            try:
                # Run Slither with JSON output
                findings = self._run_slither_analysis(temp_file_path, file_path)
            finally:
                # Clean up temporary file
                Path(temp_file_path).unlink(missing_ok=True)
        
        except Exception as e:
            self.logger.error(f"Error running Slither on {file_path}: {e}")
        
        return findings
    
    def _run_slither_analysis(self, temp_file_path: str, original_file_path: str) -> List[Finding]:
        """Run Slither analysis and parse results."""
        findings = []
        
        # Build Slither command
        cmd = [self.tool_path, temp_file_path, '--json', '-']
        
        # Add detector filters
        if self.exclude_detectors:
            cmd.extend(['--exclude', ','.join(self.exclude_detectors)])
        
        if self.include_detectors:
            cmd.extend(['--include', ','.join(self.include_detectors)])
        
        # Add Solidity compiler version if specified
        if self.solc_version:
            cmd.extend(['--solc', self.solc_version])
        
        try:
            # Execute Slither
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode != 0 and not result.stdout:
                self.logger.warning(f"Slither analysis failed: {result.stderr}")
                return findings
            
            # Parse JSON output
            if result.stdout:
                slither_data = json.loads(result.stdout)
                findings = self._parse_slither_results(slither_data, original_file_path)
        
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Slither analysis timed out after {self.timeout}s")
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Slither JSON output: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error during Slither analysis: {e}")
        
        return findings
    
    def _parse_slither_results(self, slither_data: Dict[str, Any], file_path: str) -> List[Finding]:
        """Parse Slither JSON results into Finding objects."""
        findings = []
        
        # Slither JSON structure: {"success": bool, "error": str, "results": {...}}
        if not slither_data.get('success', True):
            self.logger.warning(f"Slither reported error: {slither_data.get('error', 'Unknown error')}")
            return findings
        
        results = slither_data.get('results', {})
        detectors = results.get('detectors', [])
        
        for detector_result in detectors:
            try:
                finding = self._create_finding_from_detector(detector_result, file_path)
                if finding:
                    findings.append(finding)
            except Exception as e:
                self.logger.warning(f"Error parsing Slither detector result: {e}")
        
        return findings
    
    def _create_finding_from_detector(self, detector: Dict[str, Any], file_path: str) -> Optional[Finding]:
        """Create a Finding object from a Slither detector result."""
        try:
            # Extract basic information
            check = detector.get('check', 'unknown')
            impact = detector.get('impact', 'Unknown')
            confidence = detector.get('confidence', 'Unknown')
            description = detector.get('description', 'No description available')
            
            # Map Slither impact to our severity levels
            severity_mapping = {
                'High': Severity.HIGH,
                'Medium': Severity.MEDIUM,
                'Low': Severity.LOW,
                'Informational': Severity.INFO,
                'Optimization': Severity.INFO
            }
            severity = severity_mapping.get(impact, Severity.MEDIUM)
            
            # Extract location information
            elements = detector.get('elements', [])
            if not elements:
                return None
            
            # Use the first element for primary location
            first_element = elements[0]
            source_mapping = first_element.get('source_mapping', {})
            
            line_number = source_mapping.get('lines', [1])[0] if source_mapping.get('lines') else 1
            
            # Extract code snippet if available
            code_snippet = self._extract_code_snippet(detector, source_mapping)
            
            # Create recommendation based on check type
            recommendation = self._get_recommendation_for_check(check)
            
            # Determine bounty potential based on severity and check type
            bounty_potential = self._assess_bounty_potential(severity, check)
            
            finding = Finding(
                filename=file_path,
                line=line_number,
                vuln_type=check.replace('-', ' ').title(),
                severity=severity.value,
                description=description,
                code_snippet=code_snippet,
                impact=f"Impact: {impact}, Confidence: {confidence}",
                recommendation=recommendation,
                bounty_potential=bounty_potential,
                category="Static Analysis",
                confidence=confidence.lower()
            )
            
            return finding
            
        except Exception as e:
            self.logger.error(f"Error creating finding from Slither detector: {e}")
            return None
    
    def _extract_code_snippet(self, detector: Dict[str, Any], source_mapping: Dict[str, Any]) -> str:
        """Extract code snippet from Slither detector result."""
        # Try to get code from elements
        elements = detector.get('elements', [])
        for element in elements:
            if 'source_mapping' in element and 'content' in element['source_mapping']:
                return element['source_mapping']['content']
        
        # Fallback to description if no code snippet available
        return detector.get('description', 'No code snippet available')[:200] + "..."
    
    def _get_recommendation_for_check(self, check: str) -> str:
        """Get recommendation based on Slither check type."""
        recommendations = {
            'reentrancy-eth': 'Use checks-effects-interactions pattern or reentrancy guard',
            'reentrancy-no-eth': 'Use checks-effects-interactions pattern',
            'uninitialized-state': 'Initialize state variables in constructor',
            'uninitialized-storage': 'Initialize storage variables before use',
            'arbitrary-send': 'Validate recipient addresses and use pull payment pattern',
            'controlled-delegatecall': 'Avoid delegatecall with user-controlled data',
            'reentrancy-benign': 'Consider using reentrancy guard for consistency',
            'timestamp': 'Avoid using block.timestamp for critical logic',
            'assembly': 'Review assembly code for security issues',
            'low-level-calls': 'Check return values of low-level calls',
            'naming-convention': 'Follow Solidity naming conventions',
            'pragma': 'Use specific Solidity version pragma',
            'solc-version': 'Use recent Solidity compiler version',
            'unused-state': 'Remove unused state variables',
            'costly-loop': 'Optimize loops to avoid gas limit issues'
        }
        
        return recommendations.get(check, 'Review the identified issue and apply appropriate fixes')
    
    def _assess_bounty_potential(self, severity: Severity, check: str) -> str:
        """Assess bounty potential based on severity and check type."""
        high_value_checks = [
            'reentrancy-eth', 'arbitrary-send', 'controlled-delegatecall',
            'uninitialized-state', 'suicidal'
        ]
        
        if severity == Severity.CRITICAL or check in high_value_checks:
            return "HIGH - Critical vulnerabilities often pay $10k-$100k+"
        elif severity == Severity.HIGH:
            return "MEDIUM-HIGH - High severity issues typically $1k-$25k"
        elif severity == Severity.MEDIUM:
            return "MEDIUM - Medium severity issues usually $500-$5k"
        else:
            return "LOW - Low severity issues typically $100-$1k"
    
    def get_config(self) -> Dict[str, Any]:
        """Get current plugin configuration."""
        return {
            'tool_path': self.tool_path,
            'timeout': self.timeout,
            'enabled': self.enabled,
            'exclude_detectors': self.exclude_detectors,
            'include_detectors': self.include_detectors,
            'solc_version': self.solc_version,
            'available': self.is_available()
        }
