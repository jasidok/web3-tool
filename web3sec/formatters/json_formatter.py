
"""
JSON output formatter for Web3Sec Framework.
"""

import json
from typing import Dict, Any

from .base_formatter import BaseFormatter


class JSONFormatter(BaseFormatter):
    """
    Formats scan results as JSON.
    
    Provides structured, machine-readable output suitable for
    programmatic consumption and integration with other tools.
    """
    
    def __init__(self):
        """Initialize JSON formatter."""
        super().__init__()
        self.format_name = "json"
        self.file_extension = ".json"
    
    def format(self, results: Dict[str, Any]) -> str:
        """
        Format scan results as JSON.
        
        Args:
            results: Dictionary containing scan results and metadata
            
        Returns:
            JSON-formatted string
        """
        try:
            # Ensure all data is JSON serializable
            serializable_results = self._make_serializable(results)
            
            # Format with proper indentation for readability
            return json.dumps(
                serializable_results,
                indent=2,
                ensure_ascii=False,
                sort_keys=True
            )
        
        except Exception as e:
            # Fallback to basic JSON structure
            error_result = {
                "error": f"JSON formatting failed: {str(e)}",
                "scan_info": results.get("scan_info", {}),
                "summary": results.get("summary", {}),
                "findings": []
            }
            return json.dumps(error_result, indent=2)
    
    def _make_serializable(self, obj: Any) -> Any:
        """
        Recursively convert object to JSON-serializable format.
        
        Args:
            obj: Object to convert
            
        Returns:
            JSON-serializable object
        """
        if isinstance(obj, dict):
            return {key: self._make_serializable(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(item) for item in obj]
        elif isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        else:
            # Convert other types to string
            return str(obj)
    
    def format_compact(self, results: Dict[str, Any]) -> str:
        """
        Format scan results as compact JSON (no indentation).
        
        Args:
            results: Dictionary containing scan results and metadata
            
        Returns:
            Compact JSON-formatted string
        """
        try:
            serializable_results = self._make_serializable(results)
            return json.dumps(serializable_results, ensure_ascii=False, separators=(',', ':'))
        except Exception as e:
            return json.dumps({"error": f"JSON formatting failed: {str(e)}"})
    
    def format_findings_only(self, results: Dict[str, Any]) -> str:
        """
        Format only the findings as JSON array.
        
        Args:
            results: Dictionary containing scan results and metadata
            
        Returns:
            JSON array of findings
        """
        try:
            findings = results.get("findings", [])
            serializable_findings = self._make_serializable(findings)
            return json.dumps(serializable_findings, indent=2, ensure_ascii=False)
        except Exception as e:
            return json.dumps([{"error": f"JSON formatting failed: {str(e)}"}])
