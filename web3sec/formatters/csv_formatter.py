
"""
CSV output formatter for Web3Sec Framework.
"""

import csv
from io import StringIO
from typing import Dict, Any, List

from .base_formatter import BaseFormatter


class CSVFormatter(BaseFormatter):
    """
    Formats scan results as CSV.
    
    Provides tabular output suitable for spreadsheet applications
    and data analysis tools.
    """
    
    def __init__(self):
        """Initialize CSV formatter."""
        super().__init__()
        self.format_name = "csv"
        self.file_extension = ".csv"
    
    def format(self, results: Dict[str, Any]) -> str:
        """
        Format scan results as CSV.
        
        Args:
            results: Dictionary containing scan results and metadata
            
        Returns:
            CSV-formatted string
        """
        try:
            findings = results.get("findings", [])
            
            if not findings:
                return self._create_empty_csv()
            
            # Create CSV content
            output = StringIO()
            
            # Define CSV columns
            fieldnames = [
                'filename', 'line', 'vuln_type', 'severity', 'description',
                'category', 'confidence', 'plugin', 'impact', 'recommendation',
                'bounty_potential'
            ]
            
            writer = csv.DictWriter(output, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
            writer.writeheader()
            
            # Write findings
            for finding in findings:
                csv_row = self._prepare_csv_row(finding, fieldnames)
                writer.writerow(csv_row)
            
            return output.getvalue()
        
        except Exception as e:
            return f"Error formatting CSV: {str(e)}\n"
    
    def _create_empty_csv(self) -> str:
        """Create CSV with headers but no data."""
        output = StringIO()
        fieldnames = [
            'filename', 'line', 'vuln_type', 'severity', 'description',
            'category', 'confidence', 'plugin', 'impact', 'recommendation',
            'bounty_potential'
        ]
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        return output.getvalue()
    
    def _prepare_csv_row(self, finding: Dict[str, Any], fieldnames: List[str]) -> Dict[str, str]:
        """
        Prepare a finding for CSV output.
        
        Args:
            finding: Finding dictionary
            fieldnames: List of CSV column names
            
        Returns:
            Dictionary with CSV-safe values
        """
        csv_row = {}
        
        for field in fieldnames:
            value = finding.get(field, '')
            
            # Convert to string and clean for CSV
            if value is None:
                csv_value = ''
            elif isinstance(value, (list, dict)):
                csv_value = str(value)
            else:
                csv_value = str(value)
            
            # Clean multiline strings and special characters
            csv_value = csv_value.replace('\n', ' ').replace('\r', ' ')
            csv_value = csv_value.replace('\t', ' ')
            
            # Limit length to prevent extremely long cells
            if len(csv_value) > 500:
                csv_value = csv_value[:497] + "..."
            
            csv_row[field] = csv_value
        
        return csv_row
    
    def format_summary(self, results: Dict[str, Any]) -> str:
        """
        Format scan summary as CSV.
        
        Args:
            results: Dictionary containing scan results and metadata
            
        Returns:
            CSV-formatted summary
        """
        try:
            scan_info = results.get("scan_info", {})
            summary = results.get("summary", {})
            
            output = StringIO()
            writer = csv.writer(output, quoting=csv.QUOTE_ALL)
            
            # Write summary information
            writer.writerow(["Metric", "Value"])
            writer.writerow(["Target", scan_info.get("target", "Unknown")])
            writer.writerow(["Scan Time", scan_info.get("timestamp", "Unknown")])
            writer.writerow(["Framework Version", scan_info.get("framework_version", "Unknown")])
            writer.writerow(["Total Files", scan_info.get("total_files", 0)])
            writer.writerow(["Files Processed", scan_info.get("files_processed", 0)])
            writer.writerow(["Files Skipped", scan_info.get("files_skipped", 0)])
            writer.writerow(["Scan Duration (s)", scan_info.get("scan_time_seconds", 0)])
            writer.writerow(["Total Findings", summary.get("total_findings", 0)])
            
            # Write severity breakdown
            writer.writerow([])  # Empty row
            writer.writerow(["Severity", "Count"])
            
            by_severity = summary.get("by_severity", {})
            severity_order = ["critical", "high", "medium", "low", "info"]
            
            for severity in severity_order:
                count = by_severity.get(severity, 0)
                if count > 0:
                    writer.writerow([severity.title(), count])
            
            return output.getvalue()
        
        except Exception as e:
            return f"Error formatting summary CSV: {str(e)}\n"
    
    def format_by_file(self, results: Dict[str, Any]) -> str:
        """
        Format findings grouped by file as CSV.
        
        Args:
            results: Dictionary containing scan results and metadata
            
        Returns:
            CSV-formatted file summary
        """
        try:
            summary = results.get("summary", {})
            by_file = summary.get("by_file", {})
            
            if not by_file:
                return "Filename,Finding Count\n"
            
            output = StringIO()
            writer = csv.writer(output, quoting=csv.QUOTE_ALL)
            
            writer.writerow(["Filename", "Finding Count"])
            
            # Sort files by finding count (descending)
            sorted_files = sorted(by_file.items(), key=lambda x: x[1], reverse=True)
            
            for filename, count in sorted_files:
                writer.writerow([filename, count])
            
            return output.getvalue()
        
        except Exception as e:
            return f"Error formatting file summary CSV: {str(e)}\n"
