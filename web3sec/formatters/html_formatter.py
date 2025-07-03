
"""
HTML output formatter for Web3Sec Framework.
"""

import html
from datetime import datetime
from typing import Dict, Any, List

from .base_formatter import BaseFormatter


class HTMLFormatter(BaseFormatter):
    """
    Formats scan results as HTML.
    
    Provides rich, visual output suitable for human consumption
    with styling, navigation, and interactive elements.
    """
    
    def __init__(self):
        """Initialize HTML formatter."""
        super().__init__()
        self.format_name = "html"
        self.file_extension = ".html"
    
    def format(self, results: Dict[str, Any]) -> str:
        """
        Format scan results as HTML.
        
        Args:
            results: Dictionary containing scan results and metadata
            
        Returns:
            HTML-formatted string
        """
        try:
            scan_info = results.get("scan_info", {})
            summary = results.get("summary", {})
            findings = results.get("findings", [])
            
            html_content = self._build_html_document(scan_info, summary, findings)
            return html_content
        
        except Exception as e:
            return self._create_error_html(str(e))
    
    def _build_html_document(self, scan_info: Dict[str, Any], summary: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
        """Build complete HTML document."""
        html_parts = [
            self._get_html_header(),
            self._get_css_styles(),
            "</head>",
            "<body>",
            self._build_header_section(scan_info),
            self._build_summary_section(summary),
            self._build_findings_section(findings),
            self._build_footer_section(),
            self._get_javascript(),
            "</body>",
            "</html>"
        ]
        
        return "\n".join(html_parts)
    
    def _get_html_header(self) -> str:
        """Get HTML document header."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web3Sec Framework - Vulnerability Scan Report</title>"""
    
    def _get_css_styles(self) -> str:
        """Get CSS styles for the HTML report."""
        return """
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .summary {
            background: white;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        .summary h2 {
            color: #4a5568;
            margin-bottom: 20px;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 10px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: #f7fafc;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #4299e1;
        }
        
        .stat-card .label {
            font-size: 0.9em;
            color: #718096;
            margin-bottom: 5px;
        }
        
        .stat-card .value {
            font-size: 1.5em;
            font-weight: bold;
            color: #2d3748;
        }
        
        .severity-badges {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 15px;
        }
        
        .severity-badge {
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }
        
        .severity-critical {
            background-color: #fed7d7;
            color: #c53030;
        }
        
        .severity-high {
            background-color: #feebc8;
            color: #dd6b20;
        }
        
        .severity-medium {
            background-color: #fefcbf;
            color: #d69e2e;
        }
        
        .severity-low {
            background-color: #c6f6d5;
            color: #38a169;
        }
        
        .severity-info {
            background-color: #bee3f8;
            color: #3182ce;
        }
        
        .findings {
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }
        
        .findings h2 {
            background: #4a5568;
            color: white;
            padding: 20px;
            margin: 0;
        }
        
        .finding {
            border-bottom: 1px solid #e2e8f0;
            padding: 25px;
        }
        
        .finding:last-child {
            border-bottom: none;
        }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
        }
        
        .finding-title {
            font-size: 1.3em;
            font-weight: bold;
            color: #2d3748;
            margin-bottom: 5px;
        }
        
        .finding-meta {
            font-size: 0.9em;
            color: #718096;
        }
        
        .finding-description {
            margin: 15px 0;
            line-height: 1.7;
        }
        
        .code-snippet {
            background: #1a202c;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin: 15px 0;
        }
        
        .finding-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        
        .detail-item {
            background: #f7fafc;
            padding: 12px;
            border-radius: 6px;
        }
        
        .detail-label {
            font-weight: bold;
            color: #4a5568;
            margin-bottom: 5px;
        }
        
        .detail-value {
            color: #2d3748;
        }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #718096;
            font-size: 0.9em;
        }
        
        .no-findings {
            text-align: center;
            padding: 60px 20px;
            color: #718096;
        }
        
        .no-findings .icon {
            font-size: 4em;
            margin-bottom: 20px;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            .finding-header {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .finding-details {
                grid-template-columns: 1fr;
            }
        }
    </style>"""
    
    def _build_header_section(self, scan_info: Dict[str, Any]) -> str:
        """Build header section."""
        target = html.escape(str(scan_info.get("target", "Unknown")))
        timestamp = scan_info.get("timestamp", "Unknown")
        
        return f"""
    <div class="container">
        <div class="header">
            <h1>🔒 Web3Sec Framework</h1>
            <div class="subtitle">Vulnerability Scan Report</div>
            <div style="margin-top: 15px; font-size: 1em;">
                <strong>Target:</strong> {target}<br>
                <strong>Scan Date:</strong> {timestamp}
            </div>
        </div>"""
    
    def _build_summary_section(self, summary: Dict[str, Any]) -> str:
        """Build summary section."""
        total_findings = summary.get("total_findings", 0)
        by_severity = summary.get("by_severity", {})
        
        # Build stats cards
        stats_html = f"""
        <div class="stats-grid">
            <div class="stat-card">
                <div class="label">Total Findings</div>
                <div class="value">{total_findings}</div>
            </div>
        </div>"""
        
        # Build severity badges
        severity_badges = []
        severity_order = ["critical", "high", "medium", "low", "info"]
        severity_emojis = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        
        for severity in severity_order:
            count = by_severity.get(severity, 0)
            if count > 0:
                emoji = severity_emojis.get(severity, "⚫")
                badges_html = f'<span class="severity-badge severity-{severity}">{emoji} {severity.title()}: {count}</span>'
                severity_badges.append(badges_html)
        
        badges_html = "\n".join(severity_badges) if severity_badges else '<span class="severity-badge severity-info">No vulnerabilities found</span>'
        
        return f"""
        <div class="summary">
            <h2>📊 Scan Summary</h2>
            {stats_html}
            <div class="severity-badges">
                {badges_html}
            </div>
        </div>"""
    
    def _build_findings_section(self, findings: List[Dict[str, Any]]) -> str:
        """Build findings section."""
        if not findings:
            return """
        <div class="findings">
            <h2>🔍 Findings</h2>
            <div class="no-findings">
                <div class="icon">✅</div>
                <h3>No vulnerabilities found!</h3>
                <p>Your code appears to be secure based on the configured scans.</p>
            </div>
        </div>"""
        
        # Sort findings by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings,
            key=lambda x: (severity_order.get(x.get("severity", "").lower(), 5), x.get("filename", ""))
        )
        
        findings_html = []
        for i, finding in enumerate(sorted_findings, 1):
            finding_html = self._build_finding_html(finding, i)
            findings_html.append(finding_html)
        
        return f"""
        <div class="findings">
            <h2>🔍 Findings ({len(findings)} total)</h2>
            {"".join(findings_html)}
        </div>"""
    
    def _build_finding_html(self, finding: Dict[str, Any], index: int) -> str:
        """Build HTML for a single finding."""
        # Extract and escape finding data
        vuln_type = html.escape(str(finding.get("vuln_type", "Unknown Vulnerability")))
        severity = finding.get("severity", "unknown").lower()
        filename = html.escape(str(finding.get("filename", "Unknown")))
        line = finding.get("line", "Unknown")
        description = html.escape(str(finding.get("description", "No description available")))
        code_snippet = html.escape(str(finding.get("code_snippet", "")))
        
        # Get severity emoji and badge
        severity_emojis = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        emoji = severity_emojis.get(severity, "⚫")
        
        # Build code snippet section
        code_section = ""
        if code_snippet and code_snippet.strip():
            code_section = f"""
            <div class="code-snippet">{code_snippet}</div>"""
        
        # Build details section
        details = []
        detail_fields = [
            ("category", "Category"),
            ("confidence", "Confidence"),
            ("plugin", "Plugin"),
            ("impact", "Impact"),
            ("recommendation", "Recommendation"),
            ("bounty_potential", "Bounty Potential")
        ]
        
        for field, label in detail_fields:
            value = finding.get(field)
            if value:
                escaped_value = html.escape(str(value))
                details.append(f"""
                <div class="detail-item">
                    <div class="detail-label">{label}</div>
                    <div class="detail-value">{escaped_value}</div>
                </div>""")
        
        details_html = f'<div class="finding-details">{"".join(details)}</div>' if details else ""
        
        return f"""
        <div class="finding">
            <div class="finding-header">
                <div>
                    <div class="finding-title">{index}. {vuln_type}</div>
                    <div class="finding-meta">
                        📁 {filename} • 📍 Line {line}
                    </div>
                </div>
                <span class="severity-badge severity-{severity}">{emoji} {severity.title()}</span>
            </div>
            <div class="finding-description">{description}</div>
            {code_section}
            {details_html}
        </div>"""
    
    def _build_footer_section(self) -> str:
        """Build footer section."""
        return f"""
        <div class="footer">
            <p>Report generated by Web3Sec Framework v2.0.0 • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>🔗 <a href="https://github.com/web3sec/web3sec-framework" style="color: #4299e1;">Web3Sec Framework</a></p>
        </div>
    </div>"""
    
    def _get_javascript(self) -> str:
        """Get JavaScript for interactive features."""
        return """
    <script>
        // Add any interactive features here
        document.addEventListener('DOMContentLoaded', function() {
            // Add click handlers for expandable sections
            const findings = document.querySelectorAll('.finding');
            findings.forEach(finding => {
                finding.addEventListener('click', function() {
                    // Could add expand/collapse functionality
                });
            });
        });
    </script>"""
    
    def _create_error_html(self, error_message: str) -> str:
        """Create error HTML page."""
        escaped_error = html.escape(error_message)
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web3Sec Framework - Error</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .error {{ background: #fee; border: 1px solid #fcc; padding: 20px; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="error">
        <h1>Report Generation Error</h1>
        <p>An error occurred while generating the HTML report:</p>
        <pre>{escaped_error}</pre>
    </div>
</body>
</html>"""
