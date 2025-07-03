
#!/usr/bin/env python3
"""
Web3Sec - Unified Smart Contract Security Scanner
A focused, streamlined tool for Solidity security analysis
"""

import os
import sys
import json
import subprocess
import argparse
from pathlib import Path
from typing import Dict, List, Any
import re

class Web3SecScanner:
    def __init__(self):
        self.results = {
            'static_analysis': [],
            'slither_results': [],
            'mythril_results': [],
            'gas_optimization': [],
            'best_practices': [],
            'summary': {}
        }
    
    def scan(self, target_path: str) -> Dict[str, Any]:
        """Main scan function - runs all analysis types"""
        print(f"🔍 Scanning {target_path}...")
        
        # Determine if single file or directory
        path = Path(target_path)
        if path.is_file():
            contracts = [path] if path.suffix == '.sol' else []
        else:
            contracts = list(path.glob('**/*.sol'))
        
        if not contracts:
            print("❌ No Solidity files found")
            return self.results
        
        print(f"📄 Found {len(contracts)} Solidity contract(s)")
        
        # Run all analysis types
        for contract in contracts:
            print(f"\n🔎 Analyzing {contract.name}...")
            self._run_static_analysis(contract)
            self._run_slither_analysis(contract)
            self._run_mythril_analysis(contract)
            self._check_gas_optimization(contract)
            self._check_best_practices(contract)
        
        self._generate_summary()
        return self.results
    
    def _run_static_analysis(self, contract_path: Path):
        """Built-in static analysis for common vulnerabilities"""
        print("  🔍 Running static analysis...")
        
        try:
            content = contract_path.read_text()
            
            # Reentrancy detection
            reentrancy_patterns = [
                r'\.call\s*\(',
                r'\.send\s*\(',
                r'\.transfer\s*\(',
                r'external.*payable.*{[^}]*\.call'
            ]
            
            for pattern in reentrancy_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    self.results['static_analysis'].append({
                        'file': str(contract_path),
                        'type': 'Potential Reentrancy',
                        'severity': 'HIGH',
                        'line': line_num,
                        'description': 'External call detected - check for reentrancy protection',
                        'code': match.group()
                    })
            
            # Integer overflow/underflow (pre-0.8.0)
            if 'pragma solidity' in content:
                version_match = re.search(r'pragma solidity\s*[^;]*([0-9]+\.[0-9]+)', content)
                if version_match:
                    version = float(version_match.group(1))
                    if version < 0.8:
                        math_operations = re.finditer(r'[a-zA-Z_][a-zA-Z0-9_]*\s*[\+\-\*\/]\s*[a-zA-Z0-9_]+', content)
                        for match in math_operations:
                            line_num = content[:match.start()].count('\n') + 1
                            self.results['static_analysis'].append({
                                'file': str(contract_path),
                                'type': 'Potential Integer Overflow',
                                'severity': 'MEDIUM',
                                'line': line_num,
                                'description': 'Math operation without SafeMath (Solidity < 0.8.0)',
                                'code': match.group()
                            })
            
            # Access control issues
            public_functions = re.finditer(r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*public', content)
            for match in public_functions:
                func_content = content[match.start():match.start() + 500]  # Check next 500 chars
                if 'onlyOwner' not in func_content and 'require(' not in func_content:
                    line_num = content[:match.start()].count('\n') + 1
                    self.results['static_analysis'].append({
                        'file': str(contract_path),
                        'type': 'Missing Access Control',
                        'severity': 'MEDIUM',
                        'line': line_num,
                        'description': f'Public function {match.group(1)} lacks access control',
                        'code': match.group()
                    })
            
        except Exception as e:
            print(f"    ⚠️  Static analysis error: {e}")
    
    def _run_slither_analysis(self, contract_path: Path):
        """Run Slither static analysis tool"""
        print("  🐍 Running Slither analysis...")
        
        try:
            result = subprocess.run(
                ['slither', str(contract_path), '--json', '-'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0 and result.stdout:
                slither_data = json.loads(result.stdout)
                for detector in slither_data.get('results', {}).get('detectors', []):
                    self.results['slither_results'].append({
                        'file': str(contract_path),
                        'type': detector.get('check', 'Unknown'),
                        'severity': detector.get('impact', 'INFO').upper(),
                        'description': detector.get('description', ''),
                        'confidence': detector.get('confidence', 'Unknown')
                    })
            else:
                print(f"    ⚠️  Slither failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print("    ⚠️  Slither timeout")
        except FileNotFoundError:
            print("    ⚠️  Slither not installed")
        except Exception as e:
            print(f"    ⚠️  Slither error: {e}")
    
    def _run_mythril_analysis(self, contract_path: Path):
        """Run Mythril symbolic execution"""
        print("  🔮 Running Mythril analysis...")
        
        try:
            result = subprocess.run(
                ['myth', 'analyze', str(contract_path), '--output', 'json'],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0 and result.stdout:
                mythril_data = json.loads(result.stdout)
                for issue in mythril_data.get('issues', []):
                    self.results['mythril_results'].append({
                        'file': str(contract_path),
                        'type': issue.get('title', 'Unknown'),
                        'severity': issue.get('severity', 'INFO').upper(),
                        'description': issue.get('description', ''),
                        'line': issue.get('lineno', 0)
                    })
            else:
                print(f"    ⚠️  Mythril failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print("    ⚠️  Mythril timeout")
        except FileNotFoundError:
            print("    ⚠️  Mythril not installed")
        except Exception as e:
            print(f"    ⚠️  Mythril error: {e}")
    
    def _check_gas_optimization(self, contract_path: Path):
        """Check for gas optimization opportunities"""
        print("  ⛽ Checking gas optimization...")
        
        try:
            content = contract_path.read_text()
            
            # Check for storage vs memory usage
            storage_vars = re.finditer(r'storage\s+[a-zA-Z_][a-zA-Z0-9_]*', content)
            for match in storage_vars:
                line_num = content[:match.start()].count('\n') + 1
                self.results['gas_optimization'].append({
                    'file': str(contract_path),
                    'type': 'Storage Usage',
                    'severity': 'INFO',
                    'line': line_num,
                    'description': 'Consider using memory instead of storage for temporary variables',
                    'code': match.group()
                })
            
            # Check for loops that could be optimized
            for_loops = re.finditer(r'for\s*\([^)]*\)\s*{', content)
            for match in for_loops:
                line_num = content[:match.start()].count('\n') + 1
                self.results['gas_optimization'].append({
                    'file': str(contract_path),
                    'type': 'Loop Optimization',
                    'severity': 'INFO',
                    'line': line_num,
                    'description': 'Review loop for gas optimization opportunities',
                    'code': match.group()
                })
                
        except Exception as e:
            print(f"    ⚠️  Gas optimization check error: {e}")
    
    def _check_best_practices(self, contract_path: Path):
        """Check for Solidity best practices"""
        print("  ✅ Checking best practices...")
        
        try:
            content = contract_path.read_text()
            
            # Check for proper error messages
            requires = re.finditer(r'require\s*\([^,)]+\)', content)
            for match in requires:
                if ',' not in match.group():  # No error message
                    line_num = content[:match.start()].count('\n') + 1
                    self.results['best_practices'].append({
                        'file': str(contract_path),
                        'type': 'Missing Error Message',
                        'severity': 'LOW',
                        'line': line_num,
                        'description': 'require() statement should include error message',
                        'code': match.group()
                    })
            
            # Check for proper event emissions
            state_changes = re.finditer(r'[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[^;]+;', content)
            for match in state_changes:
                # Simple heuristic: if it's a state variable assignment
                if not re.search(r'(uint|int|bool|address|string)', match.group()):
                    continue
                line_num = content[:match.start()].count('\n') + 1
                # Check if there's an event emission nearby
                surrounding = content[max(0, match.start()-200):match.end()+200]
                if 'emit ' not in surrounding:
                    self.results['best_practices'].append({
                        'file': str(contract_path),
                        'type': 'Missing Event Emission',
                        'severity': 'LOW',
                        'line': line_num,
                        'description': 'Consider emitting an event for state changes',
                        'code': match.group()
                    })
                    
        except Exception as e:
            print(f"    ⚠️  Best practices check error: {e}")
    
    def _generate_summary(self):
        """Generate summary statistics"""
        total_issues = (
            len(self.results['static_analysis']) +
            len(self.results['slither_results']) +
            len(self.results['mythril_results']) +
            len(self.results['gas_optimization']) +
            len(self.results['best_practices'])
        )
        
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        
        for category in ['static_analysis', 'slither_results', 'mythril_results', 'gas_optimization', 'best_practices']:
            for issue in self.results[category]:
                severity = issue.get('severity', 'INFO')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        self.results['summary'] = {
            'total_issues': total_issues,
            'severity_breakdown': severity_counts,
            'categories': {
                'static_analysis': len(self.results['static_analysis']),
                'slither_results': len(self.results['slither_results']),
                'mythril_results': len(self.results['mythril_results']),
                'gas_optimization': len(self.results['gas_optimization']),
                'best_practices': len(self.results['best_practices'])
            }
        }
    
    def print_report(self):
        """Print unified consolidated report"""
        print("\n" + "="*80)
        print("🛡️  WEB3SEC SECURITY ANALYSIS REPORT")
        print("="*80)
        
        summary = self.results['summary']
        print(f"\n📊 SUMMARY:")
        print(f"   Total Issues Found: {summary['total_issues']}")
        print(f"   🔴 High Severity: {summary['severity_breakdown']['HIGH']}")
        print(f"   🟡 Medium Severity: {summary['severity_breakdown']['MEDIUM']}")
        print(f"   🟢 Low Severity: {summary['severity_breakdown']['LOW']}")
        print(f"   ℹ️  Info: {summary['severity_breakdown']['INFO']}")
        
        # Print issues by category
        categories = [
            ('🔍 STATIC ANALYSIS', 'static_analysis'),
            ('🐍 SLITHER RESULTS', 'slither_results'),
            ('🔮 MYTHRIL RESULTS', 'mythril_results'),
            ('⛽ GAS OPTIMIZATION', 'gas_optimization'),
            ('✅ BEST PRACTICES', 'best_practices')
        ]
        
        for title, key in categories:
            issues = self.results[key]
            if issues:
                print(f"\n{title} ({len(issues)} issues):")
                print("-" * 60)
                for i, issue in enumerate(issues, 1):
                    severity_icon = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFO': 'ℹ️'}.get(issue['severity'], '❓')
                    print(f"{i:2d}. {severity_icon} {issue['type']}")
                    print(f"     File: {Path(issue['file']).name}")
                    if 'line' in issue and issue['line']:
                        print(f"     Line: {issue['line']}")
                    print(f"     {issue['description']}")
                    if 'code' in issue and issue['code']:
                        print(f"     Code: {issue['code'][:100]}...")
                    print()
        
        print("="*80)
        print("🎯 Scan completed successfully!")

def main():
    parser = argparse.ArgumentParser(description='Web3Sec - Unified Smart Contract Security Scanner')
    parser.add_argument('target', help='Solidity file or directory to scan')
    parser.add_argument('--output', '-o', help='Output JSON file for results')
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress output, only show summary')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.target):
        print(f"❌ Target not found: {args.target}")
        sys.exit(1)
    
    scanner = Web3SecScanner()
    results = scanner.scan(args.target)
    
    if not args.quiet:
        scanner.print_report()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n💾 Results saved to {args.output}")

if __name__ == '__main__':
    main()
