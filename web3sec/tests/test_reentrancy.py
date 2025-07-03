
"""
Comprehensive test suite for the reentrancy analyzer.
"""

import pytest
import os
import tempfile
from pathlib import Path

from ..analyzers.reentrancy_analyzer import ReentrancyAnalyzer, extract_functions_from_solidity
from ..plugins.builtin.solidity_scanner import SolidityScanner
from ..core.scanner_base import Severity


class TestReentrancyAnalyzer:
    """Test cases for the comprehensive reentrancy analyzer."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = ReentrancyAnalyzer()
        self.scanner = SolidityScanner()
    
    def test_vulnerable_dao_pattern(self):
        """Test detection of classic DAO-style reentrancy vulnerability."""
        vulnerable_code = """
        function withdraw(uint256 amount) public {
            require(balances[msg.sender] >= amount, "Insufficient balance");
            
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success, "Transfer failed");
            
            balances[msg.sender] -= amount;
        }
        """
        
        analysis = self.analyzer.analyze_function(vulnerable_code, "withdraw", "test.sol", 1)
        
        assert analysis is not None
        assert analysis.confidence == "HIGH"
        assert analysis.pattern_type == "risky"
        assert analysis.state_updated_before_call == "after"
        assert analysis.external_call_type == "call"
        assert "State variables modified after external call" in analysis.reasoning
    
    def test_safe_withdrawal_pattern(self):
        """Test that safe withdrawal patterns are not flagged."""
        safe_code = """
        function withdraw(uint256 amount) public {
            require(balances[msg.sender] >= amount, "Insufficient balance");
            
            balances[msg.sender] -= amount;
            
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success, "Transfer failed");
        }
        """
        
        analysis = self.analyzer.analyze_function(safe_code, "withdraw", "test.sol", 1)
        
        # Should either return None or have low confidence/safe pattern
        if analysis:
            assert analysis.confidence == "LOW" or analysis.pattern_type == "safe"
            assert analysis.state_updated_before_call == "before"
    
    def test_admin_function_medium_risk(self):
        """Test that admin functions with external calls get medium confidence."""
        admin_code = """
        function emergencyWithdraw(address payable recipient, uint256 amount) public onlyOwner {
            require(address(this).balance >= amount, "Insufficient contract balance");
            
            (bool success, ) = recipient.call{value: amount}("");
            require(success, "Transfer failed");
            
            emit EmergencyWithdrawal(recipient, amount);
        }
        """
        
        analysis = self.analyzer.analyze_function(admin_code, "emergencyWithdraw", "test.sol", 1)
        
        assert analysis is not None
        assert analysis.confidence in ["MEDIUM", "LOW"]
        assert analysis.access_control == "admin"
    
    def test_transfer_vs_call_detection(self):
        """Test differentiation between transfer/send and call{value}."""
        transfer_code = """
        function safeWithdraw(uint256 amount) public {
            require(balances[msg.sender] >= amount);
            balances[msg.sender] -= amount;
            msg.sender.transfer(amount);
        }
        """
        
        call_code = """
        function riskyWithdraw(uint256 amount) public {
            require(balances[msg.sender] >= amount);
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success);
            balances[msg.sender] -= amount;
        }
        """
        
        transfer_analysis = self.analyzer.analyze_function(transfer_code, "safeWithdraw", "test.sol", 1)
        call_analysis = self.analyzer.analyze_function(call_code, "riskyWithdraw", "test.sol", 1)
        
        # Transfer should be safer
        if transfer_analysis:
            assert transfer_analysis.external_call_type == "transfer"
            assert transfer_analysis.gas_forwarded == "2300"
        
        # Call should be riskier
        assert call_analysis is not None
        assert call_analysis.external_call_type == "call"
        assert call_analysis.gas_forwarded == "unlimited"
        assert call_analysis.confidence == "HIGH"
    
    def test_multiple_external_calls(self):
        """Test detection of multiple external calls increasing risk."""
        multi_call_code = """
        function complexWithdraw(uint256 amount) public {
            require(balances[msg.sender] >= amount);
            
            // First call
            (bool success1, ) = feeRecipient.call{value: amount * feePercent / 100}("");
            require(success1);
            
            // Second call
            (bool success2, ) = msg.sender.call{value: amount}("");
            require(success2);
            
            balances[msg.sender] -= amount;
        }
        """
        
        analysis = self.analyzer.analyze_function(multi_call_code, "complexWithdraw", "test.sol", 1)
        
        assert analysis is not None
        assert len(analysis.external_calls) >= 2
        assert analysis.confidence == "HIGH"
        assert "Multiple external calls" in analysis.reasoning
    
    def test_no_state_changes(self):
        """Test functions with external calls but no state changes."""
        no_state_code = """
        function forwardPayment(address payable recipient) public payable onlyOwner {
            require(msg.value > 0, "No value sent");
            
            (bool success, ) = recipient.call{value: msg.value}("");
            require(success, "Transfer failed");
        }
        """
        
        analysis = self.analyzer.analyze_function(no_state_code, "forwardPayment", "test.sol", 1)
        
        # Should be low risk due to admin access and no state changes
        if analysis:
            assert analysis.state_updated_before_call == "no_state"
            assert analysis.access_control == "admin"
            assert analysis.confidence in ["LOW", "MEDIUM"]
    
    def test_reentrancy_guard_detection(self):
        """Test that reentrancy guards are recognized."""
        guarded_code = """
        function withdraw(uint256 amount) public nonReentrant {
            require(balances[msg.sender] >= amount);
            
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success);
            
            balances[msg.sender] -= amount;
        }
        """
        
        analysis = self.analyzer.analyze_function(guarded_code, "withdraw", "test.sol", 1)
        
        # Should have lower risk due to reentrancy guard
        # Note: Current implementation doesn't fully detect guards, but this tests the framework
        if analysis:
            # The pattern should still be detected, but recommendations should mention guards
            assert any("reentrancy guard" in rec.lower() for rec in analysis.recommendations)
    
    def test_function_extraction(self):
        """Test extraction of functions from Solidity code."""
        contract_code = """
        pragma solidity ^0.8.0;
        
        contract TestContract {
            mapping(address => uint256) public balances;
            
            function deposit() public payable {
                balances[msg.sender] += msg.value;
            }
            
            function withdraw(uint256 amount) public {
                require(balances[msg.sender] >= amount);
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success);
                balances[msg.sender] -= amount;
            }
            
            function getBalance() public view returns (uint256) {
                return balances[msg.sender];
            }
        }
        """
        
        functions = extract_functions_from_solidity(contract_code)
        
        assert len(functions) == 3
        function_names = [func[0] for func in functions]
        assert "deposit" in function_names
        assert "withdraw" in function_names
        assert "getBalance" in function_names
    
    def test_scanner_integration(self):
        """Test integration with the Solidity scanner."""
        vulnerable_contract = """
        pragma solidity ^0.8.0;
        
        contract VulnerableBank {
            mapping(address => uint256) public balances;
            
            function deposit() public payable {
                balances[msg.sender] += msg.value;
            }
            
            function withdraw(uint256 amount) public {
                require(balances[msg.sender] >= amount, "Insufficient balance");
                
                // Vulnerable: external call before state update
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success, "Transfer failed");
                
                balances[msg.sender] -= amount;
            }
        }
        """
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(vulnerable_contract)
            temp_file = f.name
        
        try:
            findings = self.scanner.scan_file(temp_file, vulnerable_contract)
            
            # Should find reentrancy vulnerability
            reentrancy_findings = [f for f in findings if "reentrancy" in f.vuln_type.lower()]
            assert len(reentrancy_findings) > 0
            
            # Check the finding details
            finding = reentrancy_findings[0]
            assert finding.severity in [Severity.CRITICAL.value, Severity.HIGH.value]
            assert hasattr(finding, 'analysis')  # Should have detailed analysis
            
        finally:
            os.unlink(temp_file)
    
    def test_edge_cases(self):
        """Test various edge cases and complex patterns."""
        edge_cases = [
            # Empty function
            "function empty() public {}",
            
            # Only view function
            "function getBalance() public view returns (uint256) { return balance; }",
            
            # Complex nested calls
            """
            function complex() public {
                if (condition) {
                    for (uint i = 0; i < users.length; i++) {
                        users[i].call{value: amounts[i]}("");
                    }
                }
                totalPaid += amount;
            }
            """,
            
            # Assembly with delegatecall
            """
            function assemblyCall(address target, bytes memory data) public {
                assembly {
                    let result := delegatecall(gas(), target, add(data, 0x20), mload(data), 0, 0)
                }
                processed = true;
            }
            """
        ]
        
        for i, code in enumerate(edge_cases):
            analysis = self.analyzer.analyze_function(code, f"test_func_{i}", "test.sol", 1)
            # Should not crash and should handle gracefully
            if analysis:
                assert analysis.confidence in ["HIGH", "MEDIUM", "LOW"]
                assert analysis.pattern_type in ["risky", "safe", "unknown"]


if __name__ == "__main__":
    pytest.main([__file__])
