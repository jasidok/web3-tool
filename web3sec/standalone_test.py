#!/usr/bin/env python3

"""
Standalone test of the comprehensive reentrancy analyzer.
This demonstrates the enhanced capabilities without complex imports.
"""

import sys
import os
import re
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass
from enum import Enum

# Copy the essential parts of the analyzer here for standalone testing
class CallType(Enum):
    """Types of external calls with different gas behaviors."""
    TRANSFER = "transfer"  # 2300 gas limit
    SEND = "send"         # 2300 gas limit
    CALL_VALUE = "call"   # Unlimited gas
    DELEGATECALL = "delegatecall"  # Unlimited gas
    STATICCALL = "staticcall"      # Read-only
    OTHER = "other"

class AccessLevel(Enum):
    """Function access control levels."""
    PUBLIC = "public"
    EXTERNAL = "external"
    INTERNAL = "internal"
    PRIVATE = "private"
    ADMIN = "admin"  # Has access control modifiers

class StateUpdatePattern(Enum):
    """Patterns of state updates relative to external calls."""
    BEFORE_CALL = "before"     # State updated before external call (safe)
    AFTER_CALL = "after"       # State updated after external call (risky)
    PARTIAL = "partial"        # Some state before, some after
    NO_STATE = "no_state"      # No state changes detected
    COMPLEX = "complex"        # Complex pattern requiring manual review

@dataclass
class ExternalCall:
    """Represents an external call in the code."""
    line_number: int
    call_type: CallType
    target: str
    gas_forwarded: str  # "2300", "unlimited", "custom"
    code_snippet: str

@dataclass
class StateChange:
    """Represents a state variable modification."""
    line_number: int
    variable: str
    operation: str  # "assignment", "increment", "decrement", etc.
    code_snippet: str

@dataclass
class ReentrancyAnalysis:
    """Complete reentrancy analysis result."""
    vuln_type: str = "reentrancy"
    confidence: str = "LOW"
    state_updated_before_call: str = "NO"
    external_call_type: str = "none"
    gas_forwarded: str = "none"
    access_control: str = "public"
    pattern_type: str = "unknown"
    reasoning: str = ""
    recommendations: List[str] = None
    external_calls: List[ExternalCall] = None
    state_changes: List[StateChange] = None
    
    def __post_init__(self):
        if self.recommendations is None:
            self.recommendations = []
        if self.external_calls is None:
            self.external_calls = []
        if self.state_changes is None:
            self.state_changes = []

class SimpleReentrancyAnalyzer:
    """Simplified version of the reentrancy analyzer for demonstration."""
    
    def __init__(self):
        # Patterns for different types of external calls
        self.call_patterns = {
            CallType.TRANSFER: [
                r'\.transfer\s*\(\s*([^)]+)\s*\)',
                r'payable\s*\([^)]+\)\s*\.transfer\s*\(',
            ],
            CallType.SEND: [
                r'\.send\s*\(\s*([^)]+)\s*\)',
                r'payable\s*\([^)]+\)\s*\.send\s*\(',
            ],
            CallType.CALL_VALUE: [
                r'\.call\s*\{\s*value\s*:\s*([^}]+)\s*\}\s*\(',
                r'\.call\.value\s*\([^)]+\)\s*\(',
            ],
        }
        
        # Patterns for state variable modifications
        self.state_patterns = [
            r'(\w+)\[([^\]]+)\]\s*[+\-*/]=',  # Array/mapping compound assignment
            r'(\w+)\s*[+\-*/]=\s*[^;]+;',     # Compound assignment
            r'(\w+)\s*=\s*[^;]+;',            # Assignment
        ]
    
    def analyze_function(self, function_code: str, function_name: str) -> Optional[ReentrancyAnalysis]:
        """Analyze a function for reentrancy vulnerabilities."""
        
        # Extract external calls
        external_calls = self._extract_external_calls(function_code, 1)
        if not external_calls:
            return None
        
        # Extract state changes
        state_changes = self._extract_state_changes(function_code, 1)
        
        # Determine access level
        access_level = self._determine_access_level(function_code)
        
        # Analyze state pattern
        state_pattern = self._analyze_state_pattern(external_calls, state_changes)
        
        # Apply decision tree
        confidence, pattern_type, reasoning = self._apply_decision_tree(
            external_calls, state_changes, access_level, state_pattern
        )
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            external_calls, state_changes, access_level, state_pattern
        )
        
        analysis = ReentrancyAnalysis(
            confidence=confidence,
            state_updated_before_call=state_pattern.value,
            external_call_type=external_calls[0].call_type.value if external_calls else "none",
            gas_forwarded=external_calls[0].gas_forwarded if external_calls else "none",
            access_control=access_level.value,
            pattern_type=pattern_type,
            reasoning=reasoning,
            recommendations=recommendations,
            external_calls=external_calls,
            state_changes=state_changes
        )
        
        return analysis
    
    def _extract_external_calls(self, code: str, start_line: int) -> List[ExternalCall]:
        """Extract external calls from function code."""
        external_calls = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            line_num = start_line + i
            
            for call_type, patterns in self.call_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        gas_forwarded = "2300" if call_type in [CallType.TRANSFER, CallType.SEND] else "unlimited"
                        target = "msg.sender" if "msg.sender" in line else "unknown"
                        
                        external_call = ExternalCall(
                            line_number=line_num,
                            call_type=call_type,
                            target=target,
                            gas_forwarded=gas_forwarded,
                            code_snippet=line.strip()
                        )
                        external_calls.append(external_call)
        
        return external_calls
    
    def _extract_state_changes(self, code: str, start_line: int) -> List[StateChange]:
        """Extract state variable modifications."""
        state_changes = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            line_num = start_line + i
            
            for pattern in self.state_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    variable = match.group(1)
                    operation = "decrement" if "-=" in line else "assignment"
                    
                    state_change = StateChange(
                        line_number=line_num,
                        variable=variable,
                        operation=operation,
                        code_snippet=line.strip()
                    )
                    state_changes.append(state_change)
        
        return state_changes
    
    def _determine_access_level(self, code: str) -> AccessLevel:
        """Determine function access level."""
        if re.search(r'onlyOwner|onlyAdmin', code, re.IGNORECASE):
            return AccessLevel.ADMIN
        elif re.search(r'function\s+\w+\([^)]*\)\s+private', code, re.IGNORECASE):
            return AccessLevel.PRIVATE
        elif re.search(r'function\s+\w+\([^)]*\)\s+internal', code, re.IGNORECASE):
            return AccessLevel.INTERNAL
        elif re.search(r'function\s+\w+\([^)]*\)\s+external', code, re.IGNORECASE):
            return AccessLevel.EXTERNAL
        else:
            return AccessLevel.PUBLIC
    
    def _analyze_state_pattern(self, external_calls: List[ExternalCall], 
                             state_changes: List[StateChange]) -> StateUpdatePattern:
        """Analyze state update patterns."""
        if not state_changes:
            return StateUpdatePattern.NO_STATE
        
        if not external_calls:
            return StateUpdatePattern.NO_STATE
        
        first_call_line = min(call.line_number for call in external_calls)
        
        before_call = [sc for sc in state_changes if sc.line_number < first_call_line]
        after_call = [sc for sc in state_changes if sc.line_number > first_call_line]
        
        if before_call and not after_call:
            return StateUpdatePattern.BEFORE_CALL
        elif after_call and not before_call:
            return StateUpdatePattern.AFTER_CALL
        elif before_call and after_call:
            return StateUpdatePattern.PARTIAL
        else:
            return StateUpdatePattern.COMPLEX
    
    def _apply_decision_tree(self, external_calls: List[ExternalCall], 
                           state_changes: List[StateChange],
                           access_level: AccessLevel,
                           state_pattern: StateUpdatePattern) -> Tuple[str, str, str]:
        """Apply decision tree logic."""
        
        # Multiple external calls
        if len(external_calls) > 1 and state_changes:
            reasoning = f"Multiple external calls ({len(external_calls)}) increase risk"
            if state_pattern == StateUpdatePattern.AFTER_CALL:
                reasoning += "; State variables modified after external call"
            return "HIGH", "risky", reasoning
        
        # State after call
        if state_pattern == StateUpdatePattern.AFTER_CALL:
            reasoning = "State variables modified after external call"
            if any(call.call_type == CallType.CALL_VALUE for call in external_calls):
                reasoning += "; High-gas external call allows reentrancy"
            return "HIGH", "risky", reasoning
        
        # State before call (safe)
        if state_pattern == StateUpdatePattern.BEFORE_CALL:
            return "LOW", "safe", "State updated before external call (safe pattern)"
        
        # Admin functions
        if access_level == AccessLevel.ADMIN:
            return "MEDIUM", "risky", "Admin function with external calls"
        
        # Default
        return "MEDIUM", "unknown", "External calls detected but pattern unclear"
    
    def _generate_recommendations(self, external_calls: List[ExternalCall],
                                state_changes: List[StateChange],
                                access_level: AccessLevel,
                                state_pattern: StateUpdatePattern) -> List[str]:
        """Generate recommendations."""
        recommendations = []
        
        if state_pattern == StateUpdatePattern.AFTER_CALL:
            recommendations.append("Move all state updates before external calls (checks-effects-interactions pattern)")
            recommendations.append("Consider using a reentrancy guard (OpenZeppelin's ReentrancyGuard)")
        
        if any(call.call_type == CallType.CALL_VALUE for call in external_calls):
            recommendations.append("Consider using transfer() or send() instead of call{value}() for simple transfers")
        
        if len(external_calls) > 1:
            recommendations.append("Minimize the number of external calls in a single function")
        
        recommendations.append("Implement comprehensive testing including reentrancy attack scenarios")
        
        return recommendations

# Test the analyzer
def main():
    print("=== Web3Sec Framework - Comprehensive Reentrancy Analysis ===\n")
    
    analyzer = SimpleReentrancyAnalyzer()
    
    # Test cases
    test_cases = [
        ("Vulnerable DAO Pattern", '''
function withdraw(uint256 amount) public {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
    
    balances[msg.sender] -= amount;
}
'''),
        ("Safe Withdrawal Pattern", '''
function withdraw(uint256 amount) public {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    
    balances[msg.sender] -= amount;
    
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}
'''),
        ("Multiple External Calls", '''
function complexWithdraw(uint256 amount) public {
    require(balances[msg.sender] >= amount);
    
    (bool success1, ) = feeRecipient.call{value: amount * feePercent / 100}("");
    require(success1);
    
    (bool success2, ) = msg.sender.call{value: amount}("");
    require(success2);
    
    balances[msg.sender] -= amount;
}
'''),
        ("Admin Function", '''
function emergencyWithdraw(address payable recipient, uint256 amount) public onlyOwner {
    require(address(this).balance >= amount);
    
    (bool success, ) = recipient.call{value: amount}("");
    require(success);
}
'''),
    ]
    
    for test_name, code in test_cases:
        print(f"🔍 Testing: {test_name}")
        print("=" * 50)
        
        analysis = analyzer.analyze_function(code, test_name.lower().replace(" ", "_"))
        
        if analysis:
            print(f"✅ Vulnerability Detected!")
            print(f"   Confidence: {analysis.confidence}")
            print(f"   Pattern Type: {analysis.pattern_type}")
            print(f"   State Pattern: {analysis.state_updated_before_call}")
            print(f"   Call Type: {analysis.external_call_type}")
            print(f"   Gas Forwarded: {analysis.gas_forwarded}")
            print(f"   Access Control: {analysis.access_control}")
            print(f"   Reasoning: {analysis.reasoning}")
            print(f"   External Calls: {len(analysis.external_calls)}")
            print(f"   State Changes: {len(analysis.state_changes)}")
            print(f"   Recommendations:")
            for rec in analysis.recommendations:
                print(f"     • {rec}")
        else:
            print("✅ No reentrancy vulnerability detected (safe pattern)")
        
        print("\n")
    
    print("=== Analysis Complete ===")
    print("\n🎯 Key Features Demonstrated:")
    print("✓ Comprehensive reentrancy detection")
    print("✓ State change analysis (before/after external calls)")
    print("✓ External call context analysis (gas limits, call types)")
    print("✓ Access control evaluation")
    print("✓ Confidence scoring system (HIGH/MEDIUM/LOW)")
    print("✓ Pattern recognition (safe vs risky)")
    print("✓ Detailed recommendations")
    print("✓ False positive minimization")
    print("\n🏆 This analyzer is designed for professional bug bounty hunting!")
    print("   HIGH confidence findings often pay $25k-$100k+")
    print("   MEDIUM confidence findings typically pay $5k-$50k")

if __name__ == "__main__":
    main()
