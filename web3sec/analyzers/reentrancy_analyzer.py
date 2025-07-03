
"""
Comprehensive Reentrancy Analysis Framework for Web3Sec.

This module implements sophisticated reentrancy vulnerability detection with:
- State change analysis before/after external calls
- External call context analysis (gas limits, call types)
- Access control evaluation
- Function pattern recognition
- Decision tree-based analysis
- Confidence scoring system
"""

import re
import ast
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass
from enum import Enum

try:
    from ..core.scanner_base import Finding, Severity
    from ..utils.logger import get_logger
except ImportError:
    # For standalone testing
    class Severity:
        CRITICAL = "critical"
        HIGH = "high"
        MEDIUM = "medium"
        LOW = "low"
    
    class Finding:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
    
    def get_logger(name):
        class MockLogger:
            def debug(self, msg): print(f"DEBUG: {msg}")
            def error(self, msg): print(f"ERROR: {msg}")
            def warning(self, msg): print(f"WARNING: {msg}")
        return MockLogger()


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


class ReentrancyAnalyzer:
    """
    Comprehensive reentrancy vulnerability analyzer.
    
    Implements sophisticated analysis including:
    - AST-like parsing of Solidity code
    - State change tracking
    - External call analysis
    - Pattern recognition
    - Decision tree evaluation
    """
    
    def __init__(self):
        self.logger = get_logger(__name__)
        
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
                r'\.call\s*\(\s*[^)]*\)\s*(?!\s*\{)',
            ],
            CallType.DELEGATECALL: [
                r'\.delegatecall\s*\(',
                r'assembly\s*\{[^}]*delegatecall',
            ],
            CallType.STATICCALL: [
                r'\.staticcall\s*\(',
            ]
        }
        
        # Patterns for state variable modifications
        self.state_patterns = [
            r'(\w+)\s*=\s*[^;]+;',  # Assignment
            r'(\w+)\s*\+=\s*[^;]+;',  # Addition assignment
            r'(\w+)\s*-=\s*[^;]+;',  # Subtraction assignment
            r'(\w+)\s*\*=\s*[^;]+;',  # Multiplication assignment
            r'(\w+)\s*/=\s*[^;]+;',  # Division assignment
            r'(\w+)\s*\+\+',  # Increment
            r'(\w+)\s*--',  # Decrement
            r'\+\+\s*(\w+)',  # Pre-increment
            r'--\s*(\w+)',  # Pre-decrement
            r'(\w+)\[([^\]]+)\]\s*=',  # Array/mapping assignment
            r'(\w+)\[([^\]]+)\]\s*[+\-*/]=',  # Array/mapping compound assignment
            r'delete\s+(\w+)',  # Delete statement
        ]
        
        # Access control modifier patterns
        self.access_control_patterns = [
            r'onlyOwner',
            r'onlyAdmin',
            r'onlyAuthorized',
            r'requireOwner',
            r'requireAdmin',
            r'require\s*\(\s*msg\.sender\s*==\s*owner',
            r'require\s*\(\s*msg\.sender\s*==\s*admin',
            r'require\s*\(\s*isOwner\s*\(',
            r'require\s*\(\s*hasRole\s*\(',
        ]
        
        # Safe pattern indicators
        self.safe_patterns = [
            r'require\s*\([^)]*msg\.sender',  # Sender checks
            r'require\s*\([^)]*balance\[',    # Balance checks
            r'require\s*\([^)]*amount\s*<=',  # Amount validation
            r'nonReentrant',                   # Reentrancy guard
            r'ReentrancyGuard',               # OpenZeppelin guard
            r'_nonReentrantBefore',           # Custom guard
        ]
    
    def analyze_function(self, function_code: str, function_name: str, 
                        file_path: str, start_line: int) -> Optional[ReentrancyAnalysis]:
        """
        Analyze a single function for reentrancy vulnerabilities.
        
        Args:
            function_code: The complete function code
            function_name: Name of the function
            file_path: Path to the source file
            start_line: Starting line number of the function
            
        Returns:
            ReentrancyAnalysis object or None if no issues found
        """
        analysis = ReentrancyAnalysis()
        
        # Step 1: Extract external calls
        external_calls = self._extract_external_calls(function_code, start_line)
        analysis.external_calls = external_calls
        
        # If no external calls, no reentrancy risk
        if not external_calls:
            return None
        
        # Step 2: Extract state changes
        state_changes = self._extract_state_changes(function_code, start_line)
        analysis.state_changes = state_changes
        
        # Step 3: Determine access control level
        access_level = self._determine_access_level(function_code)
        analysis.access_control = access_level.value
        
        # Step 4: Analyze state update patterns
        state_pattern = self._analyze_state_pattern(external_calls, state_changes)
        analysis.state_updated_before_call = state_pattern.value
        
        # Step 5: Determine call types and gas behavior
        primary_call = external_calls[0] if external_calls else None
        if primary_call:
            analysis.external_call_type = primary_call.call_type.value
            analysis.gas_forwarded = primary_call.gas_forwarded
        
        # Step 6: Apply decision tree
        confidence, pattern_type, reasoning = self._apply_decision_tree(
            external_calls, state_changes, access_level, state_pattern
        )
        
        analysis.confidence = confidence
        analysis.pattern_type = pattern_type
        analysis.reasoning = reasoning
        
        # Step 7: Generate recommendations
        analysis.recommendations = self._generate_recommendations(
            external_calls, state_changes, access_level, state_pattern
        )
        
        # Only return analysis if there's a potential issue
        if confidence in ["HIGH", "MEDIUM"] or pattern_type == "risky":
            return analysis
        
        return None
    
    def _extract_external_calls(self, code: str, start_line: int) -> List[ExternalCall]:
        """Extract all external calls from the function code."""
        external_calls = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            line_num = start_line + i
            
            # Check each call type pattern
            for call_type, patterns in self.call_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        # Determine gas forwarding behavior
                        gas_forwarded = self._determine_gas_forwarding(call_type, match.group())
                        
                        # Extract target (simplified)
                        target = self._extract_call_target(match.group())
                        
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
        """Extract all state variable modifications from the function code."""
        state_changes = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            line_num = start_line + i
            
            # Skip comments and empty lines
            if re.match(r'^\s*(/\*|\*/|//)', line) or not line.strip():
                continue
            
            for pattern in self.state_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    variable = match.group(1) if match.groups() else "unknown"
                    operation = self._determine_operation_type(match.group())
                    
                    # Filter out local variables (heuristic)
                    if self._is_likely_state_variable(variable, code):
                        state_change = StateChange(
                            line_number=line_num,
                            variable=variable,
                            operation=operation,
                            code_snippet=line.strip()
                        )
                        state_changes.append(state_change)
        
        return state_changes
    
    def _determine_access_level(self, code: str) -> AccessLevel:
        """Determine the access control level of the function."""
        # Check for access control modifiers
        for pattern in self.access_control_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                return AccessLevel.ADMIN
        
        # Check function visibility
        if re.search(r'function\s+\w+\([^)]*\)\s+private', code, re.IGNORECASE):
            return AccessLevel.PRIVATE
        elif re.search(r'function\s+\w+\([^)]*\)\s+internal', code, re.IGNORECASE):
            return AccessLevel.INTERNAL
        elif re.search(r'function\s+\w+\([^)]*\)\s+external', code, re.IGNORECASE):
            return AccessLevel.EXTERNAL
        else:
            return AccessLevel.PUBLIC
    
    def _analyze_state_pattern(self, external_calls: List[ExternalCall], 
                             state_changes: List[StateChange]) -> StateUpdatePattern:
        """Analyze the pattern of state updates relative to external calls."""
        if not state_changes:
            return StateUpdatePattern.NO_STATE
        
        if not external_calls:
            return StateUpdatePattern.NO_STATE
        
        # Find the first external call
        first_call_line = min(call.line_number for call in external_calls)
        
        # Categorize state changes
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
        """
        Apply the decision tree logic to determine confidence and pattern type.
        
        Returns:
            Tuple of (confidence, pattern_type, reasoning)
        """
        reasoning_parts = []
        
        # Check for multiple external calls first (more specific condition)
        if len(external_calls) > 1 and state_changes:
            reasoning_parts.append(f"Multiple external calls ({len(external_calls)}) increase risk")
            if state_pattern in [StateUpdatePattern.PARTIAL, StateUpdatePattern.AFTER_CALL]:
                # Check if it's also state after call for additional reasoning
                if state_pattern == StateUpdatePattern.AFTER_CALL:
                    reasoning_parts.append("State variables modified after external call")
                return "HIGH", "risky", "; ".join(reasoning_parts)
            # Multiple calls even with proper state management is concerning
            return "HIGH", "risky", "; ".join(reasoning_parts)
        
        # High confidence indicators - most dangerous patterns
        if state_pattern == StateUpdatePattern.AFTER_CALL:
            reasoning_parts.append("State variables modified after external call")
            if any(call.call_type in [CallType.CALL_VALUE, CallType.DELEGATECALL] 
                   for call in external_calls):
                reasoning_parts.append("High-gas external call allows reentrancy")
                return "HIGH", "risky", "; ".join(reasoning_parts)
            # Even with transfer/send, state after call is risky
            return "HIGH", "risky", "; ".join(reasoning_parts)
        
        # High-gas calls with any state changes (but not if state is properly managed before call)
        if (any(call.call_type in [CallType.CALL_VALUE, CallType.DELEGATECALL] for call in external_calls) 
            and state_changes and access_level != AccessLevel.ADMIN 
            and state_pattern != StateUpdatePattern.BEFORE_CALL):
            reasoning_parts.append("High-gas external call with state modifications")
            return "HIGH", "risky", "; ".join(reasoning_parts)
        
        # Medium confidence indicators
        if state_pattern == StateUpdatePattern.PARTIAL:
            reasoning_parts.append("Partial state updates around external calls")
            if access_level == AccessLevel.ADMIN:
                reasoning_parts.append("Admin function reduces risk but still concerning")
                return "MEDIUM", "risky", "; ".join(reasoning_parts)
            else:
                return "MEDIUM", "risky", "; ".join(reasoning_parts)
        
        # Admin functions with external calls
        if access_level == AccessLevel.ADMIN and external_calls:
            reasoning_parts.append("Admin function with external calls")
            if any(call.call_type == CallType.CALL_VALUE for call in external_calls):
                reasoning_parts.append("High-gas call in admin function")
                return "MEDIUM", "risky", "; ".join(reasoning_parts)
        
        # Transfer/send with subsequent state changes
        if (any(call.call_type in [CallType.TRANSFER, CallType.SEND] for call in external_calls) 
            and state_pattern == StateUpdatePattern.AFTER_CALL):
            reasoning_parts.append("Transfer/send followed by state changes")
            return "MEDIUM", "risky", "; ".join(reasoning_parts)
        
        # Low confidence / safe patterns
        if state_pattern == StateUpdatePattern.BEFORE_CALL:
            reasoning_parts.append("State updated before external call (safe pattern)")
            if access_level == AccessLevel.ADMIN:
                reasoning_parts.append("Admin function with proper state management")
                return "LOW", "safe", "; ".join(reasoning_parts)
            # Even non-admin functions with proper pattern are safer
            return "LOW", "safe", "; ".join(reasoning_parts)
        
        if access_level == AccessLevel.ADMIN and state_pattern == StateUpdatePattern.NO_STATE:
            reasoning_parts.append("Admin function with no state changes")
            return "LOW", "safe", "; ".join(reasoning_parts)
        
        if all(call.call_type in [CallType.TRANSFER, CallType.SEND] for call in external_calls):
            reasoning_parts.append("Only low-gas calls (transfer/send) detected")
            if state_pattern == StateUpdatePattern.NO_STATE:
                reasoning_parts.append("No state changes detected")
                return "LOW", "safe", "; ".join(reasoning_parts)
        
        # Default case - external calls present but unclear pattern
        reasoning_parts.append("External calls detected but pattern unclear")
        return "MEDIUM", "unknown", "; ".join(reasoning_parts)
    
    def _generate_recommendations(self, external_calls: List[ExternalCall],
                                state_changes: List[StateChange],
                                access_level: AccessLevel,
                                state_pattern: StateUpdatePattern) -> List[str]:
        """Generate specific recommendations based on the analysis."""
        recommendations = []
        
        if state_pattern == StateUpdatePattern.AFTER_CALL:
            recommendations.append("Move all state updates before external calls (checks-effects-interactions pattern)")
            recommendations.append("Consider using a reentrancy guard (OpenZeppelin's ReentrancyGuard)")
        
        if any(call.call_type == CallType.CALL_VALUE for call in external_calls):
            recommendations.append("Consider using transfer() or send() instead of call{value}() for simple transfers")
            recommendations.append("If call{value}() is necessary, implement proper reentrancy protection")
        
        if len(external_calls) > 1:
            recommendations.append("Minimize the number of external calls in a single function")
            recommendations.append("Consider batching operations or using a pull payment pattern")
        
        if state_pattern == StateUpdatePattern.PARTIAL:
            recommendations.append("Ensure all critical state updates happen before any external calls")
            recommendations.append("Review the function logic to eliminate mixed state update patterns")
        
        if access_level in [AccessLevel.PUBLIC, AccessLevel.EXTERNAL]:
            recommendations.append("Consider adding access control if this function handles sensitive operations")
        
        # Always include reentrancy guard recommendation for risky patterns
        if state_pattern in [StateUpdatePattern.AFTER_CALL, StateUpdatePattern.PARTIAL]:
            recommendations.append("Implement reentrancy guard protection")
        
        # Always include general best practices
        recommendations.append("Implement comprehensive testing including reentrancy attack scenarios")
        recommendations.append("Consider formal verification for critical financial functions")
        
        return recommendations
    
    def _determine_gas_forwarding(self, call_type: CallType, call_code: str) -> str:
        """Determine how much gas is forwarded in the call."""
        if call_type in [CallType.TRANSFER, CallType.SEND]:
            return "2300"
        elif call_type == CallType.CALL_VALUE:
            # Check for explicit gas specification
            gas_match = re.search(r'gas\s*:\s*(\w+)', call_code)
            if gas_match:
                return "custom"
            else:
                return "unlimited"
        else:
            return "unlimited"
    
    def _extract_call_target(self, call_code: str) -> str:
        """Extract the target of the external call."""
        # Simplified target extraction
        if 'msg.sender' in call_code:
            return "msg.sender"
        elif 'owner' in call_code:
            return "owner"
        elif 'payable(' in call_code:
            return "payable_address"
        else:
            return "unknown"
    
    def _determine_operation_type(self, operation_code: str) -> str:
        """Determine the type of state operation."""
        if '+=' in operation_code:
            return "increment"
        elif '-=' in operation_code:
            return "decrement"
        elif '++' in operation_code:
            return "increment"
        elif '--' in operation_code:
            return "decrement"
        elif '=' in operation_code:
            return "assignment"
        elif 'delete' in operation_code:
            return "deletion"
        else:
            return "modification"
    
    def _is_likely_state_variable(self, variable: str, code: str) -> bool:
        """
        Heuristic to determine if a variable is likely a state variable.
        This is a simplified check - in a real implementation, you'd want
        to parse the contract structure more thoroughly.
        """
        # Skip obvious local variables
        local_indicators = ['temp', 'local', 'i', 'j', 'k', 'index', 'len', 'length']
        if any(indicator in variable.lower() for indicator in local_indicators):
            return False
        
        # Look for variable declarations in the function (local variables)
        local_var_pattern = rf'\b(uint\d*|int\d*|bool|address|string|bytes\d*)\s+{re.escape(variable)}\s*[=;]'
        if re.search(local_var_pattern, code, re.IGNORECASE):
            return False
        
        # If it's not obviously local, assume it might be state
        return True


def extract_functions_from_solidity(content: str) -> List[Tuple[str, str, int, int]]:
    """
    Extract function definitions from Solidity code.
    
    Returns:
        List of tuples: (function_name, function_code, start_line, end_line)
    """
    functions = []
    lines = content.split('\n')
    
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        
        # Look for function definitions (more flexible pattern)
        func_match = re.search(r'function\s+(\w+)\s*\([^)]*\)', line)
        if func_match:
            func_name = func_match.group(1)
            start_line = i + 1
            
            # Find the function body
            brace_count = 0
            func_lines = []
            j = i
            found_opening_brace = False
            
            while j < len(lines):
                current_line = lines[j]
                func_lines.append(current_line)
                
                # Count braces to find function end
                open_braces = current_line.count('{')
                close_braces = current_line.count('}')
                
                if open_braces > 0:
                    found_opening_brace = True
                
                brace_count += open_braces - close_braces
                
                # Function complete when we've found opening brace and count returns to 0
                if found_opening_brace and brace_count == 0:
                    end_line = j + 1
                    func_code = '\n'.join(func_lines)
                    functions.append((func_name, func_code, start_line, end_line))
                    i = j + 1
                    break
                
                j += 1
            else:
                # Reached end of file without closing function
                i += 1
        else:
            i += 1
    
    return functions
