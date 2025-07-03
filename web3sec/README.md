
# Web3Sec - Unified Smart Contract Security Scanner

A focused, streamlined tool for Solidity security analysis that addresses the over-engineering issues of generic vulnerability frameworks.

## Key Features

✅ **Unified Command Interface** - One simple command for comprehensive analysis  
✅ **Built-in Vulnerability Detection** - No external templates needed  
✅ **Seamless Tool Integration** - Slither and Mythril feel like part of the same engine  
✅ **Consolidated Reporting** - Single unified report combining all analysis types  
✅ **Solidity-Focused** - Purpose-built for smart contract security  

## Installation

```bash
# Clone and install
git clone <repository>
cd web3sec
pip install -e .

# Install external tools (optional but recommended)
pip install slither-analyzer mythril
```

## Usage

### Scan a single contract
```bash
web3sec scan contract.sol
```

### Scan entire project
```bash
web3sec scan ./contracts/
```

### Save results to JSON
```bash
web3sec scan contract.sol --output results.json
```

### Quiet mode (summary only)
```bash
web3sec scan contract.sol --quiet
```

## What It Analyzes

### Built-in Static Analysis
- **Reentrancy vulnerabilities** - Detects external calls without proper protection
- **Integer overflow/underflow** - For Solidity versions < 0.8.0
- **Access control issues** - Public functions without proper restrictions
- **And more common patterns...**

### Slither Integration
- Seamlessly runs Slither static analysis
- Results integrated into unified report
- No separate plugin configuration needed

### Mythril Integration  
- Symbolic execution analysis
- Automatic timeout handling
- Results correlated with other findings

### Gas Optimization
- Storage vs memory usage analysis
- Loop optimization opportunities
- Gas-efficient pattern suggestions

### Best Practices
- Error message requirements
- Event emission patterns
- Code quality checks

## Sample Output

```
🛡️  WEB3SEC SECURITY ANALYSIS REPORT
================================================================================

📊 SUMMARY:
   Total Issues Found: 12
   🔴 High Severity: 2
   🟡 Medium Severity: 4
   🟢 Low Severity: 3
   ℹ️  Info: 3

🔍 STATIC ANALYSIS (3 issues):
────────────────────────────────────────────────────────────────
 1. 🔴 Potential Reentrancy
     File: MyContract.sol
     Line: 45
     External call detected - check for reentrancy protection
     Code: .call(msg.value)("")...

 2. 🟡 Missing Access Control
     File: MyContract.sol  
     Line: 23
     Public function withdraw lacks access control
     Code: function withdraw() public...
```

## Why This Approach?

### Problems with Generic Frameworks
- ❌ Nuclei templates are for network/web scanning, not smart contracts
- ❌ Modular plugin systems add unnecessary complexity  
- ❌ Separate tool outputs are hard to correlate
- ❌ Generic approaches miss Solidity-specific patterns

### Our Solution
- ✅ **Purpose-built** for smart contract security
- ✅ **Hardcoded vulnerability patterns** for common issues
- ✅ **Seamless integration** with specialized tools
- ✅ **Unified output** combining all analysis types
- ✅ **Simple interface** - one command does everything

## Architecture

```
web3sec scan contract.sol
    ↓
┌─────────────────────────────────────┐
│         Web3Sec Engine              │
├─────────────────────────────────────┤
│ Built-in Static Analysis            │
│ ├─ Reentrancy Detection            │
│ ├─ Integer Overflow Checks         │
│ ├─ Access Control Analysis         │
│ └─ Common Vulnerability Patterns   │
├─────────────────────────────────────┤
│ Integrated Tool Analysis            │
│ ├─ Slither (seamless integration)  │
│ └─ Mythril (symbolic execution)    │
├─────────────────────────────────────┤
│ Optimization & Best Practices      │
│ ├─ Gas Optimization Checks         │
│ └─ Solidity Best Practices         │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│      Unified Report Output          │
│  All results correlated and         │
│  presented in single format         │
└─────────────────────────────────────┘
```

## Contributing

This tool focuses on being a specialized smart contract security scanner. When adding features:

1. **Keep it focused** - Only add Solidity/Web3 specific functionality
2. **Avoid over-engineering** - Hardcode common patterns instead of making them configurable
3. **Maintain simplicity** - One command should do everything
4. **Unified output** - All new analysis should integrate into the single report format

## License

MIT License - see LICENSE file for details.
