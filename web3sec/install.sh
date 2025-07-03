
#!/bin/bash

echo "🚀 Installing Web3Sec - Unified Smart Contract Security Scanner"
echo "================================================================"

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip install -e .

# Try to install Slither
echo "🐍 Installing Slither..."
pip install slither-analyzer

# Try to install Mythril  
echo "🔮 Installing Mythril..."
pip install mythril

# Make the script executable
chmod +x web3sec.py

echo "✅ Installation complete!"
echo ""
echo "Usage examples:"
echo "  web3sec scan contract.sol"
echo "  web3sec scan ./contracts/"
echo "  web3sec scan contract.sol --output results.json"
echo ""
echo "Test with the example contract:"
echo "  web3sec scan example_contract.sol"
