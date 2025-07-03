
/**
 * Vulnerable dApp Frontend Code
 * This file contains multiple Web3.js vulnerabilities for testing
 * DO NOT USE IN PRODUCTION
 */

const Web3 = require('web3');

// Vulnerability: Hardcoded private key
const PRIVATE_KEY = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

// Vulnerability: Hardcoded mnemonic
const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// Vulnerability: Insecure HTTP endpoint
const web3 = new Web3('http://localhost:8545'); // Should use HTTPS

// Vulnerability: Exposed API key
const INFURA_API_KEY = "1234567890abcdef1234567890abcdef";
const ALCHEMY_API_KEY = "abcdef1234567890abcdef1234567890";

class VulnerableDApp {
    constructor() {
        this.web3 = web3;
        this.account = null;
        this.contract = null;
    }
    
    // Vulnerability: Missing error handling
    async connectWallet() {
        const accounts = await this.web3.eth.getAccounts();
        this.account = accounts[0];
        return this.account;
    }
    
    // Vulnerability: Missing gas estimation
    async sendTransaction(to, value) {
        const tx = {
            from: this.account,
            to: to,
            value: this.web3.utils.toWei(value, 'ether')
            // Missing gas estimation
        };
        
        return this.web3.eth.sendTransaction(tx);
    }
    
    // Vulnerability: Unsafe user input
    async transferTokens(userInput) {
        const amount = this.web3.utils.toWei(userInput, 'ether'); // No validation
        
        return this.contract.methods.transfer(this.account, amount).send({
            from: this.account,
            value: userInput // Direct user input usage
        });
    }
    
    // Vulnerability: Missing network check
    async deployContract() {
        const contract = new this.web3.eth.Contract(ABI);
        
        return contract.deploy({
            data: BYTECODE
        }).send({
            from: this.account,
            gas: 1000000
            // No chain ID verification
        });
    }
    
    // Vulnerability: Weak signature verification
    async verifySignature(message, signature) {
        const recovered = this.web3.eth.accounts.recover(message, signature);
        // No proper verification against expected signer
        return recovered;
    }
    
    // Vulnerability: Console logging in production
    async debugTransaction(txHash) {
        const receipt = await this.web3.eth.getTransactionReceipt(txHash);
        console.log("Transaction receipt:", receipt); // Sensitive data exposure
        console.warn("Gas used:", receipt.gasUsed);
        return receipt;
    }
    
    // Vulnerability: Missing slippage protection
    async swapTokens(tokenA, tokenB, amount) {
        const router = new this.web3.eth.Contract(ROUTER_ABI, ROUTER_ADDRESS);
        
        return router.methods.swapExactTokensForTokens(
            amount,
            0, // No minimum amount out - no slippage protection
            [tokenA, tokenB],
            this.account
            // Missing deadline
        ).send({ from: this.account });
    }
    
    // Vulnerability: Unlimited allowance
    async approveToken(tokenAddress, spenderAddress) {
        const token = new this.web3.eth.Contract(ERC20_ABI, tokenAddress);
        
        return token.methods.approve(
            spenderAddress,
            this.web3.utils.toWei('999999999', 'ether') // Unlimited approval
        ).send({ from: this.account });
    }
    
    // Vulnerability: Insufficient error handling
    async batchTransactions(transactions) {
        for (const tx of transactions) {
            this.web3.eth.sendTransaction(tx); // No await, no error handling
        }
    }
    
    // Vulnerability: Hardcoded contract addresses
    getContractAddress(network) {
        const addresses = {
            mainnet: "0x1234567890123456789012345678901234567890",
            goerli: "0x0987654321098765432109876543210987654321"
        };
        return addresses[network];
    }
    
    // Vulnerability: Missing input validation
    async calculateRewards(userAddress, stakingPeriod) {
        // No validation of inputs
        const rewards = stakingPeriod * 100; // Arbitrary calculation
        
        return this.contract.methods.claimRewards(rewards).send({
            from: userAddress // Using user input directly
        });
    }
}

// Vulnerability: Global variables with sensitive data
window.PRIVATE_KEY = PRIVATE_KEY;
window.API_KEYS = {
    infura: INFURA_API_KEY,
    alchemy: ALCHEMY_API_KEY
};

module.exports = VulnerableDApp;
