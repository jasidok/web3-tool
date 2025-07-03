
/**
 * Vulnerable TypeScript Frontend Code
 * This file contains multiple TypeScript vulnerabilities for testing
 * DO NOT USE IN PRODUCTION
 */

import Web3 from 'web3';
import { Contract } from 'web3-eth-contract';

// Vulnerability: Any type usage
let web3: any = new Web3();
let contract: any;
let userAccount: any;

// Vulnerability: Weak Web3 types
interface WeakConfig {
    provider: any;
    contract: any;
    signer: any;
}

class VulnerableWeb3Service {
    private web3: any; // Vulnerability: any type
    private config: WeakConfig;
    
    constructor(config: WeakConfig) {
        this.config = config;
        this.web3 = config.provider;
    }
    
    // Vulnerability: Missing async error handling
    async connectWallet(): Promise<string> {
        const accounts = await this.web3.eth.getAccounts();
        return accounts[0];
    }
    
    // Vulnerability: Unsafe type assertion
    async getBalance(address: string): Promise<number> {
        const balance = await this.web3.eth.getBalance(address);
        return balance as number; // Unsafe assertion
    }
    
    // Vulnerability: Missing error types
    async sendTransaction(tx: any) {
        try {
            return await this.web3.eth.sendTransaction(tx);
        } catch (error) {
            // No proper error type checking
            console.log(error);
        }
    }
    
    // Vulnerability: Unsafe environment access
    getApiKey(): string {
        return process.env.API_KEY; // No fallback or validation
    }
    
    // Vulnerability: Missing input validation
    transferTokens(amount: string, recipient: string) {
        // No validation of inputs
        return this.config.contract.methods.transfer(recipient, amount).send();
    }
    
    // Vulnerability: Unsafe JSON parsing
    parseContractData(jsonString: string) {
        return JSON.parse(jsonString); // No error handling
    }
    
    // Vulnerability: Weak random generation
    generateNonce(): number {
        return Math.random() * 1000000; // Weak randomness
    }
    
    // Vulnerability: Console statements in production
    debugMode(data: any) {
        console.log("Debug data:", data);
        console.warn("Warning:", data.sensitive);
        console.error("Error state:", data.private);
    }
}

// Vulnerability: Hardcoded contract addresses
const CONTRACT_ADDRESSES = {
    mainnet: "0x1234567890123456789012345678901234567890",
    testnet: "0x0987654321098765432109876543210987654321"
};

// Vulnerability: Unsafe DOM manipulation
function updateUI(userInput: string) {
    document.getElementById('output')!.innerHTML = userInput; // XSS vulnerability
}

// Vulnerability: Missing null checks
function processUserData(user: any) {
    return user.profile.address.street; // No null checks
}

// Vulnerability: Weak signature verification
async function verifySignature(message: string, signature: string): Promise<boolean> {
    const recovered = web3.eth.accounts.recover(message, signature);
    return recovered !== null; // Weak verification
}

// Vulnerability: Unsafe allowance handling
async function approveMaxTokens(tokenContract: Contract, spender: string) {
    const maxUint = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    return tokenContract.methods.approve(spender, maxUint).send();
}

// Vulnerability: Missing deadline in DeFi operations
async function swapTokens(router: Contract, path: string[], amountIn: string) {
    return router.methods.swapExactTokensForTokens(
        amountIn,
        0, // No slippage protection
        path,
        userAccount
        // Missing deadline parameter
    ).send();
}

// Vulnerability: Unhandled promise rejections
function batchOperations(operations: Promise<any>[]) {
    operations.forEach(op => {
        op; // No await or error handling
    });
}

// Vulnerability: Eval usage
function executeUserCode(code: string) {
    return eval(code); // Dangerous code execution
}

// Vulnerability: Weak error handling
class ErrorProneService {
    async riskyOperation(): Promise<any> {
        // No try-catch for async operation
        const result = await fetch('/api/sensitive-data');
        return result.json();
    }
    
    // Vulnerability: Missing input validation
    processAmount(amount: string): number {
        return parseInt(amount); // No validation
    }
    
    // Vulnerability: Unsafe type casting
    convertToNumber(value: any): number {
        return value as number; // Unsafe cast
    }
}

export { VulnerableWeb3Service, CONTRACT_ADDRESSES };
