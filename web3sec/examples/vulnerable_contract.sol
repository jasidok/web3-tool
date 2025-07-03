
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableContract
 * @dev This contract contains multiple vulnerabilities for testing purposes
 * DO NOT USE IN PRODUCTION
 */
contract VulnerableContract {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalSupply;
    
    constructor() {
        owner = msg.sender;
        totalSupply = 1000000;
        balances[owner] = totalSupply;
    }
    
    // Vulnerability: Reentrancy
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // External call before state change - VULNERABLE TO REENTRANCY
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount; // State change after external call
    }
    
    // Vulnerability: tx.origin authentication
    function transferOwnership(address newOwner) public {
        require(tx.origin == owner, "Only owner"); // Should use msg.sender
        owner = newOwner;
    }
    
    // Vulnerability: Unchecked external call
    function unsafeTransfer(address to, uint256 amount) public {
        balances[msg.sender] -= amount;
        balances[to] += amount;
        
        // Unchecked external call
        to.call{value: amount}("");
    }
    
    // Vulnerability: Integer overflow (pre-0.8.0 behavior simulation)
    function unsafeAdd(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b; // No overflow protection
    }
    
    // Vulnerability: Weak randomness
    function generateRandomNumber() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty))) % 100;
    }
    
    // Vulnerability: Unprotected function
    function emergencyWithdraw() public {
        // No access control - anyone can call this
        payable(msg.sender).transfer(address(this).balance);
    }
    
    // Vulnerability: Timestamp dependence
    function timeLock(uint256 unlockTime) public view returns (bool) {
        return block.timestamp >= unlockTime; // Miners can manipulate timestamp
    }
    
    // Vulnerability: DoS with gas limit
    function distributeTokens(address[] memory recipients, uint256 amount) public {
        for (uint256 i = 0; i < recipients.length; i++) {
            balances[recipients[i]] += amount;
            // External call in loop - gas limit DoS
            recipients[i].call{value: amount}("");
        }
    }
    
    // Vulnerability: Missing zero address check
    function setOwner(address newOwner) public {
        require(msg.sender == owner, "Only owner");
        owner = newOwner; // No check for address(0)
    }
    
    // Vulnerability: Unsafe type casting
    function unsafeCast(uint256 value) public pure returns (uint8) {
        return uint8(value); // Potential data loss
    }
    
    // Vulnerability: Selfdestruct
    function destroy() public {
        require(msg.sender == owner, "Only owner");
        selfdestruct(payable(owner)); // Contract can be destroyed
    }
    
    receive() external payable {}
}
