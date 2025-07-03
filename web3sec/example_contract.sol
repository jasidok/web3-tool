
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

contract VulnerableContract {
    mapping(address => uint256) public balances;
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    // Vulnerable to reentrancy
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0);
        
        // External call before state change - VULNERABLE!
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        
        balances[msg.sender] = 0;  // State change after external call
    }
    
    // Missing access control
    function emergencyWithdraw() public {
        // Anyone can call this! Should have onlyOwner modifier
        payable(msg.sender).transfer(address(this).balance);
    }
    
    // Integer overflow potential (Solidity < 0.8.0)
    function deposit() public payable {
        balances[msg.sender] += msg.value;  // No SafeMath!
    }
    
    // Missing error message
    function setOwner(address newOwner) public {
        require(msg.sender == owner);  // No error message
        owner = newOwner;
    }
    
    // Gas inefficient loop
    function massTransfer(address[] memory recipients, uint256 amount) public {
        for (uint256 i = 0; i < recipients.length; i++) {
            balances[recipients[i]] += amount;  // Could be optimized
        }
    }
    
    receive() external payable {
        deposit();
    }
}
