// SPDX-License-Identifier: MIT

/// Title: Kekalor
/// Author: K.L.M
/// Difficulty: Medium


pragma solidity ^0.8.19;

import './KekalorNFT.sol';

contract Challenge {
    bool public Solved = false;
    address public admin;
    KekalorNFT public kekalornft;

    uint256 public constant POINTS_NEEDED_FOR_TAKEOVER = 10;
    uint256 public constant MAX_POINTS = 11;
    uint256 public pointsclaimed = 0;
    mapping(string => mapping(string => bool)) private NameSurname;
    mapping(bytes32 => uint256) private points;
    mapping(address => bool) private claimed;


    constructor(){
        kekalornft = new KekalorNFT(address(this));
        admin = msg.sender;
    }


    function claimNFT(bytes32 identifier) public {
        require(points[identifier] >= POINTS_NEEDED_FOR_TAKEOVER, "Not enough points to claim NFT");
        require(claimed[msg.sender] == false, "You already claimed your NFT");

        kekalornft.mint(msg.sender);

        points[identifier] = 0;
        claimed[msg.sender] = true;
    }

    function getPoints(string memory name, string memory surname) public {
        require(pointsclaimed < MAX_POINTS, "All points have been claimed");
        bytes32 identifier = keccak256(abi.encodePacked(name, surname));
        require (!NameSurname[name][surname], "You already claimed your points");
        points[identifier] += 1;
        pointsclaimed += 1;
    }

    function solve() public {
        require(kekalornft.balanceOf(msg.sender)>=2, "You need at least 2 NFTs to solve this challenge");
        Solved = true;
    }

    function isSolved() public view returns(bool){
        return Solved;
    }
}