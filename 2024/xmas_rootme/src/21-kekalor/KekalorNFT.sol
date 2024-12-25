// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract KekalorNFT {
    string public name = "KekalorNFT";
    string public symbol = "KKNFT";

    address private kekalor;
    uint256 private _tokenId = 0;

    mapping(uint256 tokenId => address) private _owners;
    mapping(address owner => uint256) private _balances;
    mapping(uint256 tokenId => address) private _tokenApprovals;
    mapping(address owner => mapping(address operator => bool)) private _operatorApprovals;

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    constructor(address kekalorAddress) {
        kekalor = kekalorAddress;
    }

    modifier onlyKekalor() {
        require(msg.sender == kekalor, "KekalorNFT: caller is not authorized");
        _;
    }

    function balanceOf(address owner) public view returns (uint256) {
        require(owner != address(0), "KekalorNFT: invalid owner address");
        return _balances[owner];
    }

    function ownerOf(uint256 tokenId) public view returns (address) {
        address owner = _owners[tokenId];
        require(owner != address(0), "KekalorNFT: queried owner for nonexistent token");
        return owner;
    }

    function approve(address to, uint256 tokenId) public {
        address owner = ownerOf(tokenId);
        require(msg.sender == owner, "KekalorNFT: approve caller is not the owner");
        _tokenApprovals[tokenId] = to;
        emit Approval(owner, to, tokenId);
    }

    function getApproved(uint256 tokenId) public view returns (address) {
        require(_owners[tokenId] != address(0), "KekalorNFT: queried approvals for nonexistent token");
        return _tokenApprovals[tokenId];
    }

    function setApprovalForAll(address operator, bool approved) public {
        require(operator != address(0), "KekalorNFT: invalid operator");
        _operatorApprovals[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function isApprovedForAll(address owner, address operator) public view returns (bool) {
        return _operatorApprovals[owner][operator];
    }

    function transferFrom(address from, address to, uint256 tokenId) public {
        require(to != address(0), "KekalorNFT: invalid transfer receiver");
        address owner = ownerOf(tokenId);
        require(from == owner, "KekalorNFT: transfer caller is not the owner");
        require(msg.sender == owner || msg.sender == getApproved(tokenId) || isApprovedForAll(owner, msg.sender), "KekalorNFT: caller is not approved to transfer");

        _balances[from] -= 1;
        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(from, to, tokenId);
    }

    function mint(address to) public onlyKekalor returns (uint256) {
        uint256 currentTokenId = _tokenId;
        _mint(to, currentTokenId);
        return currentTokenId;
    }

    function burn(uint256 tokenId) public onlyKekalor {
        _burn(tokenId);
    }

    function _mint(address to, uint256 tokenId) internal {
        require(to != address(0), "KekalorNFT: invalid mint receiver");
        require(_owners[tokenId] == address(0), "KekalorNFT: token already minted");

        _balances[to] += 1;
        _owners[tokenId] = to;
        _tokenId += 1;

        //verify the receiver is a payable address
        to.call{value: 0}("");

        emit Transfer(address(0), to, tokenId);
    }

    function _burn(uint256 tokenId) internal {
        address owner = ownerOf(tokenId);
        require(msg.sender == owner, "KekalorNFT: caller is not the owner");
        _balances[owner] -= 1;
        delete _owners[tokenId];

        emit Transfer(owner, address(0), tokenId);
    }
}