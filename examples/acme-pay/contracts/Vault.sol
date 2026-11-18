// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Vault {
    address public owner = msg.sender;
    function withdraw(address payable to, uint256 amount) external {
        require(tx.origin == owner, "not owner");
        to.transfer(amount);
    }
}
