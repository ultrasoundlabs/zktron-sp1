// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITronRelay {
    function latestBlock() external returns (uint256);
    function blocks(uint256) external returns (bytes32);
    function blockTimestamps(bytes32) external returns (uint256);
    function timestamps() external returns (uint256[]);
}
