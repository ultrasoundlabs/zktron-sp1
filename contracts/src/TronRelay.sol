// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./interfaces/ITronRelay.sol";
import "./Tronlib.sol";

contract TronRelay is ITronRelay, Ownable {
    ISP1Verifier constant verifier = ISP1Verifier(address(0)); // TODO: change
    bytes32 constant vkey = bytes32(0); // TODO: change

    uint256 public latestBlock;
    uint256[] public timestamps;
    mapping(uint256 => bytes32) public blocks; // block number -> block id
    mapping(bytes32 => uint256) public blockTimestamps; // block id -> timestamp

    mapping(address => bool) internal srs;
    bytes32 internal srPrint;

    struct LightClientOutput {
        bytes32 startBlock;
        bytes32 endBlock;
        bytes32 srPrint;
        bytes32 blockprint;
    }

    constructor() Ownable(msg.sender) {}

    // We do a little optimization trick here.
    // Instead of parsing protobuf which would be pretty expensive
    // in Solidity, we just ask for offset of the prevBlockId
    // in the block header off-chain and use it to check if
    // the header actually contains prevBlockId and
    // is not larger than 128 bytes (by our research,
    // blocks in Tron can't be larger than that).
    // We believe that the risks related to this
    // simplification are negligible, as the walkthrough
    // circuit still fully verifies the contents of
    // the header against the blockid.
    function isValidHeader(bytes32 prevBlockId, bytes memory header, uint256 offset) internal pure returns (bool) {
        bytes32 chunk;
        assembly {
            chunk := mload(add(header, offset))
        }
        if (chunk == prevBlockId && header.length < 128) {
            return true;
        }
        return false;
    }

    function update(
        uint256 reorgDepth,
        bytes[] calldata newBlocks,
        bytes[] calldata signatures,
        uint256[] calldata offsets
    ) external {
        require(reorgDepth == 0 || newBlocks.length >= 19);
        require(reorgDepth < 19);
        latestBlock -= reorgDepth;

        for (uint256 i = 0; i < newBlocks.length; i++) {
            bytes memory rawData = newBlocks[i];
            bytes32 blockHash = sha256(rawData);

            (uint8 v, bytes32 r, bytes32 s) = abi.decode(signatures[i], (uint8, bytes32, bytes32));
            address sr = ecrecover(blockHash, v, r, s);
            require(srs[sr]);

            require(isValidHeader(blocks[latestBlock], rawData, offsets[i]));

            latestBlock++;
            bytes32 blockId = Tronlib.getBlockId(blockHash, latestBlock);
            blocks[latestBlock] = blockId;

            uint256 blockTimestamp = Tronlib.getBlockTimestamp(rawData);
            blockTimestamps[blockId] = blockTimestamp;
            timestamps.push(blockTimestamp);
        }
    }

    function zkUpdate(bytes calldata proof, bytes calldata publicValues, bytes32[] calldata blockIds, uint256[] calldata _blockTimestamps) external {
        verifier.verifyProof(vkey, publicValues, proof);

        LightClientOutput memory output = abi.decode(publicValues, (LightClientOutput));
        require(output.startBlock == blockIds[latestBlock]);
        require(output.srPrint == srPrint);
        require(sha256(abi.encode(blockIds)) == output.blockprint);

        for (uint256 i = 0; i < blockIds.length; i++) {
            bytes32 blockId = blockIds[i];
            blocks[Tronlib.blockIdToNumber(blockId)] = blockId;
            blockTimestamps[blockId] = _blockTimestamps[i]; 
            timestamps.push(_blockTimestamps[i]);
        }
        latestBlock += blockIds.length;
    }

    function changeSrs(bytes[] calldata oldSrs, bytes[] calldata newSrs) external onlyOwner {
        require(sha256(abi.encode(oldSrs)) == srPrint);

        for (uint256 i = 0; i < oldSrs.length; i++) {
            srs[address(uint160(uint256(keccak256(abi.encodePacked(oldSrs[i])))))] = false;
        }
        for (uint256 i = 0; i < newSrs.length; i++) {
            srs[address(uint160(uint256(keccak256(abi.encodePacked(newSrs[i])))))] = true;
        }

        srPrint = sha256(abi.encode(newSrs));
    }
}
