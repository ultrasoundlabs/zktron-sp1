// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./interfaces/ITronRelay.sol";
import "./interfaces/ISender.sol";
import "./Tronlib.sol";

contract Untron is Ownable {
    IERC20 constant usdt = IERC20(0x493257fD37EDB34451f62EDf8D2a0C418852bA4C); // bridged USDT @ zksync era

    constructor() Ownable(msg.sender) {}

    uint64 constant ORDER_TTL = 100; // 100 blocks = 5 min

    struct Params {
        ISP1Verifier verifier;
        ITronRelay relay;
        ISender sender;
        bytes32 vkey;
        address relayer;
        address paymaster;
        uint64 minSize;
        uint64 feePerBlock;
        uint64 revealerFee;
        uint64 fulfillerFee;
        uint256 rateLimit;
        uint256 limitPer;
    }

    Params public params;

    function setParams(Params calldata _params) external onlyOwner {
        params = _params;
    }

    bytes32 public stateHash = bytes32(0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855); // sha256("")
    bytes32 public latestKnownBlock;
    bytes32 public latestKnownOrder;

    bytes32 public latestOrder;
    uint256 public totalOrders;

    bytes32[] public orderChains; // order chain hashes in order
    mapping(bytes32 => uint256) public orderTimestamps; // order chained hash -> timestamp
    mapping(address => Order) public orders; // tron address -> Order
    mapping(address => address) public tronAddresses; // tron address -> evm address
    mapping(address => Buyer) public buyers; // EVM address -> Buyer
    mapping(address => uint256) public orderCount; // tron address -> order count

    struct Order {
        uint64 size;
        uint64 rate;
        bytes transferData;
        address fulfiller;
        uint64 fulfilledAmount;
    }

    struct Buyer {
        bool active;
        uint64 liquidity;
        uint64 rate;
        uint64 minDeposit;
    }

    struct ClosedOrder {
        address tronAddress;
        uint32 timestamp;
        uint64 inflow;
        uint64 minDeposit; // needed for reverse swaps
    }

    struct OrderChain {
        bytes32 prev;
        uint32 timestamp;
        address tronAddress;
        uint64 minDeposit;
    }

    function setBuyer(uint64 liquidity, uint64 rate, uint64 minDeposit) external {
        require(usdt.transferFrom(msg.sender, address(this), liquidity));

        buyers[msg.sender].active = true;
        buyers[msg.sender].liquidity += liquidity;
        buyers[msg.sender].rate = rate;
        buyers[msg.sender].minDeposit = minDeposit;
    }

    function closeBuyer() external {
        require(usdt.transfer(msg.sender, buyers[msg.sender].liquidity));

        delete buyers[msg.sender];
    }

    mapping(address => uint256[]) userActions; // address -> timestamps of actions
    // wtf is happening:
    // this is an inverse flag for whether the user has
    // an active order. when they have, it must be false,
    // and vice versa. by default, all users are "busy"
    // unless they register so this is set to true.
    // this was made to save storage slots.
    mapping(address => bool) internal _isBusy;

    function isBusy(address who) internal view returns (bool) {
        return !_isBusy[who];
    }

    function register(bytes calldata paymasterSig) external {
        require(ECDSA.recover(bytes32(uint256(uint160(msg.sender))), paymasterSig) == params.paymaster);
        require(userActions[msg.sender].length == 0);
        _isBusy[msg.sender] = true; // see: inverse flag "_isBusy"
    }

    function createOrder(address tronAddress, uint64 size, bytes calldata transferData) external {
        require(!isBusy(msg.sender), "bs");
        require(
            userActions[msg.sender][userActions[msg.sender].length - params.rateLimit] + params.limitPer
                < block.timestamp,
            "rl"
        );
        require(size >= params.minSize);
        require(orders[tronAddress].size == 0);

        address buyer = tronAddresses[tronAddress];
        require(buyers[buyer].active);
        require(buyers[buyer].liquidity >= size);
        buyers[buyer].liquidity -= size;

        orders[tronAddress] = Order({
            size: size,
            rate: buyers[buyer].rate,
            transferData: transferData,
            fulfiller: address(0),
            fulfilledAmount: 0
        });

        uint256 orderTimestamp = Tronlib.unixToTron(block.timestamp);
        latestOrder = sha256(
            abi.encode(
                OrderChain({
                    prev: latestOrder,
                    timestamp: orderTimestamp,
                    tronAddress: tronAddress,
                    minDeposit: buyers[buyer].minDeposit
                })
            )
        );
        totalOrders++;

        userActions[msg.sender].push(block.timestamp);
        orderTimestamps[latestOrder] = orderTimestamp;
        orderChains.push(latestOrder);
        _isBusy[msg.sender] = false; // see: inverse flag "_isBusy"
    }

    function fulfill(address[] calldata _tronAddresses, uint64[] calldata amounts) external {
        for (uint256 i = 0; i < _tronAddresses.length; i++) {
            address tronAddress = _tronAddresses[i];

            if (orders[tronAddress].fulfilledAmount != 0) {
                continue; // not require bc someone could fulfill ahead of them
            }

            uint64 amount = amounts[i];
            require(usdt.transferFrom(msg.sender, address(this), amount));

            params.sender.send(amount, orders[tronAddress].transferData);
            orders[tronAddress].fulfiller = msg.sender;
            orders[tronAddress].fulfilledAmount = amount;
        }
    }

    function revealDeposits(bytes calldata proof, bytes calldata publicValues, ClosedOrder[] calldata closedOrders)
        external
    {
        require(msg.sender == params.relayer || params.relayer == address(0));

        params.verifier.verifyProof(params.vkey, publicValues, proof);
        (
            address relayer,
            bytes32 startBlock,
            bytes32 endBlock,
            bytes32 startOrder,
            bytes32 endOrder,
            uint256 endOrderIndex,
            bytes32 oldStateHash,
            bytes32 newStateHash,
            bytes32 closedOrdersHash,
            uint64 _feePerBlock,
            uint64 totalFee
        ) = abi.decode(
            publicValues, (address, bytes32, bytes32, bytes32, bytes32, bytes32, bytes32, bytes32, uint64, uint64)
        );

        require(msg.sender == relayer);
        require(startBlock == latestKnownBlock);

        uint256 endBlockNumber = Tronlib.blockIdToNumber(endBlock);
        require(params.relay.blocks(endBlockNumber) == endBlock);
        require(endBlockNumber < params.relay.latestBlock() - 18);
        require(startOrder == latestKnownOrder);
        require(oldStateHash == stateHash);
        require(_feePerBlock == params.feePerBlock);

        bytes32 storedEndOrder = orderChains[endOrderIndex];
        require(storedEndOrder == endOrder);

        uint256 endOrderTimestamp = orderTimestamps[endOrder];
        uint256 endBlockTimestamp = params.relay.blockTimestamps(endBlock);
        uint256[] storage blockTimestamps = params.relay.timestamps();

        uint256 closestTimestamp = findUpperBound(blockTimestamps, endOrderTimestamp);
        require(closestTimestamp == endBlockTimestamp);

        bytes32 nextOrder = orderChains[endOrderIndex + 1];
        if (nextOrder != bytes32(0)) {
            uint256 closestNextOrderTimestamp = findUpperBound(blockTimestamps, endOrderTimestamp);
            require(closestNextOrderTimestamp > endBlockTimestamp);
        }

        stateHash = newStateHash;
        latestKnownOrder = endOrder;

        require(sha256(abi.encode(closedOrders)) == closedOrdersHash);

        uint64 paymasterFine = 0;
        for (uint256 i = 0; i < closedOrders.length; i++) {
            ClosedOrder memory state = closedOrders[i];
            Order memory order = orders[state.tronAddress];

            uint64 amount = order.size < state.inflow ? order.size : state.inflow;
            amount = amount * 1e6 / order.rate;
            uint64 _paymasterFine = params.feePerBlock * ORDER_TTL - amount;
            amount -= params.feePerBlock * ORDER_TTL;
            amount -= params.revealerFee;
            uint64 left = order.size - amount;
            buyers[tronAddresses[state.tronAddress]].liquidity += left;

            paymasterFine += _paymasterFine;
            if (order.fulfilledAmount + params.fulfillerFee == amount) {
                require(usdt.transfer(order.fulfiller, amount));
            } else {
                params.sender.send(amount, order.transferData);
            }
        }
        totalFee += params.revealerFee * uint64(closedOrders.length);

        require(usdt.transfer(msg.sender, totalFee));
    }

    function jailbreak() external {
        require(params.relay.latestBlock() > Tronlib.blockIdToNumber(latestKnownBlock) + 600); // 30 minutes
        params.relayer = address(0);
    }

    // Taken from https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.2/contracts/utils/Arrays.sol
    /**
     * @dev Searches a sorted `array` and returns the first index that contains
     * a value greater or equal to `element`. If no such index exists (i.e. all
     * values in the array are strictly less than `element`), the array length is
     * returned. Time complexity O(log n).
     *
     * `array` is expected to be sorted in ascending order, and to contain no
     * repeated elements.
     */
    function findUpperBound(uint256[] storage array, uint256 element) internal view returns (uint256) {
        uint256 low = 0;
        uint256 high = array.length;

        if (high == 0) {
            return 0;
        }

        while (low < high) {
            uint256 mid = Math.average(low, high);

            // Note that mid will always be strictly less than high (i.e. it will be a valid array index)
            // because Math.average rounds towards zero (it does integer division with truncation).
            if (unsafeAccess(array, mid).value > element) {
                high = mid;
            } else {
                low = mid + 1;
            }
        }

        // At this point `low` is the exclusive upper bound. We will return the inclusive upper bound.
        if (low > 0 && unsafeAccess(array, low - 1).value == element) {
            return low - 1;
        } else {
            return low;
        }
    }
}
