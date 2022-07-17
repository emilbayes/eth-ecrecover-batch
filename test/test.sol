// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import "../contracts/batch-ecrecover.sol";

contract Test {
    constructor() payable {}

    function verify(
        uint256 threshold,
        bytes32 hash,
        bytes calldata validators,
        bytes calldata signatures
    ) public view returns (uint256 validSignatures) {
        return ecrecoverBatch(threshold, hash, validators, signatures);
    }

    function verify2(
        uint256 threshold,
        bytes32 hash,
        bytes calldata validators,
        bytes calldata signatures
    )
        public
        view
        returns (
            bytes memory pre,
            uint256 validSignatures,
            bytes memory post
        )
    {
        pre = new bytes(64);
        validSignatures = ecrecoverBatch(
            threshold,
            hash,
            validators,
            signatures
        );
        post = new bytes(64);
    }
}
