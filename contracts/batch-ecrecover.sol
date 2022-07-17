// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

// Predefined constants to set bounaries of memory layout. See below for full explaination
// Keccak hash is fixed at 256 bits so this cannot be adjusted
uint8 constant KECCAKHASH_BYTES = 32;
// We use the compact layout for addresses, occupying 20 bytes instead of the EVM word-size of 32 bytes
// this will make calls cheaper, but requires more care when loading addresses
uint8 constant ADDRESS_BYTES = 20;
// Signatures are encoded as v, r, s as that allows direct memory copy into the arguments instead of decoding
// reassembly from the stack. v must be [27, 28]
uint8 constant SIGNATURE_V_BYTES = 1;
uint8 constant SIGNATURE_R_BYTES = 32;
uint8 constant SIGNATURE_S_BYTES = 32;
uint8 constant SIGNATURE_BYTES = 65; // Assembly does not accept these aritmetic operations: SIGNATURE_V_BYTES + SIGNATURE_R_BYTES + SIGNATURE_S_BYTES;

uint256 constant MAX_S_VALUE = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
// The precompile address of the ecrecover contract
uint160 constant ECRECOVER_ADDRESS = 0x1;
uint8 constant ECRECOVER_CALLDATASIZE = 128;
uint8 constant ECRECOVER_RETURNDATASIZE = 32;

// Verify a prehashed message, with signatures sorted in validator order
// The algorithm is using constant memory overhead
function ecrecoverBatch (uint threshold, bytes32 hash, bytes calldata validators, bytes calldata signatures) view returns (uint256 validSignatures) {
    require(validators.length % ADDRESS_BYTES == 0);
    require(signatures.length % SIGNATURE_BYTES == 0);

    validSignatures = 0;

    assembly ("memory-safe") {
        let args_ptr, ret_ptr, hash_ptr, sig_ptr := allocate_ecrecover()

        // As the message hash stays constant between all ecrecover calls we can already load
        // this into the appropiate memory position now
        mstore(hash_ptr, hash)

        // Iterating through the validators array we increment the pointer, hence we precompute
        // the end of the array instead of checking the length in for-loop stopping condition
        let validators_ptr := validators.offset
        let validators_end := add(validators.offset, validators.length)

        let signatures_ptr := signatures.offset
        let signatures_end := add(signatures.offset, signatures.length)

        for {} lt(signatures_ptr, signatures_end) { signatures_ptr := add(signatures_ptr, SIGNATURE_BYTES) } {
            // This check is redundant since we only allow each signer to present a single signature, hence
            // presenting a negated s with a flipped v value will not cause two signatures to be validated
            // for the same signer
            if signature_is_big_s(signatures_ptr) { revert(0,0) }

            // Load the next signature into the ecrecover calldata
            calldatacopy(sig_ptr, signatures_ptr, SIGNATURE_BYTES)

            let recovered_address := staticcall_ecrecover(args_ptr, ret_ptr)

            // Check the next validators for a match
            for {} lt(validators_ptr, validators_end) {} {
                let validator_addr := to_address(calldataload(validators_ptr))

                // We increment the validator pointer here since we want to look at the next one
                // regardless in the next iteration
                validators_ptr := add(validators_ptr, ADDRESS_BYTES)

                if eq(recovered_address, validator_addr) {
                    // Increment valid signatures
                    validSignatures := add(validSignatures, 1)
                    // We found a match so we break the validator loop and look at the next signature
                    break
                }
            }

            if eq(validSignatures, threshold) {
              break
            }

            if eq(validators_end, validators_ptr) {
                break
            }
        }

        function staticcall_ecrecover (_args_ptr, _ret_ptr) -> _recovered_address {
            // Cannot error unless out of gas, which would cause the current transaction to revert
            // Sources:
            //      https://github.com/ethereum/go-ethereum/blob/e394d01f2a578765868355e98898bd17d3d076c1/core/vm/contracts.go#L158-L194
            //      https://github.com/ethereumjs/ethereumjs-monorepo/blob/master/packages/evm/src/precompiles/01-ecrecover.ts
            pop(staticcall(
                gas(),
                ECRECOVER_ADDRESS,
                _args_ptr,
                ECRECOVER_CALLDATASIZE,
                _ret_ptr,
                ECRECOVER_RETURNDATASIZE
            ))

            _recovered_address := mload(_ret_ptr)
        }

        // Allocate space for the calldata and returndata for ecrecover
        // The call convention for ecrecover is:
        // Calldata: 32 byte keccak hash || 31 zero bytes || 1 byte v || 32 byte r || 32 byte s
        // Returndata: 12 zero bytes || 20 byte address
        function allocate_ecrecover () ->
            _args_ptr, // returndataptr
            _ret_ptr, // calldataptr
            _hash_ptr, _sig_ptr //, // calldata
            // _recover_ptr // returndata
        {
            // These items should be const-folded
            let _args_length := add(KECCAKHASH_BYTES, add(sub(32, SIGNATURE_V_BYTES), SIGNATURE_BYTES))
            let _ret_length := add(sub(32, ADDRESS_BYTES), ADDRESS_BYTES)

            // Find next free memory range that can be used for calldata and returndata.
            // Note that since we perform all computation in a single assembly block and
            // do not return any allocated data from the assembly block, we do not need to
            // allocate any memory
            let ptr := allocated_unbounded()

            // Place returndata right after calldata. We could potentially save some memory
            // by overlapping the returndata with the calldata since we overwrite the
            // signature on each call while keeping the hash constant
            _args_ptr := ptr
            _ret_ptr := add(ptr, _args_length)

            // Return pointers to each argument area, so we can ignore padding when loading
            // values
            _hash_ptr := _args_ptr
            _sig_ptr := add(_args_ptr, add(KECCAKHASH_BYTES, sub(32, SIGNATURE_V_BYTES)))
            // _recover_ptr := add(_ret_ptr, sub(32, ADDRESS_BYTES))
        }

        function signature_is_big_s (_ptr) -> is_big_s {
            // 1 byte v + 32 byte r = 33 byte offset
            let s := calldataload(add(_ptr, add(SIGNATURE_V_BYTES, SIGNATURE_R_BYTES)))
            is_big_s := gt(s, MAX_S_VALUE)
        }

        // Transform a flush-left 20 byte address to a flush-right 32 byte address as is expected
        // in EVM
        function to_address(v) -> _addr {
            // The intermediate calculations here should be const-folded, but are kept in case we
            // may want to adjust the ADDRESS_BYTES
            _addr := shr(mul(8, sub(32, ADDRESS_BYTES)), v)
        }

        // We do not have to update the allocation pointer since we will only use the memory
        // for the duration of this asm block
        function allocated_unbounded() -> _ptr {
            _ptr := mload(0x40)
        }
    }
}
