// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

contract vkVerifier {
    uint256 public vk_digest;
    uint256 public k;
    uint256 public n_inv;
    uint256 public omega;

    constructor() {
        assembly {
            mstore(0x00, 0x00996ed64113d5d86f42caab0f3d25466b0856015472de4bb809f168aabc2567) // vk_digest
            mstore(0x20, 0x0000000000000000000000000000000000000000000000000000000000000011) // k
            mstore(0x40, 0x30643640b9f82f90e83b698e5ea6179c7c05542e859533b48b9953a2f5360801) // n_inv
            mstore(0x60, 0x304cd1e79cfa5b0f054e981a27ed7706e7ea6b06a7f266ef8db819c179c2c3ea) // omega
        }

        assembly {
            sstore(vk_digest.slot, mload(0x00)) // Store value from memory to storage using slot
            sstore(k.slot, mload(0x20))         
            sstore(n_inv.slot, mload(0x40))    
            sstore(omega.slot, mload(0x60))     
        }
    }

    // Function to verify the vk_digest, k, n_inv, omega
    function verifying_vk(uint256 _vk_digest, uint256 _k, uint256 _n_inv, uint256 _omega) public view returns (bool) {
        return (vk_digest == _vk_digest && k == _k && n_inv == _n_inv && omega == _omega);
    }
}
