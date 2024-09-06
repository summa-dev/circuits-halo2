// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

interface IVkverifier{
    function verifying_vk(uint256 _vk_digest, uint256 _k, uint256 _n_inv, uint256 _omega) external view returns (bool);
}