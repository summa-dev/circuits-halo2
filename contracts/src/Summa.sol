// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

// Uncomment this line to use console.log
//import "hardhat/console.sol";

import "@openzeppelin/contracts/access/Ownable.sol";

import "./interfaces/IVerifier.sol";
import "./interfaces/IInclusionVerifier.sol";

contract Summa is Ownable {
    /**
     * @dev Struct representing the configuration of the Summa instance
     * @param cryptocurrencyNames The names of the cryptocurrencies whose balances are interpolated in the polynomials
     * @param cryptocurrencyChains The chains of the cryptocurrencies whose balances are interpolated in the polynomials
     * @param balanceByteRange The number of bytes used to represent the balance of a cryptocurrency in the polynomials
     */
    struct SummaConfig {
        string[] cryptocurrencyNames;
        string[] cryptocurrencyChains;
        uint8 balanceByteRange;
    }
    /**
     * @dev Struct representing an address ownership proof submitted by the CEX
     * @param cexAddress The address owned by the CEX (submitted as a string, as it can be a non-EVM address)
     * @param chain The name of the chain name where the address belongs (e.g., ETH, BTC)
     * @param signature The signature of the message signed by the address public key
     * @param message The message signed by the address public key
     */
    struct AddressOwnershipProof {
        string cexAddress;
        string chain;
        bytes signature;
        bytes message;
    }

    // Summa configuration
    SummaConfig public config;

    // Verification key contract address
    address public immutable verifyingKey;

    // List of all address ownership proofs submitted by the CEX
    AddressOwnershipProof[] public addressOwnershipProofs;

    // Liabilities commitments by timestamp submitted by the CEX
    mapping(uint256 => bytes) public commitments;

    // Convenience mapping to check if an address has already been verified
    mapping(bytes32 => uint256) private _ownershipProofByAddress;

    // zkSNARK verifier of the valid polynomial interpolation
    IVerifier private immutable polynomialInterpolationVerifier;
    
    // KZG verifier of the grand sum
    IVerifier private immutable grandSumVerifier;
    
    // KZG verifier of the inclusion proof
    IInclusionVerifier private immutable inclusionVerifier;

    event AddressOwnershipProofSubmitted(
        AddressOwnershipProof[] addressOwnershipProofs
    );
    event LiabilitiesCommitmentSubmitted(
        uint256 indexed timestamp,
        uint256[] totalBalances,
        bytes snarkProof,
        bytes grandSumProof
    );

    /**
     * Summa contract
     * @param _verifyingKey The address of the verification key contract
     * @param _polynomialInterpolationVerifier the address of the polynomial interpolation zkSNARK verifier
     * @param _grandSumVerifier the address of the grand sum KZG verifier
     * @param _inclusionVerifier the address of the inclusion KZG verifier
     * @param cryptocurrencyNames the names of the cryptocurrencies whose balances are interpolated in the polynomials
     * @param cryptocurrencyChains the chain names of the cryptocurrencies whose balances are interpolated in the polynomials
     * @param balanceByteRange maximum accepted byte range for the balance of a cryptocurrency
     */
    constructor(
        address _verifyingKey,
        IVerifier _polynomialInterpolationVerifier,
        IVerifier _grandSumVerifier,
        IInclusionVerifier _inclusionVerifier,
        string[] memory cryptocurrencyNames,
        string[] memory cryptocurrencyChains,
        uint8 balanceByteRange
    ) {
        require(_verifyingKey != address(0), "Invalid verifying key address");
        verifyingKey = _verifyingKey;
        require(
            cryptocurrencyNames.length == cryptocurrencyChains.length,
            "Cryptocurrency names and chains number mismatch"
        );
        for (uint i = 0; i < cryptocurrencyNames.length; i++) {
            require(
                bytes(cryptocurrencyNames[i]).length != 0 &&
                    bytes(cryptocurrencyChains[i]).length != 0,
                "Invalid cryptocurrency"
            );
        }
        require(
            validateVKPermutationsLength(
                _verifyingKey,
                cryptocurrencyNames.length,
                balanceByteRange
            ),
            "The config parameters do not correspond to the verifying key"
        );
        require(
            address(_polynomialInterpolationVerifier) != address(0),
            "Invalid polynomial interpolation verifier address"
        );
        polynomialInterpolationVerifier = _polynomialInterpolationVerifier;
        require(
            address(_grandSumVerifier) != address(0),
            "Invalid grand sum verifier address"
        );
        grandSumVerifier = _grandSumVerifier;
        require(
            address(_inclusionVerifier) != address(0),
            "Invalid inclusion verifier address"
        );
        inclusionVerifier = _inclusionVerifier;
        config = SummaConfig(
            cryptocurrencyNames,
            cryptocurrencyChains,
            balanceByteRange
        );
    }

    /**
     * @dev Validate the number of permutations in the verifying key
     * @param vkContract The address of the verifying key contract
     * @param numberOfCurrencies The number of cryptocurrencies whose polynomials are committed in the proof
     * @return isValid True if the number of permutations in the verifying key corresponds to the number of cryptocurrencies
     *
     * WARNING: The permutation length may not be correctly calculated by the method 'calculatePermutationLength' if the prover
     * deliberately tries to deceive the process. This issue cannot be resolved even if we change the approach to rely on user input
     * for the length instead of calculating it within the method. The ultimate solution is to implement a validation process for the
     * verifying key contract that can be performed by the user themselves. This issue will be addressed in the following: 
     * https://github.com/summa-dev/summa-solvency/issues/299
     */
     */
    function validateVKPermutationsLength(
        address vkContract,
        uint256 numberOfCurrencies,
        uint8 balanceByteRange
    ) internal view returns (bool isValid) {
        // The number of permutations is 2 + (balanceByteRange/2) * numberOfCurrencies because of the circuit structure:
        // 1 per instance column, 1 per constant column (range check) and balanceByteRange/2 per range check columns times the number of currencies
        uint256 numPermutations = 2 +
            (balanceByteRange / 2) *
            numberOfCurrencies;

        uint256 startOffsetForPermutations = 0x2e0; // The value can be observed in the VerificationKey contract, the offset is pointing after all the parameters and the fixed column commitment

        // The offset after the last permutation is the start offset plus the number of permutations times 0x40 (the size of a permutation)
        uint256 offsetAfterLastPermutation = startOffsetForPermutations +
            numPermutations *
            0x40;

        // extcodecopy is a gas-expensive operation per byte, so we want to minimize the number of bytes we read.
        // This hack is to read the 32 (0x20) bytes that overlap the last permutation and the empty memory location behind it.
        // For example, a circuit with 2 currencies will have 10 permutations, so the location behind the last permutation will be at 0x2e0 + 10 * 0x40 = 0x0560
        // We read 0x20 bytes starting from 0x0550, which will include a piece of the last permutation and the empty memory location behind it.
        uint256 readOffset = offsetAfterLastPermutation - 0x10;
        bool valid;
        // Extract the last permutation
        assembly {
            // Read the memory location into 0x00
            extcodecopy(vkContract, 0x00, readOffset, 0x20)
            // Load the read bytes from 0x00 into a variable
            let readBytes := mload(0x00)

            let leftHalf  := shr(128, readBytes)                                // Shift right by 128 bits to get the left half
            let rightHalf := and(readBytes, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) // Mask the right half

            // We expect the left 16 bytes to be nonzero and the right 16 bytes to be zero
            valid := and(not(iszero(leftHalf)), iszero(rightHalf))
        }
        return valid;
    }

    function getAddressOwnershipProof(
        bytes32 addressHash
    ) public view returns (AddressOwnershipProof memory) {
        require(
            _ownershipProofByAddress[addressHash] > 0,
            "Address not verified"
        );
        // -1 comes from the fact that 0 is reserved to distinguish the case when the proof has not yet been submitted
        return
            addressOwnershipProofs[_ownershipProofByAddress[addressHash] - 1];
    }

    /**
     * @dev Submit an optimistic proof of multiple address ownership for a CEX. The proof is subject to an off-chain verification as it's not feasible to verify the signatures of non-EVM chains in an Ethereum smart contract.
     * @param _addressOwnershipProofs The list of address ownership proofs
     */
    function submitProofOfAddressOwnership(
        AddressOwnershipProof[] memory _addressOwnershipProofs
    ) public onlyOwner {
        for (uint i = 0; i < _addressOwnershipProofs.length; i++) {
            bytes32 addressHash = keccak256(
                abi.encodePacked(_addressOwnershipProofs[i].cexAddress)
            );
            uint256 proofIndex = _ownershipProofByAddress[addressHash];
            require(proofIndex == 0, "Address already verified");

            addressOwnershipProofs.push(_addressOwnershipProofs[i]);
            _ownershipProofByAddress[addressHash] = addressOwnershipProofs
                .length;
            require(
                bytes(_addressOwnershipProofs[i].cexAddress).length != 0 &&
                    bytes(_addressOwnershipProofs[i].chain).length != 0 &&
                    _addressOwnershipProofs[i].signature.length != 0 &&
                    _addressOwnershipProofs[i].message.length != 0,
                "Invalid proof of address ownership"
            );
        }

        emit AddressOwnershipProofSubmitted(_addressOwnershipProofs);
    }

    /**
     * @dev Submit commitment for a CEX
     * @param snarkProof ZK proof of the valid polynomial interpolation
     * @param grandSumProof kzg proof of the grand sum
     * @param totalBalances The array of total balances in the grand sum
     * @param timestamp The timestamp at which the CEX took the snapshot of its assets and liabilities
     */
    function submitCommitment(
        bytes calldata snarkProof,
        bytes calldata grandSumProof,
        uint256[] memory totalBalances,
        uint256 timestamp
    ) public onlyOwner {
        // Check input length
        require(totalBalances.length > 0, "Invalid total balances length");
        require(grandSumProof.length == (totalBalances.length * 0x40), "Invalid grand sum proof length");
        require(snarkProof.length > grandSumProof.length, "Invalid snark proof length");
        
        uint[] memory args = new uint[](1);

        // This is the instance value for checking zero value inside circuit
        args[0] = 0; 
        require(
            polynomialInterpolationVerifier.verifyProof(verifyingKey, snarkProof, args),
            "Invalid snark proof"
        );
        require(
            totalBalances.length == config.cryptocurrencyNames.length,
            "Liability commitments and cryptocurrencies number mismatch"
        );

        bytes calldata slicedSnarkProof = snarkProof[0:64 + grandSumProof.length];
        bytes memory combinedProofs = abi.encodePacked(grandSumProof, slicedSnarkProof[64:]);

        require(grandSumVerifier.verifyProof(verifyingKey, combinedProofs, totalBalances), "Invalid grand sum proof");

        commitments[timestamp] = slicedSnarkProof;

        emit LiabilitiesCommitmentSubmitted(timestamp, totalBalances, slicedSnarkProof, grandSumProof);
    }

    function verifyInclusionProof(
        uint256 timestamp,
        bytes memory inclusionProof,
        uint256[] memory challenges,
        uint256[] memory values
    ) public view returns (bool) {
        require(challenges.length == 4, "Invalid challenges length");
        
        // Excluding `usename` in the values
        require((values.length - 1) == config.cryptocurrencyNames.length, "Values length mismatch with config");

        bytes memory snarkProof = commitments[timestamp];
    
        bytes memory combinedProofs = new bytes(snarkProof.length + inclusionProof.length);
        for (uint256 i = 0; i < inclusionProof.length; i++) {
            combinedProofs[i] = inclusionProof[i];
        }
        for (uint256 i = 0; i < snarkProof.length; i++) {
            combinedProofs[i + inclusionProof.length] = snarkProof[i];
        }

        return inclusionVerifier.verifyProof(verifyingKey, combinedProofs, challenges, values);
    }
}
