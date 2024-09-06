// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

// Uncomment this line to use console.log
//import "hardhat/console.sol";

import "@openzeppelin/contracts/access/Ownable.sol";
import "./Vkverifier.sol";

import "./interfaces/IVerifier.sol";


contract Summa is Ownable , vkVerifier {
    /**
     * @dev Struct representing the configuration of the Summa instance
     * @param mstLevels The number of levels of the Merkle sum tree
     * @param currenciesCount The number of cryptocurrencies supported by the Merkle sum tree
     * @param balanceByteRange The number of bytes used to represent the balance of a cryptocurrency in the Merkle sum tree
     */
    struct SummaConfig {
        uint16 mstLevels;
        uint16 currenciesCount;
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

    /**
     * @dev Struct identifying a cryptocurrency traded on the CEX
     * @param name The name of the cryptocurrency
     * @param chain The name of the chain name where the cryptocurrency lives (e.g., ETH, BTC)
     */
    struct Cryptocurrency {
        string name;
        string chain;
    }

    /**
     * @dev Struct representing a commitment submitted by the CEX.
     * @param mstRoot Merkle sum tree root of the CEX's liabilities
     * @param rootBalances The total sums of the liabilities included in the tree
     * @param blockchainNames The names of the blockchains where the CEX holds the cryptocurrencies included into the tree
     * @param cryptocurrencyNames The names of the cryptocurrencies included into the tree
     */
    struct Commitment {
        uint256 mstRoot;
        uint256[] rootBalances;
        string[] cryptocurrencyNames;
        string[] blockchainNames;
    }

    // Summa configuration
    SummaConfig public config;

    // User inclusion proof verifier
    IVerifier private immutable inclusionVerifier;

    // List of all address ownership proofs submitted by the CEX
    AddressOwnershipProof[] public addressOwnershipProofs;

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

    // Convenience mapping to check if an address has already been verified
    mapping(bytes32 => uint256) private _ownershipProofByAddress;

    // Solvency commitments by timestamp submitted by the CEX
    mapping(uint256 => Commitment) public commitments;

    event AddressOwnershipProofSubmitted(
        AddressOwnershipProof[] addressOwnershipProofs
    );
    event LiabilitiesCommitmentSubmitted(
        uint256 indexed timestamp,
        uint256 mstRoot,
        uint256[] rootBalances,
        Cryptocurrency[] cryptocurrencies
    );

    constructor(
        IVerifier _inclusionVerifier,
        uint16 mstLevels,
        uint16 currenciesCount,
        uint8 balanceByteRange
    ) {
        inclusionVerifier = _inclusionVerifier;
        config = SummaConfig(mstLevels, currenciesCount, balanceByteRange);
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
     * @param mstRoot Merkle sum tree root of the CEX's liabilities
     * @param rootBalances The total sums of the liabilities included into the Merkle sum tree
     * @param cryptocurrencies The cryptocurrencies included into the Merkle sum tree
     * @param timestamp The timestamp at which the CEX took the snapshot of its assets and liabilities
     */
    function submitCommitment(
        uint256 mstRoot,
        uint256[] memory rootBalances,
        Cryptocurrency[] memory cryptocurrencies,
        uint256 timestamp
    ) public onlyOwner {
        require(mstRoot != 0, "Invalid MST root");
        require(
            rootBalances.length == cryptocurrencies.length,
            "Root liabilities sums and liabilities number mismatch"
        );
        string[] memory cryptocurrencyNames = new string[](
            cryptocurrencies.length
        );
        string[] memory blockchainNames = new string[](cryptocurrencies.length);
        for (uint i = 0; i < cryptocurrencies.length; i++) {
            require(
                bytes(cryptocurrencies[i].chain).length != 0 &&
                    bytes(cryptocurrencies[i].name).length != 0,
                "Invalid cryptocurrency"
            );
            require(
                rootBalances[i] != 0,
                "All root sums should be greater than zero"
            );
            cryptocurrencyNames[i] = cryptocurrencies[i].name;
            blockchainNames[i] = cryptocurrencies[i].chain;
        }

        commitments[timestamp] = Commitment(
            mstRoot,
            rootBalances,
            cryptocurrencyNames,
            blockchainNames
        );

        emit LiabilitiesCommitmentSubmitted(
            timestamp,
            mstRoot,
            rootBalances,
            cryptocurrencies
        );
    }

    /**
     * Verify the proof of user inclusion into the liabilities tree
     * @param proof ZK proof
     * @param publicInputs proof inputs
     */
    function verifyInclusionProof(
        bytes memory proof,
        uint256[] memory publicInputs,
        uint256 timestamp
    ) public view returns (bool) {
        require(
            commitments[timestamp].mstRoot == publicInputs[1],
            "Invalid MST root"
        );
        for (uint i = 2; i < publicInputs.length; i++) {
            require(
                commitments[timestamp].rootBalances[i - 2] == publicInputs[i],
                "Invalid root balance"
            );
        }

        // "require" won't catch the exception thrown by the verifier, so we need to catch it manually
        try inclusionVerifier.verifyProof(proof, publicInputs) returns (
            bool result
        ) {
            return result;
        } catch (bytes memory /*lowLevelData*/) {
            // force revert to return the error message
            require(false, "Invalid inclusion proof");
            return false;
        }
    }
}
