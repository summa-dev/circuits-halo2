#[cfg(test)]
mod test {

    use crate::circuits::merkle_sum_tree::MerkleSumTreeCircuit;
    use crate::circuits::utils::{full_prover, full_verifier};
    use crate::merkle_sum_tree::{big_int_to_fp, MerkleProof, MerkleSumTree};
    use halo2_proofs::{
        dev::{FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::Fr as Fp,
        plonk::{keygen_pk, keygen_vk, Any},
    };
    use num_bigint::ToBigInt;
    use rand::rngs::OsRng;

    fn instantiate_circuit(assets_sum: Fp, path: &str) -> MerkleSumTreeCircuit {
        let merkle_sum_tree = MerkleSumTree::new(path).unwrap();

        let proof: MerkleProof = merkle_sum_tree.generate_proof(0).unwrap();

        MerkleSumTreeCircuit {
            leaf_hash: proof.entry.compute_leaf().hash,
            leaf_balance: big_int_to_fp(proof.entry.balance()),
            path_element_hashes: proof.sibling_hashes,
            path_element_balances: proof.sibling_sums,
            path_indices: proof.path_indices,
            assets_sum,
            root_hash: proof.root_hash,
        }
    }

    fn instantiate_empty_circuit() -> MerkleSumTreeCircuit {
        MerkleSumTreeCircuit {
            leaf_hash: Fp::zero(),
            leaf_balance: Fp::zero(),
            path_element_hashes: vec![Fp::zero(); 4],
            path_element_balances: vec![Fp::zero(); 4],
            path_indices: vec![Fp::zero(); 4],
            assets_sum: Fp::zero(),
            root_hash: Fp::zero(),
        }
    }

    #[test]
    fn test_valid_merkle_sum_tree() {
        let merkle_sum_tree = MerkleSumTree::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        // loop over each index and generate a proof for each one
        for user_index in 0..16 {
            let mt_proof: MerkleProof = merkle_sum_tree.generate_proof(user_index).unwrap();

            let assets_sum = merkle_sum_tree.root().balance + Fp::from(1u64); // assets_sum are defined as liabilities_sum + 1

        let circuit = instantiate_circuit(assets_sum, "src/merkle_sum_tree/csv/entry_16.csv");

            let public_input = vec![
                circuit.leaf_hash,
                circuit.leaf_balance,
                circuit.root_hash,
                circuit.assets_sum,
            ];

            let valid_prover = MockProver::run(9, &circuit, vec![public_input]).unwrap();

            valid_prover.assert_satisfied();
        }
    }

    #[test]
    fn test_valid_merkle_sum_tree_2() {
        // Same as above but now the entries contain a balance that is greater than 64 bits
        // liabilities sum is 18446744073710096590

        let merkle_sum_tree =
            MerkleSumTree::new("src/merkle_sum_tree/csv/entry_16_bigints.csv").unwrap();

        let user_index = 0;

        let mt_proof: MerkleProof = merkle_sum_tree.generate_proof(user_index).unwrap();

        let assets_sum = merkle_sum_tree.root().balance + Fp::from(1u64); // assets_sum are defined as liabilities_sum + 1

        let circuit = instantiate_circuit(assets_sum, "src/merkle_sum_tree/csv/entry_16.csv");

        let public_input = vec![
            circuit.leaf_hash,
            circuit.leaf_balance,
            circuit.root_hash,
            circuit.assets_sum,
        ];

        let valid_prover = MockProver::run(9, &circuit, vec![public_input]).unwrap();

        valid_prover.assert_satisfied();
    }

    #[test]
    fn test_valid_merkle_sum_tree_with_full_prover() {
        let merkle_sum_tree = MerkleSumTree::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let levels = 4;

        let circuit = instantiate_empty_circuit();

        // we generate a universal trusted setup of our own for testing
        let params = generate_setup_params(levels);

        // we generate the verification key and the proving key
        // we use an empty circuit just to enphasize that the circuit input are not relevant when generating the keys
        // Note: the dimension of the empty circuit used to generate the keys must be the same as the dimension of the circuit used to generate the proof
        // In this case, the dimension are represented by the heigth of the merkle tree
        let vk = keygen_vk(&params, &circuit).expect("vk generation should not fail");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk generation should not fail");

        // Only now we can instantiate the circuit with the actual inputs
        let circuit = instantiate_circuit(assets_sum, "src/merkle_sum_tree/csv/entry_16.csv");

        let public_input = vec![
            circuit.leaf_hash,
            circuit.leaf_balance,
            circuit.root_hash,
            circuit.assets_sum,
        ];

        // Generate the proof
        let proof = full_prover(&params, &pk, circuit, &public_input);

        // verify the proof to be true
        assert!(full_verifier(&params, &vk, proof, &public_input));
    }

    // Passing an invalid root hash in the instance column should fail the permutation check between the computed root hash and the instance column root hash
    #[test]
    fn test_invalid_root_hash() {
        let merkle_sum_tree = MerkleSumTree::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let user_index = 0;

        let mt_proof: MerkleProof = merkle_sum_tree.generate_proof(user_index).unwrap();

        let assets_sum = merkle_sum_tree.root().balance + Fp::from(1u64); // assets_sum are defined as liabilities_sum + 1

        let circuit = instantiate_circuit(assets_sum, "src/merkle_sum_tree/csv/entry_16.csv");

        let invalid_root_hash = Fp::from(1000u64);

        let public_input = vec![
            circuit.leaf_hash,
            circuit.leaf_balance,
            invalid_root_hash,
            circuit.assets_sum,
        ];

        let invalid_prover = MockProver::run(9, &circuit, vec![public_input]).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 2 }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 5).into(),
                    location: FailureLocation::InRegion {
                        region: (16, "permute state").into(),
                        offset: 38
                    }
                }
            ])
        );
    }

    #[test]
    fn test_invalid_root_hash_with_full_prover() {
        let merkle_sum_tree = MerkleSumTree::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let levels = 4;

        let circuit = instantiate_empty_circuit();

        // we generate a universal trusted setup of our own for testing
        let params = generate_setup_params(levels);

        // we generate the verification key and the proving key
        // we use an empty circuit just to enphasize that the circuit input are not relevant when generating the keys
        let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk should not fail");

        // Only now we can instantiate the circuit with the actual inputs
        let circuit = instantiate_circuit(assets_sum, "src/merkle_sum_tree/csv/entry_16.csv");

        let invalid_root_hash = Fp::from(1000u64);

        let public_input = vec![
            circuit.leaf_hash,
            circuit.leaf_balance,
            invalid_root_hash,
            circuit.assets_sum,
        ];

        // Generate the proof
        let proof = full_prover(&params, &pk, circuit, &public_input);

        // verify the proof to be false
        assert!(!full_verifier(&params, &vk, proof, &public_input));
    }

    // Passing an invalid leaf hash as input for the witness generation should fail the permutation check between the computed root hash and the instance column root hash
    #[test]
    fn test_invalid_leaf_hash_as_witness() {
        let merkle_sum_tree = MerkleSumTree::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let user_index = 0;

        let mt_proof: MerkleProof = merkle_sum_tree.generate_proof(user_index).unwrap();

        let assets_sum = merkle_sum_tree.root().balance + Fp::from(1u64); // assets_sum are defined as liabilities_sum + 1

        let mut circuit = instantiate_circuit(assets_sum, "src/merkle_sum_tree/csv/entry_16.csv");

        // invalidate leaf hash
        circuit.leaf_hash = Fp::from(1000u64);

        let public_input = vec![
            circuit.leaf_hash,
            circuit.leaf_balance,
            circuit.root_hash,
            circuit.assets_sum,
        ];

        let invalid_prover = MockProver::run(9, &circuit, vec![public_input]).unwrap();
        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 2 }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 5).into(),
                    location: FailureLocation::InRegion {
                        region: (16, "permute state").into(),
                        offset: 38
                    }
                }
            ])
        );
    }

    // Passing an invalid leaf hash in the instance column should fail the permutation check between the (valid) leaf hash added as part of the witness and the instance column leaf hash
    #[test]
    fn test_invalid_leaf_hash_as_instance() {
        let merkle_sum_tree = MerkleSumTree::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let user_index = 0;

        let mt_proof: MerkleProof = merkle_sum_tree.generate_proof(user_index).unwrap();

        let circuit = instantiate_circuit(assets_sum, "src/merkle_sum_tree/csv/entry_16.csv");

        let circuit = instantiate_circuit(assets_sum, mt_proof);
        // add invalid leaf hash in the instance column
        let invalid_leaf_hash = Fp::from(1000u64);

        let public_input = vec![
            invalid_leaf_hash,
            circuit.leaf_balance,
            circuit.root_hash,
            circuit.assets_sum,
        ];

        let invalid_prover = MockProver::run(9, &circuit, vec![public_input]).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::advice(), 0).into(),
                    location: FailureLocation::InRegion {
                        region: (1, "merkle prove layer").into(),
                        offset: 0
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 0 }
                },
            ])
        );
    }

    // Passing an invalid leaf balance as input for the witness generation should fail the permutation check between the computed root hash and the instance column root hash
    #[test]
    fn test_invalid_leaf_balance_as_witness() {
        let merkle_sum_tree = MerkleSumTree::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let user_index = 0;

        let mt_proof: MerkleProof = merkle_sum_tree.generate_proof(user_index).unwrap();

        let assets_sum = merkle_sum_tree.root().balance + Fp::from(1u64); // assets_sum are defined as liabilities_sum + 1

        let mut circuit = instantiate_circuit(assets_sum, mt_proof);

        let user_balance = Fp::from(11888u64);

        let mut circuit = instantiate_circuit(assets_sum, "src/merkle_sum_tree/csv/entry_16.csv");

        // invalid leaf balance
        circuit.leaf_hash = Fp::from(1000u64);

        let public_input = vec![
            circuit.leaf_hash,
            user_balance,
            circuit.root_hash,
            assets_sum,
        ];

        let invalid_prover = MockProver::run(9, &circuit, vec![public_input]).unwrap();
        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 2 }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 5).into(),
                    location: FailureLocation::InRegion {
                        region: (16, "permute state").into(),
                        offset: 38
                    }
                }
            ])
        );
    }

    // Passing an invalid leaf balance in the instance column should fail the permutation check between the (valid) leaf balance added as part of the witness and the instance column leaf balance
    #[test]
    fn test_invalid_leaf_balance_as_instance() {
        let merkle_sum_tree = MerkleSumTree::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let user_index = 0;

        let mt_proof: MerkleProof = merkle_sum_tree.generate_proof(user_index).unwrap();

        let assets_sum = merkle_sum_tree.root().balance + Fp::from(1u64); // assets_sum are defined as liabilities_sum + 1

        let circuit = instantiate_circuit(assets_sum, "src/merkle_sum_tree/csv/entry_16.csv");

        // add invalid leaf balance in the instance column
        let invalid_leaf_balance = Fp::from(1000u64);

        let public_input = vec![
            circuit.leaf_hash,
            invalid_leaf_balance,
            circuit.root_hash,
            circuit.assets_sum,
        ];

        let invalid_prover = MockProver::run(9, &circuit, vec![public_input]).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::advice(), 1).into(),
                    location: FailureLocation::InRegion {
                        region: (1, "merkle prove layer").into(),
                        offset: 0
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 1 }
                },
            ])
        );
    }

    // Passing a non binary index should fail the bool constraint check and the permutation check between the computed root hash and the instance column root hash
    #[test]
    fn test_non_binary_index() {
        let merkle_sum_tree = MerkleSumTree::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let user_index = 0;

        let mt_proof: MerkleProof = merkle_sum_tree.generate_proof(user_index).unwrap();

        let assets_sum = merkle_sum_tree.root().balance + Fp::from(1u64); // assets_sum are defined as liabilities_sum + 1

        let mut circuit = instantiate_circuit(assets_sum, "src/merkle_sum_tree/csv/entry_16.csv");

        // invalidate path index inside the circuit
        circuit.path_indices[0] = Fp::from(2);

        let public_input = vec![
            circuit.leaf_hash,
            circuit.leaf_balance,
            circuit.root_hash,
            circuit.assets_sum,
        ];

        let invalid_prover = MockProver::run(9, &circuit, vec![public_input]).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::ConstraintNotSatisfied {
                    constraint: ((0, "bool constraint").into(), 0, "").into(),
                    location: FailureLocation::InRegion {
                        region: (1, "merkle prove layer").into(),
                        offset: 0
                    },
                    cell_values: vec![(((Any::advice(), 4).into(), 0).into(), "0x2".to_string()),]
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 2 }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 5).into(),
                    location: FailureLocation::InRegion {
                        region: (16, "permute state").into(),
                        offset: 38
                    }
                }
            ])
        );
    }

    // Swapping the indices should fail the permutation check between the computed root hash and the instance column root hash
    #[test]
    fn test_swapping_index() {
        let merkle_sum_tree = MerkleSumTree::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let user_index = 0;

        let mt_proof: MerkleProof = merkle_sum_tree.generate_proof(user_index).unwrap();

        let mut circuit = instantiate_circuit(assets_sum, "src/merkle_sum_tree/csv/entry_16.csv");

        let mut circuit = instantiate_circuit(assets_sum, mt_proof);
        // swap indices
        circuit.path_indices[0] = Fp::from(1);

        let public_input = vec![
            circuit.leaf_hash,
            circuit.leaf_balance,
            circuit.root_hash,
            circuit.assets_sum,
        ];

        let invalid_prover = MockProver::run(9, &circuit, vec![public_input]).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 2 }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 5).into(),
                    location: FailureLocation::InRegion {
                        region: (16, "permute state").into(),
                        offset: 38
                    }
                }
            ])
        );
    }

    // Passing an assets sum that is less than the liabilities sum should fail the lessThan constraint check
    #[test]
    fn test_is_not_less_than() {
        let merkle_sum_tree = MerkleSumTree::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let user_index = 0;

        let mt_proof: MerkleProof = merkle_sum_tree.generate_proof(user_index).unwrap();

        let less_than_assets_sum = merkle_sum_tree.root().balance - Fp::from(1u64); // assets_sum are defined as liabilities_sum + 1

        let circuit =
            instantiate_circuit(less_than_assets_sum, "src/merkle_sum_tree/csv/entry_16.csv");

        let public_input = vec![
            circuit.leaf_hash,
            circuit.leaf_balance,
            circuit.root_hash,
            circuit.assets_sum,
        ];

        let invalid_prover = MockProver::run(9, &circuit, vec![public_input]).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![VerifyFailure::ConstraintNotSatisfied {
                constraint: (
                    (
                        7,
                        "verifies that `check` from current config equal to is_lt from LtChip"
                    )
                        .into(),
                    0,
                    ""
                )
                    .into(),
                location: FailureLocation::InRegion {
                    region: (18, "enforce sum to be less than total assets").into(),
                    offset: 0
                },
                cell_values: vec![
                    (((Any::advice(), 2).into(), 0).into(), "1".to_string()),
                    // The zero means that is not less than
                    (((Any::advice(), 11).into(), 0).into(), "0".to_string())
                ]
            }])
        );

        assert!(invalid_prover.verify().is_err());
    }

    use crate::circuits::ecdsa::EcdsaVerifyCircuit;
    use ecc::maingate::{big_to_fe, decompose, fe_to_big};
    use halo2_proofs::arithmetic::{CurveAffine, Field};
    use halo2_proofs::halo2curves::{
        ff::PrimeField, group::Curve, secp256k1::Secp256k1Affine as Secp256k1,
    };

    fn mod_n(x: <Secp256k1 as CurveAffine>::Base) -> <Secp256k1 as CurveAffine>::ScalarExt {
        let x_big = fe_to_big(x);
        big_to_fe(x_big)
    }

    #[test]
    fn test_ecdsa_valid_verifier() {
        let g = Secp256k1::generator();

        // Generate a key pair (sk, pk)
        // sk is a random scalar (exists within the scalar field, which is the order of the group generated by g
        // Note that the scalar field is different from the prime field of the curve.
        // pk is a point on the curve
        let sk = <Secp256k1 as CurveAffine>::ScalarExt::random(OsRng);

        let public_key = (g * sk).to_affine();

        let msg_hash = <Secp256k1 as CurveAffine>::ScalarExt::random(OsRng);

        // Draw arandomness -> k is also a scalar living in the order of the group generated by generator point g.
        let k = <Secp256k1 as CurveAffine>::ScalarExt::random(OsRng);
        let k_inv = k.invert().unwrap();

        let r_point = (g * k).to_affine().coordinates().unwrap();
        let x = r_point.x();

        // perform r mod n to ensure that r is a valid scalar
        let r = mod_n(*x);

        let s = k_inv * (msg_hash + (r * sk));

        // Sanity check. Ensure we construct a valid signature. So lets verify it
        {
            let s_inv = s.invert().unwrap();
            let u_1 = msg_hash * s_inv;
            let u_2 = r * s_inv;
            let r_point = ((g * u_1) + (public_key * u_2))
                .to_affine()
                .coordinates()
                .unwrap();
            let x_candidate = r_point.x();
            let r_candidate = mod_n(*x_candidate);
            assert_eq!(r, r_candidate);
        }

        let limbs_x = decompose(public_key.x, 4, 68)
            .iter()
            .map(|x| big_to_fe(fe_to_big(*x)))
            .collect::<Vec<Fp>>();

        let limbs_y = decompose(public_key.y, 4, 68)
            .iter()
            .map(|y| big_to_fe(fe_to_big(*y)))
            .collect::<Vec<Fp>>();

        // merge limbs_x and limbs_y into a single vector
        let mut pub_input = vec![];
        pub_input.extend(limbs_x);
        pub_input.extend(limbs_y);

        let instance = vec![vec![], pub_input];

        let circuit = EcdsaVerifyCircuit::init(public_key, r, s, msg_hash);

        let valid_prover = MockProver::run(18, &circuit, instance).unwrap();

        valid_prover.assert_satisfied();
    }

    // signature input obtained from an actual signer => https://gist.github.com/enricobottazzi/58c52754cabd8dd8e7ee9ed5d7591814
    #[test]
    fn test_ecdsa_no_random() {
        let secret_key = <Secp256k1 as CurveAffine>::ScalarExt::from_repr([
            154, 213, 29, 179, 82, 32, 97, 124, 125, 25, 241, 239, 17, 36, 119, 73, 209, 25, 253,
            111, 255, 254, 166, 249, 243, 69, 250, 217, 23, 156, 1, 61,
        ])
        .unwrap();

        let g = Secp256k1::generator();

        let public_key = (g * secret_key).to_affine();

        let r = <Secp256k1 as CurveAffine>::ScalarExt::from_repr([
            239, 76, 20, 99, 168, 118, 101, 14, 199, 216, 110, 228, 253, 132, 166, 78, 13, 120, 59,
            128, 32, 197, 192, 196, 58, 157, 69, 172, 73, 244, 76, 202,
        ])
        .unwrap();

        let s = <Secp256k1 as CurveAffine>::ScalarExt::from_repr([
            68, 27, 200, 44, 31, 175, 180, 124, 55, 112, 24, 91, 32, 136, 237, 17, 71, 137, 28,
            120, 126, 52, 175, 114, 197, 239, 156, 80, 112, 115, 237, 79,
        ])
        .unwrap();

        let msg_hash = <Secp256k1 as CurveAffine>::ScalarExt::from_repr([
            115, 139, 142, 103, 234, 97, 224, 87, 102, 70, 65, 216, 226, 136, 248, 62, 44, 36, 172,
            170, 253, 70, 103, 220, 126, 83, 27, 233, 159, 149, 214, 28,
        ])
        .unwrap();

        let limbs_x = decompose(public_key.x, 4, 68)
            .iter()
            .map(|x| big_to_fe(fe_to_big(*x)))
            .collect::<Vec<Fp>>();

        let limbs_y = decompose(public_key.y, 4, 68)
            .iter()
            .map(|y| big_to_fe(fe_to_big(*y)))
            .collect::<Vec<Fp>>();

        // merge limbs_x and limbs_y into a single vector
        let mut pub_input = vec![];
        pub_input.extend(limbs_x);
        pub_input.extend(limbs_y);

        let instance = vec![vec![], pub_input];

        let circuit = EcdsaVerifyCircuit::init(public_key, r, s, msg_hash);

        let valid_prover = MockProver::run(18, &circuit, instance).unwrap();

        valid_prover.assert_satisfied();
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_merkle_sum_tree() {
        use plotters::prelude::*;

        let merkle_sum_tree = MerkleSumTree::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let user_index = 0;

        let mt_proof: MerkleProof = merkle_sum_tree.generate_proof(user_index).unwrap();

        let assets_sum = merkle_sum_tree.root().balance + Fp::from(1u64); // assets_sum are defined as liabilities_sum + 1

        let circuit = instantiate_circuit(assets_sum, "src/merkle_sum_tree/csv/entry_16.csv");

        let root = BitMapBackend::new("prints/merkle-sum-tree-layout.png", (2048, 16384))
            .into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Merkle Sum Tree Layout", ("sans-serif", 60))
            .unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            .render(8, &circuit, &root)
            .unwrap();
    }
}
