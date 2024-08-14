#[cfg(test)]
mod test {
    use crate::merkle_sum_tree::utils::{
        big_uint_to_fp, build_leaves_from_entries, build_merkle_tree_from_leaves,
        parse_csv_to_entries,
    };
    use crate::merkle_sum_tree::{Entry, MerkleSumTree, Node, Tree};
    use num_bigint::{BigUint, ToBigUint};
    use rand::Rng as _;

    const N_CURRENCIES: usize = 2;
    const N_BYTES: usize = 8;

    #[test]
    fn test_mst() {
        // create new merkle tree
        let merkle_tree =
            MerkleSumTree::<N_CURRENCIES, N_BYTES>::from_csv("../csv/entry_16.csv").unwrap();

        // get root
        let root = merkle_tree.root();

        // expect root hash to be different than 0
        assert!(root.hash != 0.into());
        // expect balance to match the sum of all entries
        assert!(root.balances == [556862.into(), 556862.into()]);
        // expect depth to be 4
        assert!(*merkle_tree.depth() == 4_usize);

        // get proof for entry 0
        let proof = merkle_tree.generate_proof(0).unwrap();

        // verify proof
        assert!(merkle_tree.verify_proof(&proof));

        // Should generate different root hashes when changing the entry order
        let merkle_tree_2 =
            MerkleSumTree::<N_CURRENCIES, N_BYTES>::from_csv("../csv/entry_16_switched_order.csv")
                .unwrap();
        assert_ne!(root.hash, merkle_tree_2.root().hash);

        // the balance total should be the same
        assert_eq!(root.balances, merkle_tree_2.root().balances);

        // should create valid proof for each entry in the tree and verify it
        for i in 0..=15 {
            let proof = merkle_tree.generate_proof(i).unwrap();
            assert!(merkle_tree.verify_proof(&proof));
        }

        // shouldn't create a proof for an entry that doesn't exist in the tree
        assert!(merkle_tree.generate_proof(16).is_err());

        // shouldn't verify a proof with a wrong leaf
        let invalid_entry = Entry::new(
            "AtwIxZHo".to_string(),
            [35479.to_biguint().unwrap(), 35479.to_biguint().unwrap()],
        );
        let invalid_entry = invalid_entry;
        let mut proof_invalid_1 = proof.clone();
        proof_invalid_1.entry = invalid_entry;
        assert!(!merkle_tree.verify_proof(&proof_invalid_1));

        // shouldn't verify a proof with a wrong root hash
        let mut proof_invalid_2 = proof.clone();
        proof_invalid_2.root.hash = 0.into();
        assert!(!merkle_tree.verify_proof(&proof_invalid_2));
    }

    #[test]
    #[should_panic(expected = "Node balance is exceed limit")]
    fn test_node_and_root_balance_limit() {
        let (_, entries) = parse_csv_to_entries::<&str, N_CURRENCIES, N_BYTES>(
            "../csv/entry_16_max_node_balance.csv",
        )
        .unwrap();

        let leaves = build_leaves_from_entries::<N_CURRENCIES>(&entries);
        let depth = (entries.len() as f64).log2().ceil() as usize;

        let _ = build_merkle_tree_from_leaves::<N_CURRENCIES, N_BYTES>(&leaves, depth);
    }

    #[test]
    fn test_update_mst_leaf() {
        let merkle_tree_1 =
            MerkleSumTree::<N_CURRENCIES, N_BYTES>::from_csv("../csv/entry_16.csv").unwrap();

        let root_hash_1 = merkle_tree_1.root().hash;

        //Create the second tree with the 7th entry different from the the first tree
        let mut merkle_tree_2 =
            MerkleSumTree::<N_CURRENCIES, N_BYTES>::from_csv("../csv/entry_16_modified.csv")
                .unwrap();

        let root_hash_2 = merkle_tree_2.root().hash;
        assert!(root_hash_1 != root_hash_2);

        //Update the 7th leaf of the second tree so all the entries now match the first tree
        let new_root = merkle_tree_2
            .update_leaf(
                "RkLzkDun",
                &[2087.to_biguint().unwrap(), 79731.to_biguint().unwrap()],
            )
            .unwrap();
        //The roots should match
        assert!(root_hash_1 == new_root.hash);
    }

    #[test]
    fn test_update_invalid_mst_leaf() {
        let mut merkle_tree =
            MerkleSumTree::<N_CURRENCIES, N_BYTES>::from_csv_sorted("../csv/entry_16.csv").unwrap();

        let new_root = merkle_tree.update_leaf(
            "non_existing_user", //This username is not present in the tree
            &[11888.to_biguint().unwrap(), 41163.to_biguint().unwrap()],
        );

        if let Err(e) = new_root {
            assert_eq!(e.to_string(), "Username not found");
        }
    }

    #[test]
    fn test_sorted_mst() {
        let merkle_tree =
            MerkleSumTree::<N_CURRENCIES, N_BYTES>::from_csv("../csv/entry_16.csv").unwrap();

        let old_root_balances = merkle_tree.root().balances;
        let old_root_hash = merkle_tree.root().hash;

        let sorted_merkle_tree =
            MerkleSumTree::<N_CURRENCIES, N_BYTES>::from_csv_sorted("../csv/entry_16.csv").unwrap();

        let new_root_balances = sorted_merkle_tree.root().balances;
        let new_root_hash = sorted_merkle_tree.root().hash;

        // The root balances should be the same for sorted and unsorted MST
        assert!(old_root_balances == new_root_balances);
        // The root hash should not be the same for sorted and unsorted MST
        assert!(old_root_hash != new_root_hash);
    }

    #[test]
    fn test_big_uint_conversion() {
        let big_uint = 3.to_biguint().unwrap();
        let fp = big_uint_to_fp(&big_uint);

        assert_eq!(fp, 3.into());

        let big_int_over_64 = (18446744073709551616_i128).to_biguint().unwrap();
        let fp_2 = big_uint_to_fp(&big_int_over_64);

        let big_int_to_bytes = {
            let mut bytes = BigUint::to_bytes_le(&big_int_over_64);
            bytes.resize(32, 0);
            bytes
        };

        assert_eq!(fp_2.to_bytes().to_vec(), big_int_to_bytes);

        let fp_3 = fp_2 - fp;
        assert_eq!(fp_3, 18446744073709551613.into());
    }

    #[test]
    fn get_middle_node_hash_preimage() {
        let merkle_tree =
            MerkleSumTree::<N_CURRENCIES, N_BYTES>::from_csv("../csv/entry_16.csv").unwrap();

        let depth = *merkle_tree.depth();

        // The tree has 16 leaves, so the levels are 0, 1, 2, 3, 4. Where level 0 is the leaves and level 4 is the root
        // Fetch a random level from 1 to depth
        let mut rng = rand::thread_rng();
        let level = rng.gen_range(1..depth);

        // Fetch a random index inside the level. For example level 1 has 8 nodes, so the index can be 0, 1, 2, 3, 4, 5, 6, 7
        let index = rng.gen_range(0..merkle_tree.nodes()[level].len());

        // Fetch middle node with index from level
        let middle_node = merkle_tree.nodes()[level][index].clone();

        // Fetch the hash preimage of the middle node
        let hash_preimage = merkle_tree
            .get_middle_node_hash_preimage(level, index)
            .unwrap();

        let computed_middle_node = Node::<N_CURRENCIES>::middle_node_from_preimage(&hash_preimage);

        // The hash of the middle node should match the hash computed from the hash preimage
        assert_eq!(middle_node.hash, computed_middle_node.hash);
    }

    #[test]
    fn get_leaf_node_hash_preimage() {
        let merkle_tree =
            MerkleSumTree::<N_CURRENCIES, N_BYTES>::from_csv("../csv/entry_16.csv").unwrap();

        // Generate a random number between 0 and 15
        let mut rng = rand::thread_rng();
        let index = rng.gen_range(0..16);

        // Fetch leaf with index
        let leaf = merkle_tree.leaves()[index].clone();

        // Fetch the hash preimage of the leaf
        let hash_preimage = merkle_tree.get_leaf_node_hash_preimage(index).unwrap();

        let computed_leaf = Node::<N_CURRENCIES>::leaf_node_from_preimage(&hash_preimage);

        // The hash of the leaf should match the hash computed from the hash preimage
        assert_eq!(leaf.hash, computed_leaf.hash);
    }

    #[test]
    fn test_tree_with_zero_element_1() {
        // create new merkle tree
        let merkle_tree =
            MerkleSumTree::<N_CURRENCIES, N_BYTES>::from_csv("../csv/entry_13.csv").unwrap();

        // get root
        let root = merkle_tree.root();

        // The last 3 entries of the merkle tree should be zero entries
        for i in 13..16 {
            let entry = merkle_tree.entries()[i].clone();
            assert_eq!(entry, Entry::<N_CURRENCIES>::init_empty());
        }

        // expect root hash to be different than 0
        assert!(root.hash != 0.into());
        // expect balance to match the sum of all entries
        assert!(root.balances == [385969.into(), 459661.into()]);
        // expect depth to be 4
        assert!(*merkle_tree.depth() == 4_usize);

        // should create valid proof for each entry in the tree and verify it
        for i in 0..=15 {
            let proof = merkle_tree.generate_proof(i).unwrap();
            assert!(merkle_tree.verify_proof(&proof));
        }

        // shouldn't create a proof for an entry that doesn't exist in the tree
        assert!(merkle_tree.generate_proof(16).is_err());
    }

    #[test]
    fn test_tree_with_zero_element_2() {
        // create new merkle tree
        let merkle_tree =
            MerkleSumTree::<N_CURRENCIES, N_BYTES>::from_csv("../csv/entry_17.csv").unwrap();

        // get root
        let root = merkle_tree.root();

        // The last 15 entries of the merkle tree should be zero entries
        for i in 17..32 {
            let entry = merkle_tree.entries()[i].clone();
            assert_eq!(entry, Entry::<N_CURRENCIES>::init_empty());
        }

        // expect root hash to be different than 0
        assert!(root.hash != 0.into());
        // expect balance to match the sum of all entries
        assert!(root.balances == [556863.into(), 556863.into()]);
        // expect depth to be 5
        assert!(*merkle_tree.depth() == 5_usize);

        // should create valid proof for each entry in the tree and verify it
        for i in 0..=31 {
            let proof = merkle_tree.generate_proof(i).unwrap();
            assert!(merkle_tree.verify_proof(&proof));
        }

        // shouldn't create a proof for an entry that doesn't exist in the tree
        assert!(merkle_tree.generate_proof(32).is_err());
    }
}
