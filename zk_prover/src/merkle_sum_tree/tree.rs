use crate::merkle_sum_tree::{Entry, MerkleProof, Node};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use num_bigint::BigUint;

/// A trait representing the basic operations for a Merkle-Sum-like Tree.
pub trait Tree<const N_ASSETS: usize, const N_BYTES: usize> {
    /// Returns a reference to the root node.
    fn root(&self) -> &Node<N_ASSETS>;

    /// Returns the depth of the tree.
    fn depth(&self) -> &usize;

    /// Returns a slice of the leaf nodes.
    fn leaves(&self) -> &[Node<N_ASSETS>];

    /// Returns a slice of the nodes.
    fn nodes(&self) -> &[Vec<Node<N_ASSETS>>];

    fn get_entry(&self, index: usize) -> &Entry<N_ASSETS>;

    /// Returns the nodes stored at the penultimate level of the tree, namely the one before the root
    fn penultimate_level_data(&self) -> Result<(&Node<N_ASSETS>, &Node<N_ASSETS>), &'static str>;

    /// Generates a MerkleProof for the user with the given index.
    fn generate_proof(&self, index: usize) -> Result<MerkleProof<N_ASSETS, N_BYTES>, &'static str> {
        let nodes = self.nodes();
        let depth = *self.depth();
        let root = self.root();

        if index >= nodes[0].len() {
            return Err("The leaf does not exist in this tree");
        }

        let mut sibling_hashes = vec![Fp::from(0); depth];
        let mut sibling_sums = vec![[Fp::from(0); N_ASSETS]; depth];
        let mut path_indices = vec![Fp::from(0); depth];
        let mut current_index = index;

        let leaf = &nodes[0][index];

        for level in 0..depth {
            let position = current_index % 2;
            let level_start_index = current_index - position;
            let level_end_index = level_start_index + 2;

            path_indices[level] = Fp::from(position as u64);

            for i in level_start_index..level_end_index {
                if i != current_index {
                    sibling_hashes[level] = nodes[level][i].hash;
                    sibling_sums[level] = nodes[level][i].balances;
                }
            }
            current_index /= 2;
        }

        Ok(MerkleProof {
            leaf: leaf.clone(),
            root_hash: root.hash,
            sibling_hashes,
            sibling_sums,
            path_indices,
        })
    }

    /// Verifies a MerkleProof.
    fn verify_proof(&self, proof: &MerkleProof<N_ASSETS, N_BYTES>) -> bool
    where
        [usize; N_ASSETS + 1]: Sized,
        [usize; 2 * (1 + N_ASSETS)]: Sized,
    {
        let mut node = proof.leaf.clone();

        let mut balances = proof.leaf.balances;

        for i in 0..proof.sibling_hashes.len() {
            let sibling_node = Node {
                hash: proof.sibling_hashes[i],
                balances: proof.sibling_sums[i],
            };

            if proof.path_indices[i] == 0.into() {
                node = Node::middle(&node, &sibling_node);
            } else {
                node = Node::middle(&sibling_node, &node);
            }

            for (balance, sibling_balance) in balances.iter_mut().zip(sibling_node.balances.iter())
            {
                *balance += sibling_balance;
            }
        }

        proof.root_hash == node.hash && balances == node.balances
    }

    /// Returns the index of the user with the given username and balances in the tree
    fn index_of(&self, username: &str, balances: [BigUint; N_ASSETS]) -> Option<usize>
    where
        [usize; N_ASSETS + 1]: Sized,
    {
        let entry: Entry<N_ASSETS> = Entry::new(username.to_string(), balances).unwrap();
        let leaf = entry.compute_leaf();
        let leaf_hash = leaf.hash;

        self.nodes()[0]
            .iter()
            .position(|node| node.hash == leaf_hash)
    }
}
