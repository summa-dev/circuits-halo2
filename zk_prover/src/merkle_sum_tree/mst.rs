use crate::merkle_sum_tree::utils::{
    build_leaves_from_entries, build_merkle_tree_from_leaves, parse_csv_to_entries,
};
use crate::merkle_sum_tree::{Entry, Node, Tree};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use num_bigint::BigUint;

/// Merkle Sum Tree Data Structure.
///
/// A Merkle Sum Tree is a binary Merkle Tree with the following properties:
/// * Each Entry of a Merkle Sum Tree is a pair of a username and #N_CURRENCIES balances.
/// * Each Leaf Node contains a hash and #N_CURRENCIES balances. The hash is equal to `H(username, balance[0], balance[1], ... balance[N_CURRENCIES - 1])`. The balances are equal to the balances associated to the entry
/// * Each Middle Node contains a hash and #N_CURRENCIES balances. The hash is equal to `H(LeftChild.balance[0] + RightChild.balance[0], LeftChild.balance[1] + RightChild.balance[1], ..., LeftChild.balance[N_CURRENCIES - 1] + RightChild.balance[N_CURRENCIES - 1], LeftChild.hash, RightChild.hash)`. The balances are equal to the sum of the balances of the child nodes per each cryptocurrency.
/// * The Root Node represents the committed state of the Tree and contains the sum of all the entries' balances per each cryptocurrency.
///
/// # Type Parameters
///
/// * `N_CURRENCIES`: The number of cryptocurrencies for each user account
/// * `N_BYTES`: Range in which each node balance should lie
#[derive(Debug, Clone)]
pub struct MerkleSumTree<const N_CURRENCIES: usize, const N_BYTES: usize> {
    root: Node<N_CURRENCIES>,
    nodes: Vec<Vec<Node<N_CURRENCIES>>>,
    depth: usize,
    entries: Vec<Entry<N_CURRENCIES>>,
    cryptocurrencies: Vec<Cryptocurrency>,
    is_sorted: bool,
}

impl<const N_CURRENCIES: usize, const N_BYTES: usize> Tree<N_CURRENCIES>
    for MerkleSumTree<N_CURRENCIES, N_BYTES>
{
    fn root(&self) -> &Node<N_CURRENCIES> {
        &self.root
    }

    fn depth(&self) -> &usize {
        &self.depth
    }

    fn nodes(&self) -> &[Vec<Node<N_CURRENCIES>>] {
        &self.nodes
    }

    fn get_entry(&self, index: usize) -> &Entry<N_CURRENCIES> {
        &self.entries[index]
    }

    fn cryptocurrencies(&self) -> &[Cryptocurrency] {
        &self.cryptocurrencies
    }
}

#[derive(Debug, Clone)]
pub struct Cryptocurrency {
    pub name: String,
    pub chain: String,
}

impl<const N_CURRENCIES: usize, const N_BYTES: usize> MerkleSumTree<N_CURRENCIES, N_BYTES> {
    /// Returns the leaves of the tree
    pub fn leaves(&self) -> &[Node<N_CURRENCIES>] {
        &self.nodes[0]
    }
    /// Returns the entries of the tree
    pub fn entries(&self) -> &[Entry<N_CURRENCIES>] {
        &self.entries
    }
    /// Builds a Merkle Sum Tree from a CSV file stored at `path`. The CSV file must be formatted as follows:
    ///
    /// `username,balance_<cryptocurrency>_<chain>,balance_<cryptocurrency>_<chain>,...`
    ///
    /// `dxGaEAii,11888,41163`
    pub fn from_csv(path: &str) -> Result<Self, Box<dyn std::error::Error>>
    where
        [usize; N_CURRENCIES + 1]: Sized,
        [usize; N_CURRENCIES + 2]: Sized,
    {
        let (cryptocurrencies, entries) =
            parse_csv_to_entries::<&str, N_CURRENCIES, N_BYTES>(path)?;
        Self::from_entries(entries, cryptocurrencies, false)
    }

    /// Builds a Merkle Sum Tree from a CSV file stored at `path`. The MST leaves are sorted by the username byte values. The CSV file must be formatted as follows:
    ///
    /// `username,balance_<cryptocurrency>_<chain>,balance_<cryptocurrency>_<chain>,...`
    ///
    /// `dxGaEAii,11888,41163`
    pub fn from_csv_sorted(path: &str) -> Result<Self, Box<dyn std::error::Error>>
    where
        [usize; N_CURRENCIES + 1]: Sized,
        [usize; N_CURRENCIES + 2]: Sized,
    {
        let (cryptocurrencies, mut entries) =
            parse_csv_to_entries::<&str, N_CURRENCIES, N_BYTES>(path)?;

        entries.sort_by(|a, b| a.username().cmp(b.username()));

        Self::from_entries(entries, cryptocurrencies, true)
    }

    /// Builds a Merkle Sum Tree from a vector of entries
    pub fn from_entries(
        mut entries: Vec<Entry<N_CURRENCIES>>,
        cryptocurrencies: Vec<Cryptocurrency>,
        is_sorted: bool,
    ) -> Result<MerkleSumTree<N_CURRENCIES, N_BYTES>, Box<dyn std::error::Error>>
    where
        [usize; N_CURRENCIES + 1]: Sized,
        [usize; N_CURRENCIES + 2]: Sized,
    {
        let depth = (entries.len() as f64).log2().ceil() as usize;

        // Pad the entries with empty entries to make the number of entries equal to 2^depth
        if entries.len() < 2usize.pow(depth as u32) {
            entries.extend(vec![
                Entry::init_empty();
                2usize.pow(depth as u32) - entries.len()
            ]);
        }

        let leaves = build_leaves_from_entries(&entries);

        let (root, nodes) = build_merkle_tree_from_leaves::<N_CURRENCIES, N_BYTES>(&leaves, depth)?;

        Ok(MerkleSumTree {
            root,
            nodes,
            depth,
            entries,
            cryptocurrencies,
            is_sorted,
        })
    }

    /// Builds a Merkle Sum Tree from a root node, a vector of nodes, a depth, a vector of entries, a vector of cryptocurrencies and a boolean indicating whether the leaves are sorted by the username byte values.
    pub fn from_params(
        root: Node<N_CURRENCIES>,
        nodes: Vec<Vec<Node<N_CURRENCIES>>>,
        depth: usize,
        entries: Vec<Entry<N_CURRENCIES>>,
        cryptocurrencies: Vec<Cryptocurrency>,
        is_sorted: bool,
    ) -> Result<Self, Box<dyn std::error::Error>>
    where
        [usize; N_CURRENCIES + 1]: Sized,
        [usize; N_CURRENCIES + 2]: Sized,
    {
        Ok(MerkleSumTree::<N_CURRENCIES, N_BYTES> {
            root,
            nodes,
            depth,
            entries,
            cryptocurrencies,
            is_sorted,
        })
    }

    /// Updates the balances of the entry with the given username and returns the new root of the tree.
    ///
    /// # Arguments
    ///
    /// * `username`: The username of the entry to update
    /// * `new_balances`: The new balances of the entry
    ///
    /// # Returns
    ///
    /// The new root of the tree
    pub fn update_leaf(
        &mut self,
        username: &str,
        new_balances: &[BigUint; N_CURRENCIES],
    ) -> Result<Node<N_CURRENCIES>, Box<dyn std::error::Error>>
    where
        [usize; N_CURRENCIES + 1]: Sized,
        [usize; N_CURRENCIES + 2]: Sized,
    {
        let index = self.index_of_username(username)?;

        // Update the leaf node.
        let updated_leaf = self.entries[index].recompute_leaf(new_balances);
        self.nodes[0][index] = updated_leaf;

        // Recompute the hashes and balances up the tree.
        let mut current_index = index;
        for depth in 1..=self.depth {
            let parent_index = current_index / 2;
            let left_child = &self.nodes[depth - 1][2 * parent_index];
            let right_child = &self.nodes[depth - 1][2 * parent_index + 1];

            let mut hash_preimage = [Fp::zero(); N_CURRENCIES + 2];
            for (i, balance) in hash_preimage.iter_mut().enumerate().take(N_CURRENCIES) {
                *balance = left_child.balances[i] + right_child.balances[i];
            }
            hash_preimage[N_CURRENCIES] = left_child.hash;
            hash_preimage[N_CURRENCIES + 1] = right_child.hash;

            self.nodes[depth][parent_index] = Node::middle_node_from_preimage(&hash_preimage);
            current_index = parent_index;
        }

        let root = self.nodes[self.depth][0].clone();
        Ok(root)
    }

    /// Returns the index of the leaf with the matching username
    pub fn index_of_username(&self, username: &str) -> Result<usize, Box<dyn std::error::Error>>
    where
        [usize; N_CURRENCIES + 1]: Sized,
    {
        if !self.is_sorted {
            self.entries
                .iter()
                .enumerate()
                .find(|(_, entry)| entry.username() == username)
                .map(|(index, _)| index)
                .ok_or_else(|| Box::from("Username not found"))
        } else {
            self.entries
                .binary_search_by_key(&username, |entry| entry.username())
                .map_err(|_| Box::from("Username not found"))
        }
    }
}
