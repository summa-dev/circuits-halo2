use crate::merkle_sum_tree::Node;
use ethers::utils::keccak256;
use num_bigint::BigUint;

/// An entry in the Merkle Sum Tree from the database of the CEX.
/// It contains the username and the balances of the user.
#[derive(Clone, Debug, std::cmp::PartialEq)]
pub struct Entry<const N_CURRENCIES: usize> {
    hashed_username: BigUint,
    balances: [BigUint; N_CURRENCIES],
    username: String,
}

impl<const N_CURRENCIES: usize> Entry<N_CURRENCIES> {
    pub fn new(username: String, balances: [BigUint; N_CURRENCIES]) -> Self {
        // Security Assumptions:
        // Using `keccak256` for `hashed_username` ensures high collision resistance,
        // appropriate for the assumed userbase of $2^{30}$.
        // The `hashed_username` utilizes the full 256 bits produced by `keccak256`,
        // but is adjusted to the field size through the Poseidon hash function's modulo operation.
        let hashed_username: BigUint = BigUint::from_bytes_be(&keccak256(username.as_bytes()));
        Entry {
            hashed_username,
            balances,
            username,
        }
    }

    /// Returns a zero entry where the username is 0 and the balances are all 0
    pub fn init_empty() -> Self {
        let empty_balances: [BigUint; N_CURRENCIES] = std::array::from_fn(|_| BigUint::from(0u32));

        Entry {
            hashed_username: BigUint::from(0u32),
            balances: empty_balances,
            username: "0".to_string(),
        }
    }

    pub fn compute_leaf(&self) -> Node<N_CURRENCIES>
    where
        [usize; N_CURRENCIES + 1]: Sized,
    {
        Node::leaf(&self.hashed_username, &self.balances)
    }

    /// Stores the new balance values
    ///
    /// Returns the updated node
    pub fn recompute_leaf(
        &mut self,
        updated_balances: &[BigUint; N_CURRENCIES],
    ) -> Node<N_CURRENCIES>
    where
        [usize; N_CURRENCIES + 1]: Sized,
    {
        self.balances = updated_balances.clone();
        Node::leaf(&self.hashed_username, updated_balances)
    }

    pub fn balances(&self) -> &[BigUint; N_CURRENCIES] {
        &self.balances
    }

    pub fn username_as_big_uint(&self) -> &BigUint {
        &self.hashed_username
    }

    pub fn username(&self) -> &str {
        &self.username
    }
}
