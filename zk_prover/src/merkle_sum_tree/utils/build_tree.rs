use crate::merkle_sum_tree::{utils::big_uint_to_fp, Entry, Node};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use num_bigint::BigInt;
use rayon::prelude::*;

pub fn build_merkle_tree_from_leaves<const N_CURRENCIES: usize, const N_BYTES: usize>(
    leaves: &[Node<N_CURRENCIES>],
    depth: usize,
) -> Result<(Node<N_CURRENCIES>, Vec<Vec<Node<N_CURRENCIES>>>), Box<dyn std::error::Error>>
where
    [usize; N_CURRENCIES + 1]: Sized,
    [usize; N_CURRENCIES + 2]: Sized,
{
    let mut tree: Vec<Vec<Node<N_CURRENCIES>>> = Vec::with_capacity(depth + 1);

    // the size of a leaf layer must be a power of 2
    // if not, the `leaves` Vec should be completed with "zero entries" until a power of 2
    assert_eq!(leaves.len(), 2usize.pow(depth as u32));

    tree.push(leaves.to_vec());

    // The allowed_max_root_balance should be safe if set to half of `calculate_max_root_balance`.
    // To achieve this, we use a depth one level lower here.
    let allowed_max_node_balance = big_uint_to_fp(
        &calculate_max_root_balance(N_BYTES, depth - 1)
            .to_biguint()
            .unwrap(),
    );
    let allowed_max_root_balance = big_uint_to_fp(
        &calculate_max_root_balance(N_BYTES, depth)
            .to_biguint()
            .unwrap(),
    );

    for level in 1..=depth {
        // Determine the maximum node balance based on the current level
        let max_node_balance = if level == depth {
            allowed_max_root_balance
        } else {
            allowed_max_node_balance
        };

        build_middle_level::<N_CURRENCIES, N_BYTES>(level, &mut tree, max_node_balance)
    }

    let root = tree[depth][0].clone();
    Ok((root, tree))
}

pub fn build_leaves_from_entries<const N_CURRENCIES: usize>(
    entries: &[Entry<N_CURRENCIES>],
) -> Vec<Node<N_CURRENCIES>>
where
    [usize; N_CURRENCIES + 1]: Sized,
{
    // Precompute the zero leaf (this will only be used if we encounter a zero entry)
    let zero_leaf = Entry::<N_CURRENCIES>::init_empty().compute_leaf();

    let leaves = entries
        .par_iter()
        .map(|entry| {
            // If the entry is the zero entry then we return the precomputed zero leaf
            // Otherwise, we compute the leaf as usual
            if entry == &Entry::<N_CURRENCIES>::init_empty() {
                zero_leaf.clone()
            } else {
                entry.compute_leaf()
            }
        })
        .collect::<Vec<_>>();

    leaves
}

fn build_middle_level<const N_CURRENCIES: usize, const N_BYTES: usize>(
    level: usize,
    tree: &mut Vec<Vec<Node<N_CURRENCIES>>>,
    max_node_balance: Fp,
) where
    [usize; N_CURRENCIES + 2]: Sized,
{
    let results: Vec<Node<N_CURRENCIES>> = (0..tree[level - 1].len())
        .into_par_iter()
        .step_by(2)
        .map(|index| {
            let mut hash_preimage = [Fp::zero(); N_CURRENCIES + 2];

            for (i, balance) in hash_preimage.iter_mut().enumerate().take(N_CURRENCIES) {
                *balance =
                    tree[level - 1][index].balances[i] + tree[level - 1][index + 1].balances[i];

                // This conditional is for the test case `test_balance_not_in_range` that performs exceed case while generating proof
                if !cfg!(feature = "skip-node-balance-check") {
                    assert!(
                        balance.to_owned() <= max_node_balance,
                        "{}",
                        format!("Node balance is exceed limit: {:#?}", max_node_balance),
                    );
                }
            }

            hash_preimage[N_CURRENCIES] = tree[level - 1][index].hash;
            hash_preimage[N_CURRENCIES + 1] = tree[level - 1][index + 1].hash;
            Node::middle_node_from_preimage(&hash_preimage)
        })
        .collect();

    tree.push(results);
}

// Calculate the maximum value that the Merkle Root can have, given N_BYTES and LEVELS
pub fn calculate_max_root_balance(n_bytes: usize, n_levels: usize) -> BigInt {
    // The max value that can be stored in a leaf node or a sibling node, according to the constraint set in the circuit
    let max_leaf_value = BigInt::from(2).pow(n_bytes as u32 * 8) - 1;
    max_leaf_value * (n_levels + 1)
}
