use crate::merkle_sum_tree::{Entry, Node};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use rayon::prelude::*;

pub fn build_merkle_tree_from_leaves<const N_ASSETS: usize>(
    leaves: &[Node<N_ASSETS>],
    depth: usize,
    nodes: &mut Vec<Vec<Node<N_ASSETS>>>,
) -> Result<Node<N_ASSETS>, Box<dyn std::error::Error>>
where
    [usize; N_ASSETS + 1]: Sized,
    [usize; 2 * (1 + N_ASSETS)]: Sized,
{
    let n = leaves.len();

    let mut tree: Vec<Vec<Node<N_ASSETS>>> = Vec::with_capacity(depth + 1);

    tree.push(vec![
        Node {
            hash: Fp::from(0),
            balances: [Fp::from(0); N_ASSETS]
        };
        n
    ]);

    for _ in 1..=depth {
        let previous_level = tree.last().unwrap();
        let nodes_in_level = (previous_level.len() + 1) / 2;

        tree.push(vec![
            Node {
                hash: Fp::from(0),
                balances: [Fp::from(0); N_ASSETS]
            };
            nodes_in_level
        ]);
    }

    for (index, leaf) in leaves.iter().enumerate() {
        tree[0][index] = leaf.clone();
    }

    for level in 1..=depth {
        build_middle_level(level, &mut tree)
    }

    let root = tree[depth][0].clone();
    *nodes = tree;
    Ok(root)
}

pub fn build_leaves_from_entries<const N_ASSETS: usize>(
    entries: &[Entry<N_ASSETS>],
) -> Vec<Node<N_ASSETS>>
where
    [usize; N_ASSETS + 1]: Sized,
{
    let leaves = entries
        .par_iter()
        .map(|entry| entry.compute_leaf())
        .collect::<Vec<_>>();

    leaves
}

fn build_middle_level<const N_ASSETS: usize>(level: usize, tree: &mut [Vec<Node<N_ASSETS>>])
where
    [usize; 2 * (1 + N_ASSETS)]: Sized,
{
    let results: Vec<Node<N_ASSETS>> = (0..tree[level - 1].len())
        .into_par_iter()
        .step_by(2)
        .map(|index| Node::middle(&tree[level - 1][index], &tree[level - 1][index + 1]))
        .collect();

    for (index, new_node) in results.into_iter().enumerate() {
        tree[level][index] = new_node;
    }
}
