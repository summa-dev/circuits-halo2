mod entry;
mod mst;
mod params;
mod tests;
mod utils;
use halo2_proofs::halo2curves::bn256::Fr as Fp;

pub use params::MST_WIDTH;
pub use params::N_ASSETS;
pub use params::R_L_ENTRY;
pub use params::R_L_NODE;
pub use params::WIDTH_ENTRY;
pub use params::WIDTH_NODE;

#[derive(Clone, Debug)]
pub struct MerkleProof<const N_ASSETS: usize> {
    pub root_hash: Fp,
    pub entry: Entry<N_ASSETS>,
    pub sibling_hashes: Vec<Fp>,
    pub sibling_sums: Vec<[Fp; N_ASSETS]>,
    pub path_indices: Vec<Fp>,
}

#[derive(Clone, Debug)]
pub struct Node<const N_ASSETS: usize> {
    pub hash: Fp,
    pub balances: [Fp; N_ASSETS],
}

pub use entry::Entry;
pub use mst::MerkleSumTree;
pub use utils::{big_int_to_fp, big_intify_username};
