use num_bigint::BigInt;
use std::collections::HashMap;

use halo2_proofs::{
    halo2curves::bn256::Fr as Fp,
    plonk::{keygen_pk, keygen_vk},
};
use snark_verifier_sdk::CircuitExt;

use summa_solvency::{
    circuits::{
        merkle_sum_tree::MstInclusionCircuit,
        solvency::SolvencyCircuit,
        utils::{full_prover, generate_setup_params},
    },
    merkle_sum_tree::{Entry, MerkleSumTree},
};

use crate::apis::csv_parser::parse_csv_to_assets;

#[derive(Debug)]
struct SnapshotData<
    const LEVELS: usize,
    const L: usize,
    const N_ASSETS: usize,
    const N_BYTES: usize,
    const K: u32,
> {
    exchange_id: String,
    commit_hash: Fp,
    entries: HashMap<usize, Entry<N_ASSETS>>,
    assets: Vec<Asset>,
    user_proofs: HashMap<u64, InclusionProof>,
    on_chain_proof: Option<SolvencyProof<N_ASSETS>>,
}

#[derive(Debug, Clone)]
pub struct Asset {
    pub name: String,
    pub pubkeys: Vec<String>,
    pub balances: Vec<BigInt>,
    pub sum_balances: Fp,
    pub signature: Vec<String>,
}

#[derive(Debug, Clone)]
struct InclusionProof {
    // public input
    leaf_hash: Fp,
    vk: Vec<u8>,
    proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
struct SolvencyProof<const N_ASSETS: usize> {
    // public inputs
    penultimate_node_hash: [Fp; 2],
    assets_sum: [Fp; N_ASSETS],
    vk: Vec<u8>,
    proof: Vec<u8>,
}

impl<
        const LEVELS: usize,
        const L: usize,
        const N_ASSETS: usize,
        const N_BYTES: usize,
        const K: u32,
    > SnapshotData<LEVELS, L, N_ASSETS, N_BYTES, K>
{
    pub fn new(
        exchange_id: &str,
        entry_csv: &str,
        asset_csv: &str,
    ) -> Result<SnapshotData<LEVELS, L, N_ASSETS, N_BYTES, K>, Box<dyn std::error::Error>> {
        let assets = parse_csv_to_assets(asset_csv).unwrap();
        let mst = MerkleSumTree::<N_ASSETS>::new(entry_csv).unwrap();

        let entries = mst
            .entries()
            .into_iter()
            .enumerate()
            .map(|(i, entry)| (i, entry.clone()))
            .collect::<HashMap<usize, Entry<N_ASSETS>>>();

        let root_node = mst.root();
        let user_proofs = HashMap::<u64, InclusionProof>::new();

        Ok(SnapshotData {
            exchange_id: exchange_id.to_owned(),
            commit_hash: root_node.hash,
            entries,
            assets,
            user_proofs,
            on_chain_proof: None,
        })
    }

    fn generate_inclusion_proof(
        entry_csv: &str,
        user_index: usize,
    ) -> Result<InclusionProof, &'static str> {
        let circuit = MstInclusionCircuit::<LEVELS, L, N_ASSETS>::init_empty();
        let params = generate_setup_params(K);

        let vk = keygen_vk(&params, &circuit).expect("vk generation should not fail");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk generation should not fail");

        // Only now we can instantiate the circuit with the actual inputs
        let circuit = MstInclusionCircuit::<LEVELS, L, N_ASSETS>::init(entry_csv, user_index);
        let instances = circuit.instances().clone();
        let proof = full_prover(&params, &pk, circuit.clone(), instances.clone());

        Ok(InclusionProof {
            leaf_hash: instances[0][0],
            vk: vk.to_bytes(halo2_proofs::SerdeFormat::RawBytes),
            proof,
        })
    }

    pub fn generate_solvency_proof(&mut self, entry_csv: &str) -> Result<(), &'static str> {
        // Prepare public inputs for solvency
        let mut assets_sum = [Fp::from(0u64); N_ASSETS];
        let asset_names = self
            .assets
            .iter()
            .map(|asset| asset.name.clone())
            .collect::<Vec<String>>();

        for asset in &self.assets {
            let index = asset_names.iter().position(|x| *x == asset.name).unwrap();
            assets_sum[index] = asset.sum_balances;
        }

        // generate solvency proof
        let circuit = SolvencyCircuit::<L, N_ASSETS, N_BYTES>::init_empty();
        let params = generate_setup_params(K);

        let vk = keygen_vk(&params, &circuit).expect("vk generation should not fail");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk generation should not fail");

        let circuit = SolvencyCircuit::<L, N_ASSETS, N_BYTES>::init(entry_csv, assets_sum);
        let instances = circuit.instances();

        self.on_chain_proof = Some(SolvencyProof::<N_ASSETS> {
            penultimate_node_hash: [instances[0][0], instances[0][1]],
            assets_sum,
            vk: vk.to_bytes(halo2_proofs::SerdeFormat::RawBytes),
            proof: full_prover(&params, &pk, circuit.clone(), instances),
        });

        Ok(())
    }

    pub fn get_user_proof(&mut self, user_index: u64) -> Result<InclusionProof, &'static str> {
        let user_proof = self.user_proofs.get(&user_index);
        match user_proof {
            Some(proof) => Ok(proof.clone()),
            None => {
                let user_proof = Self::generate_inclusion_proof(
                    "src/apis/csv/entry_16.csv",
                    user_index as usize,
                )
                .unwrap();
                self.user_proofs.insert(user_index, user_proof.clone());
                Ok(user_proof)
            }
        }
    }

    pub fn get_onchain_proof(&self) -> Result<SolvencyProof<N_ASSETS>, &'static str> {
        match &self.on_chain_proof {
            Some(proof) => Ok(proof.clone()),
            None => Err("on-chain proof not initialized"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const N_ASSETS: usize = 2;
    const L: usize = 2 + (N_ASSETS * 2);
    const LEVELS: usize = 4;
    const N_BYTES: usize = 31;
    const K: u32 = 11;

    #[test]
    fn test_snapshot_data_initialization() {
        let entry_csv = "src/apis/csv/entry_16.csv";
        let asset_csv = "src/apis/csv/assets_2.csv";
        let snapshot_data =
            SnapshotData::<LEVELS, L, N_ASSETS, N_BYTES, K>::new("CEX_1", entry_csv, asset_csv)
                .unwrap();

        // Check assets
        assert!(snapshot_data.assets[0].name.contains(&"eth".to_string()));
        assert!(snapshot_data.assets[1].name.contains(&"dai".to_string()));
        assert!(snapshot_data.assets[0].balances[0] == BigInt::from(1500u32));
        assert!(snapshot_data.assets[0].balances[1] == BigInt::from(2500u32));
    }

    #[test]
    fn test_snapshot_data_generate_solvency_proof() {
        let entry_csv = "src/apis/csv/entry_16.csv";
        let asset_csv = "src/apis/csv/assets_2.csv";
        let mut snapshot_data =
            SnapshotData::<LEVELS, L, N_ASSETS, N_BYTES, K>::new("CEX_1", entry_csv, asset_csv)
                .unwrap();

        assert!(snapshot_data.on_chain_proof.is_none());
        let empty_on_chain_proof = snapshot_data.get_onchain_proof();
        assert_eq!(empty_on_chain_proof, Err("on-chain proof not initialized"));

        let result = snapshot_data.generate_solvency_proof(entry_csv);
        assert_eq!(result.is_ok(), true);

        // Check updated on-chain proof
        let on_chain_proof = snapshot_data.get_onchain_proof();
        assert_eq!(on_chain_proof.is_ok(), true);
    }

    #[test]
    fn test_snapshot_data_generate_inclusion_proof() {
        let entry_csv = "src/apis/csv/entry_16.csv";
        let asset_csv = "src/apis/csv/assets_2.csv";
        let mut snapshot_data =
            SnapshotData::<LEVELS, L, N_ASSETS, N_BYTES, K>::new("CEX_1", entry_csv, asset_csv)
                .unwrap();

        assert_eq!(snapshot_data.user_proofs.len(), 0);

        // Check updated on-chain proof
        let user_proof = snapshot_data.get_user_proof(0);
        assert!(user_proof.is_ok());
        assert_eq!(snapshot_data.user_proofs.len(), 1);
    }
}
