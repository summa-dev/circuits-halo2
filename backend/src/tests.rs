use std::{sync::Arc, time::Duration};

use ethers::{
    abi::Token,
    prelude::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    types::{H160, U256},
    utils::{Anvil, AnvilInstance},
};
use tokio::time;

use crate::contracts::generated::{inclusion_verifier::InclusionVerifier, summa_contract::Summa};

// Setup test environment on the anvil instance
pub async fn initialize_test_env(
    block_time: Option<u64>,
) -> (
    AnvilInstance,
    H160,
    H160,
    Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
    Summa<SignerMiddleware<Provider<Http>, LocalWallet>>,
) {
    // Initiate anvil by following assign block time or instant mining
    let anvil = match block_time {
        Some(interval) => Anvil::new()
            .mnemonic("test test test test test test test test test test test junk")
            .block_time(interval)
            .spawn(),
        None => Anvil::new()
            .mnemonic("test test test test test test test test test test test junk")
            .spawn(),
    };

    // Extracting two exchange addresses from the Anvil instance
    let cex_addr_1 = anvil.addresses()[1];
    let cex_addr_2 = anvil.addresses()[2];

    // Setup wallet from the first key in the Anvil and an HTTP provider with a 10ms interval from the Anvil endpoint
    let wallet: LocalWallet = anvil.keys()[0].clone().into();
    let provider = Provider::<Http>::try_from(anvil.endpoint())
        .unwrap()
        .interval(Duration::from_millis(10u64));

    // Creating a client by wrapping the provider with a signing middleware and the Anvil chainid
    let client = Arc::new(SignerMiddleware::new(
        provider,
        wallet.with_chain_id(anvil.chain_id()),
    ));

    // Send RPC requests with `anvil_setBalance` method via provider to set ETH balance of `cex_addr_1` and `cex_addr_2`
    for addr in [cex_addr_1, cex_addr_2].iter().copied() {
        let _res = client
            .provider()
            .request::<(H160, U256), ()>("anvil_setBalance", (addr, U256::from(278432)))
            .await;
    }

    if block_time.is_some() {
        time::sleep(Duration::from_secs(block_time.unwrap())).await;
    };

    let inclusion_verifier_contract = InclusionVerifier::deploy(Arc::clone(&client), ())
        .unwrap()
        .send()
        .await
        .unwrap();

    if block_time.is_some() {
        time::sleep(Duration::from_secs(block_time.unwrap())).await;
    };

    //The number of cryptocurrencies supported by the Merkle sum tree
    let currencies_count = 2;
    // The number of bytes used to represent the balance of a cryptocurrency in the Merkle sum tree
    let balance_byte_range = 14;

    let args: &[Token] = &[
        Token::Address(inclusion_verifier_contract.address()),
        Token::Address(inclusion_verifier_contract.address()),
        Token::Uint(currencies_count.into()),
        Token::Uint(balance_byte_range.into()),
    ];
    // Deploy Summa contract
    let summa_contract = Summa::deploy(Arc::clone(&client), args)
        .unwrap()
        .send()
        .await
        .unwrap();

    time::sleep(Duration::from_secs(3)).await;

    (anvil, cex_addr_1, cex_addr_2, client, summa_contract)
}

#[cfg(test)]
mod test {
    use ethers::{
        abi::AbiEncode,
        providers::{Http, Middleware, Provider},
        types::U64,
        utils::to_checksum,
    };
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    use rand::{rngs::OsRng, Rng};
    use std::{convert::TryFrom, error::Error};
    use tokio::{
        join,
        time::{sleep, Duration},
    };

    use crate::apis::{address_ownership::AddressOwnership, round::Round};
    use crate::contracts::{
        generated::summa_contract::{AddressOwnershipProof, AddressOwnershipProofSubmittedFilter},
        signer::{AddressInput, SummaSigner},
    };
    use crate::tests::initialize_test_env;
    use summa_solvency::{
        circuits::{
            univariate_grand_sum::UnivariateGrandSum,
            utils::{full_prover, generate_setup_artifacts},
        },
        cryptocurrency::Cryptocurrency,
        entry::Entry,
        utils::parse_csv_to_entries,
    };

    const K: u32 = 17;
    const N_CURRENCIES: usize = 2;
    const N_POINTS: usize = 3;
    const N_USERS: usize = 16;

    #[tokio::test]
    async fn test_deployed_address() -> Result<(), Box<dyn Error>> {
        let (anvil, _, _, _, summa_contract) = initialize_test_env(None).await;

        // Hardhat development environment, usually updates the address of a deployed contract in the `artifacts` directory.
        // However, in our custom deployment script, `contracts/scripts/deploy.ts`,
        // the address gets updated in `backend/src/contracts/deployments.json`.
        let contract_address = summa_contract.address();

        let signer = SummaSigner::new(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            anvil.endpoint().as_str(),
            AddressInput::Path("./src/contracts/deployments.json".into()), // the file contains the address of the deployed contract
        )
        .await?;

        assert_eq!(contract_address, signer.get_summa_address());

        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_sumbit_commitments() -> Result<(), Box<dyn Error>> {
        let (anvil, _, _, _, summa_contract) = initialize_test_env(Some(1)).await;

        // This test ensures that two proofs, when dispatched concurrently, do not result in nonce collisions.
        // It checks that both proofs are processed and mined within a reasonable timeframe,
        // indicating that there's no interference or delay when the two are submitted simultaneously.
        let signer = SummaSigner::new(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            anvil.endpoint().as_str(),
            AddressInput::Address(summa_contract.address()),
        )
        .await?;

        let params_path = "ptau/hermez-raw-17";
        let entry_csv = "../csv/entry_16.csv";
        let mut entries: Vec<Entry<N_CURRENCIES>> = vec![Entry::init_empty(); N_USERS];
        let mut cryptos = vec![Cryptocurrency::init_empty(); N_CURRENCIES];
        parse_csv_to_entries::<&str, N_CURRENCIES>(entry_csv, &mut entries, &mut cryptos).unwrap();

        let univariate_grand_sum_circuit =
            UnivariateGrandSum::<N_USERS, N_CURRENCIES>::init(entries.to_vec());

        let (params, pk, vk) =
            generate_setup_artifacts(K, None, &univariate_grand_sum_circuit).unwrap();

        // Create a proof
        let instances = vec![Fp::one(); 1]; // This instance is necessary to verify proof on solidity verifier.
        let (zk_snark_proof, advice_polys, _omega) = full_prover(
            &params,
            &pk,
            univariate_grand_sum_circuit.clone(),
            &[instances.clone()],
        );

        let mut round_one =
            Round::<2, 3, 16>::new(&signer, advice_polys.clone(), params.clone(), vk.clone(), 1)
                .unwrap();
        let mut round_two = Round::<2, 3, 16>::new(&signer, advice_polys, params, vk, 2).unwrap();

        // Checking block number before sending transaction of liability commitment
        let outer_provider: Provider<Http> = Provider::try_from(anvil.endpoint().as_str())?;
        let start_block_number = outer_provider.get_block_number().await?;

        // Send two commitments simultaneously
        let (round_one_result, round_two_result) = join!(
            round_one.dispatch_commitment(),
            round_two.dispatch_commitment()
        );

        // Check two blocks has been mined
        for _ in 0..5 {
            sleep(Duration::from_millis(500)).await;
            let updated_block_number = outer_provider.get_block_number().await?;
            if (updated_block_number - start_block_number) > U64::from(2) {
                break;
            }
        }

        // Check two rounds' result are both Ok
        assert!(round_one_result.is_ok());
        assert!(round_two_result.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn test_round_features() -> Result<(), Box<dyn Error>> {
        let (anvil, cex_addr_1, cex_addr_2, _, summa_contract) = initialize_test_env(None).await;

        let signer = SummaSigner::new(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            anvil.endpoint().as_str(),
            AddressInput::Address(summa_contract.address()),
        )
        .await?;

        let mut address_ownership_client =
            AddressOwnership::new(&signer, "../csv/signatures.csv").unwrap();

        address_ownership_client
            .dispatch_proof_of_address_ownership()
            .await?;

        let ownership_proof_logs = summa_contract
            .address_ownership_proof_submitted_filter()
            .query()
            .await?;

        assert_eq!(ownership_proof_logs.len(), 1);
        assert_eq!(
        ownership_proof_logs[0],
        AddressOwnershipProofSubmittedFilter {
                address_ownership_proofs: vec![AddressOwnershipProof {
        chain: "ETH".to_string(),
        cex_address: to_checksum(&cex_addr_1, None),
        signature:
            ("0x089b32327d332c295dc3b8873c205b72153211de6dc1c51235782b091cefb9d06d6df2661b86a7d441cd322f125b84901486b150e684221a7b7636eb8182af551b").parse().unwrap(),
            message:  "Summa proof of solvency for CryptoExchange".encode().into(),
        },AddressOwnershipProof {
        chain: "ETH".to_string(),
        cex_address:to_checksum(&cex_addr_2, None),
        signature:
            ("0xb17a9e25265d3b88de7bfad81e7accad6e3d5612308ff83cc0fef76a34152b0444309e8fc3dea5139e49b6fc83a8553071a7af3d0cfd3fb8c1aea2a4c171729c1c").parse().unwrap(),
            message:  "Summa proof of solvency for CryptoExchange".encode().into(),
        },
                ],
            }
        );

        // Initialize round
        let params_path = "ptau/hermez-raw-17";
        let entry_csv = "../csv/entry_16.csv";
        let mut entries: Vec<Entry<N_CURRENCIES>> = vec![Entry::init_empty(); N_USERS];
        let mut cryptos = vec![Cryptocurrency::init_empty(); N_CURRENCIES];
        parse_csv_to_entries::<&str, N_CURRENCIES>(entry_csv, &mut entries, &mut cryptos).unwrap();

        let univariate_grand_sum_circuit =
            UnivariateGrandSum::<N_USERS, N_CURRENCIES>::init(entries.to_vec());

        let (params, pk, vk) =
            generate_setup_artifacts(K, None, &univariate_grand_sum_circuit).unwrap();

        // Create a proof
        let instances = vec![Fp::one(); 1]; // This instance is necessary to verify proof on solidity verifier.
        let (zk_snark_proof, advice_polys, _omega) = full_prover(
            &params,
            &pk,
            univariate_grand_sum_circuit.clone(),
            &[instances.clone()],
        );

        let mut round =
            Round::<N_CURRENCIES, N_POINTS, N_USERS>::new(&signer, advice_polys, params, vk, 1)
                .unwrap();

        // TODO: fix checking inclusion proof after Summa contract is concrete
        // let mut liability_commitment_logs = summa_contract
        //     .liabilities_commitment_submitted_filter()
        //     .query()
        //     .await?;

        // assert_eq!(liability_commitment_logs.len(), 0);

        // // Send liability commitment transaction
        // round.dispatch_commitment().await?;

        // // After sending transaction of liability commitment, logs should be updated
        // liability_commitment_logs = summa_contract
        //     .liabilities_commitment_submitted_filter()
        //     .query()
        //     .await?;

        // assert_eq!(liability_commitment_logs.len(), 1);
        // assert_eq!(
        //     liability_commitment_logs[0],
        //     LiabilitiesCommitmentSubmittedFilter {
        //         timestamp: U256::from(1),
        //         mst_root: "0x18d6ab953235a811edffa4cead74ea045e7cd2085771a2269d59dca054c955b1"
        //             .parse()
        //             .unwrap(),
        //         root_balances: vec![U256::from(556862), U256::from(556862)],
        //         cryptocurrencies: vec![
        //             Cryptocurrency {
        //                 name: "ETH".to_string(),
        //                 chain: "ETH".to_string(),
        //             },
        //             Cryptocurrency {
        //                 name: "USDT".to_string(),
        //                 chain: "ETH".to_string(),
        //             },
        //         ],
        //     }
        // );

        // Test inclusion proof
        let user_range: std::ops::Range<usize> = 0..N_USERS;
        let random_user_index = OsRng.gen_range(user_range) as usize;
        let inclusion_proof = round.get_proof_of_inclusion(random_user_index).unwrap();

        // check inclusion proof is not non
        assert!(inclusion_proof.get_proof().len() > 0);

        // TODO: fix this after Summa contract is concrete
        // // Verify inclusion proof with onchain function
        // let verified = summa_contract
        //     .verify_inclusion_proof(
        //         inclusion_proof.get_proof().clone(),
        //         inclusion_proof.get_public_inputs().clone(),
        //         U256::from(1),
        //     )
        //     .await?;

        // assert!(verified);

        drop(anvil);
        Ok(())
    }
}
