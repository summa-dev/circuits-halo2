use std::{fs::File, ops::Range};

use ark_std::{end_timer, start_timer};
use ethers::types::U256;
use halo2_proofs::{
    arithmetic::{eval_polynomial, Field},
    halo2curves::{
        bn256::{Bn256, Fr as Fp, G1Affine},
        ff::{PrimeField, WithSmallOrderMulGroup},
    },
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, AdviceSingle, Circuit, Error, ProvingKey,
        VerifyingKey,
    },
    poly::{
        commitment::{Blind, CommitmentScheme, Params, ParamsProver, Prover, Verifier},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::{AccumulatorStrategy, SingleStrategy},
        },
        Coeff, Polynomial, ProverQuery, VerificationStrategy, VerifierQuery,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, EncodedChallenge, TranscriptRead,
        TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use num_bigint::BigUint;
use rand::rngs::OsRng;

use crate::utils::fp_to_big_uint;

/// Generate setup artifacts for a circuit of size `k`, where 2^k represents the number of rows in the circuit.
///
/// If the trusted setup parameters are not found, the function performs an unsafe trusted setup to generate the necessary parameters
/// If the provided `k` value is larger than the `k` value of the loaded parameters, an error is returned, as the provided `k` is too large.
/// Otherwise, if the `k` value is smaller than the `k` value of the loaded parameters, the parameters are downsized to fit the requested `k`.
pub fn generate_setup_artifacts<C: Circuit<Fp>>(
    k: u32,
    params_path: Option<&str>,
    circuit: &C,
) -> Result<
    (
        ParamsKZG<Bn256>,
        ProvingKey<G1Affine>,
        VerifyingKey<G1Affine>,
    ),
    &'static str,
> {
    let mut params: ParamsKZG<Bn256>;

    match params_path {
        Some(path) => {
            let timer = start_timer!(|| "Creating params");
            let mut params_fs = File::open(path).expect("couldn't load params");
            params = ParamsKZG::<Bn256>::read(&mut params_fs).expect("Failed to read params");
            end_timer!(timer);

            if params.k() < k {
                return Err("k is too large for the given params");
            }

            if params.k() > k {
                let timer = start_timer!(|| "Downsizing params");
                params.downsize(k);
                end_timer!(timer);
            }
        }
        None => {
            let timer = start_timer!(|| "None Creating params");
            params = ParamsKZG::<Bn256>::setup(k, OsRng);
            end_timer!(timer);
        }
    }

    let vk = keygen_vk(&params, circuit).expect("vk generation should not fail");
    let pk = keygen_pk(&params, vk.clone(), circuit).expect("pk generation should not fail");

    Ok((params, pk, vk))
}

/// Generates a proof given the public setup, the proving key, the initialized circuit and its public inputs.
pub fn full_prover<C: Circuit<Fp>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    public_inputs: &[Vec<Fp>],
) -> (
    Vec<u8>,
    AdviceSingle<halo2_proofs::halo2curves::bn256::G1Affine, Coeff>,
    Fp,
) {
    #[cfg(feature = "profiling")]
    let pf_time = start_timer!(|| "Creating proof");

    let instance: Vec<&[Fp]> = public_inputs.iter().map(|input| &input[..]).collect();
    let instances = &[&instance[..]];

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    let result = create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        _,
    >(params, pk, &[circuit], instances, OsRng, &mut transcript);
    let result_unwrapped = result.unwrap();
    result_unwrapped.0.expect("prover should not fail");
    let advice_polys = result_unwrapped.1.clone();
    let proof = transcript.finalize();

    #[cfg(feature = "profiling")]
    end_timer!(pf_time);
    let advice_polys = advice_polys[0].clone();

    let omega = pk.get_vk().get_domain().get_omega();

    (proof, advice_polys, omega)
}

/// Creates the univariate polynomial grand sum openings.
/// The polynomials are evaluated at X = 0 to obtain their constant term.
///
/// * `N_CURRENCIES` - the number of cryptocurrency balances
///
/// # Arguments
///
/// * `advice_polys` - the advice polynomials
/// * `advice_blinds` - the advice polynomials blinds
/// * `params` - the KZG parameters
/// * `balance_column_range` - the range of the balance columns used to calculate the grand sums
///
/// # Returns
///
/// * `Vec<u8>` - the KZG batch proof containing the quotient polynomial commitments
/// and the evaluations of the polynomials at X = 0
pub fn open_grand_sums<const N_CURRENCIES: usize>(
    advice_polys: &[Polynomial<Fp, Coeff>],
    advice_blinds: &[Blind<Fp>],
    params: &ParamsKZG<Bn256>,
    balance_column_range: Range<usize>,
) -> Vec<u8> {
    let challenge = Fp::zero();
    create_opening_proof_at_challenge::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
    >(
        params,
        &advice_polys[balance_column_range],
        advice_blinds,
        challenge,
    )
}

/// Creates a KZG batch proof for the `advice_polys` polynomial openings
/// at a point corresponding to the `user_index`
///
/// * `N_CURRENCIES` - the number of cryptocurrency balances
///
/// # Arguments
///
/// * `advice_polys` - the advice polynomials
/// * `advice_blinds` - the advice polynomials blinds
/// * `params` - the KZG parameters
/// * `column_range` - the advice column range to be used for the proof
/// * `omega` - $\omega$, the generator of the $2^k$ order multiplicative subgroup used to interpolate the polynomials.
/// * `user_index` - the index of the user whose entry is being proven
///
/// # Returns
///
/// * `Vec<u8>` - the KZG batch proof containing the quotient polynomial commitments
/// and the evaluations of the polynomials at the point corresponding to the `user_index`
pub fn open_user_points<const N_CURRENCIES: usize>(
    advice_polys: &[Polynomial<Fp, Coeff>],
    advice_blinds: &[Blind<Fp>],
    params: &ParamsKZG<Bn256>,
    column_range: Range<usize>,
    omega: Fp,
    user_index: u16,
) -> Vec<u8> {
    let omega_raised = omega.pow_vartime([u64::from(user_index)]);
    create_opening_proof_at_challenge::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
    >(
        params,
        &advice_polys[column_range],
        advice_blinds,
        omega_raised,
    )
}

/// Verifies the univariate polynomial grand sum openings
/// and calculates the grand sums
///
/// * `N_CURRENCIES` - the number of cryptocurrency balances
///
/// # Arguments
///
/// * `params` - the KZG parameters
/// * `zk_snark_proof` - the ZK-SNARK proof of the circuit whose advice columns contain the user balance polynomials
/// * `grand_sum_opening_batch_proof` - the KZG batch proof of the grand sum polynomials
/// * `polynomial_length` - the length of the polynomials
/// * `balance_column_range` - the range of the advice columns that represent user balances
///
/// # Returns
///
/// * `bool` - whether the grand sum openings are verified correctly
/// * `Vec<BigUint>` - the grand sums
pub fn verify_grand_sum_openings<const N_CURRENCIES: usize>(
    params: &ParamsKZG<Bn256>,
    zk_snark_proof: &[u8],
    grand_sum_opening_batch_proof: &[u8],
    polynomial_length: u64,
    balance_column_range: Range<usize>,
) -> (bool, Vec<BigUint>) {
    let mut transcript: Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>> =
        Blake2bRead::<_, _, Challenge255<_>>::init(zk_snark_proof);

    //Read the commitment points for all the advice polynomials from the proof transcript and put them into a vector
    let mut advice_commitments = Vec::new();
    for i in 0..N_CURRENCIES + balance_column_range.start {
        let point = transcript.read_point().unwrap();
        // Skip the advice commitments before the desired range
        if i >= balance_column_range.start {
            advice_commitments.push(point);
        }
    }

    let (verified, constant_terms) = verify_opening::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<_, _, Challenge255<_>>,
        AccumulatorStrategy<_>,
        N_CURRENCIES,
    >(
        params,
        grand_sum_opening_batch_proof,
        Fp::zero(),
        &advice_commitments,
    );

    (
        verified,
        constant_terms
            .iter()
            .map(|eval| fp_to_big_uint(eval * Fp::from(polynomial_length)))
            .collect(),
    )
}

/// Verifies the KZG batch proof of the polynomial openings being the evaluations
/// of the advice polynomials at the point corresponding to the user index
///
/// * `N_POINTS` - the size of the user entry being verified (e.g., 1 ID value + 4 balance values = 5)
///
/// # Arguments
/// * `params` - the KZG parameters
/// * `zk_snark_proof` - the ZK-SNARK proof of the circuit whose advice columns contain the user entry polynomials
/// * `balance_opening_batch_proof` - the KZG batch proof of the user entry polynomials
/// * `column_range` - the range of the advice columns that represent user entry
/// * `omega` - $\omega$, the generator of the $2^k$ order multiplicative subgroup used to interpolate the polynomials.
/// * `user_index` - the index of the user whose entry is being proven
///
/// # Returns
/// * `bool` - whether the user entry openings are verified correctly
/// * `Vec<BigUint>` - the evaluations of the advice polynomials at the point corresponding to the user index
pub fn verify_user_inclusion<const N_POINTS: usize>(
    params: &ParamsKZG<Bn256>,
    zk_snark_proof: &[u8],
    balance_opening_batch_proof: &[u8],
    column_range: Range<usize>,
    omega: Fp,
    user_index: u16,
) -> (bool, Vec<BigUint>) {
    let mut transcript: Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>> =
        Blake2bRead::<_, _, Challenge255<_>>::init(zk_snark_proof);

    //Read the commitment points for all the  advice polynomials from the proof transcript and put them into a vector
    let mut advice_commitments = Vec::new();
    for i in 0..column_range.end {
        let point = transcript.read_point().unwrap();
        //Skip advice polynomial commitments before the desired range
        if i >= column_range.start {
            advice_commitments.push(point);
        }
    }

    let mut verification_results = Vec::<bool>::new();

    let (verified, evaluations_at_challenge) = verify_opening::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<_, _, Challenge255<_>>,
        AccumulatorStrategy<_>,
        N_POINTS,
    >(
        params,
        balance_opening_batch_proof,
        omega.pow_vartime([user_index as u64]),
        &advice_commitments,
    );
    verification_results.push(verified);

    (
        verified,
        evaluations_at_challenge
            .iter()
            .map(|eval| fp_to_big_uint(*eval))
            .collect(),
    )
}

/// Creates a KZG batch proof for the polynomial evaluations at a challenge
///
/// # Arguments
///
/// * `params` - the KZG parameters
/// * `polynomials` - the polynomials to be opened
/// * `blinds` - the polynomials blinds
/// * `challenge` - the challenge at which the polynomials are evaluated
///
/// # Returns
///
/// * `Vec<u8>` containing the quotient polynomial commitments
/// and the evaluations of the polynomials at the challenge
fn create_opening_proof_at_challenge<
    'params,
    Scheme: CommitmentScheme<Curve = halo2_proofs::halo2curves::bn256::G1Affine, Scalar = Fp>,
    P: Prover<'params, Scheme>,
    E: EncodedChallenge<Scheme::Curve>,
    T: TranscriptWriterBuffer<Vec<u8>, Scheme::Curve, E>,
>(
    params: &'params Scheme::ParamsProver,
    polynomials: &[Polynomial<<Scheme as CommitmentScheme>::Scalar, Coeff>],
    blinds: &[Blind<Fp>],
    challenge: Fp,
) -> Vec<u8>
where
    Scheme::Scalar: WithSmallOrderMulGroup<3>,
{
    let mut transcript = T::init(vec![]);

    // Evaluate the polynomials at the challenge
    let polynomial_evaluations = polynomials
        .iter()
        .map(|poly| eval_polynomial(poly, challenge))
        .collect::<Vec<_>>();

    // Write evaluations to the transcript
    polynomial_evaluations
        .iter()
        .for_each(|eval| transcript.write_scalar(*eval).unwrap());

    // Prepare prover queries for the polynomial
    let queries = polynomials
        .iter()
        .enumerate()
        .map(|(i, polynomial)| ProverQuery::new(challenge, polynomial, blinds[i]))
        .collect::<Vec<_>>();

    // Create proof
    let prover = P::new(params);
    prover
        .create_proof(&mut OsRng, &mut transcript, queries)
        .unwrap();

    // Finalize transcript and return the proof
    transcript.finalize()
}

/// Verifies a KZG batch proof for a polynomial evaluation at a challenge
/// and returns the evaluations of the polynomials at the challenge
/// as well as the verification result
///
/// # Arguments
///
/// * `params` - the KZG parameters
/// * `proof` - the KZG batch proof
/// * `challenge` - the challenge at which the polynomials are evaluated
/// * `commitment_points` - the commitment points of the polynomials
///
/// # Returns
///
/// * `bool` - whether the proof is verified correctly
/// * `Vec<Fp>` - the evaluations of the polynomials at the challenge
fn verify_opening<
    'a,
    'params,
    Scheme: CommitmentScheme<Curve = halo2_proofs::halo2curves::bn256::G1Affine, Scalar = Fp>,
    V: Verifier<'params, Scheme>,
    E: EncodedChallenge<Scheme::Curve>,
    T: TranscriptReadBuffer<&'a [u8], Scheme::Curve, E>,
    Strategy: VerificationStrategy<'params, Scheme, V, Output = Strategy>,
    const N_POINTS: usize,
>(
    params: &'params Scheme::ParamsVerifier,
    proof: &'a [u8],
    challenge: Fp,
    commitment_points: &[G1Affine],
) -> (bool, Vec<Fp>)
where
    Scheme::Scalar: WithSmallOrderMulGroup<3>,
{
    let mut transcript = T::init(proof);

    // Read the polynomial evaluations from the transcript
    let evaluations = (0..N_POINTS)
        .map(|_| transcript.read_scalar().unwrap())
        .collect::<Vec<_>>();

    // Prepare verifier queries for the commitment
    let queries = (0..N_POINTS)
        .map(|i| VerifierQuery::new_commitment(&commitment_points[i], challenge, evaluations[i]))
        .collect::<Vec<_>>();

    // Initialize the verifier
    let verifier = V::new(params);

    // Use the provided strategy for verification
    let strategy = Strategy::new(params);
    let strategy = strategy
        .process(|msm_accumulator| {
            verifier
                .verify_proof(&mut transcript, queries.iter().cloned(), msm_accumulator)
                .map_err(|_| Error::Opening)
        })
        .unwrap();

    // Return the result of the verification
    (strategy.finalize(), evaluations)
}

/// Verifies a proof given the public setup, the verification key, the proof and the public inputs of the circuit.
pub fn full_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    proof: &[u8],
    public_inputs: &[Vec<Fp>],
) -> bool {
    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(params);
    let mut transcript: Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>> =
        Blake2bRead::<_, _, Challenge255<_>>::init(proof);

    let instance: Vec<&[Fp]> = public_inputs.iter().map(|input| &input[..]).collect();
    let instances = &[&instance[..]];

    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(verifier_params, vk, strategy, instances, &mut transcript)
    .is_ok()
}

/// Converts a field element to a Solidity calldata
pub fn field_element_to_solidity_calldata(field_element: Fp) -> U256 {
    let bytes = field_element.to_repr();
    let u = U256::from_little_endian(bytes.as_slice());
    u
}
