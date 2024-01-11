#![feature(generic_const_exprs)]
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{rngs::OsRng, Rng};

use summa_solvency::{
    circuits::{
        univariate_grand_sum::UnivariateGrandSum,
        utils::{
            full_prover, generate_setup_artifacts, open_grand_sums, open_user_points,
            verify_grand_sum_openings, verify_user_inclusion,
        },
    },
    cryptocurrency::Cryptocurrency,
    entry::Entry,
    utils::parse_csv_to_entries,
};

fn bench_kzg<const K: u32, const N_USERS: usize, const N_CURRENCIES: usize, const N_POINTS: usize>(
    name: &str,
    csv_path: &str,
) where
    [(); N_CURRENCIES + 1]:,
{
    let mut c = Criterion::default().sample_size(10);

    // Initialize an empty circuit
    let circuit = UnivariateGrandSum::<N_USERS, N_CURRENCIES>::init_empty();
    let (params, pk, vk) = generate_setup_artifacts(K, None, &circuit).unwrap();

    let range_check_bench_name = format!("<{}> range check", name);
    let opening_grand_sum_bench_name = format!("<{}> opening grand sum", name);
    let opening_user_bench_name = format!("<{}> opening user inclusion", name);
    let verifying_grand_sum_bench_name = format!("<{}> verifying grand sum", name);
    let verifying_user_bench_name = format!("<{}> verifying user inclusion", name);

    let mut entries: Vec<Entry<N_CURRENCIES>> = vec![Entry::init_empty(); N_USERS];
    let mut cryptos = vec![Cryptocurrency::init_empty(); N_CURRENCIES];
    parse_csv_to_entries::<&str, N_CURRENCIES>(csv_path, &mut entries, &mut cryptos).unwrap();

    c.bench_function(&range_check_bench_name, |b| {
        b.iter_batched(
            || circuit.clone(), // Setup function: clone the circuit for each iteration
            |circuit| {
                full_prover(&params, &pk, circuit, &[vec![]]);
            },
            criterion::BatchSize::SmallInput, // Choose an appropriate batch size
        );
    });

    let (zk_snark_proof, advice_polys, omega) = full_prover(&params, &pk, circuit, &[vec![]]);

    c.bench_function(&opening_grand_sum_bench_name, |b| {
        b.iter_batched(
            || 1..N_CURRENCIES + 1,
            |balance_column_range| {
                open_grand_sums::<N_CURRENCIES>(
                    &advice_polys.advice_polys,
                    &advice_polys.advice_blinds,
                    &params,
                    balance_column_range,
                )
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Generate a random user index
    let get_random_user_index = || {
        let user_range: std::ops::Range<usize> = 0..N_USERS;
        OsRng.gen_range(user_range) as u16
    };

    c.bench_function(&opening_user_bench_name, |b| {
        b.iter_batched(
            || (get_random_user_index(), 0..N_CURRENCIES + 1),
            |(user_index, column_range)| {
                open_user_points::<N_CURRENCIES>(
                    &advice_polys.advice_polys,
                    &advice_polys.advice_blinds,
                    &params,
                    column_range,
                    omega,
                    user_index,
                )
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Open grand sum for benchmark verifying grand sum
    let balance_column_range = 1..N_CURRENCIES + 1;
    let grand_sums_batch_proof = open_grand_sums::<N_CURRENCIES>(
        &advice_polys.advice_polys,
        &advice_polys.advice_blinds,
        &params,
        balance_column_range.clone(),
    );

    c.bench_function(&verifying_grand_sum_bench_name, |b| {
        b.iter_batched(
            || {
                (
                    grand_sums_batch_proof.clone(),
                    u64::try_from(advice_polys.advice_polys[0].len()).unwrap(),
                    balance_column_range.clone(),
                )
            },
            |(grand_sums_batch_proof, poly_degree, balance_column_range)| {
                verify_grand_sum_openings::<N_CURRENCIES>(
                    &params,
                    &zk_snark_proof,
                    &grand_sums_batch_proof,
                    poly_degree,
                    balance_column_range,
                )
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Open user inclusion for benchmark verifying user inclusion
    let column_range = 0..N_CURRENCIES + 1;
    let omega = vk.get_domain().get_omega();
    let user_index = get_random_user_index();
    let openings_batch_proof = open_user_points::<N_CURRENCIES>(
        &advice_polys.advice_polys,
        &advice_polys.advice_blinds,
        &params,
        column_range.clone(),
        omega,
        user_index,
    );

    c.bench_function(&verifying_user_bench_name, |b| {
        b.iter_batched(
            || (column_range.clone(), omega, user_index),
            |(column_range, omega, user_index)| {
                verify_user_inclusion::<N_POINTS>(
                    &params,
                    &zk_snark_proof,
                    &openings_batch_proof,
                    column_range,
                    omega,
                    user_index,
                );
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn criterion_benchmark(_c: &mut Criterion) {
    bench_kzg::<17, 16, 2, 3>(
        "K = 17, N_USER = 16, N_CURRENCIES = 2",
        "../csv/entry_16.csv",
    );
    bench_kzg::<17, 64, 2, 3>(
        "K = 17, N_USER = 64, N_CURRENCIES = 2",
        "../csv/entry_64.csv",
    );
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
