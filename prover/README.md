# Summa V3: Hyperplonk Prover

## Motivation

While [Summa V2](https://github.com/summa-dev/summa-solvency/tree/v2) significantly improved the generation of inclusion proofs for all users, it faced a performance bottleneck during the interpolation of univariate polynomials. These were generated using the discrete Fourier transform (DFT), which became particularly challenging when interpolating large polynomials. To address this bottleneck, we decided to transition our backend from Plonk to HyperPlonk, an adaptation of Plonk to the boolean hypercube that uses multilinear polynomial commitments and avoids the need for an FFT during proof generation.

## Implementation and Evaluation of HyperPlonk

Encoding data into the polynomial that interpolates on the boolean hypercube offers significant performance advantages over interpolating a univariate polynomial. However, we cannot get a "total balance" in the same way as in Summa V2, which uses a method called ["Univariate Grand Sum Calculation"](https://github.com/summa-dev/summa-solvency/tree/v2/prover#univariate-grand-sum-calculation). Therefore, in the Summa V3 circuit, we have added "Running Sum" columns and created constraints to obtain a valid "total balance". This means that the commitment size is exactly double that of Summa V2.

To mitigate the increase in commitment size in V3, we have implemented two variants, V3b and V3c. These variants introduce a workaround to address the total sum calculation with a "non-zero constraint" in the backend. More details can be found in the ["Summa V3 variations analysis"](https://hackmd.io/hM7panOkTg6MZcqGCA5HDA).

## Usage

To build, test and print the circuits, execute

```bash
cargo build
cargo test --release --features dev-graph
```

## Power of Tau Trusted Setup for HyerPlonk

Summa V1 and V2 have utilized the SRS, known as `hyperplonk-srs-#`, which is formatted for [pse/halo2](https://github.com/privacy-scaling-explorations/halo2). This has been converted using the [han0110/halo2-kzg-srs](https://github.com/han0110/halo2-kzg-srs/) repo.
However, the SRS files for `pse/halo2`, namely `hermez-raw`, are not compatible with HyperPlonk.

Therefore, we need to create a SRS generator for HyperPlonk.

You can find the generator script here: <br>
https://github.com/summa-dev/plonkish/blob/feat-read-params/plonkish_backend/bin/hyperplonk_srs_generator.rs

You can generate SRS for the HyperPlonk backend using the following commands:

```bash
$ git clone --branch feat-read-params https://github.com/summa-dev/plonkish
$ cd plonkish/plonkish_backend
plonkish/plonkish_backend $ cargo run --bin generate_hyperplonk_srs hermez-hyperplonk- 17
```

The generate command is structured as "generate_hyperplonk_srs" `output_file_name` `degree_number`.

If you wish to generate a higher degree of SRS, you should increase the degree_number in the command.

Alternatively, you can download pre-generated SRS files from  [here - Prerequisites of backend](../backend/README.md#prerequisites)

## Benchmarks

The following benchmarks are available in the `proof_of_liabilities` module:

- `grand_sum_proof`: the time to generate a commitment proof of the grand sum with a range check of every balance;
- `inclusion_proof`: the time to generate the KZG opening proof of a user inclusion;
- `grand_sum_verification`: the time to verify the commitment proof of the grand sum of user balances;
- `inclusion_verification`: the time to verify the KZG opening proof of a single user inclusion.

To run the benchmarks use the following command:

```bash
cargo bench
```

## Potential Improvement point

### Using Gemini to avoid trusted setup in Summa

As we explored alternative solutions to make the SRS compatible between Plonk and HyperPlonk, we came across another backend proving system supported in the Plonkish-backend. This system, known as Gemini, eliminates the need for a trusted setup in multilinear KZG. Consequently, there is no need to concern ourselves with the SRS file and other elements as described in the section [`Power of Tau Trusted Setup for HyerPlonk`](#power-of-tau-trusted-setup-for-hyerplonk).

We believe that switching to another backend in [Plonkish](https://github.com/summa-dev/plonkish) would not be difficult. However, due to our project goals and time constraints, we have decided to defer this improvement point to future contributors.

You can find the Gemini Paper [here](https://eprint.iacr.org/2022/420.pdf) and the Gemini implementation in Plonkish [here](https://github.com/summa-dev/plonkish/blob/main/plonkish_backend/src/pcs/multilinear/gemini.rs).
