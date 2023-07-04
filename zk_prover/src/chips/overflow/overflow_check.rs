use crate::chips::overflow::utils::*;
use halo2_proofs::circuit::{AssignedCell, Layouter, Value};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector};
use halo2_proofs::poly::Rotation;
use std::fmt::Debug;

/// Configuration for the Overflow Check Chip
///
/// # Type Parameters
///
/// * `MAX_BITS`: Number of bits of each chunk in which the value to be checked is decomposed into.
/// * `MOD_BITS`: Range in which the value to be checked should be.
///
/// # Fields
///
/// * `a`: Advice column for the value to be checked.
/// * `b`: Advice column for the decomposed values.
/// * `range`: Fixed column for the range table.
/// * `toggle_decomposed_value_check`: Selector to toggle the equality check between the decomposed value and the value.
/// * `toggle_lookup_check`: Selector to toggle the lookup check.
#[derive(Debug, Clone)]
pub struct OverflowCheckConfig<const MAX_BITS: u8, const MOD_BITS: usize> {
    pub a: Column<Advice>,
    pub b: Column<Advice>,
    pub range: Column<Fixed>,
    pub toggle_decomposed_value_check: Selector,
    pub toggle_lookup_check: Selector,
}

/// Chip that verifies that the value to be checked doesn't overflow the range specified by `MOD_BITS`.
/// Contains the following constraints:
/// * `value` = `decomposed_value_sum` (if `toggle_decomposed_value_check` is toggled)
/// * `decomposed_value` ∈ to `MAX_BITS` lookup table (if `toggle_lookup_check` is toggled). Namely `decomposed_value` should be in the `MAX_BITS` range 
#[derive(Debug, Clone)]
pub struct OverflowChip<const MAX_BITS: u8, const MOD_BITS: usize> {
    config: OverflowCheckConfig<MAX_BITS, MOD_BITS>,
}

impl<const MAX_BITS: u8, const MOD_BITS: usize> OverflowChip<MAX_BITS, MOD_BITS> {
    /// Constructs a new Overflow Chip given an OverflowCheckConfig
    pub fn construct(config: OverflowCheckConfig<MAX_BITS, MOD_BITS>) -> Self {
        let num_rows = MOD_BITS / MAX_BITS as usize;
        let remainder = MOD_BITS % MAX_BITS as usize;

        // Check if MOD_BITS is not evenly divisible by MAX_BITS
        if remainder != 0 {
            eprintln!(
                "Warning: MOD_BITS ({}) is not evenly divisible by MAX_BITS ({}). Number of rows is {}.\nIs this intended?",
                MOD_BITS, MAX_BITS, num_rows
            );
        }

        Self { config }
    }

    /// Configures the Overflow Chip
    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        a: Column<Advice>,
        b: Column<Advice>,
        range: Column<Fixed>,
        toggle_decomposed_value_check: Selector,
        toggle_lookup_check: Selector,
    ) -> OverflowCheckConfig<MAX_BITS, MOD_BITS> {
        let num_rows = MOD_BITS / MAX_BITS as usize;

        meta.create_gate(
            "equality check between decomposed_value and value",
            |meta| {
                let s = meta.query_selector(toggle_decomposed_value_check);

                let value = meta.query_advice(a, Rotation::cur());

                let decomposed_value_vec: Vec<Expression<Fp>> = (0..num_rows)
                    .map(|i| meta.query_advice(b, Rotation(i as i32)))
                    .collect();

                // multiplier by position of `b`(decomposed_value) column
                let multiplier = |pos: usize| {
                    let mut shift_chunk = Fp::one();
                    for _ in 1..pos {
                        shift_chunk *= Fp::from(1 << MAX_BITS);
                    }
                    Expression::Constant(shift_chunk)
                };

                // We are performing an important calculation here to check for overflow in finite field numbers.
                // A single range table is utilized which applies `1 << MAX_BITS` to decompose the column 'b' for range checking.
                //
                // the decomposed values would be represented as follows:
                //
                // |     | a (value)   | b    |
                // |-----|-------------|------|
                // |  0  | 0x1f2f3f    | 0x1f |
                // |  1  |             | 0x2f |
                // |  2  |             | 0x3f |
                //
                // Here, each column `b_n` represents a decomposed value.
                // So, decomposed_value_sum would be calculated as b_0 * 2^16 + b_1 * 2^8 + b_2 * 1
                //
                // During the iteration process in fold, the following would be the values of `acc`:
                // iteration 0: acc = decomposed_value_vec[1] * ( 1 << 8 ) + decomposed_value_vec[2]
                // iteration 1: acc = decomposed_value_vec[0] * ( 1 << 16 ) + decomposed_value_vec[1] * ( 1 << 8 ) + decomposed_value_vec[2]
                let decomposed_value_sum = (0..=num_rows - 2).fold(
                    // decomposed value at right-most advice columnis is least significant byte
                    decomposed_value_vec[num_rows - 1].clone(),
                    |acc, i| {
                        let cursor = num_rows - i;
                        acc + (decomposed_value_vec[i].clone() * multiplier(cursor))
                    },
                );

                vec![s * (decomposed_value_sum - value)]
            },
        );

        meta.annotate_lookup_any_column(range, || "LOOKUP_MAXBITS_RANGE");

        meta.lookup_any("range check for MAXBITS", |meta| {
            let cell = meta.query_advice(b, Rotation::cur());
            let range = meta.query_fixed(range, Rotation::cur());

            let enable_lookup = meta.query_selector(toggle_lookup_check);
            vec![(enable_lookup * cell, range)]
        });

        OverflowCheckConfig {
            a,
            b,
            range,
            toggle_decomposed_value_check,
            toggle_lookup_check,
        }
    }

    /// Assigns the value to be checked to the chip by splitting it into `MOD_BITS / MAX_BITS` chunks.
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Fp>,
        value: &AssignedCell<Fp, Fp>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "assign decomposed values",
            |mut region| {
                self.config
                    .toggle_decomposed_value_check
                    .enable(&mut region, 0)?;

                let num_rows = MOD_BITS / MAX_BITS as usize;

                // Assign input value to the cell inside the region
                value.copy_advice(|| "assign value", &mut region, self.config.a, 0)?;

                // Just used helper function for decomposing. In other halo2 application used functions based on Field.
                let decomposed_values: Vec<Fp> = decompose_bigint_to_ubits(
                    &value_fp_to_big_uint(value.value().copied()),
                    num_rows,
                    MAX_BITS as usize,
                ) as Vec<Fp>;

                // Note that, decomposed result is little edian. So, we need to reverse it.
                for (idx, val) in decomposed_values.iter().rev().enumerate() {
                    self.config.toggle_lookup_check.enable(&mut region, idx)?;

                    region.assign_advice(
                        || format!("assign decomposed {} row", idx),
                        self.config.b,
                        idx,
                        || Value::known(*val),
                    )?;
                }

                Ok(())
            },
        )
    }

    /// Loads the lookup table with values from `0` to `2^MAX_BITS - 1`
    pub fn load(&self, layouter: &mut impl Layouter<Fp>) -> Result<(), Error> {
        let range = 1 << (MAX_BITS as usize);

        layouter.assign_region(
            || format!("load range check table of {} bits", MAX_BITS),
            |mut region| {
                for i in 0..range {
                    region.assign_fixed(
                        || "assign cell in fixed column",
                        self.config.range,
                        i,
                        || Value::known(Fp::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }
}
