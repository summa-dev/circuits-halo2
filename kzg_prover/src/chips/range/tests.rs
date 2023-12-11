use crate::chips::range::range_check::{RangeCheckChip, RangeCheckConfig};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr as Fp,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Selector},
    poly::Rotation,
};

#[derive(Debug, Clone)]
pub struct AddConfig {
    pub col_a: Column<Advice>, // stores the value of a
    pub col_b: Column<Advice>, // stores the value of b
    pub col_c: Column<Advice>, // stores the value of c = a + b
    pub selector: Selector,
}

#[derive(Debug, Clone)]
pub struct AddChip {
    pub config: AddConfig,
}

impl AddChip {
    pub fn construct(config: AddConfig) -> Self {
        Self { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        col_a: Column<Advice>,
        col_b: Column<Advice>,
        col_c: Column<Advice>,
        add_selector: Selector,
    ) -> AddConfig {
        meta.create_gate("add", |meta| {
            let s = meta.query_selector(add_selector);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
            vec![s * (a + b - c)]
        });

        AddConfig {
            col_a,
            col_b,
            col_c,
            selector: add_selector,
        }
    }

    pub fn assign(
        &self,
        a: Fp,
        b: Fp,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<
        (
            AssignedCell<Fp, Fp>,
            AssignedCell<Fp, Fp>,
            AssignedCell<Fp, Fp>,
        ),
        Error,
    > {
        layouter.assign_region(
            || "initialize value and sum",
            |mut region| {
                self.config.selector.enable(&mut region, 0)?;

                let a_cell =
                    region.assign_advice(|| "a", self.config.col_a, 0, || Value::known(a))?;

                let b_cell =
                    region.assign_advice(|| "b", self.config.col_b, 0, || Value::known(b))?;

                let c_cell = region.assign_advice(
                    || "a + b",
                    self.config.col_c,
                    0,
                    || a_cell.value().copied() + b_cell.value(),
                )?;

                Ok((a_cell, b_cell, c_cell))
            },
        )
    }
}

#[derive(Debug, Clone)]
pub struct TestConfig<const N_BYTES: usize> {
    pub addchip_config: AddConfig,
    pub range_check_config: RangeCheckConfig<N_BYTES>,
    pub range: Column<Fixed>,
}

// The test circuit takes two inputs a and b.
// It adds them together by using the add chip to produce c = a + b.
// Performs a range check on c that should lie in N_BYTES.
#[derive(Default, Clone, Debug)]
struct TestCircuit<const N_BYTES: usize> {
    pub a: Fp,
    pub b: Fp,
}

impl<const N_BYTES: usize> Circuit<Fp> for TestCircuit<N_BYTES> {
    type Config = TestConfig<N_BYTES>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let range = meta.fixed_column();

        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();

        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(c);

        let constants = meta.fixed_column();
        meta.enable_constant(constants);

        let zs = [(); N_BYTES].map(|_| meta.advice_column());

        for column in zs.iter() {
            meta.enable_equality(*column);
        }

        let add_selector = meta.selector();

        let range_check_config = RangeCheckChip::<N_BYTES>::configure(meta, c, zs, range);

        let addchip_config = AddChip::configure(meta, a, b, c, add_selector);

        {
            TestConfig {
                addchip_config,
                range_check_config,
                range,
            }
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        // Initiate the range check chip
        let range_chip = RangeCheckChip::construct(config.range_check_config);

        // Load the lookup table
        let range = 1 << 8;

        layouter.assign_region(
            || format!("load range check table of {} bits", 8 * N_BYTES),
            |mut region| {
                for i in 0..range {
                    region.assign_fixed(
                        || "assign cell in fixed column",
                        config.range,
                        i,
                        || Value::known(Fp::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )?;

        // Initiate the add chip
        let addchip = AddChip::construct(config.addchip_config);
        let (_, _, c) = addchip.assign(self.a, self.b, layouter.namespace(|| "add chip"))?;

        // Perform the range check
        layouter.assign_region(
            || "Perform range check on c",
            |mut region| {
                range_chip.assign(&mut region, &c)?;

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod testing {
    use super::TestCircuit;
    use halo2_proofs::{
        dev::{FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::Fr as Fp,
        plonk::Any,
    };

    // a = (1 << 16) - 2 = 0xfffe
    // b = 1
    // c = a + b = 0xffff
    // All the values are within 2 bytes range.
    #[test]
    fn test_none_overflow_16bits() {
        let k = 9;

        // a: new value
        let a = Fp::from((1 << 16) - 2);
        let b = Fp::from(1);

        let circuit = TestCircuit::<2> { a, b };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    // a = (1 << 16) - 2 = 0xfffe
    // b = 2
    // c = a + b = 0x10000
    // a and b are within 2 bytes range.
    // c overflows 2 bytes so the circuit should fail.
    #[test]
    fn test_overflow_16bits() {
        let k = 9;

        let a = Fp::from((1 << 16) - 2);
        let b = Fp::from(2);

        let circuit = TestCircuit::<2> { a, b };
        let invalid_prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::Fixed, 1).into(),
                    location: FailureLocation::OutsideRegion { row: 0 }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 4).into(),
                    location: FailureLocation::InRegion {
                        region: (2, "Perform range check on c").into(),
                        offset: 0
                    }
                },
            ])
        );
    }

    // a is the max value within the range (32 bits / 4 bytes)
    // a = 0x-ff-ff-ff-ff
    // b = 1
    // a and b are within 4 bytes range.
    // c overflows 4 bytes so the circuit should fail.
    #[test]
    fn test_overflow_32bits() {
        let k = 9;

        let a = Fp::from(0xffffffff);
        let b = Fp::from(1);

        let circuit = TestCircuit::<4> { a, b };
        let invalid_prover = MockProver::run(k, &circuit, vec![]).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::Fixed, 1).into(),
                    location: FailureLocation::OutsideRegion { row: 0 }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 6).into(),
                    location: FailureLocation::InRegion {
                        region: (2, "Perform range check on c").into(),
                        offset: 0
                    }
                },
            ])
        );
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_range_check_test() {
        use plotters::prelude::*;

        let root =
            BitMapBackend::new("prints/range-check-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Range Check Layout", ("sans-serif", 60))
            .unwrap();

        let circuit = TestCircuit::<4> {
            a: Fp::from(0x1f2f3f4f),
            b: Fp::from(1),
        };
        halo2_proofs::dev::CircuitLayout::default()
            .render(9, &circuit, &root)
            .unwrap();
    }
}
