use std::marker::PhantomData;

use crate::chips::range::range_check::{RangeCheckU64Chip, RangeCheckU64Config};
use crate::entry::Entry;
use crate::utils::big_uint_to_fp;
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance};

#[derive(Clone)]
pub struct UnivariateGrandSum<
    const N_USERS: usize,
    const N_CURRENCIES: usize,
    CONFIG: CircuitConfig<N_CURRENCIES, N_USERS>,
> {
    pub entries: Vec<Entry<N_CURRENCIES>>,
    _marker: PhantomData<CONFIG>,
}

impl<
        const N_USERS: usize,
        const N_CURRENCIES: usize,
        CONFIG: CircuitConfig<N_CURRENCIES, N_USERS>,
    > UnivariateGrandSum<N_USERS, N_CURRENCIES, CONFIG>
{
    pub fn init_empty() -> Self
    where
        [(); N_CURRENCIES + 1]:,
    {
        Self {
            entries: vec![Entry::init_empty(); N_USERS],
            _marker: PhantomData,
        }
    }

    /// Initializes the circuit with the user entries that are part of the solvency proof
    pub fn init(user_entries: Vec<Entry<N_CURRENCIES>>) -> Self {
        Self {
            entries: user_entries,
            _marker: PhantomData,
        }
    }
}

/// Configuration for the univariate grand sum circuit
/// # Type Parameters
///
/// * `N_CURRENCIES`: The number of currencies for which the solvency is verified.
/// * `N_USERS`: The number of users for which the solvency is verified.
///
/// # Fields
///
/// * `username`: Advice column used to store the usernames of the users
/// * `balances`: Advice columns used to store the balances of the users
/// * `range_check_configs`: Configurations for the range check chip
/// * `range_u16`: Fixed column used to store the lookup table [0, 2^16 - 1] for the range check chip
#[derive(Debug, Clone)]
pub struct UnivariateGrandSumConfig<const N_CURRENCIES: usize, const N_USERS: usize>
where
    [(); N_CURRENCIES + 1]:,
{
    username: Column<Advice>,
    balances: [Column<Advice>; N_CURRENCIES],
    range_check_configs: [RangeCheckU64Config; N_CURRENCIES],
    range_u16: Column<Fixed>,
    instance: Column<Instance>,
}

impl<const N_CURRENCIES: usize, const N_USERS: usize> CircuitConfig<N_CURRENCIES, N_USERS>
    for UnivariateGrandSumConfig<N_CURRENCIES, N_USERS>
where
    [(); N_CURRENCIES + 1]:,
{
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        // By default, the username is in a blinded column like any other private inputs in common Halo2 circuit.
        // However, this makes it indistinguishable between fake user data and real user data that has zero values in Summa circuit.
        // Therefore, we have introduced a feature that allows the username to be unblinded instead of blinded, which may be necessary for the prover in the future.
        // Refer to this comment for more details: https://github.com/zBlock-2/summa-solvency/issues/9#issuecomment-2143427298
        let username: Column<Advice> = if cfg!(feature = "unblind-username") {
            meta.unblinded_advice_column()
        } else {
            meta.advice_column()
        };

        let balances = [(); N_CURRENCIES].map(|_| meta.unblinded_advice_column());

        let range_u16 = meta.fixed_column();

        meta.enable_constant(range_u16);

        meta.annotate_lookup_any_column(range_u16, || "LOOKUP_MAXBITS_RANGE");

        // Create an empty array of range check configs
        let mut range_check_configs = Vec::with_capacity(N_CURRENCIES);

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        for item in balances.iter().take(N_CURRENCIES) {
            let z = *item;
            // Create 4 advice columns for each range check chip
            let zs = [(); 4].map(|_| meta.advice_column());

            for column in &zs {
                meta.enable_equality(*column);
            }

            let range_check_config = RangeCheckU64Chip::configure(meta, z, zs, range_u16);

            range_check_configs.push(range_check_config);
        }

        Self {
            username,
            balances,
            range_check_configs: range_check_configs.try_into().unwrap(),
            range_u16,
            instance,
        }
    }

    fn synthesize(
        &self,
        mut layouter: impl Layouter<Fp>,
        assigned_balances: Vec<Vec<AssignedCell<Fp, Fp>>>,
    ) -> Result<(), Error>
    where
        [(); N_CURRENCIES + 1]:,
        [(); N_CURRENCIES + 1]:,
    {
        // Initiate the range check chips
        let range_check_chips = self
            .range_check_configs
            .iter()
            .map(|config| RangeCheckU64Chip::construct(*config))
            .collect::<Vec<_>>();

        // Load lookup table for range check u64 chip
        let range = 1 << 16;

        layouter.assign_region(
            || format!("load range check table of 16 bits"),
            |mut region| {
                for i in 0..range {
                    region.assign_fixed(
                        || "assign cell in fixed column",
                        self.range_u16,
                        i,
                        || Value::known(Fp::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )?;

        // Perform range check on the assigned balances
        for i in 0..N_USERS {
            for j in 0..N_CURRENCIES {
                let mut zs = Vec::with_capacity(4);

                layouter.assign_region(
                    || format!("Perform range check on balance {} of user {}", j, i),
                    |mut region| {
                        range_check_chips[j].assign(
                            &mut region,
                            &mut zs,
                            &assigned_balances[i][j],
                        )?;
                        Ok(())
                    },
                )?;

                layouter.constrain_instance(zs[3].cell(), self.instance, 0)?;
            }
        }

        Ok(())
    }

    fn get_username(&self) -> Column<Advice> {
        self.username
    }

    fn get_balances(&self) -> [Column<Advice>; N_CURRENCIES] {
        self.balances
    }
}

pub trait CircuitConfig<const N_CURRENCIES: usize, const N_USERS: usize>: Clone {
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self;

    fn get_username(&self) -> Column<Advice>;

    fn get_balances(&self) -> [Column<Advice>; N_CURRENCIES];

    fn synthesize(
        &self,
        layouter: impl Layouter<Fp>,
        assigned_balances: Vec<Vec<AssignedCell<Fp, Fp>>>,
    ) -> Result<(), Error>;

    /// Assigns the entries to the circuit
    /// At row i, the username is set to the username of the i-th entry, the balance is set to the balance of the i-th entry
    /// Returns a bidimensional vector of the assigned balances to the circuit.
    fn assign_entries(
        &self,
        mut layouter: impl Layouter<Fp>,
        entries: &[Entry<N_CURRENCIES>],
    ) -> Result<Vec<Vec<AssignedCell<Fp, Fp>>>, Error>
    where
        [(); N_CURRENCIES + 1]:,
    {
        layouter.assign_region(
            || "assign entries to the table",
            |mut region| {
                // create a bidimensional vector to store the assigned balances. The first dimension is N_USERS, the second dimension is N_CURRENCIES
                let mut assigned_balances = vec![];

                for i in 0..N_USERS {
                    region.assign_advice(
                        || "username",
                        self.get_username(),
                        i,
                        || Value::known(big_uint_to_fp(entries[i].username_as_big_uint())),
                    )?;

                    let mut assigned_balances_row = vec![];

                    for (j, balance) in entries[i].balances().iter().enumerate() {
                        let assigned_balance = region.assign_advice(
                            || format!("balance {}", j),
                            self.get_balances()[j],
                            i,
                            || Value::known(big_uint_to_fp(balance)),
                        )?;

                        assigned_balances_row.push(assigned_balance);
                    }

                    assigned_balances.push(assigned_balances_row);
                }

                Ok(assigned_balances)
            },
        )
    }
}

impl<
        const N_USERS: usize,
        const N_CURRENCIES: usize,
        CONFIG: CircuitConfig<N_CURRENCIES, N_USERS>,
    > Circuit<Fp> for UnivariateGrandSum<N_USERS, N_CURRENCIES, CONFIG>
where
    [(); N_CURRENCIES + 1]:,
{
    type Config = CONFIG;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::init_empty()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config
    where
        [(); N_CURRENCIES + 1]:,
    {
        CONFIG::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        // Assign entries
        let assigned_balances =
            config.assign_entries(layouter.namespace(|| "assign entries"), &self.entries)?;

        config.synthesize(layouter, assigned_balances)
    }
}

/// Configuration that does not perform range checks. Warning: not for use in production!
/// The circuit without range checks can use a lower K value than the full circuit (convenient for prototyping and testing).
///
/// # Type Parameters
///
/// * `N_CURRENCIES`: The number of currencies for which the solvency is verified.
/// * `N_USERS`: The number of users for which the solvency is verified.
///
/// # Fields
///
/// * `username`: Advice column used to store the usernames of the users
/// * `balances`: Advice columns used to store the balances of the users
#[derive(Clone)]
pub struct NoRangeCheckConfig<const N_CURRENCIES: usize, const N_USERS: usize> {
    username: Column<Advice>,
    balances: [Column<Advice>; N_CURRENCIES],
}

impl<const N_CURRENCIES: usize, const N_USERS: usize> CircuitConfig<N_CURRENCIES, N_USERS>
    for NoRangeCheckConfig<N_CURRENCIES, N_USERS>
where
    [(); N_CURRENCIES + 1]:,
{
    fn configure(meta: &mut ConstraintSystem<Fp>) -> NoRangeCheckConfig<N_CURRENCIES, N_USERS> {
        let username = meta.advice_column();

        let balances = [(); N_CURRENCIES].map(|_| meta.unblinded_advice_column());

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        Self { username, balances }
    }

    fn synthesize(
        &self,
        _: impl Layouter<Fp>,
        _: Vec<Vec<AssignedCell<Fp, Fp>>>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn get_username(&self) -> Column<Advice> {
        self.username
    }

    fn get_balances(&self) -> [Column<Advice>; N_CURRENCIES] {
        self.balances
    }
}
