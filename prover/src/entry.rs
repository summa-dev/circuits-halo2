use halo2_proofs::halo2curves::bn256::Fr as Fp;
use num_bigint::BigUint;

use crate::utils::{big_intify_username, fp_to_big_uint};

/// An entry in the Merkle Sum Tree from the database of the CEX.
/// It contains the username and the balances of the user.
#[derive(Clone, Debug)]
pub struct Entry<const N_CURRENCIES: usize> {
    username_as_big_uint: BigUint,
    balances: [BigUint; N_CURRENCIES],
    username: String,
}

impl<const N_CURRENCIES: usize> Entry<N_CURRENCIES> {
    pub fn new(username: String, balances: [BigUint; N_CURRENCIES]) -> Result<Self, &'static str> {
        let username_as_big_uint = big_intify_username(&username);
        let max_allowed_value = fp_to_big_uint(Fp::zero() - Fp::one());

        // Ensure the username, when converted to a BigUint, does not exceed the field modulus
        // This prevents potential overflow issues by asserting that the username's numeric value
        // is within the allowable range defined by the field modulus
        // Please refer to https://github.com/zBlock-2/audit-report/blob/main/versionB.md#4-high-missing-username-range-check-in-big_intify_username--big_uint_to_fp
        if username_as_big_uint > max_allowed_value {
            return Err("The value that converted username should not exceed field modulus");
        }

        Ok(Entry {
            username_as_big_uint,
            balances,
            username,
        })
    }

    pub fn init_empty() -> Self {
        let empty_balances: [BigUint; N_CURRENCIES] = std::array::from_fn(|_| BigUint::from(0u32));

        Entry {
            username_as_big_uint: BigUint::from(0u32),
            balances: empty_balances,
            username: String::new(),
        }
    }

    pub fn balances(&self) -> &[BigUint; N_CURRENCIES] {
        &self.balances
    }

    pub fn username_as_big_uint(&self) -> &BigUint {
        &self.username_as_big_uint
    }

    pub fn username(&self) -> &str {
        &self.username
    }
}

#[cfg(test)]
#[test]
fn test_entry_new() {
    let short_username_entry = Entry::new(String::from("userA"), [BigUint::from(0u32)]);
    assert!(short_username_entry.is_ok());

    let long_username_entry = Entry::new(
        String::from("userABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
        [BigUint::from(0u32)],
    );
    assert!(long_username_entry.is_err())
}
