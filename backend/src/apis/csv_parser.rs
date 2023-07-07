use crate::apis::snapshot_data::Asset;
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::halo2curves::serde::SerdeObject;
use num_bigint::BigInt;
use serde::Deserialize;
use std::error::Error;
use std::fs::File;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct CsvAsset {
    name: String,
    pubkey: String,
    balances: String,
    signature: String,
}

pub fn parse_csv_to_assets<P: AsRef<Path>>(path: P) -> Result<Vec<Asset>, Box<dyn Error>> {
    let mut assets: Vec<Asset> = Vec::new();

    let file = File::open(path)?;
    let mut rdr = csv::ReaderBuilder::new().delimiter(b';').from_reader(file);

    for result in rdr.deserialize() {
        let record: CsvAsset = result?;

        let mut balances = Vec::new();
        let mut sum_balances = Fp::zero();

        for balance in record.balances.split(',') {
            let balance_bigint = BigInt::parse_bytes(balance.as_bytes(), 10)
                .ok_or_else(|| format!("Failed to parse balance '{}' as BigInt", balance))?;

            let balance_fp = Fp::from_str_vartime(balance)
                .ok_or_else(|| format!("Failed to convert balance '{}' to Fp", balance))?;

            balances.push(balance_bigint);
            sum_balances += balance_fp;
        }

        // Check if asset with same name already exists in the Vec
        if let Some(asset) = assets.iter_mut().find(|a| a.name == record.name) {
            asset.pubkeys.push(record.pubkey);
            asset.balances.extend(balances);
            asset.signature.push(record.signature);
        } else {
            assets.push(Asset {
                name: record.name,
                pubkeys: vec![record.pubkey],
                balances,
                sum_balances,
                signature: vec![record.signature],
            });
        }
    }

    Ok(assets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_csv_to_assets() {
        let path = "src/apis/csv/assets_2.csv";
        let assets = parse_csv_to_assets(path).unwrap();

        // Validate the first asset
        assert_eq!(assets[0].name, "eth");
        assert_eq!(
            assets[0].pubkeys[0],
            "0x627306090abaB3A6e1400e9345bC60c78a8BEf57"
        );
        assert_eq!(assets[0].balances[0], BigInt::from(1500u32));

        // Validate the second asset
        assert_eq!(assets[1].name, "dai");
        assert_eq!(
            assets[1].pubkeys[0],
            "0x44d8860b40D632163Cd4A7a8D6CC3A8c0fBbe10d"
        );
        assert_eq!(assets[1].balances[0], BigInt::from(1000u32));
    }
}
