/// The number of CEX asset balances for each user account
pub const N_ASSETS: usize = 2;
/// Poseidon hasher parameter for Length used in MST nodes (nodes take left hash, left assets, right hash, right assets as inputs)
pub const L_NODE: usize = 2 * (1 + N_ASSETS);
/// Poseidon hasher parameter for Length used in MST entries (aka levaes, they only take one hash and one set of assets as input)
pub const L_ENTRY: usize = 1 + N_ASSETS;
