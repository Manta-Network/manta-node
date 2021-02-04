use crate::priv_coin::*;
use crate::types::*;
use ark_crypto_primitives::CommitmentScheme;
use ark_serialize::CanonicalDeserialize;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Generate Params from serialized commit_seed and hash_seed
pub fn deseralize_commit_params(commit_param_seed: &[u8; 32]) -> PrivCoinCommitmentParam {
    let mut rng = ChaCha20Rng::from_seed(*commit_param_seed);
    PrivCoinCommitmentScheme::setup(&mut rng).unwrap()
}
