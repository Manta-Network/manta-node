use crate::priv_coin::*;
use crate::types::*;
use ark_crypto_primitives::CommitmentScheme;
use ark_serialize::CanonicalDeserialize;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

///  Return a serialized PVK given hash_param_seed and commit_param_seed
pub fn dap_setup(hash_param_seed: &[u8; 32], commit_param_seed: &[u8; 32]) -> Groth16VK {
    let vk_bytes = manta_zkp_key_gen(hash_param_seed, commit_param_seed);
    Groth16VK::deserialize(vk_bytes.as_ref()).unwrap()
}

/// Generate Params from serialized commit_seed and hash_seed
pub fn deseralize_commit_params(commit_param_seed: &[u8; 32]) -> PrivCoinCommitmentParam {
    let mut rng = ChaCha20Rng::from_seed(*commit_param_seed);
    PrivCoinCommitmentScheme::setup(&mut rng).unwrap()
}
