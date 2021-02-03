use crate::crypto_types::*;
use crate::priv_coin::*;
use crate::zkp_types::*;
use ark_crypto_primitives::CommitmentScheme;
use ark_crypto_primitives::FixedLengthCRH;
use ark_serialize::CanonicalDeserialize;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

///  Return a serialized PVK given hash_param_seed and commit_param_seed
pub fn dap_setup(hash_param_seed: &[u8; 32], commit_param_seed: &[u8; 32]) -> Groth16VK {
    let vk_bytes = manta_zkp_vk_gen(hash_param_seed, commit_param_seed);
    Groth16VK::deserialize(vk_bytes.as_ref()).unwrap()
}

/// Generate Params from serialized commit_seed and hash_seed
pub fn deseralize_zkp_params(hash_param_seed: &[u8; 32], commit_param_seed: &[u8; 32]) -> Param {
    let mut rng = ChaCha20Rng::from_seed(*commit_param_seed);
    let commit_param = PrivCoinCommitmentScheme::setup(&mut rng).unwrap();

    let mut rng = ChaCha20Rng::from_seed(*hash_param_seed);
    let hash_param = Hash::setup(&mut rng).unwrap();
    Param {
        commit_param,
        hash_param,
    }
}
