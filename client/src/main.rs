use ark_crypto_primitives::CommitmentScheme;
use ark_crypto_primitives::commitment;
use ark_ed_on_bls12_381::Fr;
use ark_crypto_primitives::commitment::pedersen::Randomness;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use data_encoding::BASE64;
use pallet_manta_dap::dap_setup::*;
use pallet_manta_dap::types::*;
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use structopt::StructOpt;

/// Search for a pattern in a file and display the lines that contain it.
#[derive(StructOpt)]
struct Cli {
    /// The pattern to look for
    amount: u64,
    // The path to the file to read
    //#[structopt(parse(from_os_str))]
    //path: std::path::PathBuf,
}

/// Generate manta (sk, pk) pair
pub fn manta_keygen(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // get an rng from seed
    let mut rng = ChaCha20Rng::from_seed(*seed);
    // sample a random sk
    let mut sk = [0u8; 32];
    rng.fill_bytes(&mut sk);
    let pk = manta_prf(&sk, &[0u8; 32]);
    (sk.clone(), pk.clone())
}

/// PRF used for sn, address, and commitment
pub fn manta_prf(nonce: &[u8; 32], payload: &[u8]) -> [u8;32] {
    let param = (); // TODO: ask zhenfei, what is the param here
    <commitment::blake2s::Commitment as CommitmentScheme>::commit(&param, &payload, &nonce).unwrap()
}

/// commitment scheme that is used in Manta
/// commit_param: commitment parameter
/// payload: commitment payload
/// returns (r_bytes, comm_bytes), where r_bytes is the serialized nonce, 
///     comm_bytes is the serialized commitment.
pub fn manta_commit(commit_param: &PrivCoinCommitmentParam, payload: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut rng = rand::thread_rng();
    let r = Fr::rand(&mut rng);
    let mut r_bytes = [0u8; 32];
    r.serialize(r_bytes.as_mut()).unwrap();
    let r = Randomness(r);
    let comm = PrivCoinCommitmentScheme::commit(&commit_param, &payload, &r).unwrap();
    let mut comm_bytes = [0u8; 32];
    comm.serialize(comm_bytes.as_mut()).unwrap();
    (r_bytes, comm_bytes)
}

// pub struct Coin {
//     pub pk: [u8; 32],
//     pub rho: [u8; 32],
//     pub r: PrivCoinCommitmentOpen,
//     pub s: PrivCoinCommitmentOpen,
//     pub k: PrivCoinCommitmentOutput,
//     pub cm: PrivCoinCommitmentOutput,
//     pub value: u32,
// }

fn main() {
    let args = Cli::from_args();
    let seed = [42; 32]; // TODO: remove hardcoded seed here
    let mut rng = ChaCha20Rng::from_seed(seed);
    // 1. generate key pair
    let (pk, sk) = manta_keygen(&seed);
    println!("generating manta (pk,sk) pair ......");
    println!("pk: {}, sk: {}", BASE64.encode(&pk), BASE64.encode(&sk));
    // 2. do the setup the same as the ledger
    //let hash_param_seed = [1u8; 32];
    let commit_param_seed = [2u8; 32];
    //let vk = dap_setup(&hash_param_seed, &commit_param_seed);
    //let pvk = Groth16PVK::from(vk);
    println!("public parameter for zkp generated ......");
    // 3. generate mint txn
    // prepare amount, rho, k, s, cm, and sn
    // sample a random rho
    let mut rho = [0u8; 32];
    rng.fill_bytes(&mut rho);
    // compute sn
    let sn = manta_prf(&sk, &rho);
    // k = comm(pk||rho, r)
    let comm_params = deseralize_commit_params(&commit_param_seed);
    let payload = [pk, rho].concat();
    let (r, k) = manta_commit(&comm_params, &payload);
    // cm = comm(v||k, s)
    let vandk = [args.amount.to_le_bytes().as_ref(), k.clone().as_ref()].concat();
    let (s, cm) = manta_commit(&comm_params, &vandk);
    println!("generated mint txns:");
    println!("rho (private): {:?}", rho);
    println!("sn (private): {}", BASE64.encode(&sn));
    println!("r (private): {}", BASE64.encode(&r));
    println!("amount: {}", args.amount);
    println!("k: {}", BASE64.encode(&k));
    println!("s: {}", BASE64.encode(&s));
    println!("cm: {}", BASE64.encode(&cm));
}
