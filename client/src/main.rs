use ark_crypto_primitives::prf::Blake2s;
use ark_crypto_primitives::prf::PRF;
use data_encoding::BASE64;
use pallet_manta_dap::dap_setup::*;
use pallet_manta_dap::priv_coin::*;
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
fn manta_keygen(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // get an rng from seed
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    // sample a random sk
    let mut sk = [0u8; 32];
    rng.fill_bytes(&mut sk);
    let pk = <Blake2s as PRF>::evaluate(&sk, &[0u8; 32]).unwrap();
    (sk.clone(), pk.clone())
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
    let hash_param_seed = [1u8; 32];
    let commit_param_seed = [2u8; 32];
    let vk = dap_setup(&hash_param_seed, &commit_param_seed);
    let pvk = Groth16PVK::from(vk);
    println!("public parameter for zkp generated ......");
    // 3. generate mint txn
    let zkp_params = deseralize_commit_params(&commit_param_seed);
    let (coin, pub_info, priv_info) = make_coin(&zkp_params, sk, args.amount, &mut rng);
}
