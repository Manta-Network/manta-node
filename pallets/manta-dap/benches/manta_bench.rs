#[macro_use]
extern crate criterion;
extern crate pallet_manta_dap;

use ark_crypto_primitives::CommitmentScheme;
use ark_crypto_primitives::FixedLengthCRH;
use ark_groth16::create_random_proof;
use ark_relations::r1cs::ConstraintSystem;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use criterion::Benchmark;
use criterion::Criterion;
use pallet_manta_dap::priv_coin::*;
use pallet_manta_dap::types::*;
use pallet_manta_dap::zkp::TransferCircuit;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_core::RngCore;
// use std::time::Duration;
use ark_ed_on_bls12_381::Fq;
use ark_relations::r1cs::ConstraintSynthesizer;

criterion_group!(manta_bench, bench_zkp_verify);
criterion_main!(manta_bench);

fn bench_zkp_verify(c: &mut Criterion) {
    let hash_param_seed = pallet_manta_dap::param::HASHPARAMSEED;
    let commit_param_seed = pallet_manta_dap::param::COMMITPARAMSEED;

    let mut rng = ChaCha20Rng::from_seed(commit_param_seed);
    let commit_param = PrivCoinCommitmentScheme::setup(&mut rng).unwrap();

    let mut rng = ChaCha20Rng::from_seed(hash_param_seed);
    let hash_param = Hash::setup(&mut rng).unwrap();

    let key_bytes = manta_zkp_key_gen(&hash_param_seed, &commit_param_seed);
    let pk = Groth16PK::deserialize(key_bytes.as_ref()).unwrap();

    // sender
    let mut sk = [0u8; 32];
    rng.fill_bytes(&mut sk);
    let (sender, sender_pub_info, sender_priv_info) = make_coin(&commit_param, sk, 100, &mut rng);

    // receiver
    let mut sk = [0u8; 32];
    rng.fill_bytes(&mut sk);
    let (receiver, receiver_pub_info, _receiver_priv_info) =
        make_coin(&commit_param, sk, 100, &mut rng);

    let circuit = TransferCircuit {
        commit_param,
        hash_param,
        sender_coin: sender.clone(),
        sender_pub_info: sender_pub_info.clone(),
        sender_priv_info: sender_priv_info.clone(),
        receiver_coin: receiver.clone(),
        receiver_pub_info: receiver_pub_info.clone(),
        list: Vec::new(),
    };

    let sanity_cs = ConstraintSystem::<Fq>::new_ref();
    circuit
        .clone()
        .generate_constraints(sanity_cs.clone())
        .unwrap();
    assert!(sanity_cs.is_satisfied().unwrap());

    let proof = create_random_proof(circuit, &pk, &mut rng).unwrap();
    let mut proof_bytes = [0u8; 192];
    proof.serialize(proof_bytes.as_mut()).unwrap();

    let bench_str = format!("ZKP verification");
    let bench = Benchmark::new(bench_str, move |b| {
        b.iter(|| {
            assert!(manta_verify_zkp(
                pallet_manta_dap::param::VKBYTES.to_vec(),
                proof_bytes,
                sender_priv_info.sn,
                sender_pub_info.k,
                receiver_pub_info.k,
                receiver.cm_bytes,
                [0u8; 32],
            ))
        })
    });

    // let bench = bench.warm_up_time(Duration::from_millis(1000));
    // let bench = bench.measurement_time(Duration::from_millis(5000));
    let bench = bench.sample_size(10);
    c.bench("manta_bench", bench);
}
