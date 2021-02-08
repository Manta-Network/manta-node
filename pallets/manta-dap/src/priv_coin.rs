use crate::types::*;
use crate::zkp::TransferCircuit;
use crate::MantaCoin;
use crate::MantaLedgerState;
use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::commitment::pedersen::Randomness;
use ark_crypto_primitives::prf::Blake2s;
use ark_crypto_primitives::prf::PRF;
use ark_crypto_primitives::CommitmentScheme;
use ark_crypto_primitives::FixedLengthCRH;
use ark_ed_on_bls12_381::Fq;
use ark_ed_on_bls12_381::Fr;
use ark_ff::ToConstraintField;
use ark_ff::UniformRand;
use ark_groth16::{generate_random_parameters, verify_proof};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_relations::r1cs::ConstraintSystem;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_core::CryptoRng;
use rand_core::RngCore;

#[allow(dead_code)]
pub fn comm_encode(cm: &PrivCoinCommitmentOutput) -> [u8; 32] {
    let mut res = [0u8; 32];
    cm.serialize(res.as_mut()).unwrap();
    res
}

#[allow(dead_code)]
pub fn comm_decode(bytes: &[u8; 32]) -> PrivCoinCommitmentOutput {
    PrivCoinCommitmentOutput::deserialize(bytes.as_ref()).unwrap()
}

pub fn comm_open(param_seed: &[u8; 32], r: &[u8; 32], payload: &[u8], cm: &[u8; 32]) -> bool {
    let mut rng = ChaCha20Rng::from_seed(*param_seed);
    let param = PrivCoinCommitmentScheme::setup(&mut rng).unwrap();

    let open = Randomness(Fr::deserialize(r.as_ref()).unwrap());
    let cm = PrivCoinCommitmentOutput::deserialize(cm.as_ref()).unwrap();
    PrivCoinCommitmentScheme::commit(&param, payload, &open).unwrap() == cm
}

pub fn merkle_root(param_seed: &[u8; 32], payload: &[MantaCoin]) -> MantaLedgerState {
    let mut rng = ChaCha20Rng::from_seed(*param_seed);
    let param = Hash::setup(&mut rng).unwrap();

    let leaf: Vec<PrivCoinCommitmentOutput> = payload
        .iter()
        .map(|x| PrivCoinCommitmentOutput::deserialize(x.cm_bytes.as_ref()).unwrap())
        .collect();

    let tree = LedgerMerkleTree::new(param, &leaf).unwrap();
    let root = tree.root();
    let mut bytes = [0u8; 32];
    root.serialize(bytes.as_mut()).unwrap();

    MantaLedgerState { state: bytes }
}

pub fn manta_zkp_key_gen(hash_param_seed: &[u8; 32], commit_param_seed: &[u8; 32]) -> Vec<u8> {
    // rebuild the parameters from the inputs
    let mut rng = ChaCha20Rng::from_seed(*commit_param_seed);
    let commit_param = PrivCoinCommitmentScheme::setup(&mut rng).unwrap();

    let mut rng = ChaCha20Rng::from_seed(*hash_param_seed);
    let hash_param = Hash::setup(&mut rng).unwrap();

    // we build a mock ledger of 128 users with a default seed [3; 32]
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let mut coins = Vec::new();
    let mut pub_infos = Vec::new();
    let mut priv_infos = Vec::new();
    let mut ledger = Vec::new();

    for e in 0..128 {
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);

        let (coin, pub_info, priv_info) = make_coin(&commit_param, sk, e + 100, &mut rng);

        ledger.push(coin.cm_bytes);
        coins.push(coin);
        pub_infos.push(pub_info);
        priv_infos.push(priv_info);
    }

    // sender
    let sender = coins[0].clone();
    let sender_pub_info = pub_infos[0].clone();
    let sender_priv_info = priv_infos[0].clone();

    // we do not need to build merkle tree here; circuit does it.
    // // build the merkle tree
    // let tree = LedgerMerkleTree::new(param.hash_param.clone(), &ledger).unwrap();
    // let merkle_root = tree.root();

    // receiver
    let mut sk = [0u8; 32];
    rng.fill_bytes(&mut sk);
    let (receiver, receiver_pub_info, _receiver_priv_info) =
        make_coin(&commit_param, sk, 100, &mut rng);

    // transfer circuit
    let circuit = TransferCircuit {
        commit_param,
        hash_param,
        sender_coin: sender,
        sender_pub_info,
        sender_priv_info,
        receiver_coin: receiver,
        receiver_pub_info,
        list: ledger,
    };

    let sanity_cs = ConstraintSystem::<Fq>::new_ref();
    circuit
        .clone()
        .generate_constraints(sanity_cs.clone())
        .unwrap();
    assert!(sanity_cs.is_satisfied().unwrap());

    let mut rng = ChaCha20Rng::from_seed(crate::param::ZKPPARAMSEED);
    let pk = generate_random_parameters::<Bls12_381, _, _>(circuit, &mut rng).unwrap();
    let mut pk_bytes: Vec<u8> = Vec::new();

    pk.serialize(&mut pk_bytes).unwrap();
    pk_bytes
}

pub fn manta_verify_zkp(
    key_bytes: Vec<u8>,
    proof: [u8; 192],
    sn_old: [u8; 32],
    k_old: [u8; 32],
    k_new: [u8; 32],
    cm_new: [u8; 32],
    _merkle_root: [u8; 32],
) -> bool {
    let vk = Groth16VK::deserialize(key_bytes.as_ref()).unwrap();
    let pvk = Groth16PVK::from(vk);
    let proof = Groth16Proof::deserialize(proof.as_ref()).unwrap();
    let k_old = PrivCoinCommitmentOutput::deserialize(k_old.as_ref()).unwrap();
    let k_new = PrivCoinCommitmentOutput::deserialize(k_new.as_ref()).unwrap();
    let cm_new = PrivCoinCommitmentOutput::deserialize(cm_new.as_ref()).unwrap();

    // let _merkle_root = HashOutput::deserialize(merkle_root.as_ref()).unwrap();

    let mut inputs = [k_old.x, k_old.y, k_new.x, k_new.y, cm_new.x, cm_new.y].to_vec();
    let sn: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(sn_old.as_ref()).unwrap();
    inputs = [inputs[..].as_ref(), sn.as_ref()].concat();

    verify_proof(&pvk, &proof, &inputs[..]).unwrap()
}

pub fn make_coin<R: RngCore + CryptoRng>(
    commit_param: &PrivCoinCommitmentParam,
    sk: [u8; 32],
    value: u64,
    rng: &mut R,
) -> (MantaCoin, MantaCoinPubInfo, MantaCoinPrivInfo) {
    //  sample a random rho
    let mut rho = [0u8; 32];
    rng.fill_bytes(&mut rho);

    // pk = PRF(sk, 0); which is also the address
    let pk = <Blake2s as PRF>::evaluate(&sk, &[0u8; 32]).unwrap();

    // sn = PRF(sk, rho)
    let sn = <Blake2s as PRF>::evaluate(&sk, &rho).unwrap();

    // k = com(pk||rho, r)
    let buf = [pk, rho].concat();

    let r = Fr::rand(rng);
    let mut r_bytes = [0u8; 32];
    r.serialize(r_bytes.as_mut()).unwrap();
    let r = Randomness(r);

    let k = PrivCoinCommitmentScheme::commit(&commit_param, &buf, &r).unwrap();
    let mut k_bytes = [0u8; 32];
    k.serialize(k_bytes.as_mut()).unwrap();

    // cm = com(v||k, s)
    let buf: Vec<u8> = [value.to_le_bytes().as_ref(), k_bytes.clone().as_ref()].concat();

    let s = Fr::rand(rng);
    let mut s_bytes = [0u8; 32];
    s.serialize(s_bytes.as_mut()).unwrap();
    let s = Randomness(s);

    let cm = PrivCoinCommitmentScheme::commit(&commit_param, &buf, &s).unwrap();
    let mut cm_bytes = [0u8; 32];
    cm.serialize(cm_bytes.as_mut()).unwrap();

    let coin = MantaCoin {
        cm_bytes,
    };
    let pub_info = MantaCoinPubInfo {
        pk,
        rho,
        s: s_bytes,
        r: r_bytes,
        k: k_bytes,
    };
    let priv_info = MantaCoinPrivInfo { sk, sn, value };
    (coin, pub_info, priv_info)
}
