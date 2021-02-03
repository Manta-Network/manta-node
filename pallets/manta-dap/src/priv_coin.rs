use crate::crypto_types::*;
use crate::zkp::TransferCircuit;
use crate::zkp_types::*;
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
use ark_ff::UniformRand;
use ark_ff::{FromBytes, ToBytes};
use ark_groth16::create_random_proof;
use ark_groth16::{generate_random_parameters, verify_proof};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_relations::r1cs::ConstraintSystem;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_core::CryptoRng;
use rand_core::RngCore;

pub trait PrivCoin {
    type Address;
    type Param;
    type Coin;
    type SK;
    type Mint;
    type Transfer;
    type ZKProvingKey;

    // Minting process does not concern any ZKP
    fn mint<R: RngCore + CryptoRng>(
        param: &Self::Param,
        sk: &[u8; 32],
        value: u32,
        rng: &mut R,
    ) -> (Self::Coin, Self::SK, Self::Mint);

    fn transfer<R: RngCore + CryptoRng>(
        param: &Self::Param,
        proving_key: &Self::ZKProvingKey,
        sender: &Self::Coin,
        sender_sk: &Self::SK,
        receiver: &Self::Address,
        ledger: Vec<PrivCoinCommitmentOutput>,
        rng: &mut R,
    ) -> (Self::Coin, Self::Transfer);
}

#[derive(Debug, Clone)]
pub struct Coin {
    pub pk: [u8; 32],
    pub rho: [u8; 32],
    pub r: PrivCoinCommitmentOpen,
    pub s: PrivCoinCommitmentOpen,
    pub k: PrivCoinCommitmentOutput,
    pub cm: PrivCoinCommitmentOutput,
    pub value: u32,
}

#[derive(Debug, Clone)]
pub struct CoinPrivateInfo {
    pub sk: [u8; 32],
    pub sn: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct TxMint {
    value: u32,
    k: PrivCoinCommitmentOutput,
    s: PrivCoinCommitmentOpen,
    cm: PrivCoinCommitmentOutput,
}
#[derive(Clone)]
pub struct Param {
    pub commit_param: PrivCoinCommitmentParam,
    pub hash_param: HashParam,
}

#[derive(Debug, Clone)]
pub struct Transfer {
    pub proof: Groth16Proof,
}

pub struct Manta;

#[allow(dead_code)]
pub fn comm_encode(cm: &PrivCoinCommitmentOutput) -> [u8; 64] {
    let mut res = [0u8; 64];

    cm.serialize(res.as_mut()).unwrap();
    res
}

#[allow(dead_code)]
pub fn comm_decode(bytes: &[u8; 64]) -> PrivCoinCommitmentOutput {
    PrivCoinCommitmentOutput::deserialize(bytes.as_ref()).unwrap()
}

pub fn comm_open(param_seed: &[u8; 32], r: &[u8; 32], payload: &[u8], cm: &[u8; 64]) -> bool {
    let mut rng = ChaCha20Rng::from_seed(*param_seed);
    let param = PrivCoinCommitmentScheme::setup(&mut rng).unwrap();

    let open = Randomness(Fr::read(r.as_ref()).unwrap());
    let cm = PrivCoinCommitmentOutput::read(cm.as_ref()).unwrap();
    PrivCoinCommitmentScheme::commit(&param, payload, &open).unwrap() == cm
}

pub fn merkle_root(param_seed: &[u8; 32], payload: &[MantaCoin]) -> MantaLedgerState {
    let mut rng = ChaCha20Rng::from_seed(*param_seed);
    let param = Hash::setup(&mut rng).unwrap();

    let leaf: Vec<PrivCoinCommitmentOutput> = payload
        .iter()
        .map(|x| PrivCoinCommitmentOutput::read(x.cm.as_ref()).unwrap())
        .collect();

    let tree = LedgerMerkleTree::new(param, &leaf).unwrap();
    let root = tree.root();
    let mut bytes = [0u8; 64];
    root.write(bytes.as_mut()).unwrap();

    MantaLedgerState { state: bytes }
}

pub fn manta_zkp_vk_gen(commit_param_seed: &[u8; 32], hash_param_seed: &[u8; 32]) -> Vec<u8> {
    // rebuild the parameters from the inputs
    let mut rng = ChaCha20Rng::from_seed(*commit_param_seed);
    let commit_param = PrivCoinCommitmentScheme::setup(&mut rng).unwrap();

    let mut rng = ChaCha20Rng::from_seed(*hash_param_seed);
    let hash_param = Hash::setup(&mut rng).unwrap();

    let param = Param {
        commit_param,
        hash_param,
    };

    // we build a moke ledger of 128 users with a default seed [3; 32]
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let mut coins = Vec::new();
    let mut sks = Vec::new();
    let mut ledger = Vec::new();

    for e in 0..128 {
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);
        let (coin, sk, _mint) = <Manta as PrivCoin>::mint(&param, &sk, e + 100, &mut rng);

        ledger.push(coin.cm);
        coins.push(coin);
        sks.push(sk);
    }

    // sender
    let sender = coins[0].clone();
    let sender_sk = sks[0].clone();

    // we do not need to build merkle tree here; circuit does it.
    // // build the merkle tree
    // let tree = LedgerMerkleTree::new(param.hash_param.clone(), &ledger).unwrap();
    // let merkle_root = tree.root();

    // receiver
    let mut sk = [0u8; 32];
    rng.fill_bytes(&mut sk);
    let (receiver, _receiver_sk, _mint) = <Manta as PrivCoin>::mint(&param, &sk, 100, &mut rng);

    // transfer circuit
    let circuit = TransferCircuit {
        param: param.clone(),
        sender: sender.clone(),
        sender_sk: sender_sk.clone(),
        receiver: receiver.clone(),
        list: ledger.clone(),
    };

    let sanity_cs = ConstraintSystem::<Fq>::new_ref();
    circuit
        .clone()
        .generate_constraints(sanity_cs.clone())
        .unwrap();
    assert!(sanity_cs.is_satisfied().unwrap());

    let pk = generate_random_parameters::<Bls12_381, _, _>(circuit.clone(), &mut rng).unwrap();
    let vk: Groth16VK = pk.vk;
    let mut vk_bytes: Vec<u8> = Vec::new();

    vk.serialize(&mut vk_bytes).unwrap();
    vk_bytes
}

pub fn manta_verify_zkp(
    vk_bytes: Vec<u8>,
    proof: [u8; 196],
    sn_old: [u8; 32],
    pk_old: [u8; 32],
    k_old: [u8; 64],
    k_new: [u8; 64],
    cm_new: [u8; 64],
    merkle_root: [u8; 64],
) -> bool {
    let vk = Groth16VK::deserialize(vk_bytes.as_ref()).unwrap();
    let pvk = Groth16PVK::from(vk);
    let proof = Groth16Proof::deserialize(proof.as_ref()).unwrap();
    let k_old = PrivCoinCommitmentOutput::read(k_old.as_ref()).unwrap();
    let k_new = PrivCoinCommitmentOutput::read(k_new.as_ref()).unwrap();
    let cm_new = PrivCoinCommitmentOutput::read(cm_new.as_ref()).unwrap();
    let _merkle_root = HashOutput::read(merkle_root.as_ref()).unwrap();
    
    let mut inputs = [
        k_old.x,
        k_old.y,
        k_new.x,
        k_new.y,
        cm_new.x,
        cm_new.y,
    ].to_vec();

    for e in sn_old.iter() {
        let mut f = *e;
        for _ in 0..8 {
            inputs.push((f & 0b1).into());
            f = f >> 1;
        }
    }

    for e in pk_old.iter() {
        let mut f = *e;
        for _ in 0..8 {
            inputs.push((f & 0b1).into());
            f = f >> 1;
        }
    }

    verify_proof(&pvk, &proof, &inputs[..]).unwrap()
}

impl PrivCoin for Manta {
    type Param = Param;
    type ZKProvingKey = Groth16PK;
    type Coin = Coin;
    type SK = CoinPrivateInfo;
    type Mint = TxMint;
    type Address = [u8; 32];
    type Transfer = Transfer;

    fn mint<R: RngCore + CryptoRng>(
        param: &Self::Param,
        sk: &[u8; 32],
        value: u32,
        rng: &mut R,
    ) -> (Self::Coin, Self::SK, Self::Mint) {
        // sample a random rho
        let mut rho = [0u8; 32];
        rng.fill_bytes(&mut rho);

        // pk = PRF(sk, 0); which is also the address
        let pk = <Blake2s as PRF>::evaluate(sk, &[0u8; 32]).unwrap();

        // sn = PRF(sk, rho)
        let sn = <Blake2s as PRF>::evaluate(sk, &rho).unwrap();

        // k = com(pk||rho, r)
        let buf = [pk, rho].concat();
        let r = Fr::rand(rng);
        let r = Randomness(r);
        let k = PrivCoinCommitmentScheme::commit(&param.commit_param, &buf, &r).unwrap();

        // cm = com(v||k, s)
        let mut buf: Vec<u8> = value.to_le_bytes().to_vec();
        k.write(&mut buf).unwrap();
        let s = Fr::rand(rng);
        let s = Randomness(s);
        let cm = PrivCoinCommitmentScheme::commit(&param.commit_param, &buf, &s).unwrap();

        let coin = Self::Coin {
            pk,
            value,
            rho,
            k,
            r,
            s: s.clone(),
            cm,
        };
        let spending_key = Self::SK { sk: *sk, sn };

        (coin, spending_key, TxMint { value, k, s, cm })
    }

    fn transfer<R: RngCore + CryptoRng>(
        param: &Self::Param,
        proving_key: &Self::ZKProvingKey,
        sender: &Self::Coin,
        sender_sk: &Self::SK,
        receiver: &Self::Address,
        ledger: Vec<PrivCoinCommitmentOutput>,
        rng: &mut R,
    ) -> (Self::Coin, Self::Transfer) {
        // sample a random rho
        let mut rho = [0u8; 32];
        rng.fill_bytes(&mut rho);

        // k = com(pk||rho, r)
        let buf = [*receiver, rho].concat();
        let r = Fr::rand(rng);
        let r = Randomness(r);
        let k = PrivCoinCommitmentScheme::commit(&param.commit_param, &buf, &r).unwrap();

        // cm = com(v||k, s)
        let mut buf: Vec<u8> = sender.value.to_le_bytes().to_vec();
        k.write(&mut buf).unwrap();
        let s = Fr::rand(rng);
        let s = Randomness(s);
        let cm = PrivCoinCommitmentScheme::commit(&param.commit_param, &buf, &s).unwrap();

        let new_coin = Self::Coin {
            pk: *receiver,
            value: sender.value,
            rho,
            k,
            r,
            s,
            cm,
        };

        // build the circuit
        let circuit = TransferCircuit {
            param: param.clone(),
            sender: sender.clone(),
            sender_sk: sender_sk.clone(),
            receiver: new_coin.clone(),
            list: ledger,
        };

        let proof = create_random_proof(circuit, &proving_key, rng).unwrap();
        let tx = Transfer { proof };

        (new_coin, tx)
    }
}
