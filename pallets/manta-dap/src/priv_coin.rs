use crate::crypto_types::*;
use crate::zkp::TransferCircuit;
use crate::zkp_types::*;
use crate::PrivCoin;
use ark_crypto_primitives::commitment::pedersen::Randomness;
use ark_crypto_primitives::prf::Blake2s;
use ark_crypto_primitives::prf::PRF;
use ark_crypto_primitives::CommitmentScheme;
use ark_crypto_primitives::FixedLengthCRH;
use ark_ed_on_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_ff::{FromBytes, ToBytes};
use ark_groth16::create_random_proof;
use ark_std::vec::Vec;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_core::CryptoRng;
use rand_core::RngCore;

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
    sn: [u8; 32],
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

pub fn comm_encode(cm: &PrivCoinCommitmentOutput) -> [u8; 64] {
    let mut res = [0u8; 64];
    cm.write(res.as_mut()).unwrap();
    res
}

pub fn comm_decode(bytes: &[u8; 64]) -> PrivCoinCommitmentOutput {
    PrivCoinCommitmentOutput::read(bytes.as_ref()).unwrap()
}

pub fn comm_open(r: &[u8; 32], payload: &[u8], cm: &[u8; 64]) -> bool {
    // for now the parameters is generated from a fixed seed
    // FIXME: store the seed or param in the ledger
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let param = PrivCoinCommitmentScheme::setup(&mut rng).unwrap();

    let open = Randomness(Fr::read(r.as_ref()).unwrap());
    let cm = PrivCoinCommitmentOutput::read(cm.as_ref()).unwrap();
    PrivCoinCommitmentScheme::commit(&param, payload, &open).unwrap() == cm
}

pub fn merkle_root(payload: Vec<[u8; 64]>) -> [u64; 8] {
    // for now the parameters is generated from a fixed seed
    // FIXME: store the seed or param in the ledger
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let param = Hash::setup(&mut rng).unwrap();

    let leaf: Vec<PrivCoinCommitmentOutput> = payload
        .iter()
        .map(|x| PrivCoinCommitmentOutput::read(x.as_ref()).unwrap())
        .collect();

    let tree = LedgerMerkleTree::new(param, &leaf).unwrap();
    let root = tree.root();
    let mut bytes = [0u8; 32];
    root.write(bytes.as_mut()).unwrap();

    // TODO: find a better way to implement this without std
    let mut res = [0u64; 8];
    res[0] = (bytes[0] as u64)
        + ((bytes[1] as u64) << 8)
        + ((bytes[2] as u64) << 16)
        + ((bytes[3] as u64) << 24)
        + ((bytes[4] as u64) << 32)
        + ((bytes[5] as u64) << 40)
        + ((bytes[6] as u64) << 48)
        + ((bytes[7] as u64) << 56);
    res[1] = (bytes[8] as u64)
        + ((bytes[9] as u64) << 8)
        + ((bytes[10] as u64) << 16)
        + ((bytes[11] as u64) << 24)
        + ((bytes[12] as u64) << 32)
        + ((bytes[13] as u64) << 40)
        + ((bytes[14] as u64) << 48)
        + ((bytes[15] as u64) << 56);
    res[2] = (bytes[16] as u64)
        + ((bytes[17] as u64) << 8)
        + ((bytes[18] as u64) << 16)
        + ((bytes[19] as u64) << 24)
        + ((bytes[20] as u64) << 32)
        + ((bytes[21] as u64) << 40)
        + ((bytes[22] as u64) << 48)
        + ((bytes[23] as u64) << 56);
    res[3] = (bytes[24] as u64)
        + ((bytes[25] as u64) << 8)
        + ((bytes[26] as u64) << 16)
        + ((bytes[27] as u64) << 24)
        + ((bytes[28] as u64) << 32)
        + ((bytes[29] as u64) << 40)
        + ((bytes[30] as u64) << 48)
        + ((bytes[31] as u64) << 56);
    res
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
