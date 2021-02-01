use crate::crypto_types::*;
use crate::zkp::TransferCircuit;
use crate::zkp_types::*;
use crate::PrivCoin;
use ark_crypto_primitives::commitment::pedersen::Randomness;
use ark_crypto_primitives::prf::Blake2s;
use ark_crypto_primitives::prf::PRF;
use ark_crypto_primitives::CommitmentScheme;
use ark_ed_on_bls12_381::Fr;
use ark_ff::ToBytes;
use ark_ff::UniformRand;
use ark_groth16::create_random_proof;
use ark_std::vec::Vec;
use rand::RngCore;
use rand_core::CryptoRng;

#[derive(Debug, Clone, Default)]
pub struct Coin {
    pub pk: [u8; 32],
    pub rho: [u8; 32],
    pub r: PrivCoinCommitmentOpen,
    pub s: PrivCoinCommitmentOpen,
    pub k: PrivCoinCommitmentOutput,
    pub cm: PrivCoinCommitmentOutput,
    pub value: u32,
}

#[derive(Debug, Clone, Default)]
pub struct CoinPrivateInfo {
    pub sk: [u8; 32],
    sn: [u8; 32],
}

#[derive(Debug, Clone, Default)]
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

#[derive(Debug, Clone, Default)]
pub struct Transfer {
    pub proof: Groth16Proof,
}

pub struct Manta;

/// TODO: by zhenfei
pub fn comm_encode(cm: PrivCoinCommitmentOutput) -> [u8; 64] {
    [0u8; 64]
}

/// TODO: by zhenfei
pub fn comm_decode(bytes: [u8; 64]) -> PrivCoinCommitmentOutput {
    PrivCoinCommitmentOutput::default()
}

/// TODO: by zhenfei
pub fn comm_open(r: [u8; 32], payload: &[u8], cm: [u8; 64]) -> bool {
    true
}

/// TODO: by zhenfei
/// TODO: figure out how to do hash param
pub fn merkle_root(payload: Vec<[u8; 64]>) -> [u8; 64] {
    [0u8; 64]
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
