use ark_crypto_primitives::commitment::pedersen::Commitment;
use ark_crypto_primitives::commitment::pedersen::Window;
use ark_crypto_primitives::crh::pedersen::CRH;
use ark_crypto_primitives::crh::FixedLengthCRH;
use ark_crypto_primitives::merkle_tree::Config;
use ark_crypto_primitives::merkle_tree::Digest;
use ark_crypto_primitives::merkle_tree::Path;
use ark_crypto_primitives::prf::Blake2s;
use ark_crypto_primitives::signature::schnorr;
use ark_crypto_primitives::CommitmentScheme;
use ark_crypto_primitives::MerkleTree;
use ark_ed_on_bls12_381::EdwardsProjective;
// use blake2::Blake2s;

// //=======================
// // ed25519 signature and related definitions
// //=======================
// // #[allow(dead_code)]
// // pub(crate) type Ed25519Param = String;
// #[allow(dead_code)]
// pub(crate) type Ed25519PK = ed25519_dalek::PublicKey;
// #[allow(dead_code)]
// pub(crate) type Ed25519SK = ed25519_dalek::SecretKey;
// #[allow(dead_code)]
// pub(crate) type Ed25519Keypair = ed25519_dalek::Keypair;
// #[allow(dead_code)]
// pub(crate) type Ed25519Sig = ed25519_dalek::Signature;

//=======================
// schnorr signature and related definitions
//=======================
#[allow(dead_code)]
pub(crate) type SchnorrParam = schnorr::Parameters<EdwardsProjective, Blake2s>;
pub(crate) type SchnorrPK = schnorr::PublicKey<EdwardsProjective>;
pub(crate) type SchnorrSK = schnorr::SecretKey<EdwardsProjective>;
#[derive(Clone)]
pub(crate) struct SchnorrKeypair {
    pub(crate) public: SchnorrPK,
    pub(crate) private: SchnorrSK,
}
#[allow(dead_code)]
pub(crate) type SchnorrSig = schnorr::Signature<EdwardsProjective>;

//=======================
// pedersen hash and related defintions
// the hash function is defined over the JubJub curve
//=======================
const PERDERSON_WINDOW_SIZE: usize = 4;
const PERDERSON_WINDOW_NUM: usize = 256;

// #leaves = 2^{height - 1}
#[allow(dead_code)]
const MAX_ACC: usize = 512;
const MAX_ACC_TREE_DEPTH: usize = 10;

#[derive(Clone)]
pub struct PedersenWindow;
impl Window for PedersenWindow {
    const WINDOW_SIZE: usize = PERDERSON_WINDOW_SIZE;
    const NUM_WINDOWS: usize = PERDERSON_WINDOW_NUM;
}
pub type Hash = CRH<EdwardsProjective, PedersenWindow>;
#[allow(dead_code)]
pub type HashOutput = <Hash as FixedLengthCRH>::Output;
pub type HashParam = <Hash as FixedLengthCRH>::Parameters;

//=======================
// merkle tree for the ledger, using Perderson hash
//=======================
#[derive(Debug, Clone, Copy)]
pub struct MerkleTreeParams;
impl Config for MerkleTreeParams {
    const HEIGHT: usize = MAX_ACC_TREE_DEPTH;
    type H = Hash;
}
pub type LedgerMerkleTree = MerkleTree<MerkleTreeParams>;
#[allow(dead_code)]
pub type LedgerMerkleTreeRoot = Digest<MerkleTreeParams>;

// the membership is a path on the merkle tree, including the leaf itself
#[allow(dead_code)]
pub type PrivCoinAccountMembership = Path<MerkleTreeParams>;

//=======================
// Commitments
//=======================
pub type PrivCoinCommitmentScheme = Commitment<EdwardsProjective, PedersenWindow>;
pub type PrivCoinCommitmentParam = <PrivCoinCommitmentScheme as CommitmentScheme>::Parameters;
pub type PrivCoinCommitmentOpen = <PrivCoinCommitmentScheme as CommitmentScheme>::Randomness;
pub type PrivCoinCommitmentOutput = <PrivCoinCommitmentScheme as CommitmentScheme>::Output;
