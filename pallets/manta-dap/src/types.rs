use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::commitment::pedersen::constraints::CommGadget;
use ark_crypto_primitives::commitment::pedersen::Commitment;
use ark_crypto_primitives::commitment::pedersen::Window;
use ark_crypto_primitives::crh::pedersen::CRH;
use ark_crypto_primitives::crh::FixedLengthCRH;
use ark_crypto_primitives::merkle_tree::Config;
use ark_crypto_primitives::merkle_tree::Digest;
use ark_crypto_primitives::merkle_tree::Path;
use ark_crypto_primitives::CommitmentScheme;
use ark_crypto_primitives::MerkleTree;
use ark_crypto_primitives::SNARK;
use ark_crypto_primitives::{
    crh::{pedersen::constraints::CRHGadget, FixedLengthCRHGadget},
    *,
};
use ark_ed_on_bls12_381::constraints::EdwardsVar;
use ark_ed_on_bls12_381::EdwardsParameters;
use ark_ed_on_bls12_381::EdwardsProjective;
use ark_ed_on_bls12_381::Fq;
use ark_groth16::Groth16;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;
use frame_support::codec::{Decode, Encode};

/// a MantaCoin is a pair of commitment cm, where
///  * cm = com(v||k, s), commits to the value, and
#[derive(Encode, Debug, Decode, Clone, Default, PartialEq)]
pub struct MantaCoin {
    pub cm_bytes: [u8; 32],
}

/// the state of the ledger is a root of the merkle tree
/// where the leafs are the MantaCoins
#[derive(Encode, Decode, Clone, Default, PartialEq)]
pub struct MantaLedgerState {
    pub state: [u8; 32],
}

#[derive(Encode, Decode, Default, Clone, PartialEq)]
pub struct MantaCoinPubInfo {
    pub pk: [u8; 32],
    pub rho: [u8; 32],
    pub s: [u8; 32],
    pub r: [u8; 32],
    pub k: [u8; 32],
}

#[derive(Encode, Decode, Default, Clone, PartialEq)]
pub struct MantaCoinPrivInfo {
    pub value: u64,
    pub sk: [u8; 32],
    pub sn: [u8; 32],
}

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
#[allow(dead_code)]
pub type PrivCoinCommitmentOpen = <PrivCoinCommitmentScheme as CommitmentScheme>::Randomness;
pub type PrivCoinCommitmentOutput = <PrivCoinCommitmentScheme as CommitmentScheme>::Output;

// gadgets for hash function
pub type HashVar = CRHGadget<EdwardsProjective, EdwardsVar, PedersenWindow>;
pub type HashOutputVar = <HashVar as FixedLengthCRHGadget<Hash, Fq>>::OutputVar;
pub type HashParamVar = <HashVar as FixedLengthCRHGadget<Hash, Fq>>::ParametersVar;

// gadget for private coin account membership
#[allow(dead_code)]
pub type PrivCoinAccountMembershipVar = PathVar<MerkleTreeParams, HashVar, Fq>;

//=======================
// ZK proofs over BLS curve
//=======================
#[allow(dead_code)]
pub type Groth16PK = <Groth16<Bls12_381> as SNARK<Fq>>::ProvingKey;
#[allow(dead_code)]
pub type Groth16PVK = <Groth16<Bls12_381> as SNARK<Fq>>::ProcessedVerifyingKey;
#[allow(dead_code)]
pub type Groth16VK = <Groth16<Bls12_381> as SNARK<Fq>>::VerifyingKey;
pub type Groth16Proof = <Groth16<Bls12_381> as SNARK<Fq>>::Proof;

//=======================
// Commitments
//=======================
pub type PrivCoinCommitmentSchemeVar = CommGadget<EdwardsProjective, EdwardsVar, PedersenWindow>;
pub type PrivCoinCommitmentParamVar =
    <PrivCoinCommitmentSchemeVar as CommitmentGadget<PrivCoinCommitmentScheme, Fq>>::ParametersVar;
pub type PrivCoinCommitmentOpenVar =
    <PrivCoinCommitmentSchemeVar as CommitmentGadget<PrivCoinCommitmentScheme, Fq>>::RandomnessVar;
pub type PrivCoinCommitmentOutputVar = AffineVar<EdwardsParameters, FpVar<Fq>>;
