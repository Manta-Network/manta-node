use crate::crypto_types::*;
use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::commitment::pedersen::constraints::CommGadget;
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
