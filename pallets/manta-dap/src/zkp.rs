use crate::priv_coin::*;
use crate::types::*;
use crate::MantaCoin;
use ark_crypto_primitives::commitment::pedersen::Randomness;
use ark_crypto_primitives::prf::blake2s::constraints::Blake2sGadget;
use ark_crypto_primitives::prf::PRFGadget;
use ark_crypto_primitives::CommitmentGadget;
use ark_crypto_primitives::PathVar;
use ark_ed_on_bls12_381::constraints::FqVar;
use ark_ed_on_bls12_381::EdwardsProjective;
use ark_ed_on_bls12_381::Fq;
use ark_ed_on_bls12_381::Fr;
use ark_ff::ToBytes;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
// =============================
// circuit for the following statements
// 1. both sender's and receiver's coins are well-formed
//  1.1 k = com(pk||rho, r)
//  1.2 cm = com(v||k, s)
// where both k and cm are public
// 2. address and the secret key derives public key
//  sender.pk = PRF(sender_sk, [0u8;32])
// 3. sender's commitment is in List_all
//  NOTE: we de not need to prove that sender's sn is not in List_USD
//        this can be done in the public
// 4. sender's and receiver's value are the same
// =============================
#[derive(Clone)]
pub struct TransferCircuit {
    // param
    pub(crate) commit_param: PrivCoinCommitmentParam,
    pub(crate) hash_param: HashParam,

    // sender
    pub(crate) sender_coin: MantaCoin,
    pub(crate) sender_pub_info: MantaCoinPubInfo,
    pub(crate) sender_priv_info: MantaCoinPrivInfo,

    // receiver
    pub(crate) receiver_coin: MantaCoin,
    pub(crate) receiver_pub_info: MantaCoinPubInfo,

    // ledger
    pub(crate) list: Vec<[u8; 32]>,
}

impl ConstraintSynthesizer<Fq> for TransferCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError> {
        // 1. both sender's and receiver's coins are well-formed
        //  k = com(pk||rho, r)
        //  cm = com(v||k, s)

        // parameters
        let parameters_var = PrivCoinCommitmentParamVar::new_input(
            ark_relations::ns!(cs, "gadget_parameters"),
            || Ok(&self.commit_param),
        )
        .unwrap();

        token_well_formed_circuit_helper(
            true,
            &parameters_var,
            &self.sender_coin,
            &self.sender_pub_info,
            cs.clone(),
        );

        token_well_formed_circuit_helper(
            false,
            &parameters_var,
            &self.receiver_coin,
            &self.receiver_pub_info,
            cs.clone(),
        );

        // 2. address and the secret key derives public key
        //  sender.pk = PRF(sender_sk, [0u8;32])
        //  sender.sn = PRF(sender_sk, rho)
        prf_circuit_helper(
            &self.sender_priv_info.sk,
            &[0u8; 32],
            &self.sender_coin.pk,
            cs.clone(),
        );
        prf_circuit_helper(
            &self.sender_priv_info.sk,
            &self.sender_pub_info.rho,
            &self.sender_priv_info.sn,
            cs.clone(),
        );

        // // 3. sender's commitment is in List_all
        // merkle_membership_circuit_proof(
        //     &self.hash_param,
        //     &self.sender_coin.cm,
        //     &self.list,
        //     cs.clone(),
        // );

        // 4. sender's and receiver's value are the same
        let sender_value_fq = Fq::from(self.sender_coin.value);
        let sender_value_var = FqVar::new_witness(ark_relations::ns!(cs, "sender value"), || {
            Ok(&sender_value_fq)
        })
        .unwrap();

        let receiver_value_fq = Fq::from(self.receiver_coin.value);
        let receiver_value_var =
            FqVar::new_witness(ark_relations::ns!(cs, "receiver value"), || {
                Ok(&receiver_value_fq)
            })
            .unwrap();

        sender_value_var.enforce_equal(&receiver_value_var).unwrap();

        Ok(())
    }
}

// =============================
// circuit for the following statements
// 1. k = com(pk||rho, r)
// 2. cm = com(v||k, s)
// where both k and cm are public
// =============================
fn token_well_formed_circuit_helper(
    is_sender: bool,
    parameters_var: &PrivCoinCommitmentParamVar,
    coin: &MantaCoin,
    pub_info: &MantaCoinPubInfo,
    cs: ConstraintSystemRef<Fq>,
) {
    // =============================
    // statement 1: k = com(pk||rho, r)
    // =============================
    let input: Vec<u8> = [coin.pk.as_ref(), pub_info.rho.as_ref()].concat();
    let mut input_var = Vec::new();
    for byte in &input {
        input_var.push(UInt8::new_witness(cs.clone(), || Ok(*byte)).unwrap());
    }

    // openning
    let r = Fr::deserialize(pub_info.r.as_ref()).unwrap();
    let r = Randomness::<EdwardsProjective>(r);
    let randomness_var =
        PrivCoinCommitmentOpenVar::new_witness(ark_relations::ns!(cs, "gadget_randomness"), || {
            Ok(&r)
        })
        .unwrap();

    // commitment
    let result_var =
        PrivCoinCommitmentSchemeVar::commit(&parameters_var, &input_var, &randomness_var).unwrap();

    // // circuit to compare the commited value with supplied value
    // let k = PrivCoinCommitmentOutput::deserialize(pub_info.k.as_ref()).unwrap();
    // let commitment_var2 =
    //     PrivCoinCommitmentOutputVar::new_input(ark_relations::ns!(cs, "gadget_commitment"), || {
    //         Ok(&k)
    //     })
    //     .unwrap();
    // result_var.enforce_equal(&commitment_var2).unwrap();

    // =============================
    // statement 2: cm = com(v||k, s)
    // =============================
    let mut input: Vec<u8> = coin.value.to_le_bytes().to_vec();
    pub_info.k.serialize(&mut input).unwrap();
    let mut input_var = Vec::new();
    for byte in &input {
        input_var.push(UInt8::new_witness(cs.clone(), || Ok(*byte)).unwrap());
    }

    // openning
    let s = Randomness::<EdwardsProjective>(Fr::deserialize(pub_info.s.as_ref()).unwrap());
    let randomness_var =
        PrivCoinCommitmentOpenVar::new_witness(ark_relations::ns!(cs, "gadget_randomness"), || {
            Ok(&s)
        })
        .unwrap();

    // commitment
    let result_var: PrivCoinCommitmentOutputVar =
        PrivCoinCommitmentSchemeVar::commit(&parameters_var, &input_var, &randomness_var).unwrap();

    // the other commitment
    let cm: PrivCoinCommitmentOutput =
        PrivCoinCommitmentOutput::deserialize(coin.cm_bytes.as_ref()).unwrap();
    // // if the commitment is from the sender, then the commitment is hidden
    // // else, it is public
    // let commitment_var2 = if is_sender {
    //     PrivCoinCommitmentOutputVar::new_witness(
    //         ark_relations::ns!(cs, "gadget_commitment"),
    //         || Ok(&cm),
    //     )
    //     .unwrap()
    // } else {
    //     PrivCoinCommitmentOutputVar::new_input(ark_relations::ns!(cs, "gadget_commitment"), || {
    //         Ok(&cm)
    //     })
    //     .unwrap()
    // };

    // // circuit to compare the commited value with supplied value
    // result_var.enforce_equal(&commitment_var2).unwrap();
}

fn prf_circuit_helper(
    seed: &[u8; 32],
    input: &[u8; 32],
    output: &[u8; 32],
    cs: ConstraintSystemRef<Fq>,
) {
    // step 1. Allocate seed
    let seed_var = Blake2sGadget::new_seed(cs.clone(), &seed);

    // step 2. Allocate inputs
    let input_var = UInt8::new_witness_vec(ark_relations::ns!(cs, "declare_input"), input).unwrap();

    // step 3. Allocate evaluated output
    let output_var = Blake2sGadget::evaluate(&seed_var, &input_var).unwrap();

    // step 4. Actual output
    let actual_out_var = <Blake2sGadget as PRFGadget<_, Fq>>::OutputVar::new_input(
        ark_relations::ns!(cs, "declare_output"),
        || Ok(output),
    )
    .unwrap();

    // step 5. compare the outputs
    output_var.enforce_equal(&actual_out_var).unwrap();
}

#[allow(dead_code)]
fn merkle_membership_circuit_proof(
    param: &HashParam,
    cm: &PrivCoinCommitmentOutput,
    list: &[PrivCoinCommitmentOutput],
    cs: ConstraintSystemRef<Fq>,
) {
    // check if cm is in or not; if cm is not in, panic!
    let index = list.iter().position(|x| x == cm).unwrap();

    // build the merkle tree
    let tree = LedgerMerkleTree::new(param.clone(), &list).unwrap();
    let merkle_root = tree.root();
    let path = tree.generate_proof(index, &cm).unwrap();

    // Allocate Merkle Tree Root
    let root_var =
        HashOutputVar::new_input(ark_relations::ns!(cs, "new_digest"), || Ok(merkle_root)).unwrap();

    // Allocate Parameters for CRH
    let param_var =
        HashParamVar::new_constant(ark_relations::ns!(cs, "new_parameter"), param).unwrap();

    // Allocate Merkle Tree Path
    let membership_var =
        PathVar::<_, HashVar, _>::new_witness(ark_relations::ns!(cs, "new_witness"), || Ok(&path))
            .unwrap();

    // Allocate Leaf
    // FIXME: account commitment is already a hashed element
    // we should use it directly, rather than serialize it again
    let mut buf: Vec<u8> = Vec::new();
    cm.serialize(&mut buf).unwrap();

    let leaf_g = UInt8::constant_vec(&buf);
    let leaf_g: &[_] = leaf_g.as_slice();

    // check membership
    membership_var
        .check_membership(&param_var, &root_var, &leaf_g)
        .unwrap()
        .enforce_equal(&Boolean::TRUE)
        .unwrap();
}
