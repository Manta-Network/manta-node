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
            true,
            &self.sender_priv_info.sk,
            &[0u8; 32],
            &self.sender_pub_info.pk,
            cs.clone(),
        );
        prf_circuit_helper(
            false,
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
// for the sender, the cm is hidden and k is public
// for the receiver, both are public
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
    let input: Vec<u8> = [pub_info.pk.as_ref(), pub_info.rho.as_ref()].concat();
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

    // circuit to compare the commited value with supplied value
    let k = PrivCoinCommitmentOutput::deserialize(pub_info.k.as_ref()).unwrap();
    let commitment_var2 =
        PrivCoinCommitmentOutputVar::new_input(ark_relations::ns!(cs, "gadget_commitment"), || {
            Ok(k)
        })
        .unwrap();
    result_var.enforce_equal(&commitment_var2).unwrap();

    // =============================
    // statement 2: cm = com(v||k, s)
    // =============================
    let input: Vec<u8> = [coin.value.to_le_bytes().as_ref(), pub_info.k.as_ref()].concat();
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
    // if the commitment is from the sender, then the commitment is hidden
    // else, it is public
    let commitment_var2 = if is_sender {
        PrivCoinCommitmentOutputVar::new_witness(
            ark_relations::ns!(cs, "gadget_commitment"),
            || Ok(cm),
        )
        .unwrap()
    } else {
        PrivCoinCommitmentOutputVar::new_input(ark_relations::ns!(cs, "gadget_commitment"), || {
            Ok(cm)
        })
        .unwrap()
    };

    // circuit to compare the commited value with supplied value
    result_var.enforce_equal(&commitment_var2).unwrap();
}

/// a helper function to generate the prf circuit
///     sender.pk = PRF(sender_sk, [0u8;32])
///     sender.sn = PRF(sender_sk, rho)
/// the output pk is hidden, while sn can be public
fn prf_circuit_helper(
    is_output_hidden: bool,
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
    let actual_out_var = if is_output_hidden {
        <Blake2sGadget as PRFGadget<_, Fq>>::OutputVar::new_witness(
            ark_relations::ns!(cs, "declare_output"),
            || Ok(output),
        )
        .unwrap()
    } else {
        <Blake2sGadget as PRFGadget<_, Fq>>::OutputVar::new_input(
            ark_relations::ns!(cs, "declare_output"),
            || Ok(output),
        )
        .unwrap()
    };

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

#[test]
fn test_zkp_local() {
    use crate::priv_coin::*;
    use ark_bls12_381::Bls12_381;
    use ark_crypto_primitives::CommitmentScheme;
    use ark_crypto_primitives::FixedLengthCRH;
    use ark_ff::ToConstraintField;
    use ark_groth16::create_random_proof;
    use ark_groth16::{generate_random_parameters, verify_proof};
    use ark_relations::r1cs::ConstraintSystem;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use rand_core::RngCore;

    let hash_param_seed = crate::param::HASHPARAMSEED;
    let commit_param_seed = crate::param::HASHPARAMSEED;

    let mut rng = ChaCha20Rng::from_seed(commit_param_seed);
    let commit_param = PrivCoinCommitmentScheme::setup(&mut rng).unwrap();

    let mut rng = ChaCha20Rng::from_seed(hash_param_seed);
    let hash_param = Hash::setup(&mut rng).unwrap();

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

    let mut rng = ChaCha20Rng::from_seed(crate::param::ZKPPARAMSEED);
    let pk = generate_random_parameters::<Bls12_381, _, _>(circuit.clone(), &mut rng).unwrap();
    // let vk = Groth16VK::deserialize(crate::param::VKBYTES.as_ref()).unwrap();
    // assert_eq!(pk.vk, vk);
    // let mut bytes: Vec<u8> = Vec::new();
    // pk.vk.serialize(&mut bytes).unwrap();
    // assert_eq!(bytes[..].as_ref(), crate::param::VKBYTES.as_ref());

    let proof = create_random_proof(circuit, &pk, &mut rng).unwrap();
    let pvk = Groth16PVK::from(pk.vk.clone());

    let k_old = PrivCoinCommitmentOutput::deserialize(sender_pub_info.k.as_ref()).unwrap();
    let k_new = PrivCoinCommitmentOutput::deserialize(receiver_pub_info.k.as_ref()).unwrap();
    let cm_new = PrivCoinCommitmentOutput::deserialize(receiver.cm_bytes.as_ref()).unwrap();

    // format the input to the verification
    let mut inputs = [k_old.x, k_old.y, k_new.x, k_new.y, cm_new.x, cm_new.y].to_vec();
    let sn: Vec<Fq> =
        ToConstraintField::<Fq>::to_field_elements(sender_priv_info.sn.as_ref()).unwrap();
    inputs = [inputs[..].as_ref(), sn.as_ref()].concat();

    assert!(verify_proof(&pvk, &proof, &inputs[..]).unwrap())
}

#[test]
fn test_zkp_interface() {
    use crate::priv_coin::*;
    use ark_crypto_primitives::CommitmentScheme;
    use ark_crypto_primitives::FixedLengthCRH;
    use ark_groth16::create_random_proof;
    use ark_relations::r1cs::ConstraintSystem;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use rand_core::RngCore;

    let hash_param_seed = crate::param::HASHPARAMSEED;
    let commit_param_seed = crate::param::COMMITPARAMSEED;

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

    assert!(manta_verify_zkp(
        crate::param::VKBYTES.to_vec(),
        proof_bytes,
        sender_priv_info.sn,
        sender_pub_info.k,
        receiver_pub_info.k,
        receiver.cm_bytes,
        [0u8; 32],
    ));
}
