//! This file implements Diffie-Hellman Key Agreement for value encryption
//! TODO: maybe we should simply use ecies crate
//! https://github.com/phayes/ecies-ed25519/
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockCipher, NewBlockCipher};
use aes::Aes256;
use hkdf::Hkdf;
use rand_core::CryptoRng;
use rand_core::RngCore;
use sha2::Sha512Trunc256;
use x25519_dalek::{EphemeralSecret, PublicKey};
/// encrypt the value under receiver's public key
/// steps:
///     1. sample a random, ephermal field element: sender_x
///     2. compute the grouple element sender_pk
///     3. compute the shared secret ss = receiver_pk^x
///     4. set aes_key = KDF("manta_value_encryption" | ss)
///     5. compute c = aes_enc(value.to_le_bytes(), aes_key)
/// return (sender_pk, c)
pub fn manta_dh_enc<R: RngCore + CryptoRng>(
    receiver_pk_bytes: [u8; 32],
    value: u64,
    rng: &mut R,
) -> ([u8; 32], [u8; 64]) {
    let sender_sk = EphemeralSecret::new(rng);
    let sender_pk = PublicKey::from(&sender_sk);

    let receiver_pk = PublicKey::from(receiver_pk_bytes);
    let shared_secret = sender_sk.diffie_hellman(&receiver_pk);
    let ss = manta_kdf(&shared_secret.to_bytes());
    let aes_key = GenericArray::from_slice(&ss);

    let mut block = GenericArray::clone_from_slice(&value.to_le_bytes());
    let cipher = Aes256::new(&aes_key);
    cipher.encrypt_block(&mut block);
    let mut res = [0u8;64];
    res.copy_from_slice(block.as_slice());

    (sender_pk.to_bytes(), res)
}

fn manta_kdf(input: &[u8]) -> [u8; 32] {
    // now build the hkdf-sha512: m = hkdf-extract(salt, seed)
    let salt = "manta kdf instantiated with Sha512-256 hash function";
    let output = Hkdf::<Sha512Trunc256>::extract(Some(salt.as_ref()), input);
    let mut res = [0u8; 32];
    res.copy_from_slice(&output.0[0..32]);
    res
}
