// This file is part of Substrate.

// Copyright (C) 2017-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! # Manta DAP Module
//!
//! A simple, secure module for manta anounymous payment
//!
//! ## Overview
//!
//! The Assets module provides functionality for asset management of fungible asset classes
//! with a fixed supply, including:
//!
//! * Asset Issuance
//! * Asset Transfer
//!
//!
//! To use it in your runtime, you need to implement the assets [`Trait`](./trait.Trait.html).
//!
//! The supported dispatchable functions are documented in the [`Call`](./enum.Call.html) enum.
//!
//! ### Terminology
//!
//! * **Asset issuance:** The creation of the asset (note: this asset can only be created once)
//! * **Asset transfer:** The action of transferring assets from one account to another.
//! * **Asset destruction:** The process of an account removing its entire holding of an asset.
//!
//! The assets system in Substrate is designed to make the following possible:
//!
//! * Issue a unique asset to its creator's account.
//! * Move assets between accounts.
//!
//! ## Interface
//!
//! ### Dispatchable Functions
//!
//! * `issue` - Issues the total supply of a new fungible asset to the account of the caller of the function.
//! * `transfer` - Transfers an `amount` of units of fungible asset `id` from the balance of
//! the function caller's account (`origin`) to a `target` account.
//! * `destroy` - Destroys the entire holding of a fungible asset `id` associated with the account
//! that called the function.
//!
//! Please refer to the [`Call`](./enum.Call.html) enum and its associated variants for documentation on each function.
//!
//! ### Public Functions
//! <!-- Original author of descriptions: @gavofyork -->
//!
//! * `balance` - Get the asset balance of `who`.
//! * `total_supply` - Get the total supply of an asset `id`.
//!
//! Please refer to the [`Module`](./struct.Module.html) struct for details on publicly available functions.
//!
//! ## Usage
//!
//! The following example shows how to use the Assets module in your runtime by exposing public functions to:
//!
//! * Initiate the fungible asset for a token distribution event (airdrop).
//! * Query the fungible asset holding balance of an account.
//! * Query the total supply of a fungible asset that has been issued.
//!
//! ### Prerequisites
//!
//! Import the Assets module and types and derive your runtime's configuration traits from the Assets module trait.
//!
//! ## Related Modules
//!
//! * [`System`](../frame_system/index.html)
//! * [`Support`](../frame_support/index.html)

// Ensure we're `no_std` when compiling for Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

extern crate ark_crypto_primitives;
extern crate ark_ed_on_bls12_381;
extern crate ark_groth16;
extern crate ark_r1cs_std;
extern crate ark_relations;
extern crate ark_serialize;
extern crate ark_std;
extern crate generic_array;
extern crate rand_chacha;
extern crate x25519_dalek;

pub mod dap_setup;
pub mod dh;
pub mod param;
pub mod priv_coin;
pub mod types;
pub mod zkp;

use crate::types::*;
use ark_std::vec::Vec;
use frame_support::{decl_error, decl_event, decl_module, decl_storage, ensure};
use frame_system::ensure_signed;
use sp_runtime::traits::{StaticLookup, Zero};

/// The module configuration trait.
pub trait Trait: frame_system::Trait {
    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        type Error = Error<T>;

        fn deposit_event() = default;
        /// Issue a new class of fungible assets. There are, and will only ever be, `total`
        /// such assets and they'll all belong to the `origin` initially. It will have an
        /// identifier `AssetId` instance: this will be specified in the `Issued` event.
        ///
        /// # <weight>
        /// - `O(1)`
        /// - 1 storage mutation (codec `O(1)`).
        /// - 2 storage writes (condec `O(1)`).
        /// - 1 event.
        /// # </weight>
        #[weight = 0]
        fn init(origin, total: u64) {

            ensure!(!Self::is_init(), <Error<T>>::AlreadyInitialized);
            let origin = ensure_signed(origin)?;

            // for now we hard code the seeds as:
            //  * hash parameter seed: [1u8; 32]
            //  * commitment parameter seed: [2u8; 32]
            // We may want to pass those two in for `init`
            let hash_param_seed = param::HASHPARAMSEED;
            let commit_param_seed = param::COMMITPARAMSEED;

            // push the ZKP verification key to the ledger storage
            //
            // NOTE:
            //    this is is generated via
            //      let zkp_key = priv_coin::manta_zkp_key_gen(&hash_param_seed, &commit_param_seed);
            //
            // for prototype, we use this function to generate the ZKP verification key
            // for product we should use a MPC protocol to build the ZKP verification key
            // and then depoly that vk
            //
            ZKPKey::put(param::VKBYTES.to_vec());

            <Balances<T>>::insert(&origin, total);
            <TotalSupply>::put(total);
            Self::deposit_event(RawEvent::Issued(origin, total));
            Init::put(true);
            HashParamSeed::put(hash_param_seed);
            CommitParamSeed::put(commit_param_seed);
        }

        /// Move some assets from one holder to another.
        ///
        /// # <weight>
        /// - `O(1)`
        /// - 1 static lookup
        /// - 2 storage mutations (codec `O(1)`).
        /// - 1 event.
        /// # </weight>
        #[weight = 0]
        fn transfer(origin,
            target: <T::Lookup as StaticLookup>::Source,
            amount: u64
        ) {
            ensure!(Self::is_init(), <Error<T>>::BasecoinNotInit);
            let origin = ensure_signed(origin)?;

            let origin_account = origin.clone();
            let origin_balance = <Balances<T>>::get(&origin_account);
            let target = T::Lookup::lookup(target)?;
            ensure!(!amount.is_zero(), Error::<T>::AmountZero);
            ensure!(origin_balance >= amount, Error::<T>::BalanceLow);
            Self::deposit_event(RawEvent::Transferred(origin, target.clone(), amount));
            <Balances<T>>::insert(origin_account, origin_balance - amount);
            <Balances<T>>::mutate(target, |balance| *balance += amount);
        }

        /// Mint
        /// TODO: rename arguments
        /// TODO: do we need to store k and s?
        #[weight = 0]
        fn mint(origin,
            amount: u64,
            k: [u8; 32],
            s: [u8; 32],
            cm: [u8; 32]
        ) {
            // get the original balance
            ensure!(Self::is_init(), <Error<T>>::BasecoinNotInit);
            let origin = ensure_signed(origin)?;
            let origin_account = origin.clone();
            ensure!(!amount.is_zero(), Error::<T>::AmountZero);
            let origin_balance = <Balances<T>>::get(&origin_account);
            ensure!(origin_balance >= amount, Error::<T>::BalanceLow);

            // get the parameter seeds from the ledger
            let hash_param_seed = HashParamSeed::get();
            let commit_param_seed = CommitParamSeed::get();

            // check the validity of the commitment
            let payload = [amount.to_le_bytes().as_ref(), k.as_ref()].concat();
            ensure!(
                priv_coin::comm_open(&commit_param_seed, &s, &payload, &cm),
                <Error<T>>::MintFail
            );

            // check cm is not in coin_list
            let mut coin_list = CoinList::get();
            for e in coin_list.iter() {
                ensure!(
                    e.cm_bytes != cm,
                    Error::<T>::MantaCoinExist
                )
            }

            // add the new coin to the ledger
            let coin = MantaCoin {
                cm_bytes: cm,
                value: amount,
            };
            coin_list.push(coin);

            // update the merkle root
            let new_state = priv_coin::merkle_root(&hash_param_seed, &coin_list);

            // write back to ledger storage
            Self::deposit_event(RawEvent::Minted(origin, amount));
            CoinList::put(coin_list);
            LedgerState::put(new_state);
            let old_pool_balance = PoolBalance::get();
            PoolBalance::put(old_pool_balance + amount);
            <Balances<T>>::insert(origin_account, origin_balance - amount);
        }


        /// Private Transfer
        /// check the type of sn_old
        #[weight = 0]
        fn manta_transfer(origin,
            merkle_root: [u8; 32],
            sn_old: [u8; 32],
            k_old: [u8; 32],
            k_new: [u8; 32],
            cm_new: [u8; 32],
            // todo: amount shall be an encrypted
            amount: u64,
            proof: [u8; 192]
        ) {

            ensure!(Self::is_init(), <Error<T>>::BasecoinNotInit);
            let origin = ensure_signed(origin)?;

            // check if sn_old already spent
            let mut sn_list = SNList::get();
            ensure!(!sn_list.contains(&sn_old), <Error<T>>::MantaCoinSpent);
            sn_list.push(sn_old);

            // update coin list
            let mut coin_list = CoinList::get();
            let coin_new = MantaCoin{
                cm_bytes: cm_new,
                // todo: amount shall be an encrypted
                value: amount,
            };
            coin_list.push(coin_new);

            // get the verification key from the ledger
            let vk_bytes = ZKPKey::get();

            // get the ledger state from the ledger
            let state = LedgerState::get();

            // check validity of zkp
            ensure!(
                priv_coin::manta_verify_zkp(vk_bytes, proof, sn_old, k_old, k_new, cm_new, state.state),
                <Error<T>>::ZKPFail,
            );

            // TODO: revisit replay attack here

            // update ledger state
            Self::deposit_event(RawEvent::PrivateTransferred(origin));
            CoinList::put(coin_list);
            SNList::put(sn_list);
        }
    }
}

decl_event! {
    pub enum Event<T> where
        <T as frame_system::Trait>::AccountId,
    {
        /// The asset was issued. \[owner, total_supply\]
        Issued(AccountId, u64),
        /// The asset was transferred. \[from, to, amount\]
        Transferred(AccountId, AccountId, u64),
        /// The asset was minted to private
        Minted(AccountId, u64),
        /// Private transfer
        PrivateTransferred(AccountId),
    }
}

decl_error! {
    pub enum Error for Module<T: Trait> {
        /// This token has already been initiated
        AlreadyInitialized,
        /// Transfer when not nitialized
        BasecoinNotInit,
        /// Transfer amount should be non-zero
        AmountZero,
        /// Account balance must be greater than or equal to the transfer amount
        BalanceLow,
        /// Balance should be non-zero
        BalanceZero,
        /// Mint failure
        MintFail,
        /// MantaCoin exist
        MantaCoinExist,
        /// MantaCoin already spend
        MantaCoinSpent,
        /// ZKP verification failed
        ZKPFail
    }
}

decl_storage! {
    trait Store for Module<T: Trait> as Assets {
        /// The number of units of assets held by any given account.
        pub Balances: map hasher(blake2_128_concat) T::AccountId => u64;

        /// The total unit supply of the asset.
        pub TotalSupply get(fn total_supply): u64;

        /// Has this token been initialized (can only initiate once)
        pub Init get(fn is_init): bool;

        /// List of sns
        pub SNList get(fn sn_list): Vec<[u8; 32]>;

        /// List of Coins that has ever been created
        pub CoinList get(fn coin_list): Vec<MantaCoin>;

        /// merkle root of list of commitments
        pub LedgerState get(fn legder_state): MantaLedgerState;

        /// the balance of minted coins
        pub PoolBalance get(fn pool_balance): u64;

        /// the seed of hash parameter
        pub HashParamSeed get(fn hash_param_seed): [u8; 32];

        /// the seed of commit parameter
        pub CommitParamSeed get(fn commit_param_seed): [u8; 32];

        /// verification key for zero-knowledge proof
        /// at the moment we are storing the whole serialized key
        /// in the blockchain storage.
        pub ZKPKey get(fn zkp_vk): Vec<u8>;

    }
}

// The main implementation block for the module.
impl<T: Trait> Module<T> {
    // Public immutables

    /// Get the asset `id` balance of `who`.
    pub fn balance(who: T::AccountId) -> u64 {
        <Balances<T>>::get(who)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp::TransferCircuit;
    use ark_bls12_381::Bls12_381;
    use ark_crypto_primitives::CommitmentScheme;
    use ark_crypto_primitives::FixedLengthCRH;
    use ark_ed_on_bls12_381::Fq;
    use ark_groth16::create_random_proof;
    use ark_groth16::generate_random_parameters;
    use ark_relations::r1cs::ConstraintSynthesizer;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use data_encoding::BASE64;
    use frame_support::{
        assert_noop, assert_ok, impl_outer_origin, parameter_types, weights::Weight,
    };
    use rand::RngCore;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use sp_core::H256;
    use sp_runtime::{
        testing::Header,
        traits::{BlakeTwo256, IdentityLookup},
        Perbill,
    };

    impl_outer_origin! {
        pub enum Origin for Test where system = frame_system {}
    }

    #[derive(Clone, Eq, PartialEq)]
    pub struct Test;
    parameter_types! {
        pub const BlockHashCount: u64 = 250;
        pub const MaximumBlockWeight: Weight = 1024;
        pub const MaximumBlockLength: u32 = 2 * 1024;
        pub const AvailableBlockRatio: Perbill = Perbill::one();
    }
    impl frame_system::Trait for Test {
        type BaseCallFilter = ();
        type Origin = Origin;
        type Index = u64;
        type Call = ();
        type BlockNumber = u64;
        type Hash = H256;
        type Hashing = BlakeTwo256;
        type AccountId = u64;
        type Lookup = IdentityLookup<Self::AccountId>;
        type Header = Header;
        type Event = ();
        type BlockHashCount = BlockHashCount;
        type MaximumBlockWeight = MaximumBlockWeight;
        type DbWeight = ();
        type BlockExecutionWeight = ();
        type ExtrinsicBaseWeight = ();
        type MaximumExtrinsicWeight = MaximumBlockWeight;
        type AvailableBlockRatio = AvailableBlockRatio;
        type MaximumBlockLength = MaximumBlockLength;
        type Version = ();
        type PalletInfo = ();
        type AccountData = ();
        type OnNewAccount = ();
        type OnKilledAccount = ();
        type SystemWeightInfo = ();
    }
    impl Trait for Test {
        type Event = ();
    }
    type Assets = Module<Test>;

    fn new_test_ext() -> sp_io::TestExternalities {
        frame_system::GenesisConfig::default()
            .build_storage::<Test>()
            .unwrap()
            .into()
    }

    #[test]
    fn test_constants_should_work() {
        new_test_ext().execute_with(|| {
            assert_ok!(Assets::init(Origin::signed(1), 100));
            assert_eq!(Assets::balance(1), 100);
            let com_param_seed = CommitParamSeed::get();
            let hash_param_seed = HashParamSeed::get();
            assert_eq!(com_param_seed, param::COMMITPARAMSEED);
            assert_eq!(hash_param_seed, param::HASHPARAMSEED);
        });
    }

    #[test]
    fn test_mint_hardcode_should_work() {
        new_test_ext().execute_with(|| {
            assert_ok!(Assets::init(Origin::signed(1), 1000));
            assert_eq!(Assets::balance(1), 1000);
            assert_eq!(PoolBalance::get(), 0);

            // those are parameters for coin_1 in coin.json
            let mut k_bytes = [0u8; 32];
            let k_vec = BASE64
                .decode(b"+tMTpSikpdACxuDGZTl5pxwT7tpYcX/DFKJRZ1oLfqc=")
                .unwrap();
            k_bytes.copy_from_slice(k_vec[0..32].as_ref());

            let mut s_bytes = [0u8; 32];
            let s_vec = BASE64
                .decode(b"xsPXqMXA1SKMOehtsgVWV8xw9Mj0rh3O8Yt1ZHJzaQ4=")
                .unwrap();
            s_bytes.copy_from_slice(s_vec[0..32].as_ref());

            let mut cm_bytes = [0u8; 32];
            let cm_vec = BASE64
                .decode(b"XzoWOzhp6rXjQ/HDEN6jSLsLs64hKXWUNuFVtCUq0AA=")
                .unwrap();
            cm_bytes.copy_from_slice(cm_vec[0..32].as_ref());

            let value = 10;

            let coin = MantaCoin {
                cm_bytes: cm_bytes.clone(),
                value,
            };

            assert_ok!(Assets::mint(
                Origin::signed(1),
                10,
                k_bytes,
                s_bytes,
                cm_bytes
            ));

            assert_eq!(TotalSupply::get(), 1000);
            assert_eq!(PoolBalance::get(), 10);
            let coin_list = CoinList::get();
            assert_eq!(coin_list.len(), 1);
            assert_eq!(coin_list[0], coin);

            // those are parameters for coin_2 in coin.json
            let mut k_bytes = [0u8; 32];
            let k_vec = BASE64
                .decode(b"CutG9BBbkJMpBkbYTVX37HWunGcxHyy8+Eb1xRT9eVM=")
                .unwrap();
            k_bytes.copy_from_slice(k_vec[0..32].as_ref());

            let mut s_bytes = [0u8; 32];
            let s_vec = BASE64
                .decode(b"/KTVGbHHU8UVHLS6h54470DtjwF6MHvBkG2bKxpyBQc=")
                .unwrap();
            s_bytes.copy_from_slice(s_vec[0..32].as_ref());

            let mut cm_bytes = [0u8; 32];
            let cm_vec = BASE64
                .decode(b"3Oye4AqhzdysdWdCzMcoImTnYNGd21OmF8ztph4dRqI=")
                .unwrap();
            cm_bytes.copy_from_slice(cm_vec[0..32].as_ref());

            let value = 100;

            let coin = MantaCoin {
                cm_bytes: cm_bytes.clone(),
                value,
            };

            assert_ok!(Assets::mint(
                Origin::signed(1),
                100,
                k_bytes,
                s_bytes,
                cm_bytes
            ));

            assert_eq!(TotalSupply::get(), 1000);
            assert_eq!(PoolBalance::get(), 110);
            let coin_list = CoinList::get();
            assert_eq!(coin_list.len(), 2);
            assert_eq!(coin_list[1], coin);

            let sn_list = SNList::get();
            assert_eq!(sn_list.len(), 0);
        });
    }

    #[test]
    fn test_mint_should_work() {
        new_test_ext().execute_with(|| {
            assert_ok!(Assets::init(Origin::signed(1), 1000));
            assert_eq!(Assets::balance(1), 1000);
            assert_eq!(PoolBalance::get(), 0);
            let com_param_seed = CommitParamSeed::get();
            let mut rng = ChaCha20Rng::from_seed(com_param_seed);
            let com_param = PrivCoinCommitmentScheme::setup(&mut rng).unwrap();

            let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
            let mut sk = [0u8; 32];
            rng.fill_bytes(&mut sk);
            let (coin, pub_info, _priv_info) = priv_coin::make_coin(&com_param, sk, 10, &mut rng);
            assert_ok!(Assets::mint(
                Origin::signed(1),
                10,
                pub_info.k,
                pub_info.s,
                coin.cm_bytes
            ));

            assert_eq!(TotalSupply::get(), 1000);
            assert_eq!(PoolBalance::get(), 10);
            let coin_list = CoinList::get();
            assert_eq!(coin_list.len(), 1);
            assert_eq!(coin_list[0], coin);
            let sn_list = SNList::get();
            assert_eq!(sn_list.len(), 0);
        });
    }

    #[test]
    fn test_transfer_hardcode_should_work() {
        new_test_ext().execute_with(|| {
            assert_ok!(Assets::init(Origin::signed(1), 1000));
            assert_eq!(Assets::balance(1), 1000);
            assert_eq!(PoolBalance::get(), 0);

            // hardcoded sender 
            // those are parameters for coin_1 in coin.json
            let  mut old_k_bytes = [0u8;32];
            let old_k_vec = BASE64
                .decode(b"+tMTpSikpdACxuDGZTl5pxwT7tpYcX/DFKJRZ1oLfqc=")
                .unwrap();
            old_k_bytes.copy_from_slice(&old_k_vec[0..32].as_ref());

            let mut old_s_bytes = [0u8; 32];
            let old_s_vec = BASE64
                .decode(b"xsPXqMXA1SKMOehtsgVWV8xw9Mj0rh3O8Yt1ZHJzaQ4=")
                .unwrap();
            old_s_bytes.copy_from_slice(old_s_vec[0..32].as_ref());

            let mut old_cm_bytes = [0u8; 32];
            let old_cm_vec = BASE64
                .decode(b"XzoWOzhp6rXjQ/HDEN6jSLsLs64hKXWUNuFVtCUq0AA=")
                .unwrap();
            old_cm_bytes.copy_from_slice(&old_cm_vec[0..32].as_ref());


            let mut old_sn_bytes = [0u8; 32];
            let old_sn_vec = BASE64
                .decode(b"jqhzAPanABquT0CpMC2aFt2ze8+UqMUcUG6PZBmqFqE=")
                .unwrap();
            old_sn_bytes.copy_from_slice(&old_sn_vec[0..32].as_ref());

            let sender = MantaCoin {
                cm_bytes: old_cm_bytes.clone(),
                value: 10,
            };

            // mint the sender coin
            assert_ok!(Assets::mint(
                Origin::signed(1),
                10,
                old_k_bytes ,
                old_s_bytes,
               old_cm_bytes
            ));


            // check that minting is successful
            assert_eq!(PoolBalance::get(), 10);
            let coin_list = CoinList::get();
            assert_eq!(coin_list.len(), 1);
            assert_eq!(coin_list[0], sender);
            let sn_list = SNList::get();
            assert_eq!(sn_list.len(), 0);

            // hardcoded receiver
            // those are parameters for coin_3 in coin.json
            let  mut new_k_bytes = [0u8;32];
            let new_k_vec = BASE64
                .decode(b"2HbWGQCLOfxuA4jOiDftBRSbjjAs/a0vjrq/H4p6QBI=")
                .unwrap();
            new_k_bytes.copy_from_slice(&new_k_vec[0..32].as_ref());

            let mut new_cm_bytes = [0u8; 32];
            let new_cm_vec = BASE64
                .decode(b"1zuOv92V7e1qX1bP7+QNsV+gW5E3xUsghte/lZ7h5pg=")
                .unwrap();
            new_cm_bytes.copy_from_slice(new_cm_vec[0..32].as_ref());
            let receiver = MantaCoin{
                cm_bytes: new_cm_bytes,
                value: 10,
            };

            // hardcoded proof
            let mut proof_bytes = [0u8; 192];
            let proof_vec = BASE64
                .decode(b"SteTxuxdE9nhB7CszCgCrEarKCv4GE8toATEgMmmdgGcp6D5EEo47Jcb9f0R2UKEK7ZCZv9HBBbvwzCVfSYysx91axKSHvW5dD0tj0UkNTh0DbDDa5Tsr5HY46nKSQIUDEM3jZsNTPI8BoEbKLMfGFU+IIpugjim7iIvXF71MIM9x2Ts4oRRZGJ24KaYBvcRgvKUNtSN8OyoYdSBfk9Kp5rb5FtkyWzYQYQLV1zXI6pJkwSVaH0i0ttInnxOYlWN")
                .unwrap();
            proof_bytes.copy_from_slice(proof_vec[0..192].as_ref());

            // make the transfer
            assert_ok!(Assets::manta_transfer(
                Origin::signed(1),
                [0u8; 32],
                old_sn_bytes,
                old_k_bytes,
                new_k_bytes,
                new_cm_bytes,
                10,
                proof_bytes,
            ));

            // check the resulting status of the ledger storage
            assert_eq!(TotalSupply::get(), 1000);
            assert_eq!(PoolBalance::get(), 10);
            let coin_list = CoinList::get();
            assert_eq!(coin_list.len(), 2);
            assert_eq!(coin_list[0], sender);
            assert_eq!(coin_list[1], receiver);
            let sn_list = SNList::get();
            assert_eq!(sn_list.len(), 1);
            assert_eq!(sn_list[0], old_sn_bytes);

            // todo: check the ledger state is correctly updated
        });
    }

    #[test]
    fn test_transfer_should_work() {
        new_test_ext().execute_with(|| {
            assert_ok!(Assets::init(Origin::signed(1), 1000));
            assert_eq!(Assets::balance(1), 1000);
            assert_eq!(PoolBalance::get(), 0);
            let com_param_seed = CommitParamSeed::get();
            let mut rng = ChaCha20Rng::from_seed(com_param_seed);
            let com_param = PrivCoinCommitmentScheme::setup(&mut rng).unwrap();

            let hash_param_seed = HashParamSeed::get();
            let mut rng = ChaCha20Rng::from_seed(hash_param_seed);
            let hash_param = Hash::setup(&mut rng).unwrap();

            let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
            // mint a sender token
            let mut sk = [0u8; 32];
            rng.fill_bytes(&mut sk);
            let (sender, sender_pub_info, sender_priv_info) =
                priv_coin::make_coin(&com_param, sk, 10, &mut rng);
            assert_ok!(Assets::mint(
                Origin::signed(1),
                10,
                sender_pub_info.k,
                sender_pub_info.s,
                sender.cm_bytes
            ));

            assert_eq!(PoolBalance::get(), 10);
            let coin_list = CoinList::get();
            assert_eq!(coin_list.len(), 1);
            assert_eq!(coin_list[0], sender);
            let sn_list = SNList::get();
            assert_eq!(sn_list.len(), 0);

            // build a receiver
            rng.fill_bytes(&mut sk);
            let (receiver, receiver_pub_info, _receiver_priv_info) =
                priv_coin::make_coin(&com_param, sk, 10, &mut rng);

            // generate ZKP
            let circuit = TransferCircuit {
                commit_param: com_param,
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
            let pk =
                generate_random_parameters::<Bls12_381, _, _>(circuit.clone(), &mut rng).unwrap();
            let proof = create_random_proof(circuit, &pk, &mut rng).unwrap();
            let vk_bytes = ZKPKey::get();
            let vk = Groth16VK::deserialize(vk_bytes.as_ref()).unwrap();
            assert_eq!(pk.vk, vk);

            let mut proof_bytes = [0u8; 192];
            proof.serialize(proof_bytes.as_mut()).unwrap();

            // make the transfer
            assert_ok!(Assets::manta_transfer(
                Origin::signed(1),
                [0u8; 32],
                sender_priv_info.sn,
                sender_pub_info.k,
                receiver_pub_info.k,
                receiver.cm_bytes,
                10,
                proof_bytes,
            ));

            // check the resulting status of the ledger storage

            assert_eq!(TotalSupply::get(), 1000);
            assert_eq!(PoolBalance::get(), 10);
            let coin_list = CoinList::get();
            assert_eq!(coin_list.len(), 2);
            assert_eq!(coin_list[0], sender);
            assert_eq!(coin_list[1], receiver);
            let sn_list = SNList::get();
            assert_eq!(sn_list.len(), 1);
            assert_eq!(sn_list[0], sender_priv_info.sn);

            // todo: check the ledger state is correctly updated
        });
    }

    #[test]
    fn issuing_asset_units_to_issuer_should_work() {
        new_test_ext().execute_with(|| {
            assert_ok!(Assets::init(Origin::signed(1), 100));
            assert_eq!(Assets::balance(1), 100);
        });
    }

    #[test]
    fn querying_total_supply_should_work() {
        new_test_ext().execute_with(|| {
            assert_ok!(Assets::init(Origin::signed(1), 100));
            assert_eq!(Assets::balance(1), 100);
            assert_ok!(Assets::transfer(Origin::signed(1), 2, 50));
            assert_eq!(Assets::balance(1), 50);
            assert_eq!(Assets::balance(2), 50);
            assert_ok!(Assets::transfer(Origin::signed(2), 3, 31));
            assert_eq!(Assets::balance(1), 50);
            assert_eq!(Assets::balance(2), 19);
            assert_eq!(Assets::balance(3), 31);
            assert_eq!(Assets::total_supply(), 100);
        });
    }

    #[test]
    fn transferring_amount_above_available_balance_should_work() {
        new_test_ext().execute_with(|| {
            assert_ok!(Assets::init(Origin::signed(1), 100));
            assert_eq!(Assets::balance(1), 100);
            assert_ok!(Assets::transfer(Origin::signed(1), 2, 50));
            assert_eq!(Assets::balance(1), 50);
            assert_eq!(Assets::balance(2), 50);
        });
    }

    #[test]
    fn transferring_amount_more_than_available_balance_should_not_work() {
        new_test_ext().execute_with(|| {
            assert_ok!(Assets::init(Origin::signed(1), 100));
            assert_eq!(Assets::balance(1), 100);
            assert_ok!(Assets::transfer(Origin::signed(1), 2, 50));
            assert_eq!(Assets::balance(1), 50);
            assert_eq!(Assets::balance(2), 50);
            assert_noop!(
                Assets::transfer(Origin::signed(1), 1, 60),
                Error::<Test>::BalanceLow
            );
        });
    }

    #[test]
    fn transferring_less_than_one_unit_should_not_work() {
        new_test_ext().execute_with(|| {
            assert_ok!(Assets::init(Origin::signed(1), 100));
            assert_eq!(Assets::balance(1), 100);
            assert_noop!(
                Assets::transfer(Origin::signed(1), 2, 0),
                Error::<Test>::AmountZero
            );
        });
    }

    #[test]
    fn transferring_more_units_than_total_supply_should_not_work() {
        new_test_ext().execute_with(|| {
            assert_ok!(Assets::init(Origin::signed(1), 100));
            assert_eq!(Assets::balance(1), 100);
            assert_noop!(
                Assets::transfer(Origin::signed(1), 2, 101),
                Error::<Test>::BalanceLow
            );
        });
    }

    #[test]
    fn destroying_asset_balance_with_positive_balance_should_work() {
        new_test_ext().execute_with(|| {
            assert_ok!(Assets::init(Origin::signed(1), 100));
            assert_eq!(Assets::balance(1), 100);
        });
    }

    #[test]
    fn cannot_init_twice() {
        new_test_ext().execute_with(|| {
            assert_ok!(Assets::init(Origin::signed(1), 100));
            assert_noop!(
                Assets::init(Origin::signed(1), 100),
                Error::<Test>::AlreadyInitialized
            );
        });
    }
}
