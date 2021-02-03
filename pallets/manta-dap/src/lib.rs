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
extern crate rand_chacha;
// extern crate blake2;
// extern crate ed25519_dalek;
// extern crate rand;
// extern crate rand_core;
// extern crate sha2;

pub mod crypto_types;
pub mod priv_coin;
pub mod zkp;
pub mod zkp_types;

// use frame_system::Module;
use ark_std::vec::Vec;
use frame_support::codec::{Decode, Encode};
use frame_support::{decl_error, decl_event, decl_module, decl_storage, ensure};
use frame_system::ensure_signed;
use sp_runtime::traits::{StaticLookup, Zero};

/// a MantaCoin is a pair of commitment cm and ciphertext c, where
///  * cm = com(v||k, s), commits to the value, and
///  * c = enc(v), encrypts the value under user (receiver) public key
/// For simplicity, the prototype does not use encryption, and store the
/// raw value right now. This will be changed in a later version.
#[derive(Encode, Decode, Clone, PartialEq)]
pub struct MantaCoin {
    pub(crate) pk: [u8; 32],
    pub(crate) cm: [u8; 64],
    pub(crate) value: u64,
}

impl Default for MantaCoin {
    fn default() -> Self {
        Self {
            pk: [0u8; 32],
            cm: [0u8; 64],
            value: 0,
        }
    }
}

/// the state of the ledger is a root of the merkle tree
/// where the leafs are the MantaCoins
#[derive(Encode, Decode, Clone, PartialEq)]
pub struct MantaLedgerState {
    pub(crate) state: [u8; 64],
}

impl Default for MantaLedgerState {
    fn default() -> Self {
        Self { state: [0u8; 64] }
    }
}

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
            let hash_param_seed = [1u8; 32];
            let commit_param_seed = [2u8; 32];


            // generate the ZKP verification key and push it to the ledger storage
            // note: for prototype, we use this function to generate the ZKP verification key
            // for product we should use a MPC protocol to build the ZKP verification key
            // and then depoly that vk
            let zkp_vk = priv_coin::manta_zkp_vk_gen(&hash_param_seed, &commit_param_seed);
            ZKPVerificationKey::put(zkp_vk);


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
            pk: [u8; 32],
            k: [u8; 64],
            s: [u8; 32],
            cm: [u8; 64]
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
            ensure!(priv_coin::comm_open(&commit_param_seed, &s, &payload, &cm), <Error<T>>::MintFail);

            // check cm is not in coin_list
            let mut coin_list = CoinList::get();
            for e in coin_list.iter() {
                ensure!(
                    e.cm != cm,
                    Error::<T>::MantaCoinExist
                )
            }

            // add the new coin to the ledger
            let coin = MantaCoin {
                pk,
                cm,
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
        }


        /// Private Transfer
        /// check the type of sn_old
        #[weight = 0]
        fn manta_transfer(origin,
            merkle_root: [u8; 64],
            pk_old: [u8; 32],
            sn_old: [u8; 32],
            k_old: [u8; 64],
            pk_new: [u8; 32],
            k_new: [u8; 64],
            cm_new: [u8; 64],
            // todo: amount shall be an encrypted
            amount: u64,
            zkp: [u8; 196]
        ) {

            ensure!(Self::is_init(), <Error<T>>::BasecoinNotInit);
            let origin = ensure_signed(origin)?;

            // check if sn_old already spent
            let mut sn_list = SNList::get();
            ensure!(sn_list.contains(&sn_old), <Error<T>>::MantaCoinSpent);
            sn_list.push(sn_old);

            // update coin list
            let mut coin_list = CoinList::get();
            let coin_new = MantaCoin{
                pk: pk_new,
                cm: cm_new,
                // todo: amount shall be an encrypted
                value: amount,
            };
            coin_list.push(coin_new);

            // get the verification key from the ledger
            let vk_bytes = ZKPVerificationKey::get();

            // get the ledger state from the ledger
            let state = LedgerState::get();

            // check validity of zkp
            ensure!(
                priv_coin::manta_verify_zkp(vk_bytes, zkp, sn_old, pk_old, k_old, k_new, cm_new, state.state),
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
        pub ZKPVerificationKey get(fn zkp_vk): Vec<u8>;

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

    use frame_support::{
        assert_noop, assert_ok, impl_outer_origin, parameter_types, weights::Weight,
    };
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
        // type Balance = u64;
    }
    type Assets = Module<Test>;

    fn new_test_ext() -> sp_io::TestExternalities {
        frame_system::GenesisConfig::default()
            .build_storage::<Test>()
            .unwrap()
            .into()
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
