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
extern crate ark_std;
extern crate blake2;
extern crate ed25519_dalek;
// extern crate rand;
// extern crate rand_chacha;
// extern crate rand_core;
extern crate sha2;

mod crypto_types;
mod priv_coin;
mod zkp;
mod zkp_types;

use ark_std::vec::Vec;
use crypto_types::*;
use frame_support::{decl_error, decl_event, decl_module, decl_storage, ensure};
use frame_system::ensure_signed;
use rand::RngCore;
use rand_core::CryptoRng;
use sp_runtime::traits::{StaticLookup, Zero};

pub trait PrivCoin {
    type Address;
    type Param;
    type Coin;
    type SK;
    type Mint;
    type Transfer;
    type ZKProvingKey;

    // Minting process does not concern any ZKP
    fn mint<R: RngCore + CryptoRng>(
        param: &Self::Param,
        sk: &[u8; 32],
        value: u32,
        rng: &mut R,
    ) -> (Self::Coin, Self::SK, Self::Mint);

    fn transfer<R: RngCore + CryptoRng>(
        param: &Self::Param,
        proving_key: &Self::ZKProvingKey,
        sender: &Self::Coin,
        sender_sk: &Self::SK,
        receiver: &Self::Address,
        ledger: Vec<PrivCoinCommitmentOutput>,
        rng: &mut R,
    ) -> (Self::Coin, Self::Transfer);
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
            <Balances<T>>::insert(&origin, total);
            <TotalSupply>::put(total);
            Self::deposit_event(RawEvent::Issued(origin, total));
            Init::put(true);
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
        type Balance = u64;
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
