// This file is part of Substrate.

// Copyright (C) 2019-2020 Parity Technologies (UK) Ltd.
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

//! # Nicks Module
//!
//! - [`nicks::Trait`](./trait.Trait.html)
//! - [`Call`](./enum.Call.html)
//!
//! ## Overview
//!
//! Nicks is an example module for keeping track of account names on-chain. It makes no effort to
//! create a name hierarchy, be a DNS replacement or provide reverse lookups. Furthermore, the
//! weights attached to this module's dispatchable functions are for demonstration purposes only and
//! have not been designed to be economically secure. Do not use this pallet as-is in production.
//!
//! ## Interface
//!
//! ### Dispatchable Functions
//!
//! * `set_name` - Set the associated name of an account; a small deposit is reserved if not already
//!   taken.
//! * `clear_name` - Remove an account's associated name; the deposit is returned.
//! * `kill_name` - Forcibly remove the associated name; the deposit is lost.
//!
//! [`Call`]: ./enum.Call.html
//! [`Trait`]: ./trait.Trait.html

#![cfg_attr(not(feature = "std"), no_std)]

use sp_std::prelude::*;
use sp_runtime::{
	traits::{StaticLookup, Zero}
};
use frame_support::{
	decl_module, decl_event, decl_storage, ensure, decl_error,
	traits::{Currency, EnsureOrigin, ReservableCurrency, OnUnbalanced, Get},
};
use frame_system::ensure_signed;

type BalanceOf<T> = <<T as Trait>::Currency as Currency<<T as frame_system::Trait>::AccountId>>::Balance;
type NegativeImbalanceOf<T> = <<T as Trait>::Currency as Currency<<T as frame_system::Trait>::AccountId>>::NegativeImbalance;

pub trait Trait: frame_system::Trait {
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;

	/// The currency trait.
	type Currency: ReservableCurrency<Self::AccountId>;

	/// Reservation fee.
	type ReservationFee: Get<BalanceOf<Self>>;

	/// What to do with slashed funds.
	type Slashed: OnUnbalanced<NegativeImbalanceOf<Self>>;

	/// The origin which may forcibly set or remove a name. Root can always do this.
	type ForceOrigin: EnsureOrigin<Self::Origin>;

	/// The maximum length a name may be.
	type MaxLength: Get<usize>;
}

/// A nickname with a first and last part.
#[derive(codec::Encode, codec::Decode, Default, frame_support::RuntimeDebug, PartialEq)]
pub struct Nickname {
	first: Vec<u8>,
	last: Option<Vec<u8>>,
}

/// Utility type for managing upgrades/migrations.
#[derive(codec::Encode, codec::Decode, Clone, frame_support::RuntimeDebug, PartialEq)]
pub enum StorageVersion {
	V1Bytes,
	V2Struct,
}

decl_storage! {
	trait Store for Module<T: Trait> as MyNicks {
		/// The lookup table for names.
		NameOf: map hasher(twox_64_concat) T::AccountId => Option<(Nickname, BalanceOf<T>)>;
		/// The current version of the pallet.
		PalletVersion: StorageVersion = StorageVersion::V1Bytes;
	}
}

decl_event!(
	pub enum Event<T> where AccountId = <T as frame_system::Trait>::AccountId, Balance = BalanceOf<T> {
		/// A name was set. \[who\]
		NameSet(AccountId),
		/// A name was forcibly set. \[target\]
		NameForced(AccountId),
		/// A name was changed. \[who\]
		NameChanged(AccountId),
		/// A name was cleared, and the given balance returned. \[who, deposit\]
		NameCleared(AccountId, Balance),
		/// A name was removed and the given balance slashed. \[target, deposit\]
		NameKilled(AccountId, Balance),
	}
);

decl_error! {
	/// Error for the nicks module.
	pub enum Error for Module<T: Trait> {
		/// A name is too long.
		TooLong,
		/// An account isn't named.
		Unnamed,
	}
}

decl_module! {
	/// Nicks module declaration.
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		type Error = Error<T>;

		fn deposit_event() = default;

		/// Reservation fee.
		const ReservationFee: BalanceOf<T> = T::ReservationFee::get();

		/// The maximum length a name may be.
		const MaxLength: u32 = T::MaxLength::get() as u32;

		/// Set an account's name. The name should be a UTF-8-encoded string by convention, though
		/// we don't check it.
		///
		/// The name may not be more than `T::MaxLength` bytes, nor less than `T::MinLength` bytes.
		///
		/// If the account doesn't already have a name, then a fee of `ReservationFee` is reserved
		/// in the account.
		///
		/// The dispatch origin for this call must be _Signed_.
		///
		/// # <weight>
		/// - O(1).
		/// - At most one balance operation.
		/// - One storage read/write.
		/// - One event.
		/// # </weight>
		#[weight = 50_000_000]
		fn set_name(origin, first: Vec<u8>, last: Option<Vec<u8>>) {
			let sender = ensure_signed(origin)?;

			let len = match last {
				None => first.len(),
				Some(ref last_name) => first.len() + last_name.len(),
			};

			ensure!(len <= T::MaxLength::get(), Error::<T>::TooLong);

			let deposit = if let Some((_, deposit)) = <NameOf<T>>::get(&sender) {
				Self::deposit_event(RawEvent::NameChanged(sender.clone()));
				deposit
			} else {
				let deposit = T::ReservationFee::get();
				T::Currency::reserve(&sender, deposit.clone())?;
				Self::deposit_event(RawEvent::NameSet(sender.clone()));
				deposit
			};

			<NameOf<T>>::insert(&sender, (Nickname { first, last }, deposit));
		}

		/// Clear an account's name and return the deposit. Fails if the account was not named.
		///
		/// The dispatch origin for this call must be _Signed_.
		///
		/// # <weight>
		/// - O(1).
		/// - One balance operation.
		/// - One storage read/write.
		/// - One event.
		/// # </weight>
		#[weight = 70_000_000]
		fn clear_name(origin) {
			let sender = ensure_signed(origin)?;

			let deposit = <NameOf<T>>::take(&sender).ok_or(Error::<T>::Unnamed)?.1;

			let _ = T::Currency::unreserve(&sender, deposit.clone());

			Self::deposit_event(RawEvent::NameCleared(sender, deposit));
		}

		/// Remove an account's name and take charge of the deposit.
		///
		/// Fails if `who` has not been named. The deposit is dealt with through `T::Slashed`
		/// imbalance handler.
		///
		/// The dispatch origin for this call must match `T::ForceOrigin`.
		///
		/// # <weight>
		/// - O(1).
		/// - One unbalanced handler (probably a balance transfer)
		/// - One storage read/write.
		/// - One event.
		/// # </weight>
		#[weight = 70_000_000]
		fn kill_name(origin, target: <T::Lookup as StaticLookup>::Source) {
			T::ForceOrigin::ensure_origin(origin)?;

			// Figure out who we're meant to be clearing.
			let target = T::Lookup::lookup(target)?;
			// Grab their deposit (and check that they have one).
			let deposit = <NameOf<T>>::take(&target).ok_or(Error::<T>::Unnamed)?.1;
			// Slash their deposit from them.
			T::Slashed::on_unbalanced(T::Currency::slash_reserved(&target, deposit.clone()).0);

			Self::deposit_event(RawEvent::NameKilled(target, deposit));
		}

		/// Set a third-party account's name with no deposit.
		///
		/// No length checking is done on the name.
		///
		/// The dispatch origin for this call must match `T::ForceOrigin`.
		///
		/// # <weight>
		/// - O(1).
		/// - At most one balance operation.
		/// - One storage read/write.
		/// - One event.
		/// # </weight>
		#[weight = 70_000_000]
		fn force_name(origin, target: <T::Lookup as StaticLookup>::Source, first: Vec<u8>, last: Option<Vec<u8>>) {
			T::ForceOrigin::ensure_origin(origin)?;

			let target = T::Lookup::lookup(target)?;
			let deposit = <NameOf<T>>::get(&target).map(|x| x.1).unwrap_or_else(Zero::zero);
			<NameOf<T>>::insert(&target, (Nickname { first, last }, deposit));

			Self::deposit_event(RawEvent::NameForced(target));
		}

		fn on_runtime_upgrade() -> frame_support::weights::Weight {
			migration::migrate_to_v2::<T>()
		}
	}
}


pub mod migration {
	use super::*;

	pub mod deprecated {
		use crate::Trait;
		use frame_support::{decl_module, decl_storage, traits::Currency};
		use sp_std::prelude::*;

		type BalanceOf<T> = <<T as Trait>::Currency as Currency<<T as frame_system::Trait>::AccountId>>::Balance;

		decl_storage! {
			trait Store for Module<T: Trait> as MyNicks {
				pub NameOf: map hasher(twox_64_concat) T::AccountId => Option<(Vec<u8>, BalanceOf<T>)>;
			}
		}
		decl_module! {
			pub struct Module<T: Trait> for enum Call where origin: T::Origin { }
		}
	}

	pub fn migrate_to_v2<T: Trait>() -> frame_support::weights::Weight {
		frame_support::debug::RuntimeLogger::init();

		// Storage migrations should use storage versions for safety.
		if PalletVersion::get() == StorageVersion::V1Bytes {
			frame_support::debug::info!(" >>> Updating MyNicks storage...");
			let mut count: u64 = 0;

			// We remove the nicks from the old storage via `drain`.
			for (key, (nick, deposit)) in deprecated::NameOf::<T>::drain() {
				// We split the nick at ' ' (<space>).
				match nick.iter().rposition(|&x| x == b" "[0]) {
					Some(ndx) => NameOf::<T>::insert(&key, (Nickname {
						first: nick[0..ndx].to_vec(),
						last: Some(nick[ndx + 1..].to_vec())
					}, deposit)),
					None => NameOf::<T>::insert(&key, (Nickname { first: nick, last: None }, deposit))
				}

				frame_support::debug::info!("     Migrated nickname for {:?}...", key);
				count += 1;
			}

			// Update storage version.
			PalletVersion::put(StorageVersion::V2Struct);
			frame_support::debug::info!(" <<< MyNicks storage updated! Migrated {} nicknames ✅", count);

			// Return the weight consumed by the migration.
			T::DbWeight::get().reads_writes(2, 3)
		} else {
			frame_support::debug::info!(" >>> Unused migration!");
			0
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use frame_support::{
		assert_ok, assert_noop, impl_outer_origin, parameter_types, weights::Weight,
		ord_parameter_types
	};
	use sp_core::H256;
	use frame_system::EnsureSignedBy;
	use sp_runtime::{
		Perbill, testing::Header, traits::{BlakeTwo256, IdentityLookup, BadOrigin},
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
		type BlockNumber = u64;
		type Hash = H256;
		type Call = ();
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
		type MaximumBlockLength = MaximumBlockLength;
		type AvailableBlockRatio = AvailableBlockRatio;
		type Version = ();
		type PalletInfo = ();
		type AccountData = pallet_balances::AccountData<u64>;
		type OnNewAccount = ();
		type OnKilledAccount = ();
		type SystemWeightInfo = ();
	}
	parameter_types! {
		pub const ExistentialDeposit: u64 = 1;
	}
	impl pallet_balances::Trait for Test {
		type MaxLocks = ();
		type Balance = u64;
		type Event = ();
		type DustRemoval = ();
		type ExistentialDeposit = ExistentialDeposit;
		type AccountStore = System;
		type WeightInfo = ();
	}
	parameter_types! {
		pub const ReservationFee: u64 = 2;
		pub const MinLength: usize = 3;
		pub const MaxLength: usize = 16;
	}
	ord_parameter_types! {
		pub const One: u64 = 1;
	}
	impl Trait for Test {
		type Event = ();
		type Currency = Balances;
		type ReservationFee = ReservationFee;
		type Slashed = ();
		type ForceOrigin = EnsureSignedBy<One, u64>;
		type MaxLength = MaxLength;
	}
	type System = frame_system::Module<Test>;
	type Balances = pallet_balances::Module<Test>;
	type Nicks = Module<Test>;

	fn new_test_ext() -> sp_io::TestExternalities {
		let mut t = frame_system::GenesisConfig::default().build_storage::<Test>().unwrap();
		pallet_balances::GenesisConfig::<Test> {
			balances: vec![
				(1, 10),
				(2, 10),
			],
		}.assimilate_storage(&mut t).unwrap();
		t.into()
	}

	#[test]
	fn kill_name_should_work() {
		new_test_ext().execute_with(|| {
			assert_ok!(Nicks::set_name(Origin::signed(2), b"Dave".to_vec(), None));
			assert_eq!(Balances::total_balance(&2), 10);
			assert_ok!(Nicks::kill_name(Origin::signed(1), 2));
			assert_eq!(Balances::total_balance(&2), 8);
			assert_eq!(<NameOf<Test>>::get(2), None);
		});
	}

	#[test]
	fn force_name_should_work() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				Nicks::set_name(Origin::signed(2), b"Dr. David Brubeck, III".to_vec(), None),
				Error::<Test>::TooLong,
			);

			assert_ok!(Nicks::set_name(Origin::signed(2), b"Dave".to_vec(), None));
			assert_eq!(Balances::reserved_balance(2), 2);
			assert_ok!(Nicks::force_name(Origin::signed(1), 2, b"Dr. David Brubeck, III".to_vec(), None));
			assert_eq!(Balances::reserved_balance(2), 2);
			assert_eq!(<NameOf<Test>>::get(2).unwrap().0.first, b"Dr. David Brubeck, III".to_vec());
			assert_eq!(<NameOf<Test>>::get(2).unwrap().1, 2);
		});
	}

	#[test]
	fn normal_operation_should_work() {
		new_test_ext().execute_with(|| {
			assert_ok!(Nicks::set_name(Origin::signed(1), b"Gav".to_vec(), None));
			assert_eq!(Balances::reserved_balance(1), 2);
			assert_eq!(Balances::free_balance(1), 8);
			assert_eq!(<NameOf<Test>>::get(1).unwrap().0.first, b"Gav".to_vec());

			assert_ok!(Nicks::set_name(Origin::signed(1), b"Gavin".to_vec(), None));
			assert_eq!(Balances::reserved_balance(1), 2);
			assert_eq!(Balances::free_balance(1), 8);
			assert_eq!(<NameOf<Test>>::get(1).unwrap().0.first, b"Gavin".to_vec());

			assert_ok!(Nicks::clear_name(Origin::signed(1)));
			assert_eq!(Balances::reserved_balance(1), 0);
			assert_eq!(Balances::free_balance(1), 10);
		});
	}

	#[test]
	fn error_catching_should_work() {
		new_test_ext().execute_with(|| {
			assert_noop!(Nicks::clear_name(Origin::signed(1)), Error::<Test>::Unnamed);

			assert_noop!(
				Nicks::set_name(Origin::signed(3), b"Dave".to_vec(), None),
				pallet_balances::Error::<Test, _>::InsufficientBalance
			);

			assert_noop!(
				Nicks::set_name(Origin::signed(1), b"Gavin James Wood, Esquire".to_vec(), None),
				Error::<Test>::TooLong
			);
			assert_ok!(Nicks::set_name(Origin::signed(1), b"Dave".to_vec(), None));
			assert_noop!(Nicks::kill_name(Origin::signed(2), 1), BadOrigin);
			assert_noop!(Nicks::force_name(Origin::signed(2), 1, b"Whatever".to_vec(), None), BadOrigin);
		});
	}
}
