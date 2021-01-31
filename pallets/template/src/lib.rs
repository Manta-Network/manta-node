#![cfg_attr(not(feature = "std"), no_std)]

/// Edit this file to define custom logic or remove it if it is not needed.
/// Learn more about FRAME and the core library of Substrate FRAME pallets:
/// https://substrate.dev/docs/en/knowledgebase/runtime/frame

use frame_support::{decl_module, decl_storage, decl_event, decl_error, dispatch, traits::Get, RuntimeDebug, weights::Weight, debug};
use frame_system::ensure_signed;
use codec::{Decode, Encode};

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

/// Configure the pallet by specifying the parameters and types on which it depends.
pub trait Trait: frame_system::Trait {
	/// Because this pallet emits events, it depends on the runtime's definition of an event.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
}

#[derive(Encode, Decode, Default, RuntimeDebug, PartialEq)]
pub struct SomeStruct {
	sth_else: bool,
	something: u32,
}

#[derive(Encode, Decode, Clone, RuntimeDebug, PartialEq)]
#[allow(non_camel_case_types)]
pub enum StorageVersion {
	V1_u32,
	V2_SomeStruct,
}

// The pallet's runtime storage items.
// https://substrate.dev/docs/en/knowledgebase/runtime/storage
decl_storage! {
	// A unique name is used to ensure that the pallet's storage items are isolated.
	// This name may be updated, but each pallet in the runtime must use a unique name.
	// ---------------------------------vvvvvvvvvvvvvv
	trait Store for Module<T: Trait> as TemplateModule {
		// Learn more about declaring storage items:
		// https://substrate.dev/docs/en/knowledgebase/runtime/storage#declaring-storage-items
		Something get(fn something): Option<SomeStruct>;
		// Something get(fn something): Option<u32>;

		PalletVersion: StorageVersion = StorageVersion::V1_u32;
	}
}

// Pallets use events to inform users when important changes are made.
// https://substrate.dev/docs/en/knowledgebase/runtime/events
decl_event!(
	pub enum Event<T> where AccountId = <T as frame_system::Trait>::AccountId {
		/// Event documentation should end with an array that provides descriptive names for event
		/// parameters. [something, who]
		SomethingStored(u32, AccountId),
	}
);

// Errors inform users that something went wrong.
decl_error! {
	pub enum Error for Module<T: Trait> {
		/// Error names should be descriptive.
		NoneValue,
		/// Errors should have helpful documentation associated with them.
		StorageOverflow,
	}
}

// Dispatchable functions allows users to interact with the pallet and invoke state changes.
// These functions materialize as "extrinsics", which are often compared to transactions.
// Dispatchable functions must be annotated with a weight and must return a DispatchResult.
decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		// Errors must be initialized if they are used by the pallet.
		type Error = Error<T>;

		// Events must be initialized if they are used by the pallet.
		fn deposit_event() = default;

		/// An example dispatchable that takes a singles value as a parameter, writes the value to
		/// storage and emits an event. This function must be dispatched by a signed extrinsic.
		#[weight = 10_000 + T::DbWeight::get().writes(1)]
		pub fn do_something(origin, something: u32, sth_else: bool) -> dispatch::DispatchResult {
			// Check that the extrinsic was signed and get the signer.
			// This function will return an error if the extrinsic is not signed.
			// https://substrate.dev/docs/en/knowledgebase/runtime/origin
			let who = ensure_signed(origin)?;

			// Update storage.
			Something::put(SomeStruct { something, sth_else });

			// Emit an event.
			Self::deposit_event(RawEvent::SomethingStored(something, who));
			// Return a successful DispatchResult
			Ok(())
		}

		fn on_runtime_upgrade() -> Weight {
			migration::migrate_to_struct::<T>()
		}
	}
}

pub mod migration {
	use super::*;

	pub mod deprecated {
		use crate::Trait;
		use frame_support::{decl_module, decl_storage};
		use sp_std::prelude::*;
	
		decl_storage! {
			trait Store for Module<T: Trait> as TemplateModule {
				pub Something get(fn something): Option<u32>;
			}
		}
		decl_module! {
			pub struct Module<T: Trait> for enum Call where origin: T::Origin { }
		}
	}

	pub fn migrate_to_struct<T: Trait>() -> Weight {
		debug::RuntimeLogger::init();

		// only run the migration if the version is not up to date
		if PalletVersion::get() == StorageVersion::V1_u32 {
			debug::info!("storage updated");
			let something = deprecated::Something::take();
			Something::put(SomeStruct { sth_else: true, something: something.unwrap_or(0) });
			PalletVersion::put(StorageVersion::V2_SomeStruct);
			// return the weight consumed by our migration
			T::DbWeight::get().reads_writes(1, 2)
		} else {
			debug::info!("storage already updated");
			0
		}
	}
}