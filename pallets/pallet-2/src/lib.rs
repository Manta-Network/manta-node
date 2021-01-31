#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::{decl_module, dispatch, traits::Get};
use frame_system::ensure_signed;

pub trait Trait: frame_system::Trait {
	type MyConfig: Get<u32>;
}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		#[weight = 0]
		pub fn do_something(origin) -> dispatch::DispatchResult {
			let _ = ensure_signed(origin)?;

			// Calling `T::MyConfig::get()` will read from runtime storage
			// as configured in the runtime.
			let _my_config =  T::MyConfig::get();

			Ok(())
		}
	}
}
