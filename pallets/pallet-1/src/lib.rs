#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::{decl_module, decl_storage};
use frame_system::ensure_signed;

pub trait Trait: frame_system::Trait {}

decl_storage! {
	trait Store for Module<T: Trait> as TemplateModule {
		pub MyStorage: u32;
	}
}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		#[weight = 0]
		pub fn set_storage(origin, value: u32) {
			let _ = ensure_signed(origin)?;
			MyStorage::put(value);
		}
	}
}
