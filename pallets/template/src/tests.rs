use crate::{Error, mock::*, migration, SomeStruct};
use frame_support::{assert_ok, assert_noop, storage::StorageValue};

#[test]
fn it_works_for_default_value() {
	new_test_ext().execute_with(|| {
		// Dispatch a signed extrinsic.
		assert_ok!(TemplateModule::do_something(Origin::signed(1), 42, true));
		// Read pallet storage and assert an expected result.
		assert_eq!(TemplateModule::something(), Some(SomeStruct { something: 42, sth_else: true}));
	});
}

#[test]
fn migration_works_as_intended() {
	new_test_ext().execute_with(|| {
		migration::deprecated::Something::put(5);
		migration::migrate_to_struct::<Test>();
		assert_eq!(TemplateModule::something(), Some(SomeStruct { something: 5, sth_else: true}));
	});
}

