// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Test-only hooks for reviewed source-asset install fault injection.
//!
//! The hook is THREAD-LOCAL: an armed failure reaches only installs on the thread that armed it, so tests running in
//! parallel cannot fail each other's installs. Every current user installs on its own test thread.

use std::cell::Cell;

thread_local! {
    static REVIEWED_ASSET_INSTALL_FAIL_AFTER_CHIRHO: Cell<usize> = const { Cell::new(usize::MAX) };
}

pub fn set_reviewed_asset_install_fail_after_for_test_chirho(fail_after_chirho: Option<usize>) {
    REVIEWED_ASSET_INSTALL_FAIL_AFTER_CHIRHO
        .with(|cell_chirho| cell_chirho.set(fail_after_chirho.unwrap_or(usize::MAX)));
}

pub fn reviewed_asset_install_should_fail_chirho(installed_chirho: usize) -> bool {
    REVIEWED_ASSET_INSTALL_FAIL_AFTER_CHIRHO
        .with(|cell_chirho| installed_chirho >= cell_chirho.get())
}
