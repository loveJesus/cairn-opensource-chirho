// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use std::fs;
use std::os::unix::fs::symlink;

const COMPONENTS_CHIRHO: &[&str] = &[
    "tenant-root-move-control-chirho",
    "aa",
    "bbbb-chirho",
    "records-chirho",
];

fn address_chirho(bytes_chirho: &[u8]) -> String {
    blake3::hash(bytes_chirho).to_hex().to_string()
}

fn object_path_chirho(root_chirho: &Path, address_chirho: &str) -> std::path::PathBuf {
    namespace_path_chirho(root_chirho).join(address_chirho)
}

fn namespace_path_chirho(root_chirho: &Path) -> std::path::PathBuf {
    COMPONENTS_CHIRHO.iter().fold(
        root_chirho.to_path_buf(),
        |path_chirho, component_chirho| path_chirho.join(component_chirho),
    )
}

fn staging_path_chirho(root_chirho: &Path) -> std::path::PathBuf {
    COMPONENTS_CHIRHO[..COMPONENTS_CHIRHO.len() - 1]
        .iter()
        .fold(
            root_chirho.to_path_buf(),
            |path_chirho, component_chirho| path_chirho.join(component_chirho),
        )
        .join(NAMESPACE_STAGING_DIR_CHIRHO)
}

#[test]
fn exact_bytes_publish_read_and_list_through_the_retained_root_chirho() {
    let temp_chirho = tempfile::tempdir().expect("temp root");
    let bytes_chirho = b"signed-control-record-chirho";
    let address_chirho = address_chirho(bytes_chirho);

    publish_content_addressed_namespace_file_no_replace_chirho(
        temp_chirho.path(),
        COMPONENTS_CHIRHO,
        &address_chirho,
        bytes_chirho,
        1024,
    )
    .expect("first publication");
    publish_content_addressed_namespace_file_no_replace_chirho(
        temp_chirho.path(),
        COMPONENTS_CHIRHO,
        &address_chirho,
        bytes_chirho,
        1024,
    )
    .expect("exact retry is a no-op");

    assert_eq!(
        read_content_addressed_namespace_file_chirho(
            temp_chirho.path(),
            COMPONENTS_CHIRHO,
            &address_chirho,
            1024,
        )
        .expect("read")
        .expect("present"),
        bytes_chirho
    );
    assert_eq!(
        list_content_addressed_namespace_files_chirho(temp_chirho.path(), COMPONENTS_CHIRHO, 1,)
            .expect("list"),
        vec![address_chirho]
    );
}

#[test]
fn a_namespace_component_symlink_refuses_before_writing_outside_the_root_chirho() {
    let temp_chirho = tempfile::tempdir().expect("temp root");
    let outside_chirho = tempfile::tempdir().expect("outside root");
    symlink(
        outside_chirho.path(),
        temp_chirho.path().join(COMPONENTS_CHIRHO[0]),
    )
    .expect("plant namespace symlink");
    let bytes_chirho = b"must-stay-inside-chirho";
    let address_chirho = address_chirho(bytes_chirho);

    let error_chirho = publish_content_addressed_namespace_file_no_replace_chirho(
        temp_chirho.path(),
        COMPONENTS_CHIRHO,
        &address_chirho,
        bytes_chirho,
        1024,
    )
    .expect_err("symlink namespace must refuse");
    assert_eq!(
        error_chirho.kind_chirho(),
        ContentAddressedNamespaceErrorKindChirho::CorruptObjectChirho
    );
    assert!(
        fs::read_dir(outside_chirho.path())
            .expect("outside readable")
            .next()
            .is_none(),
        "a refusing traversal must leave zero bytes outside the retained root"
    );
}

#[test]
fn object_and_entry_bounds_refuse_without_truncation_chirho() {
    let temp_chirho = tempfile::tempdir().expect("temp root");
    let first_chirho = b"first-control-record-chirho";
    let first_address_chirho = address_chirho(first_chirho);
    publish_content_addressed_namespace_file_no_replace_chirho(
        temp_chirho.path(),
        COMPONENTS_CHIRHO,
        &first_address_chirho,
        first_chirho,
        1024,
    )
    .expect("first");
    assert_eq!(
        read_content_addressed_namespace_file_chirho(
            temp_chirho.path(),
            COMPONENTS_CHIRHO,
            &first_address_chirho,
            first_chirho.len() - 1,
        )
        .expect_err("oversize read refuses")
        .kind_chirho(),
        ContentAddressedNamespaceErrorKindChirho::BoundExceededChirho
    );

    let second_chirho = b"second-control-record-chirho";
    let second_address_chirho = address_chirho(second_chirho);
    publish_content_addressed_namespace_file_no_replace_chirho(
        temp_chirho.path(),
        COMPONENTS_CHIRHO,
        &second_address_chirho,
        second_chirho,
        1024,
    )
    .expect("second");
    assert_eq!(
        list_content_addressed_namespace_files_chirho(temp_chirho.path(), COMPONENTS_CHIRHO, 1,)
            .expect_err("entry cap refuses rather than truncating")
            .kind_chirho(),
        ContentAddressedNamespaceErrorKindChirho::BoundExceededChirho
    );
}

#[test]
fn a_retained_name_with_changed_bytes_refuses_as_corrupt_chirho() {
    let temp_chirho = tempfile::tempdir().expect("temp root");
    let bytes_chirho = b"original-control-record-chirho";
    let address_chirho = address_chirho(bytes_chirho);
    publish_content_addressed_namespace_file_no_replace_chirho(
        temp_chirho.path(),
        COMPONENTS_CHIRHO,
        &address_chirho,
        bytes_chirho,
        1024,
    )
    .expect("publish");
    fs::write(
        object_path_chirho(temp_chirho.path(), &address_chirho),
        b"tampered-control-record-chirho",
    )
    .expect("tamper fixture");

    assert_eq!(
        read_content_addressed_namespace_file_chirho(
            temp_chirho.path(),
            COMPONENTS_CHIRHO,
            &address_chirho,
            1024,
        )
        .expect_err("tamper refuses")
        .kind_chirho(),
        ContentAddressedNamespaceErrorKindChirho::CorruptObjectChirho
    );
}

#[test]
fn a_wrong_address_refuses_at_publish_time_without_writing_bytes_chirho() {
    let temp_chirho = tempfile::tempdir().expect("temp root");
    let bytes_chirho = b"address-must-come-from-these-bytes-chirho";
    let wrong_address_chirho = address_chirho(b"different-bytes-chirho");

    let error_chirho = publish_content_addressed_namespace_file_no_replace_chirho(
        temp_chirho.path(),
        COMPONENTS_CHIRHO,
        &wrong_address_chirho,
        bytes_chirho,
        1024,
    )
    .expect_err("a caller-selected address must refuse before publication");
    assert_eq!(
        error_chirho.kind_chirho(),
        ContentAddressedNamespaceErrorKindChirho::CorruptObjectChirho
    );
    assert_eq!(
        error_chirho.to_string(),
        "ContentAddressedNamespaceAddressMismatchChirho",
        "the arm must attribute the refusal to the publish-time gate, not a later read-time rehash"
    );
    assert!(
        !namespace_path_chirho(temp_chirho.path()).exists(),
        "address validation precedes every namespace mutation"
    );
}

#[test]
fn a_crash_after_pending_sync_keeps_replay_readable_and_retry_recovers_chirho() {
    let temp_chirho = tempfile::tempdir().expect("temp root");
    let bytes_chirho = b"crash-retry-control-record-chirho";
    let address_chirho = address_chirho(bytes_chirho);

    assert_eq!(
        publish_content_addressed_namespace_file_no_replace_with_injection_chirho(
            temp_chirho.path(),
            COMPONENTS_CHIRHO,
            &address_chirho,
            bytes_chirho,
            1024,
            ContentAddressedNamespacePublishInjectionChirho::AFTER_PENDING_SYNC_CHIRHO,
        )
        .expect_err("injected crash leaves the fixed pending slot")
        .kind_chirho(),
        ContentAddressedNamespaceErrorKindChirho::UnavailableChirho
    );
    assert_eq!(
        list_content_addressed_namespace_files_chirho(temp_chirho.path(), COMPONENTS_CHIRHO, 1,)
            .expect("a pending sibling cannot poison replay"),
        Vec::<String>::new()
    );
    let staged_before_retry_chirho = fs::read_dir(staging_path_chirho(temp_chirho.path()))
        .expect("staging readable")
        .map(|entry_chirho| entry_chirho.expect("staging entry").file_name())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        staged_before_retry_chirho,
        std::collections::BTreeSet::from([
            NAMESPACE_STAGING_LOCK_FILE_CHIRHO.into(),
            NAMESPACE_STAGING_PENDING_FILE_CHIRHO.into(),
        ]),
        "a crash leaves exactly one lock and one bounded pending slot"
    );

    publish_content_addressed_namespace_file_no_replace_chirho(
        temp_chirho.path(),
        COMPONENTS_CHIRHO,
        &address_chirho,
        bytes_chirho,
        1024,
    )
    .expect("retry recovers the fixed pending slot");
    assert_eq!(
        list_content_addressed_namespace_files_chirho(temp_chirho.path(), COMPONENTS_CHIRHO, 1,)
            .expect("replay after retry"),
        vec![address_chirho]
    );
    let staged_after_retry_chirho = fs::read_dir(staging_path_chirho(temp_chirho.path()))
        .expect("staging readable after retry")
        .map(|entry_chirho| entry_chirho.expect("staging entry").file_name())
        .collect::<Vec<_>>();
    assert_eq!(
        staged_after_retry_chirho,
        vec![std::ffi::OsString::from(NAMESPACE_STAGING_LOCK_FILE_CHIRHO)],
        "retry removes and durably syncs the pending slot"
    );
}

#[test]
fn a_crash_after_rename_is_recovered_by_an_exact_retry_chirho() {
    let temp_chirho = tempfile::tempdir().expect("temp root");
    let bytes_chirho = b"renamed-before-directory-sync-chirho";
    let address_chirho = address_chirho(bytes_chirho);

    let error_chirho = publish_content_addressed_namespace_file_no_replace_with_injection_chirho(
        temp_chirho.path(),
        COMPONENTS_CHIRHO,
        &address_chirho,
        bytes_chirho,
        1024,
        ContentAddressedNamespacePublishInjectionChirho::AFTER_RENAME_BEFORE_DIRECTORY_SYNC_CHIRHO,
    )
    .expect_err("injected crash follows rename but precedes both directory syncs");
    assert_eq!(
        error_chirho.to_string(),
        "ContentAddressedNamespaceInjectedCrashAfterRenameChirho"
    );
    assert_eq!(
        read_content_addressed_namespace_file_chirho(
            temp_chirho.path(),
            COMPONENTS_CHIRHO,
            &address_chirho,
            1024,
        )
        .expect("the renamed object is readable in the live filesystem")
        .expect("renamed object present"),
        bytes_chirho
    );

    publish_content_addressed_namespace_file_no_replace_chirho(
        temp_chirho.path(),
        COMPONENTS_CHIRHO,
        &address_chirho,
        bytes_chirho,
        1024,
    )
    .expect("exact retry re-syncs the existing destination and staging removal");
    assert_eq!(
        list_content_addressed_namespace_files_chirho(temp_chirho.path(), COMPONENTS_CHIRHO, 1,)
            .expect("replay after exact retry"),
        vec![address_chirho]
    );
    assert_eq!(
        fs::read_dir(staging_path_chirho(temp_chirho.path()))
            .expect("staging readable after rename recovery")
            .map(|entry_chirho| entry_chirho.expect("staging entry").file_name())
            .collect::<Vec<_>>(),
        vec![std::ffi::OsString::from(NAMESPACE_STAGING_LOCK_FILE_CHIRHO)]
    );
}

#[test]
fn an_unknown_address_entry_refuses_but_does_not_hide_later_writes_chirho() {
    let temp_chirho = tempfile::tempdir().expect("temp root");
    let first_chirho = b"first-before-orphan-chirho";
    let first_address_chirho = address_chirho(first_chirho);
    publish_content_addressed_namespace_file_no_replace_chirho(
        temp_chirho.path(),
        COMPONENTS_CHIRHO,
        &first_address_chirho,
        first_chirho,
        1024,
    )
    .expect("first publish");
    let orphan_name_chirho = ".namespace-object.tmp-chirho-424242-7";
    fs::write(
        namespace_path_chirho(temp_chirho.path()).join(orphan_name_chirho),
        b"old-layout-orphan-chirho",
    )
    .expect("plant the former in-address temp shape");
    assert_eq!(
        list_content_addressed_namespace_files_chirho(temp_chirho.path(), COMPONENTS_CHIRHO, 2,)
            .expect_err("the closed address set must not skip unknown entries")
            .kind_chirho(),
        ContentAddressedNamespaceErrorKindChirho::InvalidCoordinateChirho
    );

    let second_chirho = b"second-during-write-only-strand-chirho";
    let second_address_chirho = address_chirho(second_chirho);
    publish_content_addressed_namespace_file_no_replace_chirho(
        temp_chirho.path(),
        COMPONENTS_CHIRHO,
        &second_address_chirho,
        second_chirho,
        1024,
    )
    .expect("publication remains content-addressed while replay refuses");
    fs::remove_file(namespace_path_chirho(temp_chirho.path()).join(orphan_name_chirho))
        .expect("remove planted old-layout orphan");
    let mut expected_addresses_chirho = vec![first_address_chirho, second_address_chirho];
    expected_addresses_chirho.sort();
    assert_eq!(
        list_content_addressed_namespace_files_chirho(temp_chirho.path(), COMPONENTS_CHIRHO, 2,)
            .expect("removing the plant restores both valid writes"),
        expected_addresses_chirho
    );
}

#[test]
fn an_unknown_staging_entry_refuses_before_reusing_the_pending_slot_chirho() {
    let temp_chirho = tempfile::tempdir().expect("temp root");
    let first_chirho = b"first-before-staging-plant-chirho";
    let first_address_chirho = address_chirho(first_chirho);
    publish_content_addressed_namespace_file_no_replace_chirho(
        temp_chirho.path(),
        COMPONENTS_CHIRHO,
        &first_address_chirho,
        first_chirho,
        1024,
    )
    .expect("first publish creates the fixed staging directory");
    fs::write(
        staging_path_chirho(temp_chirho.path()).join("unreviewed-staging-entry-chirho"),
        b"must-not-be-skipped-or-deleted-chirho",
    )
    .expect("plant an entry outside the closed staging grammar");

    let second_chirho = b"second-after-staging-plant-chirho";
    let second_address_chirho = address_chirho(second_chirho);
    let error_chirho = publish_content_addressed_namespace_file_no_replace_chirho(
        temp_chirho.path(),
        COMPONENTS_CHIRHO,
        &second_address_chirho,
        second_chirho,
        1024,
    )
    .expect_err("unknown staging state must refuse before slot reuse");
    assert_eq!(
        error_chirho.kind_chirho(),
        ContentAddressedNamespaceErrorKindChirho::CorruptObjectChirho
    );
    assert_eq!(
        error_chirho.to_string(),
        "ContentAddressedNamespaceUnexpectedStagingEntryChirho"
    );
    assert!(
        !object_path_chirho(temp_chirho.path(), &second_address_chirho).exists(),
        "a refusing staging census must not publish the offered object"
    );
    assert_eq!(
        list_content_addressed_namespace_files_chirho(temp_chirho.path(), COMPONENTS_CHIRHO, 1,)
            .expect("the address directory remains independently readable"),
        vec![first_address_chirho]
    );
}
