// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Descriptor-relative immutable objects outside the general CAS namespace.
//!
//! A caller supplies a bounded sequence of already-validated domain coordinates. Every component is
//! nevertheless checked here and traversed relative to a retained root descriptor with `NOFOLLOW`.
//! This keeps a dedicated control namespace from becoming a path-based escape around the ordinary
//! CAS publisher's descriptor custody.

use crate::descriptor_root_chirho::{
    identity_from_metadata_chirho, inspect_entry_at_chirho, inspect_open_file_chirho,
    io_error_from_errno_chirho, verify_directory_inspection_chirho, verify_file_inspection_chirho,
};
use crate::DescriptorRootCustodyChirho;
use fs2::FileExt;
use rustix::fs::{
    mkdirat, openat, renameat_with, unlinkat, AtFlags, Dir, Mode, OFlags, RenameFlags,
};
use rustix::io::Errno;
use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const MAX_NAMESPACE_COMPONENT_BYTES_CHIRHO: usize = 128;
const NAMESPACE_STAGING_DIR_CHIRHO: &str = "content-addressed-staging-chirho";
const NAMESPACE_STAGING_LOCK_FILE_CHIRHO: &str = "publish.lock-chirho";
const NAMESPACE_STAGING_PENDING_FILE_CHIRHO: &str = "pending-object-chirho";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ContentAddressedNamespacePublishInjectionChirho {
    after_pending_sync_chirho: bool,
    after_rename_before_directory_sync_chirho: bool,
}

impl ContentAddressedNamespacePublishInjectionChirho {
    #[cfg(test)]
    const AFTER_PENDING_SYNC_CHIRHO: Self = Self {
        after_pending_sync_chirho: true,
        after_rename_before_directory_sync_chirho: false,
    };
    #[cfg(test)]
    const AFTER_RENAME_BEFORE_DIRECTORY_SYNC_CHIRHO: Self = Self {
        after_pending_sync_chirho: false,
        after_rename_before_directory_sync_chirho: true,
    };
}

struct OpenedContentAddressedNamespaceChirho {
    custody_chirho: std::sync::Arc<DescriptorRootCustodyChirho>,
    parent_directory_chirho: File,
    directory_chirho: File,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentAddressedNamespaceErrorKindChirho {
    InvalidCoordinateChirho,
    BoundExceededChirho,
    UnavailableChirho,
    CorruptObjectChirho,
}

#[derive(Debug)]
pub struct ContentAddressedNamespaceErrorChirho {
    kind_chirho: ContentAddressedNamespaceErrorKindChirho,
    message_chirho: String,
}

impl ContentAddressedNamespaceErrorChirho {
    pub fn kind_chirho(&self) -> ContentAddressedNamespaceErrorKindChirho {
        self.kind_chirho
    }
}

impl fmt::Display for ContentAddressedNamespaceErrorChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter_chirho, "{}", self.message_chirho)
    }
}

impl std::error::Error for ContentAddressedNamespaceErrorChirho {}

pub type ContentAddressedNamespaceResultChirho<ValueChirho> =
    Result<ValueChirho, ContentAddressedNamespaceErrorChirho>;

/// Publish one immutable object at its BLAKE3 address below a descriptor-relative namespace.
///
/// The namespace is not selected by bytes stored in the object. Domain writers should expose a
/// narrower function with fixed components and a verified input type, rather than forwarding this
/// coordinate surface to their callers.
pub fn publish_content_addressed_namespace_file_no_replace_chirho(
    root_chirho: &Path,
    namespace_components_chirho: &[&str],
    address_hex_chirho: &str,
    bytes_chirho: &[u8],
    max_bytes_chirho: usize,
) -> ContentAddressedNamespaceResultChirho<()> {
    publish_content_addressed_namespace_file_no_replace_with_injection_chirho(
        root_chirho,
        namespace_components_chirho,
        address_hex_chirho,
        bytes_chirho,
        max_bytes_chirho,
        ContentAddressedNamespacePublishInjectionChirho::default(),
    )
}

fn publish_content_addressed_namespace_file_no_replace_with_injection_chirho(
    root_chirho: &Path,
    namespace_components_chirho: &[&str],
    address_hex_chirho: &str,
    bytes_chirho: &[u8],
    max_bytes_chirho: usize,
    injection_chirho: ContentAddressedNamespacePublishInjectionChirho,
) -> ContentAddressedNamespaceResultChirho<()> {
    validate_address_hex_chirho(address_hex_chirho)?;
    if bytes_chirho.len() > max_bytes_chirho {
        return Err(bound_exceeded_chirho(
            "ContentAddressedNamespaceObjectBytesExceededChirho",
        ));
    }
    if blake3::hash(bytes_chirho).to_hex().as_str() != address_hex_chirho {
        return Err(corrupt_chirho(
            "ContentAddressedNamespaceAddressMismatchChirho",
        ));
    }

    let opened_chirho = open_namespace_chirho(root_chirho, namespace_components_chirho, true)?
        .expect("a creating namespace traversal always returns a directory");
    let staging_chirho = open_or_create_directory_at_chirho(
        &opened_chirho.parent_directory_chirho,
        NAMESPACE_STAGING_DIR_CHIRHO,
        opened_chirho.custody_chirho.owner_uid_chirho,
    )?;
    with_namespace_staging_lock_chirho(
        &staging_chirho,
        opened_chirho.custody_chirho.owner_uid_chirho,
        || {
            publish_from_staging_unlocked_chirho(
                &opened_chirho,
                &staging_chirho,
                address_hex_chirho,
                bytes_chirho,
                max_bytes_chirho,
                injection_chirho,
            )
        },
    )
}

/// Read and re-hash one immutable object from a descriptor-relative namespace.
pub fn read_content_addressed_namespace_file_chirho(
    root_chirho: &Path,
    namespace_components_chirho: &[&str],
    address_hex_chirho: &str,
    max_bytes_chirho: usize,
) -> ContentAddressedNamespaceResultChirho<Option<Vec<u8>>> {
    validate_address_hex_chirho(address_hex_chirho)?;
    let Some(opened_chirho) =
        open_namespace_chirho(root_chirho, namespace_components_chirho, false)?
    else {
        return Ok(None);
    };
    if inspect_entry_at_chirho(&opened_chirho.directory_chirho, address_hex_chirho)
        .map_err(|error_chirho| {
            unavailable_message_chirho("inspect namespace object", error_chirho)
        })?
        .is_none()
    {
        return Ok(None);
    }
    let bytes_chirho = read_verified_file_at_chirho(
        &opened_chirho.directory_chirho,
        address_hex_chirho,
        opened_chirho.custody_chirho.owner_uid_chirho,
        max_bytes_chirho,
    )?;
    opened_chirho
        .custody_chirho
        .verify_custody_chirho()
        .map_err(|error_chirho| {
            unavailable_message_chirho(
                "ContentAddressedNamespaceRootCustodyChangedChirho",
                error_chirho,
            )
        })?;
    Ok(Some(bytes_chirho))
}

/// List the canonical object addresses in one bounded namespace directory.
///
/// This enumerates only the active move shard selected by the caller, never sibling or historical
/// shards. Each returned name is a safe regular single-link file owned by the root owner.
pub fn list_content_addressed_namespace_files_chirho(
    root_chirho: &Path,
    namespace_components_chirho: &[&str],
    max_entries_chirho: usize,
) -> ContentAddressedNamespaceResultChirho<Vec<String>> {
    let Some(opened_chirho) =
        open_namespace_chirho(root_chirho, namespace_components_chirho, false)?
    else {
        return Ok(Vec::new());
    };
    let mut directory_stream_chirho =
        Dir::read_from(&opened_chirho.directory_chirho).map_err(|error_chirho| {
            unavailable_chirho(
                "open descriptor-relative namespace enumeration",
                io_error_from_errno_chirho(error_chirho),
            )
        })?;
    let mut addresses_chirho = Vec::new();
    for entry_result_chirho in &mut directory_stream_chirho {
        let entry_chirho = entry_result_chirho.map_err(|error_chirho| {
            unavailable_chirho(
                "read descriptor-relative namespace enumeration",
                io_error_from_errno_chirho(error_chirho),
            )
        })?;
        let name_chirho = entry_chirho.file_name().to_str().map_err(|error_chirho| {
            invalid_message_chirho("ContentAddressedNamespaceNonUtf8EntryChirho", error_chirho)
        })?;
        if matches!(name_chirho, "." | "..") {
            continue;
        }
        validate_address_hex_chirho(name_chirho)?;
        let inspection_chirho =
            inspect_entry_at_chirho(&opened_chirho.directory_chirho, name_chirho)
                .map_err(|error_chirho| {
                    unavailable_message_chirho("inspect enumerated namespace object", error_chirho)
                })?
                .ok_or_else(|| corrupt_chirho("ContentAddressedNamespaceEntryDisappearedChirho"))?;
        verify_file_inspection_chirho(
            &inspection_chirho,
            opened_chirho.custody_chirho.owner_uid_chirho,
        )
        .map_err(|error_chirho| {
            corrupt_message_chirho("ContentAddressedNamespaceUnsafeEntryChirho", error_chirho)
        })?;
        addresses_chirho.push(name_chirho.to_string());
        if addresses_chirho.len() > max_entries_chirho {
            return Err(bound_exceeded_chirho(
                "ContentAddressedNamespaceEntryCountExceededChirho",
            ));
        }
    }
    opened_chirho
        .custody_chirho
        .verify_custody_chirho()
        .map_err(|error_chirho| {
            unavailable_message_chirho(
                "ContentAddressedNamespaceRootCustodyChangedChirho",
                error_chirho,
            )
        })?;
    addresses_chirho.sort();
    Ok(addresses_chirho)
}

fn open_namespace_chirho(
    root_chirho: &Path,
    namespace_components_chirho: &[&str],
    create_chirho: bool,
) -> ContentAddressedNamespaceResultChirho<Option<OpenedContentAddressedNamespaceChirho>> {
    if namespace_components_chirho.is_empty() {
        return Err(invalid_chirho(
            "ContentAddressedNamespaceNeedsAComponentChirho",
        ));
    }
    let custody_chirho =
        DescriptorRootCustodyChirho::open_path_chirho(root_chirho).map_err(|error_chirho| {
            unavailable_message_chirho(
                "ContentAddressedNamespaceRootUnavailableChirho",
                error_chirho,
            )
        })?;
    custody_chirho
        .verify_custody_chirho()
        .map_err(|error_chirho| {
            unavailable_message_chirho(
                "ContentAddressedNamespaceRootCustodyInvalidChirho",
                error_chirho,
            )
        })?;
    let mut directory_chirho =
        custody_chirho
            .root_directory_chirho
            .try_clone()
            .map_err(|error_chirho| {
                unavailable_chirho("clone namespace root descriptor", error_chirho)
            })?;
    let mut parent_directory_chirho = None;
    for (index_chirho, component_chirho) in namespace_components_chirho.iter().enumerate() {
        validate_namespace_component_chirho(component_chirho)?;
        if index_chirho + 1 == namespace_components_chirho.len() {
            parent_directory_chirho =
                Some(directory_chirho.try_clone().map_err(|error_chirho| {
                    unavailable_chirho("clone namespace parent descriptor", error_chirho)
                })?);
        }
        let next_chirho = if create_chirho {
            Some(open_or_create_directory_at_chirho(
                &directory_chirho,
                component_chirho,
                custody_chirho.owner_uid_chirho,
            )?)
        } else {
            open_optional_directory_at_chirho(
                &directory_chirho,
                component_chirho,
                custody_chirho.owner_uid_chirho,
            )?
        };
        let Some(next_chirho) = next_chirho else {
            return Ok(None);
        };
        directory_chirho = next_chirho;
    }
    Ok(Some(OpenedContentAddressedNamespaceChirho {
        custody_chirho,
        parent_directory_chirho: parent_directory_chirho
            .expect("a non-empty namespace always has a parent descriptor"),
        directory_chirho,
    }))
}

fn open_or_create_directory_at_chirho(
    parent_chirho: &File,
    name_chirho: &str,
    owner_uid_chirho: u32,
) -> ContentAddressedNamespaceResultChirho<File> {
    if inspect_entry_at_chirho(parent_chirho, name_chirho)
        .map_err(|error_chirho| {
            unavailable_message_chirho("inspect namespace directory", error_chirho)
        })?
        .is_none()
    {
        match mkdirat(parent_chirho, name_chirho, Mode::RWXU) {
            Ok(()) => parent_chirho.sync_all().map_err(|error_chirho| {
                unavailable_chirho("sync namespace directory", error_chirho)
            })?,
            Err(Errno::EXIST) => {}
            Err(error_chirho) => {
                return Err(unavailable_chirho(
                    "create namespace directory",
                    io_error_from_errno_chirho(error_chirho),
                ))
            }
        }
    }
    open_optional_directory_at_chirho(parent_chirho, name_chirho, owner_uid_chirho)?
        .ok_or_else(|| unavailable_plain_chirho("ContentAddressedNamespaceDirectoryMissingChirho"))
}

fn open_optional_directory_at_chirho(
    parent_chirho: &File,
    name_chirho: &str,
    owner_uid_chirho: u32,
) -> ContentAddressedNamespaceResultChirho<Option<File>> {
    let Some(entry_chirho) =
        inspect_entry_at_chirho(parent_chirho, name_chirho).map_err(|error_chirho| {
            unavailable_message_chirho("inspect namespace directory", error_chirho)
        })?
    else {
        return Ok(None);
    };
    verify_directory_inspection_chirho(&entry_chirho, owner_uid_chirho).map_err(
        |error_chirho| {
            corrupt_message_chirho(
                "ContentAddressedNamespaceUnsafeDirectoryChirho",
                error_chirho,
            )
        },
    )?;
    let descriptor_chirho = openat(
        parent_chirho,
        name_chirho,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error_chirho| {
        unavailable_chirho(
            "open descriptor-relative namespace directory",
            io_error_from_errno_chirho(error_chirho),
        )
    })?;
    let directory_chirho = File::from(descriptor_chirho);
    let opened_identity_chirho =
        identity_from_metadata_chirho(&directory_chirho.metadata().map_err(|error_chirho| {
            unavailable_chirho("inspect namespace directory descriptor", error_chirho)
        })?);
    if opened_identity_chirho != entry_chirho.identity_chirho {
        return Err(corrupt_chirho(
            "ContentAddressedNamespaceDirectoryIdentityChangedChirho",
        ));
    }
    Ok(Some(directory_chirho))
}

fn publish_from_staging_unlocked_chirho(
    opened_chirho: &OpenedContentAddressedNamespaceChirho,
    staging_chirho: &File,
    address_hex_chirho: &str,
    bytes_chirho: &[u8],
    max_bytes_chirho: usize,
    injection_chirho: ContentAddressedNamespacePublishInjectionChirho,
) -> ContentAddressedNamespaceResultChirho<()> {
    verify_staging_entries_chirho(
        staging_chirho,
        opened_chirho.custody_chirho.owner_uid_chirho,
    )?;
    if inspect_entry_at_chirho(&opened_chirho.directory_chirho, address_hex_chirho)
        .map_err(|error_chirho| {
            unavailable_message_chirho("inspect existing namespace object", error_chirho)
        })?
        .is_some()
    {
        read_verified_file_at_chirho(
            &opened_chirho.directory_chirho,
            address_hex_chirho,
            opened_chirho.custody_chirho.owner_uid_chirho,
            max_bytes_chirho,
        )?;
        sync_namespace_object_directory_chirho(&opened_chirho.directory_chirho)?;
        remove_pending_staging_file_chirho(
            staging_chirho,
            opened_chirho.custody_chirho.owner_uid_chirho,
        )?;
        verify_staging_entries_chirho(
            staging_chirho,
            opened_chirho.custody_chirho.owner_uid_chirho,
        )?;
        return verify_namespace_custody_chirho(&opened_chirho.custody_chirho);
    }

    let mut pending_file_chirho = open_or_create_internal_file_at_chirho(
        staging_chirho,
        NAMESPACE_STAGING_PENDING_FILE_CHIRHO,
        opened_chirho.custody_chirho.owner_uid_chirho,
    )?;
    pending_file_chirho.set_len(0).map_err(|error_chirho| {
        unavailable_chirho("truncate namespace pending file", error_chirho)
    })?;
    pending_file_chirho
        .seek(SeekFrom::Start(0))
        .map_err(|error_chirho| unavailable_chirho("seek namespace pending file", error_chirho))?;
    pending_file_chirho
        .write_all(bytes_chirho)
        .map_err(|error_chirho| unavailable_chirho("write namespace pending file", error_chirho))?;
    pending_file_chirho
        .sync_all()
        .map_err(|error_chirho| unavailable_chirho("sync namespace pending file", error_chirho))?;
    if injection_chirho.after_pending_sync_chirho {
        return Err(unavailable_plain_chirho(
            "ContentAddressedNamespaceInjectedCrashAfterPendingSyncChirho",
        ));
    }
    verify_namespace_custody_chirho(&opened_chirho.custody_chirho)?;

    match renameat_with(
        staging_chirho,
        NAMESPACE_STAGING_PENDING_FILE_CHIRHO,
        &opened_chirho.directory_chirho,
        address_hex_chirho,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {
            if injection_chirho.after_rename_before_directory_sync_chirho {
                return Err(unavailable_plain_chirho(
                    "ContentAddressedNamespaceInjectedCrashAfterRenameChirho",
                ));
            }
            // Make the destination durable before the source-directory removal. A crash between
            // these syncs may leave a bounded duplicate pending entry, which retry cleans.
            sync_namespace_object_directory_chirho(&opened_chirho.directory_chirho)?;
            staging_chirho.sync_all().map_err(|error_chirho| {
                unavailable_chirho("sync namespace staging removal", error_chirho)
            })?;
        }
        Err(Errno::EXIST) => {
            read_verified_file_at_chirho(
                &opened_chirho.directory_chirho,
                address_hex_chirho,
                opened_chirho.custody_chirho.owner_uid_chirho,
                max_bytes_chirho,
            )?;
            sync_namespace_object_directory_chirho(&opened_chirho.directory_chirho)?;
            remove_pending_staging_file_chirho(
                staging_chirho,
                opened_chirho.custody_chirho.owner_uid_chirho,
            )?;
        }
        Err(error_chirho) => {
            return Err(unavailable_chirho(
                "publish namespace object no-replace",
                io_error_from_errno_chirho(error_chirho),
            ));
        }
    }
    verify_staging_entries_chirho(
        staging_chirho,
        opened_chirho.custody_chirho.owner_uid_chirho,
    )?;
    verify_namespace_custody_chirho(&opened_chirho.custody_chirho)
}

fn with_namespace_staging_lock_chirho<ValueChirho>(
    staging_chirho: &File,
    owner_uid_chirho: u32,
    action_chirho: impl FnOnce() -> ContentAddressedNamespaceResultChirho<ValueChirho>,
) -> ContentAddressedNamespaceResultChirho<ValueChirho> {
    let lock_file_chirho = open_or_create_internal_file_at_chirho(
        staging_chirho,
        NAMESPACE_STAGING_LOCK_FILE_CHIRHO,
        owner_uid_chirho,
    )?;
    lock_file_chirho
        .lock_exclusive()
        .map_err(|error_chirho| unavailable_chirho("lock namespace staging", error_chirho))?;
    let result_chirho = verify_internal_file_path_chirho(
        staging_chirho,
        NAMESPACE_STAGING_LOCK_FILE_CHIRHO,
        &lock_file_chirho,
        owner_uid_chirho,
    )
    .and_then(|()| action_chirho());
    let unlock_result_chirho = FileExt::unlock(&lock_file_chirho);
    match (result_chirho, unlock_result_chirho) {
        (Ok(value_chirho), Ok(())) => Ok(value_chirho),
        (Err(error_chirho), Ok(())) => Err(error_chirho),
        (Ok(_value_chirho), Err(error_chirho)) => {
            Err(unavailable_chirho("unlock namespace staging", error_chirho))
        }
        (Err(mut error_chirho), Err(unlock_error_chirho)) => {
            error_chirho.message_chirho.push_str(&format!(
                "; also failed to unlock namespace staging: {unlock_error_chirho}"
            ));
            Err(error_chirho)
        }
    }
}

fn open_or_create_internal_file_at_chirho(
    directory_chirho: &File,
    name_chirho: &str,
    owner_uid_chirho: u32,
) -> ContentAddressedNamespaceResultChirho<File> {
    loop {
        let before_chirho =
            inspect_entry_at_chirho(directory_chirho, name_chirho).map_err(|error_chirho| {
                unavailable_message_chirho("inspect namespace internal file", error_chirho)
            })?;
        if let Some(before_chirho) = &before_chirho {
            verify_file_inspection_chirho(before_chirho, owner_uid_chirho).map_err(
                |error_chirho| {
                    corrupt_message_chirho(
                        "ContentAddressedNamespaceUnsafeInternalFileChirho",
                        error_chirho,
                    )
                },
            )?;
        }
        let descriptor_chirho = if before_chirho.is_some() {
            openat(
                directory_chirho,
                name_chirho,
                OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
        } else {
            openat(
                directory_chirho,
                name_chirho,
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK,
                Mode::RUSR | Mode::WUSR,
            )
        };
        let descriptor_chirho = match descriptor_chirho {
            Ok(descriptor_chirho) => descriptor_chirho,
            Err(Errno::EXIST) if before_chirho.is_none() => continue,
            Err(error_chirho) => {
                return Err(unavailable_chirho(
                    "open namespace internal file",
                    io_error_from_errno_chirho(error_chirho),
                ));
            }
        };
        let file_chirho = File::from(descriptor_chirho);
        if before_chirho.is_none() {
            directory_chirho.sync_all().map_err(|error_chirho| {
                unavailable_chirho("sync namespace internal file creation", error_chirho)
            })?;
        }
        verify_internal_file_path_chirho(
            directory_chirho,
            name_chirho,
            &file_chirho,
            owner_uid_chirho,
        )?;
        if let Some(before_chirho) = before_chirho {
            let opened_chirho = inspect_open_file_chirho(&file_chirho, owner_uid_chirho).map_err(
                |error_chirho| {
                    corrupt_message_chirho(
                        "ContentAddressedNamespaceUnsafeOpenedInternalFileChirho",
                        error_chirho,
                    )
                },
            )?;
            if opened_chirho.identity_chirho != before_chirho.identity_chirho {
                return Err(corrupt_chirho(
                    "ContentAddressedNamespaceInternalFileIdentityChangedChirho",
                ));
            }
        }
        return Ok(file_chirho);
    }
}

fn verify_internal_file_path_chirho(
    directory_chirho: &File,
    name_chirho: &str,
    file_chirho: &File,
    owner_uid_chirho: u32,
) -> ContentAddressedNamespaceResultChirho<()> {
    let opened_chirho =
        inspect_open_file_chirho(file_chirho, owner_uid_chirho).map_err(|error_chirho| {
            corrupt_message_chirho(
                "ContentAddressedNamespaceUnsafeOpenedInternalFileChirho",
                error_chirho,
            )
        })?;
    let path_chirho = inspect_entry_at_chirho(directory_chirho, name_chirho)
        .map_err(|error_chirho| {
            unavailable_message_chirho("reinspect namespace internal file", error_chirho)
        })?
        .ok_or_else(|| corrupt_chirho("ContentAddressedNamespaceInternalFileMissingChirho"))?;
    verify_file_inspection_chirho(&path_chirho, owner_uid_chirho).map_err(|error_chirho| {
        corrupt_message_chirho(
            "ContentAddressedNamespaceUnsafeInternalFileChirho",
            error_chirho,
        )
    })?;
    if opened_chirho.identity_chirho != path_chirho.identity_chirho {
        return Err(corrupt_chirho(
            "ContentAddressedNamespaceInternalFileIdentityChangedChirho",
        ));
    }
    Ok(())
}

fn verify_staging_entries_chirho(
    staging_chirho: &File,
    owner_uid_chirho: u32,
) -> ContentAddressedNamespaceResultChirho<()> {
    let mut stream_chirho = Dir::read_from(staging_chirho).map_err(|error_chirho| {
        unavailable_chirho(
            "open namespace staging enumeration",
            io_error_from_errno_chirho(error_chirho),
        )
    })?;
    let mut saw_lock_chirho = false;
    for entry_result_chirho in &mut stream_chirho {
        let entry_chirho = entry_result_chirho.map_err(|error_chirho| {
            unavailable_chirho(
                "read namespace staging enumeration",
                io_error_from_errno_chirho(error_chirho),
            )
        })?;
        let name_chirho = entry_chirho.file_name().to_str().map_err(|error_chirho| {
            corrupt_message_chirho(
                "ContentAddressedNamespaceNonUtf8StagingEntryChirho",
                error_chirho,
            )
        })?;
        if matches!(name_chirho, "." | "..") {
            continue;
        }
        if !matches!(
            name_chirho,
            NAMESPACE_STAGING_LOCK_FILE_CHIRHO | NAMESPACE_STAGING_PENDING_FILE_CHIRHO
        ) {
            return Err(corrupt_chirho(
                "ContentAddressedNamespaceUnexpectedStagingEntryChirho",
            ));
        }
        let inspection_chirho = inspect_entry_at_chirho(staging_chirho, name_chirho)
            .map_err(|error_chirho| {
                unavailable_message_chirho("inspect namespace staging entry", error_chirho)
            })?
            .ok_or_else(|| corrupt_chirho("ContentAddressedNamespaceStagingEntryMissingChirho"))?;
        verify_file_inspection_chirho(&inspection_chirho, owner_uid_chirho).map_err(
            |error_chirho| {
                corrupt_message_chirho(
                    "ContentAddressedNamespaceUnsafeStagingEntryChirho",
                    error_chirho,
                )
            },
        )?;
        saw_lock_chirho |= name_chirho == NAMESPACE_STAGING_LOCK_FILE_CHIRHO;
    }
    if !saw_lock_chirho {
        return Err(corrupt_chirho(
            "ContentAddressedNamespaceStagingLockMissingChirho",
        ));
    }
    Ok(())
}

fn remove_pending_staging_file_chirho(
    staging_chirho: &File,
    owner_uid_chirho: u32,
) -> ContentAddressedNamespaceResultChirho<()> {
    let Some(inspection_chirho) =
        inspect_entry_at_chirho(staging_chirho, NAMESPACE_STAGING_PENDING_FILE_CHIRHO).map_err(
            |error_chirho| {
                unavailable_message_chirho("inspect namespace pending cleanup", error_chirho)
            },
        )?
    else {
        return staging_chirho.sync_all().map_err(|error_chirho| {
            unavailable_chirho("sync namespace staging recovery", error_chirho)
        });
    };
    verify_file_inspection_chirho(&inspection_chirho, owner_uid_chirho).map_err(
        |error_chirho| {
            corrupt_message_chirho(
                "ContentAddressedNamespaceUnsafePendingCleanupChirho",
                error_chirho,
            )
        },
    )?;
    unlinkat(
        staging_chirho,
        NAMESPACE_STAGING_PENDING_FILE_CHIRHO,
        AtFlags::empty(),
    )
    .map_err(|error_chirho| {
        unavailable_chirho(
            "unlink namespace pending file",
            io_error_from_errno_chirho(error_chirho),
        )
    })?;
    staging_chirho
        .sync_all()
        .map_err(|error_chirho| unavailable_chirho("sync namespace pending cleanup", error_chirho))
}

fn sync_namespace_object_directory_chirho(
    directory_chirho: &File,
) -> ContentAddressedNamespaceResultChirho<()> {
    directory_chirho
        .sync_all()
        .map_err(|error_chirho| unavailable_chirho("sync namespace published object", error_chirho))
}

fn verify_namespace_custody_chirho(
    custody_chirho: &DescriptorRootCustodyChirho,
) -> ContentAddressedNamespaceResultChirho<()> {
    custody_chirho
        .verify_custody_chirho()
        .map_err(|error_chirho| {
            unavailable_message_chirho(
                "ContentAddressedNamespaceRootCustodyChangedChirho",
                error_chirho,
            )
        })
}

fn read_verified_file_at_chirho(
    directory_chirho: &File,
    name_chirho: &str,
    owner_uid_chirho: u32,
    max_bytes_chirho: usize,
) -> ContentAddressedNamespaceResultChirho<Vec<u8>> {
    let before_chirho = inspect_entry_at_chirho(directory_chirho, name_chirho)
        .map_err(|error_chirho| {
            unavailable_message_chirho("inspect namespace object", error_chirho)
        })?
        .ok_or_else(|| corrupt_chirho("ContentAddressedNamespaceObjectMissingChirho"))?;
    verify_file_inspection_chirho(&before_chirho, owner_uid_chirho).map_err(|error_chirho| {
        corrupt_message_chirho("ContentAddressedNamespaceUnsafeObjectChirho", error_chirho)
    })?;
    if before_chirho.len_chirho > max_bytes_chirho as u64 {
        return Err(bound_exceeded_chirho(
            "ContentAddressedNamespaceObjectBytesExceededChirho",
        ));
    }
    let descriptor_chirho = openat(
        directory_chirho,
        name_chirho,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error_chirho| {
        unavailable_chirho(
            "open descriptor-relative namespace object",
            io_error_from_errno_chirho(error_chirho),
        )
    })?;
    let file_chirho = File::from(descriptor_chirho);
    let opened_chirho =
        inspect_open_file_chirho(&file_chirho, owner_uid_chirho).map_err(|error_chirho| {
            corrupt_message_chirho(
                "ContentAddressedNamespaceUnsafeOpenedObjectChirho",
                error_chirho,
            )
        })?;
    if opened_chirho.identity_chirho != before_chirho.identity_chirho {
        return Err(corrupt_chirho(
            "ContentAddressedNamespaceObjectIdentityChangedChirho",
        ));
    }
    let mut reader_chirho = file_chirho
        .try_clone()
        .map_err(|error_chirho| {
            unavailable_chirho("clone namespace object descriptor", error_chirho)
        })?
        .take(max_bytes_chirho as u64 + 1);
    let mut bytes_chirho = Vec::with_capacity(before_chirho.len_chirho as usize);
    reader_chirho
        .read_to_end(&mut bytes_chirho)
        .map_err(|error_chirho| unavailable_chirho("read namespace object", error_chirho))?;
    if bytes_chirho.len() > max_bytes_chirho {
        return Err(bound_exceeded_chirho(
            "ContentAddressedNamespaceObjectBytesExceededChirho",
        ));
    }
    let after_metadata_chirho = file_chirho.metadata().map_err(|error_chirho| {
        unavailable_chirho("reinspect namespace object descriptor", error_chirho)
    })?;
    let path_after_chirho = inspect_entry_at_chirho(directory_chirho, name_chirho)
        .map_err(|error_chirho| {
            unavailable_message_chirho("reinspect namespace object path", error_chirho)
        })?
        .ok_or_else(|| corrupt_chirho("ContentAddressedNamespaceObjectPathDisappearedChirho"))?;
    verify_file_inspection_chirho(&path_after_chirho, owner_uid_chirho).map_err(
        |error_chirho| {
            corrupt_message_chirho(
                "ContentAddressedNamespaceUnsafeObjectAfterReadChirho",
                error_chirho,
            )
        },
    )?;
    if after_metadata_chirho.dev() != opened_chirho.identity_chirho.device_chirho
        || after_metadata_chirho.ino() != opened_chirho.identity_chirho.inode_chirho
        || after_metadata_chirho.len() != bytes_chirho.len() as u64
        || path_after_chirho.identity_chirho != opened_chirho.identity_chirho
        || blake3::hash(&bytes_chirho).to_hex().as_str() != name_chirho
    {
        return Err(corrupt_chirho(
            "ContentAddressedNamespaceObjectBytesOrIdentityChangedChirho",
        ));
    }
    Ok(bytes_chirho)
}

fn validate_namespace_component_chirho(
    component_chirho: &str,
) -> ContentAddressedNamespaceResultChirho<()> {
    if component_chirho.is_empty()
        || component_chirho.len() > MAX_NAMESPACE_COMPONENT_BYTES_CHIRHO
        || matches!(component_chirho, "." | "..")
        || component_chirho == NAMESPACE_STAGING_DIR_CHIRHO
        || !component_chirho.bytes().all(|byte_chirho| {
            byte_chirho.is_ascii_lowercase()
                || byte_chirho.is_ascii_digit()
                || matches!(byte_chirho, b'-' | b'_' | b'.')
        })
    {
        return Err(invalid_chirho(
            "ContentAddressedNamespaceInvalidComponentChirho",
        ));
    }
    Ok(())
}

fn validate_address_hex_chirho(
    address_hex_chirho: &str,
) -> ContentAddressedNamespaceResultChirho<()> {
    if address_hex_chirho.len() != 64
        || !address_hex_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || matches!(byte_chirho, b'a'..=b'f'))
    {
        return Err(invalid_chirho(
            "ContentAddressedNamespaceInvalidAddressChirho",
        ));
    }
    Ok(())
}

fn invalid_chirho(message_chirho: impl Into<String>) -> ContentAddressedNamespaceErrorChirho {
    ContentAddressedNamespaceErrorChirho {
        kind_chirho: ContentAddressedNamespaceErrorKindChirho::InvalidCoordinateChirho,
        message_chirho: message_chirho.into(),
    }
}

fn invalid_message_chirho(
    context_chirho: &str,
    error_chirho: impl fmt::Display,
) -> ContentAddressedNamespaceErrorChirho {
    invalid_chirho(format!("{context_chirho}: {error_chirho}"))
}

fn bound_exceeded_chirho(
    message_chirho: impl Into<String>,
) -> ContentAddressedNamespaceErrorChirho {
    ContentAddressedNamespaceErrorChirho {
        kind_chirho: ContentAddressedNamespaceErrorKindChirho::BoundExceededChirho,
        message_chirho: message_chirho.into(),
    }
}

fn unavailable_plain_chirho(
    message_chirho: impl Into<String>,
) -> ContentAddressedNamespaceErrorChirho {
    ContentAddressedNamespaceErrorChirho {
        kind_chirho: ContentAddressedNamespaceErrorKindChirho::UnavailableChirho,
        message_chirho: message_chirho.into(),
    }
}

fn unavailable_chirho(
    context_chirho: &str,
    error_chirho: impl fmt::Display,
) -> ContentAddressedNamespaceErrorChirho {
    unavailable_plain_chirho(format!("{context_chirho}: {error_chirho}"))
}

fn unavailable_message_chirho(
    context_chirho: &str,
    error_chirho: impl fmt::Display,
) -> ContentAddressedNamespaceErrorChirho {
    unavailable_chirho(context_chirho, error_chirho)
}

fn corrupt_chirho(message_chirho: impl Into<String>) -> ContentAddressedNamespaceErrorChirho {
    ContentAddressedNamespaceErrorChirho {
        kind_chirho: ContentAddressedNamespaceErrorKindChirho::CorruptObjectChirho,
        message_chirho: message_chirho.into(),
    }
}

fn corrupt_message_chirho(
    context_chirho: &str,
    error_chirho: impl fmt::Display,
) -> ContentAddressedNamespaceErrorChirho {
    corrupt_chirho(format!("{context_chirho}: {error_chirho}"))
}

#[cfg(test)]
#[path = "content_addressed_namespace_tests_chirho.rs"]
mod content_addressed_namespace_tests_chirho;
