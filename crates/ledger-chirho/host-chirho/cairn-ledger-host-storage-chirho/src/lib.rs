// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Filesystem implementation of the ledger's flat logical storage namespace.

#[cfg(unix)]
mod descriptor_namespace_chirho;

use anyhow::{Context, Result};
#[cfg(not(unix))]
use cairn_durable_chirho::{
    append_durable_line_chirho, create_file_durable_chirho, fsync_dir_chirho,
    write_file_durable_chirho, CreateFileDurableOutcomeChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use std::error::Error;
use std::fmt;
use std::fs::File;
#[cfg(not(unix))]
use std::fs::{self, OpenOptions};
#[cfg(not(unix))]
use std::io::{ErrorKind, Read, Seek, SeekFrom};
#[cfg(not(unix))]
use std::path::PathBuf;
use std::path::{Component, Path};
#[cfg(unix)]
use std::sync::Arc;

#[cfg(unix)]
pub use descriptor_namespace_chirho::StableLedgerNamespaceSnapshotChirho;

const MAX_LOGICAL_PATH_BYTES_CHIRHO: usize = 512;
const DURABLE_TEMP_MARKER_CHIRHO: &str = ".tmp-chirho-";
#[cfg(any(test, feature = "test-hooks-chirho"))]
pub const STABLE_MUTABLE_TARGET_MAX_BYTES_CHIRHO: usize = 64 * 1024;

/// Typed host-boundary refusals. Host paths and hostile logical strings are not echoed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostLedgerStorageRefusalChirho {
    NamespaceUnavailableChirho,
    NamespaceNotDirectoryChirho,
    UnsafeLogicalPathChirho,
    SymlinkBoundaryChirho,
    MissingObjectChirho,
    InvalidRangeChirho,
    NonUtf8ObjectNameChirho,
    OverlappingMonitorNamespaceChirho,
    InvalidOperationalRowChirho,
    UnsupportedAuthorityPlatformChirho,
    NamespaceIdentityChangedChirho,
    MutableTargetNotRegularChirho,
    MutableTargetAliasedChirho,
    MutableTargetOwnerMismatchChirho,
    MutableTargetModeTooBroadChirho,
    ObjectExceedsBoundChirho,
    ExclusiveLockBusyChirho,
}

impl fmt::Display for HostLedgerStorageRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message_chirho = match self {
            Self::NamespaceUnavailableChirho => "ledger storage namespace is unavailable",
            Self::NamespaceNotDirectoryChirho => {
                "ledger storage namespace is not a regular directory"
            }
            Self::UnsafeLogicalPathChirho => "ledger logical storage path is unsafe",
            Self::SymlinkBoundaryChirho => "ledger storage boundary refuses a symlink",
            Self::MissingObjectChirho => "ledger storage object is missing",
            Self::InvalidRangeChirho => "ledger storage range is invalid",
            Self::NonUtf8ObjectNameChirho => "ledger storage object name is not UTF-8",
            Self::OverlappingMonitorNamespaceChirho => {
                "ledger and monitor evidence namespaces must be physically disjoint"
            }
            Self::InvalidOperationalRowChirho => {
                "monitor operational evidence row is not one framed JSON object"
            }
            Self::UnsupportedAuthorityPlatformChirho => {
                "stable ledger namespace authority is unavailable on this platform"
            }
            Self::NamespaceIdentityChangedChirho => "stable ledger namespace identity changed",
            Self::MutableTargetNotRegularChirho => {
                "stable ledger mutable target is not a regular file"
            }
            Self::MutableTargetAliasedChirho => {
                "stable ledger mutable target has a filesystem alias"
            }
            Self::MutableTargetOwnerMismatchChirho => {
                "stable ledger namespace custody owner does not match"
            }
            Self::MutableTargetModeTooBroadChirho => {
                "stable ledger namespace custody permissions are too broad"
            }
            Self::ObjectExceedsBoundChirho => "stable ledger object exceeds its fixed byte bound",
            Self::ExclusiveLockBusyChirho => "stable ledger exclusive lock is busy",
        };
        formatter_chirho.write_str(message_chirho)
    }
}

/// Dedicated operational-evidence sink. It deliberately does not implement
/// [`LedgerStoragePortChirho`], so a conservation observer cannot be injected as the storage
/// authority for the money journal it audits.
#[derive(Clone, Debug)]
pub struct FsMonitorEvidenceSinkChirho {
    storage_chirho: FsLedgerStorageChirho,
}

impl FsMonitorEvidenceSinkChirho {
    /// Open an existing evidence namespace and prove it is neither equal to nor nested with the
    /// already-open ledger namespace. Construction is read-only; H3 provisions both directories.
    pub fn open_existing_disjoint_chirho(
        ledger_storage_chirho: &FsLedgerStorageChirho,
        evidence_namespace_root_chirho: &Path,
    ) -> Result<Self> {
        let storage_chirho =
            FsLedgerStorageChirho::open_existing_chirho(evidence_namespace_root_chirho)?;
        let ledger_root_chirho = ledger_storage_chirho.namespace_root_chirho();
        let evidence_root_chirho = storage_chirho.namespace_root_chirho();
        if ledger_root_chirho.starts_with(evidence_root_chirho)
            || evidence_root_chirho.starts_with(ledger_root_chirho)
        {
            return Err(HostLedgerStorageRefusalChirho::OverlappingMonitorNamespaceChirho.into());
        }
        Ok(Self { storage_chirho })
    }

    pub fn namespace_root_chirho(&self) -> &Path {
        self.storage_chirho.namespace_root_chirho()
    }

    /// Durably append one canonical operational JSON object. Framing is owned here so callers
    /// cannot splice multiple rows into one append.
    pub fn append_operational_row_chirho(
        &self,
        logical_path_chirho: &str,
        canonical_json_chirho: &[u8],
    ) -> Result<()> {
        if canonical_json_chirho.is_empty()
            || canonical_json_chirho.first() != Some(&b'{')
            || canonical_json_chirho.last() != Some(&b'}')
            || canonical_json_chirho
                .iter()
                .any(|byte_chirho| matches!(byte_chirho, b'\r' | b'\n'))
        {
            return Err(HostLedgerStorageRefusalChirho::InvalidOperationalRowChirho.into());
        }
        validate_logical_path_chirho(logical_path_chirho, false)?;
        let path_chirho = StoragePathChirho::new_chirho(logical_path_chirho);
        let mut framed_chirho = Vec::with_capacity(canonical_json_chirho.len() + 1);
        framed_chirho.extend_from_slice(canonical_json_chirho);
        framed_chirho.push(b'\n');
        self.storage_chirho
            .append_durable_chirho(&path_chirho, &framed_chirho)
            .context("durably append monitor operational evidence")
    }
}

impl Error for HostLedgerStorageRefusalChirho {}

/// Open-existing, namespace-confined filesystem adapter.
///
/// Construction performs no write and never creates the namespace. H3 operator porcelain owns
/// provisioning; H2 serve startup may only open what was already provisioned.
#[derive(Clone, Debug)]
pub struct FsLedgerStorageChirho {
    #[cfg(unix)]
    namespace_chirho: Arc<descriptor_namespace_chirho::DescriptorLedgerNamespaceChirho>,
    #[cfg(not(unix))]
    namespace_root_chirho: PathBuf,
}

/// A lock handle, carrying the exact storage it was opened on.
///
/// The storage is not incidental context: it is what the lock AUTHORIZES. Holding it here is what
/// lets fence mutators take one parameter instead of two that must correspond, so a guard taken on
/// one root cannot be handed another root's storage. Measured before this binding existed: a guard
/// acquired on root A, given root B's storage, wrote term 7 durably to root B with root B's lock
/// never acquired.
#[derive(Debug)]
pub struct StableLedgerExclusiveLockHandleChirho {
    #[cfg(all(unix, not(target_os = "solaris")))]
    handle_chirho: descriptor_namespace_chirho::DescriptorLedgerExclusiveLockHandleChirho,
    /// Cheap on unix: `FsLedgerStorageChirho` is an `Arc` over the descriptor namespace, and this is
    /// cloned once per handle rather than per operation.
    storage_chirho: FsLedgerStorageChirho,
}

#[derive(Debug)]
pub struct StableLedgerExclusiveLockGuardChirho<'lock_chirho> {
    #[cfg(all(unix, not(target_os = "solaris")))]
    guard_chirho:
        descriptor_namespace_chirho::DescriptorLedgerExclusiveLockGuardChirho<'lock_chirho>,
    storage_chirho: &'lock_chirho FsLedgerStorageChirho,
}

impl StableLedgerExclusiveLockHandleChirho {
    pub fn try_acquire_chirho(&mut self) -> Result<StableLedgerExclusiveLockGuardChirho<'_>> {
        #[cfg(all(unix, not(target_os = "solaris")))]
        {
            // Disjoint field borrows: `&mut self.handle_chirho` for the OS lock alongside
            // `&self.storage_chirho`, both carried by the returned guard's lifetime.
            let guard_chirho = self.handle_chirho.try_acquire_chirho()?;
            Ok(StableLedgerExclusiveLockGuardChirho {
                guard_chirho,
                storage_chirho: &self.storage_chirho,
            })
        }
        #[cfg(any(not(unix), target_os = "solaris"))]
        {
            Err(HostLedgerStorageRefusalChirho::UnsupportedAuthorityPlatformChirho.into())
        }
    }
}

impl StableLedgerExclusiveLockGuardChirho<'_> {
    /// The exact storage this lock authorizes. There is no other way to name it at a fence mutator,
    /// which is what makes a storage/guard mismatch unconstructible rather than merely checked.
    pub fn storage_chirho(&self) -> &FsLedgerStorageChirho {
        self.storage_chirho
    }

    pub fn verify_custody_chirho(&self) -> Result<()> {
        #[cfg(all(unix, not(target_os = "solaris")))]
        {
            self.guard_chirho.verify_custody_chirho()
        }
        #[cfg(any(not(unix), target_os = "solaris"))]
        {
            Err(HostLedgerStorageRefusalChirho::UnsupportedAuthorityPlatformChirho.into())
        }
    }
}

impl FsLedgerStorageChirho {
    /// Open an existing regular directory without changing it.
    ///
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf6-regenesis-boundary-chirho.md`.
    pub fn open_existing_chirho(namespace_root_chirho: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self {
                namespace_chirho:
                    descriptor_namespace_chirho::DescriptorLedgerNamespaceChirho::open_existing_chirho(
                        namespace_root_chirho,
                    )?,
            })
        }
        #[cfg(not(unix))]
        {
            let metadata_chirho =
                fs::symlink_metadata(namespace_root_chirho).map_err(|_error_chirho| {
                    HostLedgerStorageRefusalChirho::NamespaceUnavailableChirho
                })?;
            if metadata_chirho.file_type().is_symlink() {
                return Err(HostLedgerStorageRefusalChirho::SymlinkBoundaryChirho.into());
            }
            if !metadata_chirho.is_dir() {
                return Err(HostLedgerStorageRefusalChirho::NamespaceNotDirectoryChirho.into());
            }
            let namespace_root_chirho =
                namespace_root_chirho
                    .canonicalize()
                    .map_err(|_error_chirho| {
                        HostLedgerStorageRefusalChirho::NamespaceUnavailableChirho
                    })?;
            Ok(Self {
                namespace_root_chirho,
            })
        }
    }

    pub fn namespace_root_chirho(&self) -> &Path {
        #[cfg(unix)]
        {
            self.namespace_chirho.canonical_root_chirho()
        }
        #[cfg(not(unix))]
        {
            &self.namespace_root_chirho
        }
    }

    pub fn clone_namespace_root_descriptor_chirho(&self) -> Result<File> {
        #[cfg(unix)]
        {
            self.namespace_chirho.clone_root_directory_chirho()
        }
        #[cfg(not(unix))]
        {
            Err(HostLedgerStorageRefusalChirho::UnsupportedAuthorityPlatformChirho.into())
        }
    }

    pub fn stable_namespace_snapshot_chirho(&self) -> Result<StableLedgerNamespaceSnapshotChirho> {
        #[cfg(unix)]
        {
            Ok(
                descriptor_namespace_chirho::DescriptorLedgerNamespaceChirho::stable_snapshot_chirho(
                    &self.namespace_chirho,
                ),
            )
        }
        #[cfg(not(unix))]
        {
            StableLedgerNamespaceSnapshotChirho::acquire_existing_chirho(
                &self.namespace_root_chirho,
            )
        }
    }

    pub fn validate_resident_identity_path_chirho(
        &self,
        logical_path_chirho: &StoragePathChirho,
    ) -> Result<()> {
        validate_logical_path_chirho(logical_path_chirho.key_chirho(), false)
    }

    pub fn open_existing_exclusive_lock_handle_chirho(
        &self,
        logical_path_chirho: &StoragePathChirho,
    ) -> Result<StableLedgerExclusiveLockHandleChirho> {
        validate_logical_path_chirho(logical_path_chirho.key_chirho(), false)?;
        #[cfg(all(unix, not(target_os = "solaris")))]
        {
            Ok(StableLedgerExclusiveLockHandleChirho {
                handle_chirho:
                    descriptor_namespace_chirho::DescriptorLedgerNamespaceChirho::open_existing_exclusive_lock_handle_chirho(
                        &self.namespace_chirho,
                        logical_path_chirho,
                    )?,
                // The binding: this is the ONLY construction site of a handle, and it is a method on
                // the storage, so a handle's storage is always the one its lock was opened on.
                storage_chirho: self.clone(),
            })
        }
        #[cfg(any(not(unix), target_os = "solaris"))]
        {
            Err(HostLedgerStorageRefusalChirho::UnsupportedAuthorityPlatformChirho.into())
        }
    }

    /// Provision one empty descriptor-relative lock marker, or reopen the exact safe marker.
    ///
    /// This is an H3 birth primitive, not a serve-startup fallback. Unsupported authority
    /// platforms refuse before the durable create call.
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/p5-cutover-and-lease-design-chirho.md` §4.
    pub fn provision_exclusive_lock_handle_chirho(
        &self,
        logical_path_chirho: &StoragePathChirho,
    ) -> Result<StableLedgerExclusiveLockHandleChirho> {
        validate_logical_path_chirho(logical_path_chirho.key_chirho(), false)?;
        #[cfg(all(unix, not(target_os = "solaris")))]
        {
            let _outcome_chirho =
                LedgerStoragePortChirho::create_durable_chirho(self, logical_path_chirho, &[])?;
            self.open_existing_exclusive_lock_handle_chirho(logical_path_chirho)
        }
        #[cfg(any(not(unix), target_os = "solaris"))]
        {
            Err(HostLedgerStorageRefusalChirho::UnsupportedAuthorityPlatformChirho.into())
        }
    }

    /// At most `max_bytes_chirho` from the FRONT of an object, without requiring the whole thing to
    /// fit a bound.
    ///
    /// Distinct from [`Self::read_bounded_object_chirho`], which refuses an object larger than its
    /// bound — correct when the caller needs the entire value, wrong when it needs a header. A
    /// journal's genesis is its first line and the journal itself is unbounded, so reading it any
    /// other way means either refusing every real journal or reading an untrusted file whole.
    /// Returns `None` when the object does not exist, and fewer bytes than asked when it is shorter.
    pub fn read_object_prefix_chirho(
        &self,
        logical_path_chirho: &StoragePathChirho,
        max_bytes_chirho: u64,
    ) -> Result<Option<Vec<u8>>> {
        validate_logical_path_chirho(logical_path_chirho.key_chirho(), false)?;
        let Some(len_chirho) = self.object_len_chirho(logical_path_chirho)? else {
            return Ok(None);
        };
        let read_len_chirho = len_chirho.min(max_bytes_chirho);
        Ok(Some(self.read_exact_range_chirho(
            logical_path_chirho,
            0,
            read_len_chirho,
        )?))
    }

    pub fn read_bounded_object_chirho(
        &self,
        logical_path_chirho: &StoragePathChirho,
        max_bytes_chirho: u64,
    ) -> Result<Option<Vec<u8>>> {
        validate_logical_path_chirho(logical_path_chirho.key_chirho(), false)?;
        #[cfg(unix)]
        {
            self.namespace_chirho
                .read_bounded_object_chirho(logical_path_chirho, max_bytes_chirho)
        }
        #[cfg(not(unix))]
        {
            let Some(len_chirho) = self.object_len_chirho(logical_path_chirho)? else {
                return Ok(None);
            };
            if len_chirho > max_bytes_chirho {
                return Err(HostLedgerStorageRefusalChirho::ObjectExceedsBoundChirho.into());
            }
            self.read_exact_range_chirho(logical_path_chirho, 0, len_chirho)
                .map(Some)
        }
    }

    #[cfg(not(unix))]
    fn target_chirho(
        &self,
        logical_path_chirho: &StoragePathChirho,
        allow_trailing_separator_chirho: bool,
    ) -> Result<PathBuf> {
        validate_logical_path_chirho(
            logical_path_chirho.key_chirho(),
            allow_trailing_separator_chirho,
        )?;
        Ok(self
            .namespace_root_chirho
            .join(logical_path_chirho.key_chirho().trim_end_matches('/')))
    }

    #[cfg(not(unix))]
    fn guard_root_chirho(&self) -> Result<()> {
        let metadata_chirho = fs::symlink_metadata(&self.namespace_root_chirho)
            .map_err(|_error_chirho| HostLedgerStorageRefusalChirho::NamespaceUnavailableChirho)?;
        if metadata_chirho.file_type().is_symlink() {
            return Err(HostLedgerStorageRefusalChirho::SymlinkBoundaryChirho.into());
        }
        if !metadata_chirho.is_dir() {
            return Err(HostLedgerStorageRefusalChirho::NamespaceNotDirectoryChirho.into());
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn guard_parent_chain_chirho(
        &self,
        target_chirho: &Path,
        create_missing_chirho: bool,
    ) -> Result<bool> {
        self.guard_root_chirho()?;
        let parent_chirho = target_chirho
            .parent()
            .ok_or(HostLedgerStorageRefusalChirho::UnsafeLogicalPathChirho)?;
        let relative_parent_chirho = parent_chirho
            .strip_prefix(&self.namespace_root_chirho)
            .map_err(|_error_chirho| HostLedgerStorageRefusalChirho::UnsafeLogicalPathChirho)?;
        let mut current_chirho = self.namespace_root_chirho.clone();
        for component_chirho in relative_parent_chirho.components() {
            let Component::Normal(component_chirho) = component_chirho else {
                return Err(HostLedgerStorageRefusalChirho::UnsafeLogicalPathChirho.into());
            };
            current_chirho.push(component_chirho);
            match fs::symlink_metadata(&current_chirho) {
                Ok(metadata_chirho) => {
                    if metadata_chirho.file_type().is_symlink() {
                        return Err(HostLedgerStorageRefusalChirho::SymlinkBoundaryChirho.into());
                    }
                    if !metadata_chirho.is_dir() {
                        return Err(
                            HostLedgerStorageRefusalChirho::NamespaceNotDirectoryChirho.into()
                        );
                    }
                }
                Err(error_chirho) if error_chirho.kind() == ErrorKind::NotFound => {
                    if !create_missing_chirho {
                        return Ok(false);
                    }
                    let containing_dir_chirho = current_chirho
                        .parent()
                        .ok_or(HostLedgerStorageRefusalChirho::UnsafeLogicalPathChirho)?;
                    fs::create_dir(&current_chirho).with_context(|| {
                        "create ledger namespace directory without following a symlink"
                    })?;
                    fsync_dir_chirho(containing_dir_chirho)?;
                }
                Err(error_chirho) => {
                    return Err(error_chirho).context("inspect ledger namespace directory boundary")
                }
            }
        }
        Ok(true)
    }

    #[cfg(not(unix))]
    fn target_metadata_chirho(&self, target_chirho: &Path) -> Result<Option<fs::Metadata>> {
        match fs::symlink_metadata(target_chirho) {
            Ok(metadata_chirho) => {
                if metadata_chirho.file_type().is_symlink() {
                    return Err(HostLedgerStorageRefusalChirho::SymlinkBoundaryChirho.into());
                }
                if !metadata_chirho.is_file() {
                    return Err(HostLedgerStorageRefusalChirho::NamespaceNotDirectoryChirho.into());
                }
                Ok(Some(metadata_chirho))
            }
            Err(error_chirho) if error_chirho.kind() == ErrorKind::NotFound => Ok(None),
            Err(error_chirho) => Err(error_chirho).context("inspect ledger storage object"),
        }
    }

    #[cfg(not(unix))]
    fn list_files_chirho(&self) -> Result<Vec<PathBuf>> {
        self.guard_root_chirho()?;
        let mut pending_chirho = vec![self.namespace_root_chirho.clone()];
        let mut files_chirho = Vec::new();
        while let Some(directory_chirho) = pending_chirho.pop() {
            let mut entries_chirho = fs::read_dir(&directory_chirho)
                .context("read ledger storage namespace")?
                .collect::<std::io::Result<Vec<_>>>()?;
            entries_chirho.sort_by_key(|entry_chirho| entry_chirho.file_name());
            for entry_chirho in entries_chirho {
                let file_type_chirho = entry_chirho.file_type()?;
                if file_type_chirho.is_symlink() {
                    return Err(HostLedgerStorageRefusalChirho::SymlinkBoundaryChirho.into());
                }
                let path_chirho = entry_chirho.path();
                if file_type_chirho.is_dir() {
                    pending_chirho.push(path_chirho);
                } else if file_type_chirho.is_file() && !is_internal_temp_chirho(&path_chirho) {
                    files_chirho.push(path_chirho);
                }
            }
        }
        Ok(files_chirho)
    }
}

impl LedgerStoragePortChirho for FsLedgerStorageChirho {
    fn create_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<CreateDurableOutcomeChirho> {
        #[cfg(unix)]
        {
            self.namespace_chirho
                .create_durable_chirho(path_chirho, bytes_chirho)
        }
        #[cfg(not(unix))]
        {
            let target_chirho = self.target_chirho(path_chirho, false)?;
            self.guard_parent_chain_chirho(&target_chirho, true)?;
            self.target_metadata_chirho(&target_chirho)?;
            match create_file_durable_chirho(&target_chirho, bytes_chirho)
                .context("durably create ledger storage object")?
            {
                CreateFileDurableOutcomeChirho::CreatedChirho => {
                    Ok(CreateDurableOutcomeChirho::CreatedChirho)
                }
                CreateFileDurableOutcomeChirho::AlreadyExistsChirho => {
                    Ok(CreateDurableOutcomeChirho::AlreadyExistsChirho)
                }
            }
        }
    }

    fn append_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()> {
        #[cfg(unix)]
        {
            self.namespace_chirho
                .append_durable_chirho(path_chirho, bytes_chirho)
        }
        #[cfg(not(unix))]
        {
            let target_chirho = self.target_chirho(path_chirho, false)?;
            self.guard_parent_chain_chirho(&target_chirho, true)?;
            self.target_metadata_chirho(&target_chirho)?;
            append_durable_line_chirho(&target_chirho, bytes_chirho)
                .context("durably append ledger storage object")
        }
    }

    fn read_all_chirho(&self, path_chirho: &StoragePathChirho) -> Result<Option<Vec<u8>>> {
        #[cfg(unix)]
        {
            self.namespace_chirho.read_all_chirho(path_chirho)
        }
        #[cfg(not(unix))]
        {
            let target_chirho = self.target_chirho(path_chirho, false)?;
            if !self.guard_parent_chain_chirho(&target_chirho, false)?
                || self.target_metadata_chirho(&target_chirho)?.is_none()
            {
                return Ok(None);
            }
            fs::read(target_chirho)
                .map(Some)
                .context("read ledger storage object")
        }
    }

    fn object_len_chirho(&self, path_chirho: &StoragePathChirho) -> Result<Option<u64>> {
        #[cfg(unix)]
        {
            self.namespace_chirho.object_len_chirho(path_chirho)
        }
        #[cfg(not(unix))]
        {
            let target_chirho = self.target_chirho(path_chirho, false)?;
            if !self.guard_parent_chain_chirho(&target_chirho, false)? {
                return Ok(None);
            }
            Ok(self
                .target_metadata_chirho(&target_chirho)?
                .map(|metadata_chirho| metadata_chirho.len()))
        }
    }

    fn read_exact_range_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        offset_chirho: u64,
        len_chirho: u64,
    ) -> Result<Vec<u8>> {
        #[cfg(unix)]
        {
            self.namespace_chirho
                .read_exact_range_chirho(path_chirho, offset_chirho, len_chirho)
        }
        #[cfg(not(unix))]
        {
            let end_chirho = offset_chirho
                .checked_add(len_chirho)
                .ok_or(HostLedgerStorageRefusalChirho::InvalidRangeChirho)?;
            let target_chirho = self.target_chirho(path_chirho, false)?;
            if !self.guard_parent_chain_chirho(&target_chirho, false)? {
                return Err(HostLedgerStorageRefusalChirho::MissingObjectChirho.into());
            }
            let metadata_chirho = self
                .target_metadata_chirho(&target_chirho)?
                .ok_or(HostLedgerStorageRefusalChirho::MissingObjectChirho)?;
            if end_chirho > metadata_chirho.len() {
                return Err(HostLedgerStorageRefusalChirho::InvalidRangeChirho.into());
            }
            let allocation_len_chirho = usize::try_from(len_chirho)
                .map_err(|_error_chirho| HostLedgerStorageRefusalChirho::InvalidRangeChirho)?;
            let mut file_chirho = File::open(target_chirho).context("open ledger storage range")?;
            let current_len_chirho = file_chirho.metadata()?.len();
            if end_chirho > current_len_chirho {
                return Err(HostLedgerStorageRefusalChirho::InvalidRangeChirho.into());
            }
            file_chirho.seek(SeekFrom::Start(offset_chirho))?;
            let mut bytes_chirho = vec![0_u8; allocation_len_chirho];
            file_chirho
                .read_exact(&mut bytes_chirho)
                .context("read exact ledger storage range")?;
            Ok(bytes_chirho)
        }
    }

    fn atomic_write_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()> {
        #[cfg(unix)]
        {
            self.namespace_chirho
                .atomic_write_chirho(path_chirho, bytes_chirho)
        }
        #[cfg(not(unix))]
        {
            let target_chirho = self.target_chirho(path_chirho, false)?;
            self.guard_parent_chain_chirho(&target_chirho, true)?;
            self.target_metadata_chirho(&target_chirho)?;
            write_file_durable_chirho(&target_chirho, bytes_chirho)
                .context("durably replace ledger storage object")
        }
    }

    fn truncate_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        new_len_chirho: u64,
    ) -> Result<()> {
        #[cfg(unix)]
        {
            self.namespace_chirho
                .truncate_durable_chirho(path_chirho, new_len_chirho)
        }
        #[cfg(not(unix))]
        {
            let target_chirho = self.target_chirho(path_chirho, false)?;
            if !self.guard_parent_chain_chirho(&target_chirho, false)? {
                return Err(HostLedgerStorageRefusalChirho::MissingObjectChirho.into());
            }
            let current_len_chirho = self
                .target_metadata_chirho(&target_chirho)?
                .ok_or(HostLedgerStorageRefusalChirho::MissingObjectChirho)?
                .len();
            if new_len_chirho > current_len_chirho {
                return Err(HostLedgerStorageRefusalChirho::InvalidRangeChirho.into());
            }
            let file_chirho = OpenOptions::new()
                .write(true)
                .open(target_chirho)
                .context("open ledger storage object for truncate")?;
            file_chirho.set_len(new_len_chirho)?;
            file_chirho.sync_all()?;
            Ok(())
        }
    }

    fn rename_chirho(
        &self,
        from_chirho: &StoragePathChirho,
        to_chirho: &StoragePathChirho,
    ) -> Result<()> {
        #[cfg(unix)]
        {
            self.namespace_chirho.rename_chirho(from_chirho, to_chirho)
        }
        #[cfg(not(unix))]
        {
            let from_target_chirho = self.target_chirho(from_chirho, false)?;
            let to_target_chirho = self.target_chirho(to_chirho, false)?;
            if !self.guard_parent_chain_chirho(&from_target_chirho, false)?
                || self.target_metadata_chirho(&from_target_chirho)?.is_none()
            {
                return Err(HostLedgerStorageRefusalChirho::MissingObjectChirho.into());
            }
            self.guard_parent_chain_chirho(&to_target_chirho, true)?;
            self.target_metadata_chirho(&to_target_chirho)?;
            fs::rename(&from_target_chirho, &to_target_chirho)
                .context("rename ledger storage object")?;
            let from_parent_chirho = from_target_chirho
                .parent()
                .ok_or(HostLedgerStorageRefusalChirho::UnsafeLogicalPathChirho)?;
            let to_parent_chirho = to_target_chirho
                .parent()
                .ok_or(HostLedgerStorageRefusalChirho::UnsafeLogicalPathChirho)?;
            fsync_dir_chirho(to_parent_chirho)?;
            if from_parent_chirho != to_parent_chirho {
                fsync_dir_chirho(from_parent_chirho)?;
            }
            Ok(())
        }
    }

    fn remove_chirho(&self, path_chirho: &StoragePathChirho) -> Result<()> {
        #[cfg(unix)]
        {
            self.namespace_chirho.remove_chirho(path_chirho)
        }
        #[cfg(not(unix))]
        {
            let target_chirho = self.target_chirho(path_chirho, false)?;
            if !self.guard_parent_chain_chirho(&target_chirho, false)?
                || self.target_metadata_chirho(&target_chirho)?.is_none()
            {
                return Ok(());
            }
            fs::remove_file(&target_chirho).context("remove ledger storage object")?;
            fsync_dir_chirho(
                target_chirho
                    .parent()
                    .ok_or(HostLedgerStorageRefusalChirho::UnsafeLogicalPathChirho)?,
            )?;
            Ok(())
        }
    }

    fn list_chirho(&self, prefix_chirho: &StoragePathChirho) -> Result<Vec<StoragePathChirho>> {
        #[cfg(unix)]
        {
            self.namespace_chirho.list_chirho(prefix_chirho)
        }
        #[cfg(not(unix))]
        {
            validate_logical_path_chirho(prefix_chirho.key_chirho(), true)?;
            let mut logical_paths_chirho = Vec::new();
            for file_chirho in self.list_files_chirho()? {
                let relative_chirho = file_chirho
                    .strip_prefix(&self.namespace_root_chirho)
                    .map_err(|_error_chirho| {
                        HostLedgerStorageRefusalChirho::UnsafeLogicalPathChirho
                    })?;
                let relative_chirho = relative_chirho
                    .to_str()
                    .ok_or(HostLedgerStorageRefusalChirho::NonUtf8ObjectNameChirho)?
                    .replace(std::path::MAIN_SEPARATOR, "/");
                if relative_chirho.starts_with(prefix_chirho.key_chirho()) {
                    logical_paths_chirho.push(StoragePathChirho::new_chirho(relative_chirho));
                }
            }
            logical_paths_chirho.sort_by(|left_chirho, right_chirho| {
                left_chirho.key_chirho().cmp(right_chirho.key_chirho())
            });
            Ok(logical_paths_chirho)
        }
    }

    fn exists_chirho(&self, path_chirho: &StoragePathChirho) -> Result<bool> {
        #[cfg(unix)]
        {
            self.namespace_chirho.exists_chirho(path_chirho)
        }
        #[cfg(not(unix))]
        {
            let target_chirho = self.target_chirho(path_chirho, false)?;
            if !self.guard_parent_chain_chirho(&target_chirho, false)? {
                return Ok(false);
            }
            Ok(self.target_metadata_chirho(&target_chirho)?.is_some())
        }
    }
}

fn validate_logical_path_chirho(
    logical_path_chirho: &str,
    allow_trailing_separator_chirho: bool,
) -> Result<()> {
    if logical_path_chirho.is_empty()
        || logical_path_chirho.len() > MAX_LOGICAL_PATH_BYTES_CHIRHO
        || logical_path_chirho.starts_with('/')
        || logical_path_chirho.contains('\\')
        || logical_path_chirho.contains('@')
        || logical_path_chirho.bytes().any(|byte_chirho| {
            !(byte_chirho.is_ascii_alphanumeric()
                || matches!(byte_chirho, b'-' | b'_' | b'.' | b'/'))
        })
    {
        return Err(HostLedgerStorageRefusalChirho::UnsafeLogicalPathChirho.into());
    }
    let components_chirho = logical_path_chirho.split('/').collect::<Vec<_>>();
    for (index_chirho, component_chirho) in components_chirho.iter().enumerate() {
        let trailing_chirho = index_chirho + 1 == components_chirho.len();
        if component_chirho.is_empty() {
            if allow_trailing_separator_chirho && trailing_chirho {
                continue;
            }
            return Err(HostLedgerStorageRefusalChirho::UnsafeLogicalPathChirho.into());
        }
        if matches!(*component_chirho, "." | "..") {
            return Err(HostLedgerStorageRefusalChirho::UnsafeLogicalPathChirho.into());
        }
    }
    let path_chirho = Path::new(logical_path_chirho.trim_end_matches('/'));
    if path_chirho
        .components()
        .any(|component_chirho| !matches!(component_chirho, Component::Normal(_)))
    {
        return Err(HostLedgerStorageRefusalChirho::UnsafeLogicalPathChirho.into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn is_internal_temp_chirho(path_chirho: &Path) -> bool {
    path_chirho
        .file_name()
        .and_then(|name_chirho| name_chirho.to_str())
        .is_some_and(|name_chirho| {
            name_chirho.starts_with('.') && name_chirho.contains(DURABLE_TEMP_MARKER_CHIRHO)
        })
}

#[cfg(unix)]
fn is_internal_temp_name_chirho(name_chirho: &str) -> bool {
    name_chirho.starts_with('.') && name_chirho.contains(DURABLE_TEMP_MARKER_CHIRHO)
}

#[cfg(not(unix))]
#[derive(Debug)]
pub struct StableLedgerNamespaceSnapshotChirho;

#[cfg(not(unix))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StableFilesystemIdentityChirho {
    pub device_chirho: u64,
    pub inode_chirho: u64,
}

#[cfg(not(unix))]
impl StableLedgerNamespaceSnapshotChirho {
    pub fn acquire_existing_chirho(_namespace_root_chirho: &Path) -> Result<Self> {
        Err(HostLedgerStorageRefusalChirho::UnsupportedAuthorityPlatformChirho.into())
    }

    pub fn identity_chirho(&self) -> Result<StableFilesystemIdentityChirho> {
        Err(HostLedgerStorageRefusalChirho::UnsupportedAuthorityPlatformChirho.into())
    }

    pub fn verify_current_path_chirho(&self, _namespace_root_chirho: &Path) -> Result<()> {
        Err(HostLedgerStorageRefusalChirho::UnsupportedAuthorityPlatformChirho.into())
    }
}
