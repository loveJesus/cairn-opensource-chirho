// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Native filesystem CAS lifecycle coordination.
//!
//! This module implements the shared/exclusive root barrier and deletion generation ruled in
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/f2-chirho/elected-door-primitives-chirho/
//! f4-cas-lifecycle-placement-ruling-chirho.md`. Semantic closure validation remains the caller's
//! typed responsibility and must run outside both short SHARED intervals.

use crate::descriptor_root_chirho::{
    identity_from_metadata_chirho, inspect_entry_at_chirho, inspect_open_file_chirho,
    io_error_from_errno_chirho, verify_directory_inspection_chirho, verify_file_inspection_chirho,
    ResidentControlFilesystemIdentityChirho,
};
use crate::DescriptorRootCustodyChirho;
use fs2::FileExt;
use rand_core::{OsRng, RngCore};
use rustix::fs::{
    mkdirat, openat, renameat, renameat_with, unlinkat, AtFlags, Mode, OFlags, RenameFlags,
};
use rustix::io::Errno;
use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::{FileExt as UnixFileExt, MetadataExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

pub const CAS_LIFECYCLE_DIR_CHIRHO: &str = "cas-lifecycle-chirho";
pub const CAS_LIFECYCLE_ANCHOR_CHIRHO: &str = "lock-anchor-chirho";
pub const CAS_LIFECYCLE_STATE_CHIRHO: &str = "state-v1-chirho.bin";
const CAS_LIFECYCLE_STATE_MAGIC_CHIRHO: &[u8; 16] = b"cairn-life-v1!!!";
const CAS_LIFECYCLE_STATE_BODY_BYTES_CHIRHO: usize = 16 + 8 + 8 + 32 + 8;
const CAS_LIFECYCLE_STATE_BYTES_CHIRHO: usize = CAS_LIFECYCLE_STATE_BODY_BYTES_CHIRHO + 32;
const CAS_LIFECYCLE_TEMP_ATTEMPTS_CHIRHO: usize = 64;
static CAS_LIFECYCLE_TEMP_COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);

/// Stable refusal identity for lifecycle callers and tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CasLifecycleErrorKindChirho {
    BusyChirho,
    StaleChirho,
    UnavailableChirho,
    RootReboundChirho,
    CorruptWinnerChirho,
}

#[derive(Debug)]
pub struct CasLifecycleErrorChirho {
    kind_chirho: CasLifecycleErrorKindChirho,
    message_chirho: String,
}

impl CasLifecycleErrorChirho {
    pub fn kind_chirho(&self) -> CasLifecycleErrorKindChirho {
        self.kind_chirho
    }
}

impl fmt::Display for CasLifecycleErrorChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter_chirho, "{}", self.message_chirho)
    }
}

impl std::error::Error for CasLifecycleErrorChirho {}

pub type CasLifecycleResultChirho<ValueChirho> = Result<ValueChirho, CasLifecycleErrorChirho>;

/// Values-only evidence captured under the initial short SHARED interval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CasLifecycleSnapshotChirho {
    root_device_chirho: u64,
    root_inode_chirho: u64,
    root_incarnation_chirho: [u8; 32],
    deletion_generation_chirho: u64,
}

impl CasLifecycleSnapshotChirho {
    pub fn root_incarnation_chirho(&self) -> &[u8; 32] {
        &self.root_incarnation_chirho
    }

    pub fn deletion_generation_chirho(&self) -> u64 {
        self.deletion_generation_chirho
    }
}

#[derive(Clone)]
pub struct CasLifecycleRootChirho {
    inner_chirho: Arc<CasLifecycleRootInnerChirho>,
}

impl fmt::Debug for CasLifecycleRootChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("CasLifecycleRootChirho")
            .field("canonical_root_chirho", &"<redacted-chirho>")
            .field(
                "root_identity_chirho",
                &self.inner_chirho.root_identity_chirho,
            )
            .field(
                "anchor_identity_chirho",
                &self.inner_chirho.anchor_identity_chirho,
            )
            .finish()
    }
}

struct CasLifecycleRootInnerChirho {
    root_custody_chirho: Arc<DescriptorRootCustodyChirho>,
    lifecycle_directory_chirho: File,
    lifecycle_identity_chirho: ResidentControlFilesystemIdentityChirho,
    root_identity_chirho: ResidentControlFilesystemIdentityChirho,
    anchor_identity_chirho: ResidentControlFilesystemIdentityChirho,
    owner_uid_chirho: u32,
    registry_entry_chirho: Arc<CasLifecycleRegistryEntryChirho>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct CasLifecycleRegistryKeyChirho {
    root_device_chirho: u64,
    root_inode_chirho: u64,
    anchor_device_chirho: u64,
    anchor_inode_chirho: u64,
}

struct CasLifecycleRegistryEntryChirho {
    state_chirho: Mutex<CasLifecycleLocalStateChirho>,
    #[cfg(test)]
    before_last_shared_unlock_chirho: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

struct CasLifecycleLocalStateChirho {
    shared_readers_chirho: usize,
    shared_file_chirho: Option<File>,
    exclusive_live_chirho: bool,
}

static CAS_LIFECYCLE_REGISTRY_CHIRHO: OnceLock<
    Mutex<HashMap<CasLifecycleRegistryKeyChirho, Weak<CasLifecycleRegistryEntryChirho>>>,
> = OnceLock::new();

/// A private, affine SHARED guard. No descriptor accessor is exposed.
///
/// The guard cannot be cloned:
///
/// ```compile_fail,E0599
/// use cairn_durable_chirho::cas_lifecycle_chirho::CasLifecycleSharedGuardChirho;
///
/// fn clone_guard_chirho(guard_chirho: CasLifecycleSharedGuardChirho) {
///     let _duplicate_chirho = guard_chirho.clone();
/// }
/// ```
///
/// The matching setup compiles when it moves rather than clones the guard:
///
/// ```
/// use cairn_durable_chirho::cas_lifecycle_chirho::CasLifecycleSharedGuardChirho;
///
/// fn clone_guard_chirho(guard_chirho: CasLifecycleSharedGuardChirho) {
///     let _duplicate_chirho = guard_chirho;
/// }
/// ```
///
/// The guard cannot expose its lock descriptor through the standard raw-FD trait:
///
/// ```compile_fail,E0599
/// use cairn_durable_chirho::cas_lifecycle_chirho::CasLifecycleSharedGuardChirho;
/// use std::os::fd::AsRawFd;
///
/// fn extract_descriptor_chirho(guard_chirho: CasLifecycleSharedGuardChirho) {
///     let _descriptor_chirho = guard_chirho.as_raw_fd();
/// }
/// ```
///
/// The matching setup compiles when it moves rather than exposes the guard:
///
/// ```
/// use cairn_durable_chirho::cas_lifecycle_chirho::CasLifecycleSharedGuardChirho;
/// use std::os::fd::AsRawFd;
///
/// fn extract_descriptor_chirho(guard_chirho: CasLifecycleSharedGuardChirho) {
///     let _descriptor_chirho = guard_chirho;
/// }
/// ```
///
/// The process-local ownership entry remains private:
///
/// ```compile_fail,E0616
/// use cairn_durable_chirho::cas_lifecycle_chirho::CasLifecycleSharedGuardChirho;
///
/// fn reach_registry_chirho(guard_chirho: CasLifecycleSharedGuardChirho) {
///     let _entry_chirho = &guard_chirho.registry_entry_chirho;
/// }
/// ```
///
/// The matching setup compiles when it borrows only the public guard:
///
/// ```
/// use cairn_durable_chirho::cas_lifecycle_chirho::CasLifecycleSharedGuardChirho;
///
/// fn reach_registry_chirho(guard_chirho: CasLifecycleSharedGuardChirho) {
///     let _entry_chirho = &guard_chirho;
/// }
/// ```
pub struct CasLifecycleSharedGuardChirho {
    root_chirho: Arc<CasLifecycleRootInnerChirho>,
    registry_entry_chirho: Arc<CasLifecycleRegistryEntryChirho>,
}

impl fmt::Debug for CasLifecycleSharedGuardChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("CasLifecycleSharedGuardChirho")
            .finish_non_exhaustive()
    }
}

/// A private, affine EXCLUSIVE guard. Generation must advance before root reads or deletion.
pub struct CasLifecycleExclusiveGuardChirho {
    root_chirho: Arc<CasLifecycleRootInnerChirho>,
    registry_entry_chirho: Arc<CasLifecycleRegistryEntryChirho>,
    lock_file_chirho: Option<File>,
    advanced_state_chirho: Option<CasLifecycleSnapshotChirho>,
}

impl fmt::Debug for CasLifecycleExclusiveGuardChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("CasLifecycleExclusiveGuardChirho")
            .field(
                "generation_advanced_chirho",
                &self.advanced_state_chirho.is_some(),
            )
            .finish_non_exhaustive()
    }
}

/// Explicitly initialize an empty root for online lifecycle participation.
pub fn bootstrap_cas_lifecycle_chirho(
    root_chirho: &Path,
) -> CasLifecycleResultChirho<CasLifecycleRootChirho> {
    initialize_cas_lifecycle_chirho(root_chirho, true)
}

/// Explicit offline migration for a quiesced legacy root.
///
/// The caller owns proof that no publisher, collector, or whole-root replacement is concurrent.
pub fn migrate_cas_lifecycle_offline_chirho(
    root_chirho: &Path,
) -> CasLifecycleResultChirho<CasLifecycleRootChirho> {
    initialize_cas_lifecycle_chirho(root_chirho, false)
}

impl CasLifecycleRootChirho {
    /// Open already-bootstrapped lifecycle state. Missing state never means generation zero.
    pub fn open_chirho(root_chirho: &Path) -> CasLifecycleResultChirho<Self> {
        let custody_chirho =
            DescriptorRootCustodyChirho::open_path_chirho(root_chirho).map_err(|error_chirho| {
                unavailable_chirho("open canonical lifecycle root", error_chirho)
            })?;
        open_from_custody_chirho(custody_chirho)
    }

    pub fn canonical_root_chirho(&self) -> &Path {
        self.inner_chirho
            .root_custody_chirho
            .canonical_root_chirho()
    }

    /// S0: one nonblocking SHARED acquisition and one fresh state read.
    pub fn snapshot_chirho(&self) -> CasLifecycleResultChirho<CasLifecycleSnapshotChirho> {
        let guard_chirho = self.try_shared_chirho()?;
        let snapshot_chirho = guard_chirho.read_fresh_state_chirho()?;
        drop(guard_chirho);
        Ok(snapshot_chirho)
    }

    /// S1: consume values-only evidence, reacquire SHARED, and fresh-read current state.
    pub fn promote_chirho(
        &self,
        snapshot_chirho: CasLifecycleSnapshotChirho,
    ) -> CasLifecycleResultChirho<CasLifecycleSharedGuardChirho> {
        if !self
            .inner_chirho
            .root_custody_chirho
            .canonical_path_still_names_custody_chirho()
            .map_err(|error_chirho| unavailable_chirho("revalidate canonical root", error_chirho))?
        {
            return Err(error_chirho(
                CasLifecycleErrorKindChirho::RootReboundChirho,
                "RootReboundChirho: canonical pathname no longer names retained root",
            ));
        }
        let guard_chirho = self.try_shared_chirho()?;
        let current_chirho = guard_chirho.read_fresh_state_chirho()?;
        if current_chirho != snapshot_chirho {
            return Err(error_chirho(
                CasLifecycleErrorKindChirho::StaleChirho,
                "CasLifecycleStaleChirho: root incarnation or deletion generation changed",
            ));
        }
        Ok(guard_chirho)
    }

    pub fn try_shared_chirho(&self) -> CasLifecycleResultChirho<CasLifecycleSharedGuardChirho> {
        let entry_chirho = Arc::clone(&self.inner_chirho.registry_entry_chirho);
        let mut local_chirho = lock_local_state_chirho(&entry_chirho)?;
        if local_chirho.exclusive_live_chirho {
            return Err(busy_chirho("local EXCLUSIVE lifecycle guard is live"));
        }
        if local_chirho.shared_readers_chirho > 0 {
            local_chirho.shared_readers_chirho = local_chirho
                .shared_readers_chirho
                .checked_add(1)
                .ok_or_else(|| unavailable_message_chirho("local SHARED reader count exhausted"))?;
            drop(local_chirho);
            return Ok(CasLifecycleSharedGuardChirho {
                root_chirho: Arc::clone(&self.inner_chirho),
                registry_entry_chirho: entry_chirho,
            });
        }

        let lock_file_chirho = self.inner_chirho.open_verified_anchor_chirho()?;
        lock_file_chirho.try_lock_shared().map_err(|error_chirho| {
            busy_chirho(format!("OS SHARED lifecycle lock refused: {error_chirho}"))
        })?;
        if let Err(error_chirho) = self
            .inner_chirho
            .verify_anchor_file_chirho(&lock_file_chirho)
        {
            let _unlock_result_chirho = FileExt::unlock(&lock_file_chirho);
            return Err(error_chirho);
        }
        local_chirho.shared_file_chirho = Some(lock_file_chirho);
        local_chirho.shared_readers_chirho = 1;
        drop(local_chirho);
        Ok(CasLifecycleSharedGuardChirho {
            root_chirho: Arc::clone(&self.inner_chirho),
            registry_entry_chirho: entry_chirho,
        })
    }

    pub fn try_exclusive_chirho(
        &self,
    ) -> CasLifecycleResultChirho<CasLifecycleExclusiveGuardChirho> {
        let entry_chirho = Arc::clone(&self.inner_chirho.registry_entry_chirho);
        let mut local_chirho = lock_local_state_chirho(&entry_chirho)?;
        if local_chirho.exclusive_live_chirho || local_chirho.shared_readers_chirho != 0 {
            return Err(busy_chirho(
                "local lifecycle guard conflicts with EXCLUSIVE",
            ));
        }
        let lock_file_chirho = self.inner_chirho.open_verified_anchor_chirho()?;
        lock_file_chirho
            .try_lock_exclusive()
            .map_err(|error_chirho| {
                busy_chirho(format!(
                    "OS EXCLUSIVE lifecycle lock refused: {error_chirho}"
                ))
            })?;
        if let Err(error_chirho) = self
            .inner_chirho
            .verify_anchor_file_chirho(&lock_file_chirho)
        {
            let _unlock_result_chirho = FileExt::unlock(&lock_file_chirho);
            return Err(error_chirho);
        }
        local_chirho.exclusive_live_chirho = true;
        drop(local_chirho);
        Ok(CasLifecycleExclusiveGuardChirho {
            root_chirho: Arc::clone(&self.inner_chirho),
            registry_entry_chirho: entry_chirho,
            lock_file_chirho: Some(lock_file_chirho),
            advanced_state_chirho: None,
        })
    }
}

impl CasLifecycleSharedGuardChirho {
    pub fn canonical_root_chirho(&self) -> &Path {
        self.root_chirho.root_custody_chirho.canonical_root_chirho()
    }

    pub fn read_fresh_state_chirho(&self) -> CasLifecycleResultChirho<CasLifecycleSnapshotChirho> {
        self.root_chirho.read_fresh_state_chirho()
    }
}

impl Drop for CasLifecycleSharedGuardChirho {
    fn drop(&mut self) {
        let Ok(mut local_chirho) = self.registry_entry_chirho.state_chirho.lock() else {
            return;
        };
        if local_chirho.shared_readers_chirho == 0 {
            return;
        }
        local_chirho.shared_readers_chirho -= 1;
        if local_chirho.shared_readers_chirho == 0 {
            if let Some(lock_file_chirho) = local_chirho.shared_file_chirho.take() {
                #[cfg(test)]
                if let Ok(mut hook_chirho) = self
                    .registry_entry_chirho
                    .before_last_shared_unlock_chirho
                    .lock()
                {
                    if let Some(hook_chirho) = hook_chirho.take() {
                        hook_chirho();
                    }
                }
                let _unlock_result_chirho = FileExt::unlock(&lock_file_chirho);
                drop(lock_file_chirho);
            }
        }
    }
}

impl CasLifecycleExclusiveGuardChirho {
    /// Advance generation durably before any root snapshot, mark, or unlink.
    pub fn advance_generation_before_roots_chirho(
        &mut self,
    ) -> CasLifecycleResultChirho<&CasLifecycleSnapshotChirho> {
        if self.advanced_state_chirho.is_some() {
            return Err(unavailable_message_chirho(
                "CasLifecycleGenerationAlreadyAdvancedChirho",
            ));
        }
        let current_chirho = self.root_chirho.read_fresh_state_chirho()?;
        let next_generation_chirho = current_chirho
            .deletion_generation_chirho
            .checked_add(1)
            .ok_or_else(|| unavailable_message_chirho("CasLifecycleGenerationExhaustedChirho"))?;
        let next_chirho = CasLifecycleSnapshotChirho {
            deletion_generation_chirho: next_generation_chirho,
            ..current_chirho
        };
        self.root_chirho.replace_state_chirho(&next_chirho)?;
        self.advanced_state_chirho = Some(next_chirho);
        Ok(self
            .advanced_state_chirho
            .as_ref()
            .expect("generation state was just installed"))
    }

    pub fn generation_chirho(&self) -> CasLifecycleResultChirho<&CasLifecycleSnapshotChirho> {
        self.advanced_state_chirho.as_ref().ok_or_else(|| {
            unavailable_message_chirho("CasLifecycleGenerationNotAdvancedBeforeRootsChirho")
        })
    }

    /// The sole online CAS-object deletion capability.
    pub fn delete_content_addressed_object_chirho(
        &mut self,
        address_hex_chirho: &str,
    ) -> CasLifecycleResultChirho<bool> {
        self.generation_chirho()?;
        validate_address_hex_chirho(address_hex_chirho)?;
        self.root_chirho
            .delete_verified_object_chirho(address_hex_chirho)
    }
}

impl Drop for CasLifecycleExclusiveGuardChirho {
    fn drop(&mut self) {
        let Ok(mut local_chirho) = self.registry_entry_chirho.state_chirho.lock() else {
            return;
        };
        if let Some(lock_file_chirho) = self.lock_file_chirho.take() {
            let _unlock_result_chirho = FileExt::unlock(&lock_file_chirho);
            drop(lock_file_chirho);
        }
        local_chirho.exclusive_live_chirho = false;
    }
}

/// Publish exact bytes beneath one retained root without replacing a concurrent winner.
pub fn publish_content_addressed_file_no_replace_chirho(
    root_chirho: &CasLifecycleRootChirho,
    address_hex_chirho: &str,
    bytes_chirho: &[u8],
) -> CasLifecycleResultChirho<()> {
    validate_address_hex_chirho(address_hex_chirho)?;
    let actual_chirho = blake3::hash(bytes_chirho).to_hex().to_string();
    if actual_chirho != address_hex_chirho {
        return Err(error_chirho(
            CasLifecycleErrorKindChirho::CorruptWinnerChirho,
            "CasLifecycleCorruptWinnerChirho: supplied bytes do not match content address",
        ));
    }
    root_chirho
        .inner_chirho
        .publish_verified_object_chirho(address_hex_chirho, bytes_chirho)
}

/// Publish immutable CAS bytes without requiring lifecycle bootstrap.
///
/// Pure CAS insertion creates no live root and therefore needs no SHARED barrier. It still uses
/// retained descriptor custody and the same no-replace/winner-verification implementation as the
/// lifecycle-aware path.
pub fn publish_content_addressed_file_at_root_no_replace_chirho(
    root_chirho: &Path,
    address_hex_chirho: &str,
    bytes_chirho: &[u8],
) -> CasLifecycleResultChirho<()> {
    validate_address_hex_chirho(address_hex_chirho)?;
    let actual_chirho = blake3::hash(bytes_chirho).to_hex().to_string();
    if actual_chirho != address_hex_chirho {
        return Err(error_chirho(
            CasLifecycleErrorKindChirho::CorruptWinnerChirho,
            "CasLifecycleCorruptWinnerChirho: supplied bytes do not match content address",
        ));
    }
    std::fs::create_dir_all(root_chirho)
        .map_err(|error_chirho| unavailable_chirho("create CAS root", error_chirho))?;
    let custody_chirho = DescriptorRootCustodyChirho::open_path_chirho(root_chirho)
        .map_err(|error_chirho| unavailable_chirho("open CAS publication root", error_chirho))?;
    publish_verified_object_in_custody_chirho(
        &custody_chirho,
        custody_chirho.owner_uid_chirho,
        address_hex_chirho,
        bytes_chirho,
    )
}

fn initialize_cas_lifecycle_chirho(
    root_chirho: &Path,
    require_empty_chirho: bool,
) -> CasLifecycleResultChirho<CasLifecycleRootChirho> {
    if require_empty_chirho {
        let mut entries_chirho = std::fs::read_dir(root_chirho).map_err(|error_chirho| {
            unavailable_chirho("inspect fresh lifecycle root", error_chirho)
        })?;
        if entries_chirho.next().is_some() {
            return Err(unavailable_message_chirho(
                "CasLifecycleLegacyRootRequiresOfflineMigrationChirho",
            ));
        }
    }
    let custody_chirho =
        DescriptorRootCustodyChirho::open_path_chirho(root_chirho).map_err(|error_chirho| {
            unavailable_chirho("open lifecycle bootstrap root", error_chirho)
        })?;
    custody_chirho
        .verify_custody_chirho()
        .map_err(|error_chirho| {
            unavailable_chirho("verify lifecycle bootstrap root", error_chirho)
        })?;
    match mkdirat(
        &custody_chirho.root_directory_chirho,
        CAS_LIFECYCLE_DIR_CHIRHO,
        Mode::RWXU,
    ) {
        Ok(()) => custody_chirho
            .root_directory_chirho
            .sync_all()
            .map_err(|error_chirho| unavailable_chirho("sync lifecycle directory", error_chirho))?,
        Err(Errno::EXIST) => {
            return Err(unavailable_message_chirho(
                "CasLifecycleAlreadyInitializedOrPartialChirho",
            ))
        }
        Err(error_chirho) => {
            return Err(unavailable_chirho(
                "create lifecycle directory",
                io_error_from_errno_chirho(error_chirho),
            ))
        }
    }
    let lifecycle_directory_chirho = open_lifecycle_directory_chirho(&custody_chirho)?;
    create_empty_file_no_replace_at_chirho(
        &lifecycle_directory_chirho,
        CAS_LIFECYCLE_ANCHOR_CHIRHO,
    )?;
    let mut root_incarnation_chirho = [0_u8; 32];
    OsRng.fill_bytes(&mut root_incarnation_chirho);
    let state_chirho = CasLifecycleSnapshotChirho {
        root_device_chirho: custody_chirho.root_identity_chirho.device_chirho,
        root_inode_chirho: custody_chirho.root_identity_chirho.inode_chirho,
        root_incarnation_chirho,
        deletion_generation_chirho: 0,
    };
    create_bytes_no_replace_at_chirho(
        &lifecycle_directory_chirho,
        CAS_LIFECYCLE_STATE_CHIRHO,
        &encode_state_chirho(&state_chirho),
    )?;
    lifecycle_directory_chirho
        .sync_all()
        .map_err(|error_chirho| unavailable_chirho("sync lifecycle bootstrap", error_chirho))?;
    open_from_custody_chirho(custody_chirho)
}

fn open_from_custody_chirho(
    custody_chirho: Arc<DescriptorRootCustodyChirho>,
) -> CasLifecycleResultChirho<CasLifecycleRootChirho> {
    let lifecycle_directory_chirho = open_lifecycle_directory_chirho(&custody_chirho)?;
    let lifecycle_metadata_chirho = lifecycle_directory_chirho
        .metadata()
        .map_err(|error_chirho| unavailable_chirho("inspect lifecycle directory", error_chirho))?;
    let lifecycle_identity_chirho = identity_from_metadata_chirho(&lifecycle_metadata_chirho);
    let anchor_file_chirho = open_verified_regular_at_chirho(
        &lifecycle_directory_chirho,
        CAS_LIFECYCLE_ANCHOR_CHIRHO,
        custody_chirho.owner_uid_chirho,
        OFlags::RDWR,
    )?;
    if anchor_file_chirho
        .metadata()
        .map_err(|error_chirho| unavailable_chirho("inspect lifecycle anchor", error_chirho))?
        .len()
        != 0
    {
        return Err(unavailable_message_chirho("CasLifecycleAnchorUnsafeChirho"));
    }
    let anchor_identity_chirho =
        identity_from_metadata_chirho(&anchor_file_chirho.metadata().map_err(|error_chirho| {
            unavailable_chirho("inspect lifecycle anchor", error_chirho)
        })?);
    let key_chirho = CasLifecycleRegistryKeyChirho {
        root_device_chirho: custody_chirho.root_identity_chirho.device_chirho,
        root_inode_chirho: custody_chirho.root_identity_chirho.inode_chirho,
        anchor_device_chirho: anchor_identity_chirho.device_chirho,
        anchor_inode_chirho: anchor_identity_chirho.inode_chirho,
    };
    let registry_entry_chirho = registry_entry_chirho(key_chirho)?;
    let inner_chirho = Arc::new(CasLifecycleRootInnerChirho {
        root_identity_chirho: custody_chirho.root_identity_chirho,
        owner_uid_chirho: custody_chirho.owner_uid_chirho,
        root_custody_chirho: custody_chirho,
        lifecycle_directory_chirho,
        lifecycle_identity_chirho,
        anchor_identity_chirho,
        registry_entry_chirho,
    });
    inner_chirho.read_fresh_state_chirho()?;
    Ok(CasLifecycleRootChirho { inner_chirho })
}

impl CasLifecycleRootInnerChirho {
    fn verify_lifecycle_directory_chirho(&self) -> CasLifecycleResultChirho<()> {
        self.root_custody_chirho
            .verify_custody_chirho()
            .map_err(|error_chirho| {
                unavailable_chirho("verify retained lifecycle root", error_chirho)
            })?;
        let entry_chirho = inspect_entry_at_chirho(
            &self.root_custody_chirho.root_directory_chirho,
            CAS_LIFECYCLE_DIR_CHIRHO,
        )
        .map_err(|error_chirho| {
            unavailable_chirho("inspect lifecycle directory entry", error_chirho)
        })?
        .ok_or_else(|| {
            unavailable_message_chirho("CasLifecycleUnavailableChirho: directory missing")
        })?;
        verify_directory_inspection_chirho(&entry_chirho, self.owner_uid_chirho).map_err(
            |error_chirho| unavailable_chirho("validate lifecycle directory entry", error_chirho),
        )?;
        let opened_identity_chirho =
            identity_from_metadata_chirho(&self.lifecycle_directory_chirho.metadata().map_err(
                |error_chirho| unavailable_chirho("inspect open lifecycle directory", error_chirho),
            )?);
        if entry_chirho.identity_chirho != self.lifecycle_identity_chirho
            || opened_identity_chirho != self.lifecycle_identity_chirho
        {
            return Err(unavailable_message_chirho(
                "CasLifecycleUnavailableChirho: lifecycle directory identity changed",
            ));
        }
        Ok(())
    }

    fn open_verified_anchor_chirho(&self) -> CasLifecycleResultChirho<File> {
        self.verify_lifecycle_directory_chirho()?;
        let file_chirho = open_verified_regular_at_chirho(
            &self.lifecycle_directory_chirho,
            CAS_LIFECYCLE_ANCHOR_CHIRHO,
            self.owner_uid_chirho,
            OFlags::RDWR,
        )?;
        self.verify_anchor_file_chirho(&file_chirho)?;
        Ok(file_chirho)
    }

    fn verify_anchor_file_chirho(&self, file_chirho: &File) -> CasLifecycleResultChirho<()> {
        self.verify_lifecycle_directory_chirho()?;
        let entry_chirho = inspect_entry_at_chirho(
            &self.lifecycle_directory_chirho,
            CAS_LIFECYCLE_ANCHOR_CHIRHO,
        )
        .map_err(|error_chirho| unavailable_chirho("inspect lifecycle anchor entry", error_chirho))?
        .ok_or_else(|| {
            unavailable_message_chirho("CasLifecycleUnavailableChirho: anchor missing")
        })?;
        verify_file_inspection_chirho(&entry_chirho, self.owner_uid_chirho).map_err(
            |error_chirho| unavailable_chirho("validate lifecycle anchor", error_chirho),
        )?;
        let opened_chirho = inspect_open_file_chirho(file_chirho, self.owner_uid_chirho).map_err(
            |error_chirho| unavailable_chirho("inspect open lifecycle anchor", error_chirho),
        )?;
        if entry_chirho.identity_chirho != self.anchor_identity_chirho
            || opened_chirho.identity_chirho != self.anchor_identity_chirho
            || opened_chirho.len_chirho != 0
        {
            return Err(unavailable_message_chirho(
                "CasLifecycleUnavailableChirho: anchor identity changed",
            ));
        }
        Ok(())
    }

    fn read_fresh_state_chirho(&self) -> CasLifecycleResultChirho<CasLifecycleSnapshotChirho> {
        self.verify_lifecycle_directory_chirho()?;
        let file_chirho = open_verified_regular_at_chirho(
            &self.lifecycle_directory_chirho,
            CAS_LIFECYCLE_STATE_CHIRHO,
            self.owner_uid_chirho,
            OFlags::RDONLY,
        )?;
        let metadata_chirho = file_chirho
            .metadata()
            .map_err(|error_chirho| unavailable_chirho("inspect lifecycle state", error_chirho))?;
        if metadata_chirho.len() != CAS_LIFECYCLE_STATE_BYTES_CHIRHO as u64 {
            return Err(unavailable_message_chirho("CasLifecycleStateCorruptChirho"));
        }
        let mut bytes_chirho = [0_u8; CAS_LIFECYCLE_STATE_BYTES_CHIRHO];
        file_chirho
            .read_exact_at(&mut bytes_chirho, 0)
            .map_err(|error_chirho| unavailable_chirho("read lifecycle state", error_chirho))?;
        let reopened_entry_chirho =
            inspect_entry_at_chirho(&self.lifecycle_directory_chirho, CAS_LIFECYCLE_STATE_CHIRHO)
                .map_err(|error_chirho| {
                    unavailable_chirho("reinspect lifecycle state", error_chirho)
                })?
                .ok_or_else(|| unavailable_message_chirho("CasLifecycleStateMissingChirho"))?;
        let opened_identity_chirho = identity_from_metadata_chirho(&metadata_chirho);
        if reopened_entry_chirho.identity_chirho != opened_identity_chirho {
            return Err(unavailable_message_chirho(
                "CasLifecycleUnavailableChirho: state changed during bounded read",
            ));
        }
        decode_state_chirho(&bytes_chirho, self.root_identity_chirho)
    }

    fn replace_state_chirho(
        &self,
        state_chirho: &CasLifecycleSnapshotChirho,
    ) -> CasLifecycleResultChirho<()> {
        self.verify_lifecycle_directory_chirho()?;
        let (temp_name_chirho, mut temp_file_chirho) =
            create_unique_temp_at_chirho(&self.lifecycle_directory_chirho, ".state.tmp-chirho")?;
        let bytes_chirho = encode_state_chirho(state_chirho);
        let write_result_chirho = (|| {
            temp_file_chirho
                .write_all(&bytes_chirho)
                .map_err(|error_chirho| {
                    unavailable_chirho("write lifecycle state temp", error_chirho)
                })?;
            temp_file_chirho.sync_all().map_err(|error_chirho| {
                unavailable_chirho("sync lifecycle state temp", error_chirho)
            })?;
            renameat(
                &self.lifecycle_directory_chirho,
                temp_name_chirho.as_str(),
                &self.lifecycle_directory_chirho,
                CAS_LIFECYCLE_STATE_CHIRHO,
            )
            .map_err(|error_chirho| {
                unavailable_chirho(
                    "replace lifecycle state",
                    io_error_from_errno_chirho(error_chirho),
                )
            })?;
            self.lifecycle_directory_chirho
                .sync_all()
                .map_err(|error_chirho| {
                    unavailable_chirho("sync lifecycle state replacement", error_chirho)
                })?;
            Ok(())
        })();
        if write_result_chirho.is_err() {
            let _unlink_result_chirho = unlinkat(
                &self.lifecycle_directory_chirho,
                temp_name_chirho.as_str(),
                AtFlags::empty(),
            );
        }
        write_result_chirho
    }

    fn publish_verified_object_chirho(
        &self,
        address_hex_chirho: &str,
        bytes_chirho: &[u8],
    ) -> CasLifecycleResultChirho<()> {
        publish_verified_object_in_custody_chirho(
            &self.root_custody_chirho,
            self.owner_uid_chirho,
            address_hex_chirho,
            bytes_chirho,
        )
    }

    fn delete_verified_object_chirho(
        &self,
        address_hex_chirho: &str,
    ) -> CasLifecycleResultChirho<bool> {
        let Some(objects_chirho) = open_optional_directory_at_chirho(
            &self.root_custody_chirho.root_directory_chirho,
            "objects-chirho",
            self.owner_uid_chirho,
        )?
        else {
            return Ok(false);
        };
        let Some(shard_chirho) = open_optional_directory_at_chirho(
            &objects_chirho,
            &address_hex_chirho[..2],
            self.owner_uid_chirho,
        )?
        else {
            return Ok(false);
        };
        let object_name_chirho = &address_hex_chirho[2..];
        let Some(before_chirho) = inspect_entry_at_chirho(&shard_chirho, object_name_chirho)
            .map_err(|error_chirho| unavailable_chirho("inspect GC object", error_chirho))?
        else {
            return Ok(false);
        };
        verify_file_inspection_chirho(&before_chirho, self.owner_uid_chirho)
            .map_err(|error_chirho| unavailable_chirho("validate GC object", error_chirho))?;
        let file_chirho = open_verified_regular_at_chirho(
            &shard_chirho,
            object_name_chirho,
            self.owner_uid_chirho,
            OFlags::RDONLY,
        )?;
        verify_open_file_hash_at_chirho(
            &shard_chirho,
            object_name_chirho,
            &file_chirho,
            self.owner_uid_chirho,
            address_hex_chirho,
        )?;
        let after_chirho = inspect_entry_at_chirho(&shard_chirho, object_name_chirho)
            .map_err(|error_chirho| unavailable_chirho("reinspect GC object", error_chirho))?
            .ok_or_else(|| {
                unavailable_message_chirho("CasLifecycleObjectChangedBeforeUnlinkChirho")
            })?;
        let opened_chirho =
            identity_from_metadata_chirho(&file_chirho.metadata().map_err(|error_chirho| {
                unavailable_chirho("inspect opened GC object", error_chirho)
            })?);
        if before_chirho.identity_chirho != after_chirho.identity_chirho
            || before_chirho.identity_chirho != opened_chirho
        {
            return Err(unavailable_message_chirho(
                "CasLifecycleObjectChangedBeforeUnlinkChirho",
            ));
        }
        unlinkat(&shard_chirho, object_name_chirho, AtFlags::empty()).map_err(|error_chirho| {
            unavailable_chirho("unlink GC object", io_error_from_errno_chirho(error_chirho))
        })?;
        shard_chirho
            .sync_all()
            .map_err(|error_chirho| unavailable_chirho("sync GC object deletion", error_chirho))?;
        Ok(true)
    }
}

fn publish_verified_object_in_custody_chirho(
    custody_chirho: &DescriptorRootCustodyChirho,
    owner_uid_chirho: u32,
    address_hex_chirho: &str,
    bytes_chirho: &[u8],
) -> CasLifecycleResultChirho<()> {
    custody_chirho
        .verify_custody_chirho()
        .map_err(|error_chirho| unavailable_chirho("verify CAS publication root", error_chirho))?;
    let objects_chirho = open_or_create_directory_at_chirho(
        &custody_chirho.root_directory_chirho,
        "objects-chirho",
        owner_uid_chirho,
    )?;
    let shard_chirho = open_or_create_directory_at_chirho(
        &objects_chirho,
        &address_hex_chirho[..2],
        owner_uid_chirho,
    )?;
    let object_name_chirho = &address_hex_chirho[2..];
    if existing_object_verified_chirho(
        &shard_chirho,
        object_name_chirho,
        owner_uid_chirho,
        address_hex_chirho,
    )? {
        return Ok(());
    }
    let (temp_name_chirho, mut temp_file_chirho) =
        create_unique_temp_at_chirho(&shard_chirho, ".object.tmp-chirho")?;
    let publish_result_chirho = (|| {
        temp_file_chirho
            .write_all(bytes_chirho)
            .map_err(|error_chirho| unavailable_chirho("write CAS temp", error_chirho))?;
        temp_file_chirho
            .sync_all()
            .map_err(|error_chirho| unavailable_chirho("sync CAS temp", error_chirho))?;
        match renameat_with(
            &shard_chirho,
            temp_name_chirho.as_str(),
            &shard_chirho,
            object_name_chirho,
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {
                shard_chirho.sync_all().map_err(|error_chirho| {
                    unavailable_chirho("sync CAS publication", error_chirho)
                })?;
                Ok(())
            }
            Err(Errno::EXIST) => {
                let winner_chirho = open_verified_regular_at_chirho(
                    &shard_chirho,
                    object_name_chirho,
                    owner_uid_chirho,
                    OFlags::RDONLY,
                )?;
                verify_open_file_hash_at_chirho(
                    &shard_chirho,
                    object_name_chirho,
                    &winner_chirho,
                    owner_uid_chirho,
                    address_hex_chirho,
                )?;
                Ok(())
            }
            Err(error_chirho) => Err(unavailable_chirho(
                "publish CAS object no-replace",
                io_error_from_errno_chirho(error_chirho),
            )),
        }
    })();
    let _unlink_result_chirho =
        unlinkat(&shard_chirho, temp_name_chirho.as_str(), AtFlags::empty());
    publish_result_chirho
}

#[cfg(test)]
thread_local! {
    /// A test-only hold point between the look and the open in `existing_object_verified_chirho`.
    static AFTER_EXISTING_OBJECT_LOOK_CHIRHO: std::cell::RefCell<Option<Box<dyn Fn()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Whether the object is already present and verified, so a publish can return with nothing
/// written.
///
/// A repeat publish of existing bytes (a cached request re-adds its input objects) used to make a
/// temp, write and fsync it, fail its no-replace rename and unlink it. Absent returns `false`, and
/// the caller publishes as before. Present is opened and verified with the same custody and hash
/// checks the EEXIST path uses on a winner: verified returns `true` with nothing written, and wrong
/// bytes refuse as a corrupt winner, never overwritten. If the object cannot be opened as a
/// verified file (gone after the look, replaced, or not a regular file), this returns `false` and
/// today's full path decides, as it always did: it publishes if the object is gone and refuses if
/// something unopenable stands in its place. So a disappearance needs no retry loop, and the
/// shortcut adds no new outcome.
/// Workflow: spec-chirho/tasklists-chirho/26-10-04_14-55-tasklist-served_overload_followups-chirho.md (cache hits).
fn existing_object_verified_chirho(
    shard_chirho: &File,
    object_name_chirho: &str,
    owner_uid_chirho: u32,
    address_hex_chirho: &str,
) -> CasLifecycleResultChirho<bool> {
    let present_chirho = inspect_entry_at_chirho(shard_chirho, object_name_chirho)
        .map_err(|error_chirho| unavailable_chirho("inspect CAS object", error_chirho))?
        .is_some();
    if !present_chirho {
        return Ok(false);
    }
    #[cfg(test)]
    AFTER_EXISTING_OBJECT_LOOK_CHIRHO.with(|hook_chirho| {
        if let Some(hook_chirho) = hook_chirho.borrow().as_ref() {
            hook_chirho();
        }
    });
    match open_verified_regular_at_chirho(
        shard_chirho,
        object_name_chirho,
        owner_uid_chirho,
        OFlags::RDONLY,
    ) {
        Ok(existing_chirho) => {
            verify_open_file_hash_at_chirho(
                shard_chirho,
                object_name_chirho,
                &existing_chirho,
                owner_uid_chirho,
                address_hex_chirho,
            )?;
            Ok(true)
        }
        Err(_not_openable_chirho) => Ok(false),
    }
}

fn registry_entry_chirho(
    key_chirho: CasLifecycleRegistryKeyChirho,
) -> CasLifecycleResultChirho<Arc<CasLifecycleRegistryEntryChirho>> {
    let registry_chirho = CAS_LIFECYCLE_REGISTRY_CHIRHO.get_or_init(|| Mutex::new(HashMap::new()));
    let mut entries_chirho = registry_chirho
        .lock()
        .map_err(|_| unavailable_message_chirho("CasLifecycleRegistryPoisonedChirho"))?;
    entries_chirho.retain(|_key_chirho, value_chirho| value_chirho.strong_count() != 0);
    if let Some(entry_chirho) = entries_chirho.get(&key_chirho).and_then(Weak::upgrade) {
        return Ok(entry_chirho);
    }
    let entry_chirho = Arc::new(CasLifecycleRegistryEntryChirho {
        state_chirho: Mutex::new(CasLifecycleLocalStateChirho {
            shared_readers_chirho: 0,
            shared_file_chirho: None,
            exclusive_live_chirho: false,
        }),
        #[cfg(test)]
        before_last_shared_unlock_chirho: Mutex::new(None),
    });
    entries_chirho.insert(key_chirho, Arc::downgrade(&entry_chirho));
    Ok(entry_chirho)
}

fn lock_local_state_chirho(
    entry_chirho: &CasLifecycleRegistryEntryChirho,
) -> CasLifecycleResultChirho<std::sync::MutexGuard<'_, CasLifecycleLocalStateChirho>> {
    entry_chirho
        .state_chirho
        .lock()
        .map_err(|_| unavailable_message_chirho("CasLifecycleRegistryPoisonedChirho"))
}

fn open_lifecycle_directory_chirho(
    custody_chirho: &DescriptorRootCustodyChirho,
) -> CasLifecycleResultChirho<File> {
    let entry_chirho = inspect_entry_at_chirho(
        &custody_chirho.root_directory_chirho,
        CAS_LIFECYCLE_DIR_CHIRHO,
    )
    .map_err(|error_chirho| unavailable_chirho("inspect lifecycle directory", error_chirho))?
    .ok_or_else(|| {
        unavailable_message_chirho("CasLifecycleUnavailableChirho: directory missing")
    })?;
    verify_directory_inspection_chirho(&entry_chirho, custody_chirho.owner_uid_chirho)
        .map_err(|error_chirho| unavailable_chirho("validate lifecycle directory", error_chirho))?;
    let descriptor_chirho = openat(
        &custody_chirho.root_directory_chirho,
        CAS_LIFECYCLE_DIR_CHIRHO,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error_chirho| {
        unavailable_chirho(
            "open lifecycle directory",
            io_error_from_errno_chirho(error_chirho),
        )
    })?;
    let file_chirho = File::from(descriptor_chirho);
    let opened_chirho =
        identity_from_metadata_chirho(&file_chirho.metadata().map_err(|error_chirho| {
            unavailable_chirho("inspect open lifecycle directory", error_chirho)
        })?);
    if opened_chirho != entry_chirho.identity_chirho {
        return Err(unavailable_message_chirho(
            "CasLifecycleDirectoryChangedChirho",
        ));
    }
    Ok(file_chirho)
}

fn open_verified_regular_at_chirho(
    directory_chirho: &File,
    name_chirho: &str,
    owner_uid_chirho: u32,
    access_chirho: OFlags,
) -> CasLifecycleResultChirho<File> {
    let before_chirho = inspect_entry_at_chirho(directory_chirho, name_chirho)
        .map_err(|error_chirho| unavailable_chirho("inspect lifecycle file", error_chirho))?
        .ok_or_else(|| unavailable_message_chirho("CasLifecycleFileMissingChirho"))?;
    verify_file_inspection_chirho(&before_chirho, owner_uid_chirho)
        .map_err(|error_chirho| unavailable_chirho("validate lifecycle file", error_chirho))?;
    let descriptor_chirho = openat(
        directory_chirho,
        name_chirho,
        access_chirho | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error_chirho| {
        unavailable_chirho(
            "open lifecycle file",
            io_error_from_errno_chirho(error_chirho),
        )
    })?;
    let file_chirho = File::from(descriptor_chirho);
    let opened_chirho =
        inspect_open_file_chirho(&file_chirho, owner_uid_chirho).map_err(|error_chirho| {
            unavailable_chirho("inspect opened lifecycle file", error_chirho)
        })?;
    if opened_chirho.identity_chirho != before_chirho.identity_chirho {
        return Err(unavailable_message_chirho(
            "CasLifecycleFileIdentityChangedChirho",
        ));
    }
    Ok(file_chirho)
}

fn create_empty_file_no_replace_at_chirho(
    directory_chirho: &File,
    name_chirho: &str,
) -> CasLifecycleResultChirho<()> {
    create_bytes_no_replace_at_chirho(directory_chirho, name_chirho, &[])
}

fn create_bytes_no_replace_at_chirho(
    directory_chirho: &File,
    name_chirho: &str,
    bytes_chirho: &[u8],
) -> CasLifecycleResultChirho<()> {
    let descriptor_chirho = openat(
        directory_chirho,
        name_chirho,
        OFlags::WRONLY
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::NOFOLLOW
            | OFlags::CLOEXEC
            | OFlags::NONBLOCK,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|error_chirho| {
        unavailable_chirho(
            "create lifecycle file no-replace",
            io_error_from_errno_chirho(error_chirho),
        )
    })?;
    let mut file_chirho = File::from(descriptor_chirho);
    file_chirho
        .write_all(bytes_chirho)
        .map_err(|error_chirho| unavailable_chirho("write lifecycle file", error_chirho))?;
    file_chirho
        .sync_all()
        .map_err(|error_chirho| unavailable_chirho("sync lifecycle file", error_chirho))?;
    directory_chirho
        .sync_all()
        .map_err(|error_chirho| unavailable_chirho("sync lifecycle directory entry", error_chirho))
}

fn create_unique_temp_at_chirho(
    directory_chirho: &File,
    prefix_chirho: &str,
) -> CasLifecycleResultChirho<(String, File)> {
    for _attempt_chirho in 0..CAS_LIFECYCLE_TEMP_ATTEMPTS_CHIRHO {
        let counter_chirho = CAS_LIFECYCLE_TEMP_COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
        let name_chirho = format!("{prefix_chirho}-{}-{counter_chirho}", std::process::id());
        match openat(
            directory_chirho,
            name_chirho.as_str(),
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(descriptor_chirho) => return Ok((name_chirho, File::from(descriptor_chirho))),
            Err(Errno::EXIST) => continue,
            Err(error_chirho) => {
                return Err(unavailable_chirho(
                    "create lifecycle temp file",
                    io_error_from_errno_chirho(error_chirho),
                ))
            }
        }
    }
    Err(unavailable_message_chirho(
        "CasLifecycleTempNamespaceExhaustedChirho",
    ))
}

fn open_or_create_directory_at_chirho(
    parent_chirho: &File,
    name_chirho: &str,
    owner_uid_chirho: u32,
) -> CasLifecycleResultChirho<File> {
    if inspect_entry_at_chirho(parent_chirho, name_chirho)
        .map_err(|error_chirho| unavailable_chirho("inspect CAS directory", error_chirho))?
        .is_none()
    {
        match mkdirat(parent_chirho, name_chirho, Mode::RWXU) {
            Ok(()) => parent_chirho
                .sync_all()
                .map_err(|error_chirho| unavailable_chirho("sync CAS directory", error_chirho))?,
            Err(Errno::EXIST) => {}
            Err(error_chirho) => {
                return Err(unavailable_chirho(
                    "create CAS directory",
                    io_error_from_errno_chirho(error_chirho),
                ))
            }
        }
    }
    open_optional_directory_at_chirho(parent_chirho, name_chirho, owner_uid_chirho)?
        .ok_or_else(|| unavailable_message_chirho("CasLifecycleDirectoryMissingChirho"))
}

fn open_optional_directory_at_chirho(
    parent_chirho: &File,
    name_chirho: &str,
    owner_uid_chirho: u32,
) -> CasLifecycleResultChirho<Option<File>> {
    let Some(entry_chirho) =
        inspect_entry_at_chirho(parent_chirho, name_chirho).map_err(|error_chirho| {
            unavailable_chirho("inspect descriptor-relative directory", error_chirho)
        })?
    else {
        return Ok(None);
    };
    verify_directory_inspection_chirho(&entry_chirho, owner_uid_chirho).map_err(
        |error_chirho| unavailable_chirho("validate descriptor-relative directory", error_chirho),
    )?;
    let descriptor_chirho = openat(
        parent_chirho,
        name_chirho,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error_chirho| {
        unavailable_chirho(
            "open descriptor-relative directory",
            io_error_from_errno_chirho(error_chirho),
        )
    })?;
    let file_chirho = File::from(descriptor_chirho);
    let opened_chirho =
        identity_from_metadata_chirho(&file_chirho.metadata().map_err(|error_chirho| {
            unavailable_chirho("inspect descriptor-relative directory", error_chirho)
        })?);
    if opened_chirho != entry_chirho.identity_chirho {
        return Err(unavailable_message_chirho(
            "CasLifecycleDirectoryChangedChirho",
        ));
    }
    Ok(Some(file_chirho))
}

fn verify_open_file_hash_at_chirho(
    directory_chirho: &File,
    name_chirho: &str,
    file_chirho: &File,
    owner_uid_chirho: u32,
    expected_hex_chirho: &str,
) -> CasLifecycleResultChirho<()> {
    let before_chirho = file_chirho.metadata().map_err(|error_chirho| {
        unavailable_chirho("inspect content-addressed file", error_chirho)
    })?;
    let mut reader_chirho = file_chirho.try_clone().map_err(|error_chirho| {
        unavailable_chirho("clone private CAS verifier descriptor", error_chirho)
    })?;
    let mut hasher_chirho = blake3::Hasher::new();
    let mut buffer_chirho = [0_u8; 64 * 1024];
    loop {
        let read_chirho = reader_chirho
            .read(&mut buffer_chirho)
            .map_err(|error_chirho| {
                unavailable_chirho("hash content-addressed file", error_chirho)
            })?;
        if read_chirho == 0 {
            break;
        }
        hasher_chirho.update(&buffer_chirho[..read_chirho]);
    }
    let after_chirho = file_chirho.metadata().map_err(|error_chirho| {
        unavailable_chirho("reinspect content-addressed file", error_chirho)
    })?;
    let path_after_chirho = inspect_entry_at_chirho(directory_chirho, name_chirho)
        .map_err(|error_chirho| {
            unavailable_chirho("reinspect content-addressed pathname", error_chirho)
        })?
        .ok_or_else(|| {
            error_chirho(
                CasLifecycleErrorKindChirho::CorruptWinnerChirho,
                "CasLifecycleCorruptWinnerChirho: winner pathname disappeared after hashing",
            )
        })?;
    verify_file_inspection_chirho(&path_after_chirho, owner_uid_chirho).map_err(
        |error_chirho| unavailable_chirho("validate content-addressed pathname", error_chirho),
    )?;
    if before_chirho.dev() != after_chirho.dev()
        || before_chirho.ino() != after_chirho.ino()
        || before_chirho.len() != after_chirho.len()
        || path_after_chirho.identity_chirho
            != (ResidentControlFilesystemIdentityChirho {
                device_chirho: after_chirho.dev(),
                inode_chirho: after_chirho.ino(),
            })
        || hasher_chirho.finalize().to_hex().as_str() != expected_hex_chirho
    {
        return Err(error_chirho(
            CasLifecycleErrorKindChirho::CorruptWinnerChirho,
            "CasLifecycleCorruptWinnerChirho: winner bytes or identity mismatch",
        ));
    }
    Ok(())
}

fn validate_address_hex_chirho(address_hex_chirho: &str) -> CasLifecycleResultChirho<()> {
    if address_hex_chirho.len() != 64
        || !address_hex_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
    {
        return Err(error_chirho(
            CasLifecycleErrorKindChirho::CorruptWinnerChirho,
            "CasLifecycleCorruptWinnerChirho: address must be canonical lowercase blake3 hex",
        ));
    }
    Ok(())
}

fn encode_state_chirho(
    state_chirho: &CasLifecycleSnapshotChirho,
) -> [u8; CAS_LIFECYCLE_STATE_BYTES_CHIRHO] {
    let mut bytes_chirho = [0_u8; CAS_LIFECYCLE_STATE_BYTES_CHIRHO];
    bytes_chirho[..16].copy_from_slice(CAS_LIFECYCLE_STATE_MAGIC_CHIRHO);
    bytes_chirho[16..24].copy_from_slice(&state_chirho.root_device_chirho.to_be_bytes());
    bytes_chirho[24..32].copy_from_slice(&state_chirho.root_inode_chirho.to_be_bytes());
    bytes_chirho[32..64].copy_from_slice(&state_chirho.root_incarnation_chirho);
    bytes_chirho[64..72].copy_from_slice(&state_chirho.deletion_generation_chirho.to_be_bytes());
    let digest_chirho = blake3::hash(&bytes_chirho[..CAS_LIFECYCLE_STATE_BODY_BYTES_CHIRHO]);
    bytes_chirho[CAS_LIFECYCLE_STATE_BODY_BYTES_CHIRHO..].copy_from_slice(digest_chirho.as_bytes());
    bytes_chirho
}

fn decode_state_chirho(
    bytes_chirho: &[u8; CAS_LIFECYCLE_STATE_BYTES_CHIRHO],
    expected_root_chirho: ResidentControlFilesystemIdentityChirho,
) -> CasLifecycleResultChirho<CasLifecycleSnapshotChirho> {
    if &bytes_chirho[..16] != CAS_LIFECYCLE_STATE_MAGIC_CHIRHO {
        return Err(unavailable_message_chirho("CasLifecycleStateCorruptChirho"));
    }
    let expected_digest_chirho =
        blake3::hash(&bytes_chirho[..CAS_LIFECYCLE_STATE_BODY_BYTES_CHIRHO]);
    if expected_digest_chirho.as_bytes() != &bytes_chirho[CAS_LIFECYCLE_STATE_BODY_BYTES_CHIRHO..] {
        return Err(unavailable_message_chirho("CasLifecycleStateCorruptChirho"));
    }
    let root_device_chirho = u64::from_be_bytes(bytes_chirho[16..24].try_into().unwrap());
    let root_inode_chirho = u64::from_be_bytes(bytes_chirho[24..32].try_into().unwrap());
    if root_device_chirho != expected_root_chirho.device_chirho
        || root_inode_chirho != expected_root_chirho.inode_chirho
    {
        return Err(unavailable_message_chirho(
            "CasLifecycleWrongRootStateChirho",
        ));
    }
    Ok(CasLifecycleSnapshotChirho {
        root_device_chirho,
        root_inode_chirho,
        root_incarnation_chirho: bytes_chirho[32..64].try_into().unwrap(),
        deletion_generation_chirho: u64::from_be_bytes(bytes_chirho[64..72].try_into().unwrap()),
    })
}

fn busy_chirho(message_chirho: impl Into<String>) -> CasLifecycleErrorChirho {
    error_chirho(
        CasLifecycleErrorKindChirho::BusyChirho,
        format!("CasLifecycleBusyChirho: {}", message_chirho.into()),
    )
}

fn unavailable_message_chirho(message_chirho: impl Into<String>) -> CasLifecycleErrorChirho {
    error_chirho(
        CasLifecycleErrorKindChirho::UnavailableChirho,
        format!("CasLifecycleUnavailableChirho: {}", message_chirho.into()),
    )
}

fn unavailable_chirho(
    context_chirho: &str,
    error_source_chirho: impl fmt::Display,
) -> CasLifecycleErrorChirho {
    unavailable_message_chirho(format!("{context_chirho}: {error_source_chirho}"))
}

fn error_chirho(
    kind_chirho: CasLifecycleErrorKindChirho,
    message_chirho: impl Into<String>,
) -> CasLifecycleErrorChirho {
    CasLifecycleErrorChirho {
        kind_chirho,
        message_chirho: message_chirho.into(),
    }
}

#[cfg(test)]
mod tests_chirho;

#[cfg(test)]
mod publish_fast_path_tests_chirho;
