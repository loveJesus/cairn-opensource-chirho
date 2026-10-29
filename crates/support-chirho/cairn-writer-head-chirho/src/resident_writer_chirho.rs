// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Lifetime-exclusive resident ownership for one bounded canonical identity under one root.
//!
//! This support primitive deliberately treats the canonical identity as opaque bytes. The ledger
//! host must build those bytes from its exact typed group, cluster, logical storage key, genesis
//! digest, and concrete filesystem namespace. Reservation is explicit and lease-bearing: a
//! provisioning lease retains the process-local slot and OS lock across journal creation or
//! recovery, then performs the exact pending-to-bound identity transition without unlocking.
//! Bound open never creates or repairs identity state. The retained lease is the outermost lock:
//! resident lease -> operation authority -> writer fence -> journal. These APIs execute no caller
//! callback, provider call, directory scan, or history scan while locked.
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/
//! p5-cutover-and-lease-design-chirho.md`. The control directory and its lock/identity files are
//! immutable while any resident may be live; rename, unlink, or replacement is permitted only as an
//! offline whole-root retirement operation after every resident lease is gone.

use anyhow::{anyhow, bail, Context, Result};
#[cfg(all(unix, test))]
use cairn_durable_chirho::DescriptorRootCustodyChirho as DescriptorResidentWriterRootChirho;
#[cfg(any(test, not(unix)))]
use cairn_durable_chirho::{fsync_dir_chirho, write_file_durable_chirho};
#[cfg(unix)]
use cairn_durable_chirho::{DescriptorResidentWriterControlChirho, DescriptorRootCustodyChirho};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::{hash_map::RandomState, HashSet};
use std::fmt;
use std::fs::File;
#[cfg(any(test, not(unix)))]
use std::fs::OpenOptions;
use std::hash::BuildHasher;
#[cfg(not(unix))]
use std::io::ErrorKind;
#[cfg(any(test, not(unix)))]
use std::io::Read;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};

pub use cairn_durable_chirho::{
    MAX_CANONICAL_FILESYSTEM_PATH_BYTES_CHIRHO, RESIDENT_WRITER_DIR_CHIRHO,
    RESIDENT_WRITER_IDENTITY_FILE_CHIRHO, RESIDENT_WRITER_LOCK_FILE_CHIRHO,
};
pub const RESIDENT_WRITER_IDENTITY_SCHEMA_CHIRHO: &str = "resident-writer-identity-v1-chirho";
pub const MAX_RESIDENT_WRITER_IDENTITY_BYTES_CHIRHO: usize = 8 * 1024;
pub const MAX_RESIDENT_WRITER_RECORD_BYTES_CHIRHO: usize = 24 * 1024;
const MAX_RESIDENT_WRITER_KIND_BYTES_CHIRHO: usize = 128;
const RESIDENT_WRITER_LOCAL_SHARD_COUNT_CHIRHO: usize = 64;
const RESIDENT_WRITER_IDLE_CAPACITY_PER_SHARD_CHIRHO: usize = 64;
const RESIDENT_WRITER_IDENTITY_DIGEST_PREFIX_CHIRHO: &str =
    "resident-writer-identity-blake3-v1-chirho:";
const CANONICAL_PATH_DIGEST_PREFIX_CHIRHO: &str = "canonical-filesystem-path-blake3-v1-chirho:";

/// One exact opaque identity under a host filesystem root.
///
/// The composing host owns the canonical encoding and must distinguish Pending from Bound.
#[derive(Clone, Copy)]
pub struct ResidentWriterBindingChirho<'binding_chirho> {
    pub root_chirho: &'binding_chirho Path,
    pub identity_kind_chirho: &'binding_chirho str,
    pub canonical_identity_chirho: &'binding_chirho [u8],
}

impl fmt::Debug for ResidentWriterBindingChirho<'_> {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("ResidentWriterBindingChirho")
            .field("root_chirho", &"<redacted-chirho>")
            .field("identity_kind_chirho", &self.identity_kind_chirho)
            .field("canonical_identity_chirho", &"<redacted-chirho>")
            .finish()
    }
}

/// Retained custody of one already-open canonical root directory.
///
/// The composing host can clone its authoritative root descriptor into this value. On Unix, all
/// resident control mutation and inspection APIs that accept this type remain relative to that
/// descriptor. The pathname is retained only as redacted coordinate evidence.
pub struct ResidentWriterRootCustodyChirho {
    canonical_root_chirho: PathBuf,
    #[cfg(unix)]
    descriptor_root_chirho: Arc<DescriptorRootCustodyChirho>,
}

impl fmt::Debug for ResidentWriterRootCustodyChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("ResidentWriterRootCustodyChirho")
            .field("canonical_root_chirho", &"<redacted-chirho>")
            .finish_non_exhaustive()
    }
}

impl ResidentWriterRootCustodyChirho {
    /// Adopt a descriptor already verified and retained by the composing host.
    pub fn from_retained_directory_chirho(
        canonical_root_chirho: &Path,
        root_directory_chirho: File,
    ) -> Result<Self> {
        #[cfg(unix)]
        {
            let descriptor_root_chirho =
                DescriptorRootCustodyChirho::from_retained_directory_chirho(
                    canonical_root_chirho.to_path_buf(),
                    root_directory_chirho,
                )?;
            Ok(Self {
                canonical_root_chirho: descriptor_root_chirho.canonical_root_chirho().to_path_buf(),
                descriptor_root_chirho,
            })
        }
        #[cfg(not(unix))]
        {
            let _root_directory_chirho = root_directory_chirho;
            let _canonical_root_chirho = canonical_root_chirho;
            bail!("ResidentWriterDescriptorCustodyUnsupportedChirho")
        }
    }

    pub fn canonical_root_chirho(&self) -> &Path {
        &self.canonical_root_chirho
    }

    #[cfg(unix)]
    fn open_path_chirho(root_chirho: &Path) -> Result<Self> {
        let descriptor_root_chirho = DescriptorRootCustodyChirho::open_path_chirho(root_chirho)?;
        Ok(Self {
            canonical_root_chirho: descriptor_root_chirho.canonical_root_chirho().to_path_buf(),
            descriptor_root_chirho,
        })
    }
}

/// One validated, bounded snapshot of the persisted opaque identity.
///
/// Inspection is read-only and lock-free so a typed host can validate the Bound coordinate before
/// journal history access. [`open_resident_writer_chirho`] must then receive
/// [`Self::as_binding_chirho`] and revalidates the exact bytes after acquiring lifetime ownership.
pub struct ResidentWriterIdentityInspectionChirho {
    canonical_root_chirho: PathBuf,
    identity_kind_chirho: String,
    canonical_identity_chirho: Vec<u8>,
    identity_digest_chirho: String,
    record_chirho: ResidentWriterIdentityRecordChirho,
    #[cfg(unix)]
    descriptor_control_chirho: Arc<DescriptorResidentWriterControlChirho>,
}

impl fmt::Debug for ResidentWriterIdentityInspectionChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("ResidentWriterIdentityInspectionChirho")
            .field("canonical_root_chirho", &"<redacted-chirho>")
            .field("identity_kind_chirho", &self.identity_kind_chirho)
            .field("identity_digest_chirho", &self.identity_digest_chirho)
            .finish_non_exhaustive()
    }
}

impl ResidentWriterIdentityInspectionChirho {
    pub fn canonical_root_chirho(&self) -> &Path {
        &self.canonical_root_chirho
    }

    pub fn identity_kind_chirho(&self) -> &str {
        &self.identity_kind_chirho
    }

    pub fn canonical_identity_chirho(&self) -> &[u8] {
        &self.canonical_identity_chirho
    }

    pub fn identity_digest_chirho(&self) -> &str {
        &self.identity_digest_chirho
    }

    pub fn as_binding_chirho(&self) -> ResidentWriterBindingChirho<'_> {
        ResidentWriterBindingChirho {
            root_chirho: &self.canonical_root_chirho,
            identity_kind_chirho: &self.identity_kind_chirho,
            canonical_identity_chirho: &self.canonical_identity_chirho,
        }
    }

    /// Acquire the lifetime lock through the same descriptor namespace used for inspection.
    pub fn open_exact_chirho(self) -> Result<ResidentWriterLeaseChirho> {
        #[cfg(unix)]
        {
            let control_chirho = Arc::clone(&self.descriptor_control_chirho);
            let lock_file_chirho = control_chirho.open_lock_chirho()?;
            let guard_chirho = acquire_descriptor_resident_writer_lock_chirho(
                lock_file_chirho,
                Arc::clone(&control_chirho),
            )?;
            verify_identity_record_in_control_chirho(&control_chirho, &self.record_chirho)?;
            Ok(guard_chirho
                .into_lease_chirho(self.canonical_root_chirho, self.identity_digest_chirho))
        }
        #[cfg(not(unix))]
        open_resident_writer_chirho(&self.as_binding_chirho())
    }
}

/// Whether the exact durable Pending record was first created or recovered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResidentWriterReservationOutcomeChirho {
    /// The control directory, lock marker, and exact Pending identity were all created now.
    CreatedPendingChirho,
    /// Incomplete control state existed, but the exact Pending identity itself was written now.
    /// A composing host must not treat this as prior authorization to adopt existing payload state.
    CompletedPendingReservationChirho,
    /// The exact validated Pending identity existed before this reservation attempt.
    RecoveredPendingChirho,
}

/// Lifetime ownership after an exact Pending-to-Bound transition or exact Bound open.
pub struct ResidentWriterLeaseChirho {
    canonical_root_chirho: PathBuf,
    identity_digest_chirho: String,
    lock_file_chirho: Option<File>,
    #[cfg(unix)]
    descriptor_control_chirho: Arc<DescriptorResidentWriterControlChirho>,
    _local_slot_chirho: ResidentWriterLocalSlotChirho,
}

impl fmt::Debug for ResidentWriterLeaseChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("ResidentWriterLeaseChirho")
            .field("canonical_root_chirho", &"<redacted-chirho>")
            .field("identity_digest_chirho", &self.identity_digest_chirho)
            .finish_non_exhaustive()
    }
}

impl ResidentWriterLeaseChirho {
    pub fn canonical_root_chirho(&self) -> &Path {
        &self.canonical_root_chirho
    }

    pub fn identity_digest_chirho(&self) -> &str {
        &self.identity_digest_chirho
    }

    /// Reinspect the bounded identity through the retained lifetime namespace and lock inode.
    pub fn inspect_identity_chirho(&self) -> Result<ResidentWriterIdentityInspectionChirho> {
        #[cfg(unix)]
        {
            let control_chirho = &self.descriptor_control_chirho;
            let lock_file_chirho = self
                .lock_file_chirho
                .as_ref()
                .expect("resident writer lease must retain its lock file");
            control_chirho.verify_lock_file_chirho(lock_file_chirho)?;
            let inspection_chirho = inspect_identity_in_control_chirho(Arc::clone(control_chirho))?;
            if inspection_chirho.identity_digest_chirho() != self.identity_digest_chirho {
                bail!("ResidentWriterIdentityMismatchChirho");
            }
            Ok(inspection_chirho)
        }
        #[cfg(not(unix))]
        inspect_resident_writer_identity_chirho(&self.canonical_root_chirho)
    }
}

impl Drop for ResidentWriterLeaseChirho {
    fn drop(&mut self) {
        if let Some(lock_file_chirho) = self.lock_file_chirho.take() {
            let _ = FileExt::unlock(&lock_file_chirho);
        }
    }
}

/// Lifetime ownership of an exact durable Pending reservation.
///
/// This type is intentionally non-Clone and carries no writer-fence authority. The composing host
/// must retain it while creating or recovering the journal, then consume it with
/// [`Self::bind_resident_writer_chirho`] before issuing any operation authority or writer fence.
pub struct ResidentWriterProvisioningLeaseChirho {
    canonical_root_chirho: PathBuf,
    pending_record_chirho: ResidentWriterIdentityRecordChirho,
    #[cfg(not(unix))]
    identity_path_chirho: PathBuf,
    #[cfg(unix)]
    descriptor_control_chirho: Arc<DescriptorResidentWriterControlChirho>,
    guard_chirho: Option<ResidentWriterLockGuardChirho>,
}

impl fmt::Debug for ResidentWriterProvisioningLeaseChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("ResidentWriterProvisioningLeaseChirho")
            .field("canonical_root_chirho", &"<redacted-chirho>")
            .field(
                "pending_identity_digest_chirho",
                &self.pending_record_chirho.identity_digest_chirho,
            )
            .finish_non_exhaustive()
    }
}

impl ResidentWriterProvisioningLeaseChirho {
    pub fn canonical_root_chirho(&self) -> &Path {
        &self.canonical_root_chirho
    }

    pub fn pending_identity_digest_chirho(&self) -> &str {
        &self.pending_record_chirho.identity_digest_chirho
    }

    pub fn bind_resident_writer_chirho(
        mut self,
        bound_chirho: &ResidentWriterBindingChirho<'_>,
    ) -> Result<ResidentWriterLeaseChirho> {
        #[cfg(unix)]
        let bound_chirho = PreparedResidentWriterBindingChirho::new_in_retained_root_chirho(
            bound_chirho,
            self.descriptor_control_chirho.canonical_root_chirho(),
            self.descriptor_control_chirho
                .binding_root_matches_chirho(bound_chirho.root_chirho)?,
        )?;
        #[cfg(not(unix))]
        let bound_chirho = PreparedResidentWriterBindingChirho::new_chirho(bound_chirho)?;
        if self.canonical_root_chirho != bound_chirho.canonical_root_chirho
            || self.pending_record_chirho.identity_kind_chirho
                != bound_chirho.record_chirho.identity_kind_chirho
        {
            bail!("ResidentWriterIdentityTransitionCoordinateMismatchChirho");
        }
        #[cfg(unix)]
        let actual_chirho = {
            self.guard_chirho
                .as_ref()
                .expect("provisioning lease must retain its resident writer guard")
                .verify_descriptor_custody_chirho()?;
            read_validated_identity_record_in_control_chirho(&self.descriptor_control_chirho)?
        };
        #[cfg(not(unix))]
        let actual_chirho = read_validated_identity_record_chirho(&self.identity_path_chirho)?;
        if actual_chirho != self.pending_record_chirho {
            bail!("ResidentWriterPendingIdentityMismatchChirho");
        }
        #[cfg(unix)]
        {
            write_identity_record_in_control_chirho(
                &self.descriptor_control_chirho,
                &bound_chirho.record_chirho,
            )?;
            self.guard_chirho
                .as_ref()
                .expect("provisioning lease must retain its resident writer guard")
                .verify_descriptor_custody_chirho()?;
        }
        #[cfg(not(unix))]
        write_identity_record_chirho(&self.identity_path_chirho, &bound_chirho.record_chirho)?;
        Ok(self
            .guard_chirho
            .take()
            .expect("provisioning lease must retain its resident writer guard")
            .into_lease_chirho(
                bound_chirho.canonical_root_chirho,
                bound_chirho.record_chirho.identity_digest_chirho,
            ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResidentWriterIdentityRecordChirho {
    schema_chirho: String,
    identity_kind_chirho: String,
    canonical_identity_hex_chirho: String,
    identity_digest_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum ResidentWriterLocalKeyChirho {
    #[cfg(unix)]
    UnixFileChirho {
        device_chirho: u64,
        inode_chirho: u64,
    },
    #[cfg(not(unix))]
    CanonicalPathChirho(PathBuf),
}

struct ResidentWriterLocalRegistryChirho {
    shard_hasher_chirho: RandomState,
    shards_chirho:
        [Mutex<HashSet<ResidentWriterLocalKeyChirho>>; RESIDENT_WRITER_LOCAL_SHARD_COUNT_CHIRHO],
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResidentWriterLocalRegistryMetricsChirho {
    active_entries_chirho: usize,
    total_capacity_chirho: usize,
    maximum_shard_capacity_chirho: usize,
}

impl ResidentWriterLocalRegistryChirho {
    fn new_chirho() -> Self {
        Self {
            shard_hasher_chirho: RandomState::new(),
            shards_chirho: std::array::from_fn(|_shard_index_chirho| Mutex::new(HashSet::new())),
        }
    }

    fn acquire_chirho(
        &'static self,
        key_chirho: &ResidentWriterLocalKeyChirho,
    ) -> Result<ResidentWriterLocalSlotChirho> {
        let shard_index_chirho = self.shard_index_chirho(key_chirho);
        let mut active_chirho = self.shards_chirho[shard_index_chirho]
            .lock()
            .map_err(|_| anyhow!("resident writer local registry shard poisoned"))?;
        if !active_chirho.insert(key_chirho.clone()) {
            bail!("ResidentWriterAlreadyHeldChirho");
        }
        Ok(ResidentWriterLocalSlotChirho {
            registry_chirho: self,
            key_chirho: key_chirho.clone(),
            shard_index_chirho,
        })
    }

    fn shard_index_chirho(&self, key_chirho: &ResidentWriterLocalKeyChirho) -> usize {
        (self.shard_hasher_chirho.hash_one(key_chirho) as usize)
            % RESIDENT_WRITER_LOCAL_SHARD_COUNT_CHIRHO
    }

    fn release_chirho(&self, slot_chirho: &ResidentWriterLocalSlotChirho) {
        let Ok(mut active_chirho) = self.shards_chirho[slot_chirho.shard_index_chirho].lock()
        else {
            return;
        };
        active_chirho.remove(&slot_chirho.key_chirho);
        if active_chirho.is_empty()
            && active_chirho.capacity() > RESIDENT_WRITER_IDLE_CAPACITY_PER_SHARD_CHIRHO
        {
            *active_chirho = HashSet::new();
        } else if !active_chirho.is_empty()
            && active_chirho.capacity()
                > RESIDENT_WRITER_IDLE_CAPACITY_PER_SHARD_CHIRHO
                    .max(active_chirho.len().saturating_mul(8))
        {
            let target_capacity_chirho = active_chirho.len().saturating_mul(2);
            active_chirho.shrink_to(target_capacity_chirho);
        }
    }

    #[cfg(test)]
    fn contains_chirho(&self, lock_path_chirho: &Path) -> bool {
        let Ok(lock_file_chirho) = OpenOptions::new()
            .read(true)
            .write(true)
            .open(lock_path_chirho)
        else {
            return false;
        };
        let Ok(key_chirho) = resident_writer_local_key_chirho(&lock_file_chirho, lock_path_chirho)
        else {
            return false;
        };
        let shard_index_chirho = self.shard_index_chirho(&key_chirho);
        self.shards_chirho[shard_index_chirho]
            .lock()
            .is_ok_and(|active_chirho| active_chirho.contains(&key_chirho))
    }

    #[cfg(test)]
    fn metrics_chirho(&self) -> ResidentWriterLocalRegistryMetricsChirho {
        let mut metrics_chirho = ResidentWriterLocalRegistryMetricsChirho {
            active_entries_chirho: 0,
            total_capacity_chirho: 0,
            maximum_shard_capacity_chirho: 0,
        };
        for shard_chirho in &self.shards_chirho {
            let active_chirho = shard_chirho
                .lock()
                .expect("resident writer registry metric shard must not be poisoned");
            metrics_chirho.active_entries_chirho += active_chirho.len();
            metrics_chirho.total_capacity_chirho += active_chirho.capacity();
            metrics_chirho.maximum_shard_capacity_chirho = metrics_chirho
                .maximum_shard_capacity_chirho
                .max(active_chirho.capacity());
        }
        metrics_chirho
    }
}

struct ResidentWriterLocalSlotChirho {
    registry_chirho: &'static ResidentWriterLocalRegistryChirho,
    key_chirho: ResidentWriterLocalKeyChirho,
    shard_index_chirho: usize,
}

impl Drop for ResidentWriterLocalSlotChirho {
    fn drop(&mut self) {
        self.registry_chirho.release_chirho(self);
    }
}

struct ResidentWriterLockGuardChirho {
    file_chirho: Option<File>,
    #[cfg(unix)]
    descriptor_control_chirho: Option<Arc<DescriptorResidentWriterControlChirho>>,
    local_slot_chirho: Option<ResidentWriterLocalSlotChirho>,
}

impl ResidentWriterLockGuardChirho {
    fn into_lease_chirho(
        mut self,
        canonical_root_chirho: PathBuf,
        identity_digest_chirho: String,
    ) -> ResidentWriterLeaseChirho {
        ResidentWriterLeaseChirho {
            canonical_root_chirho,
            identity_digest_chirho,
            lock_file_chirho: self.file_chirho.take(),
            #[cfg(unix)]
            descriptor_control_chirho: self
                .descriptor_control_chirho
                .take()
                .expect("resident writer lock guard must retain descriptor custody"),
            _local_slot_chirho: self
                .local_slot_chirho
                .take()
                .expect("resident writer lock guard must retain its local slot"),
        }
    }

    #[cfg(unix)]
    fn verify_descriptor_custody_chirho(&self) -> Result<()> {
        self.descriptor_control_chirho
            .as_ref()
            .expect("resident writer guard must retain descriptor custody")
            .verify_lock_file_chirho(
                self.file_chirho
                    .as_ref()
                    .expect("resident writer guard must retain its lock file"),
            )
    }
}

impl Drop for ResidentWriterLockGuardChirho {
    fn drop(&mut self) {
        if let Some(lock_file_chirho) = self.file_chirho.take() {
            let _ = FileExt::unlock(&lock_file_chirho);
        }
    }
}

static RESIDENT_WRITER_LOCAL_REGISTRY_CHIRHO: OnceLock<ResidentWriterLocalRegistryChirho> =
    OnceLock::new();

/// Create or recover one exact durable Pending identity and retain lifetime ownership.
///
/// A successful return has already synced a newly created Pending identity. Existing state is
/// never rebound: marker-only state from an interrupted first reservation is completed with the
/// caller's explicit Pending identity, while an existing identity must validate and match exactly.
/// Identity-without-marker, corrupt identity, or Bound identity fail closed. The returned lease
/// retains the same local slot and OS lock through journal work and binding.
pub fn reserve_resident_writer_chirho(
    pending_chirho: &ResidentWriterBindingChirho<'_>,
) -> Result<(
    ResidentWriterProvisioningLeaseChirho,
    ResidentWriterReservationOutcomeChirho,
)> {
    #[cfg(unix)]
    {
        let root_custody_chirho =
            ResidentWriterRootCustodyChirho::open_path_chirho(pending_chirho.root_chirho)?;
        reserve_resident_writer_in_custody_chirho(&root_custody_chirho, pending_chirho)
    }
    #[cfg(not(unix))]
    {
        let pending_chirho = PreparedResidentWriterBindingChirho::new_chirho(pending_chirho)?;
        let (dir_chirho, created_dir_chirho) =
            prepare_resident_writer_dir_chirho(&pending_chirho.canonical_root_chirho)?;
        let lock_path_chirho = dir_chirho.join(RESIDENT_WRITER_LOCK_FILE_CHIRHO);
        let identity_path_chirho = dir_chirho.join(RESIDENT_WRITER_IDENTITY_FILE_CHIRHO);
        let lock_exists_chirho = regular_control_file_exists_chirho(&lock_path_chirho)?;
        let identity_exists_chirho = regular_control_file_exists_chirho(&identity_path_chirho)?;
        if identity_exists_chirho && !lock_exists_chirho {
            bail!("ResidentWriterIdentityWithoutReservationMarkerChirho");
        }

        let created_lock_chirho = !lock_exists_chirho;
        let lock_file_chirho = if created_lock_chirho {
            let lock_file_chirho = create_resident_lock_for_reservation_chirho(&lock_path_chirho)?;
            lock_file_chirho
                .sync_all()
                .context("sync new resident writer reservation marker")?;
            fsync_dir_chirho(&dir_chirho)
                .context("durably record resident writer reservation marker")?;
            lock_file_chirho
        } else {
            open_existing_resident_lock_chirho(&lock_path_chirho)?
        };
        let guard_chirho =
            acquire_resident_writer_lock_chirho(lock_file_chirho, &lock_path_chirho)?;
        let identity_exists_after_lock_chirho =
            regular_control_file_exists_chirho(&identity_path_chirho)?;
        let outcome_chirho = if identity_exists_after_lock_chirho {
            verify_identity_record_chirho(&identity_path_chirho, &pending_chirho.record_chirho)?;
            ResidentWriterReservationOutcomeChirho::RecoveredPendingChirho
        } else {
            write_identity_record_chirho(&identity_path_chirho, &pending_chirho.record_chirho)?;
            if created_dir_chirho && created_lock_chirho {
                ResidentWriterReservationOutcomeChirho::CreatedPendingChirho
            } else {
                ResidentWriterReservationOutcomeChirho::CompletedPendingReservationChirho
            }
        };
        Ok((
            ResidentWriterProvisioningLeaseChirho {
                canonical_root_chirho: pending_chirho.canonical_root_chirho,
                pending_record_chirho: pending_chirho.record_chirho,
                identity_path_chirho,
                guard_chirho: Some(guard_chirho),
            },
            outcome_chirho,
        ))
    }
}

/// Create or recover Pending state under one already-retained root descriptor.
pub fn reserve_resident_writer_in_custody_chirho(
    root_custody_chirho: &ResidentWriterRootCustodyChirho,
    pending_chirho: &ResidentWriterBindingChirho<'_>,
) -> Result<(
    ResidentWriterProvisioningLeaseChirho,
    ResidentWriterReservationOutcomeChirho,
)> {
    #[cfg(unix)]
    {
        let pending_chirho = PreparedResidentWriterBindingChirho::new_in_retained_root_chirho(
            pending_chirho,
            root_custody_chirho.canonical_root_chirho(),
            root_custody_chirho
                .descriptor_root_chirho
                .binding_root_matches_chirho(pending_chirho.root_chirho)?,
        )?;
        let (control_chirho, created_dir_chirho) = root_custody_chirho
            .descriptor_root_chirho
            .prepare_control_chirho()?;
        let lock_exists_chirho = control_chirho.lock_exists_chirho()?;
        let identity_exists_chirho = control_chirho.identity_exists_chirho()?;
        if identity_exists_chirho && !lock_exists_chirho {
            bail!("ResidentWriterIdentityWithoutReservationMarkerChirho");
        }
        let (lock_file_chirho, created_lock_chirho) = if lock_exists_chirho {
            (control_chirho.open_lock_chirho()?, false)
        } else {
            control_chirho.provision_lock_chirho()?
        };
        let guard_chirho = acquire_descriptor_resident_writer_lock_chirho(
            lock_file_chirho,
            Arc::clone(&control_chirho),
        )?;
        let identity_exists_after_lock_chirho = control_chirho.identity_exists_chirho()?;
        let outcome_chirho = if identity_exists_after_lock_chirho {
            verify_identity_record_in_control_chirho(
                &control_chirho,
                &pending_chirho.record_chirho,
            )?;
            ResidentWriterReservationOutcomeChirho::RecoveredPendingChirho
        } else {
            write_identity_record_in_control_chirho(
                &control_chirho,
                &pending_chirho.record_chirho,
            )?;
            if created_dir_chirho && created_lock_chirho {
                ResidentWriterReservationOutcomeChirho::CreatedPendingChirho
            } else {
                ResidentWriterReservationOutcomeChirho::CompletedPendingReservationChirho
            }
        };
        guard_chirho.verify_descriptor_custody_chirho()?;
        Ok((
            ResidentWriterProvisioningLeaseChirho {
                canonical_root_chirho: pending_chirho.canonical_root_chirho,
                pending_record_chirho: pending_chirho.record_chirho,
                descriptor_control_chirho: control_chirho,
                guard_chirho: Some(guard_chirho),
            },
            outcome_chirho,
        ))
    }
    #[cfg(not(unix))]
    {
        let _root_custody_chirho = root_custody_chirho;
        let _pending_chirho = pending_chirho;
        bail!("ResidentWriterDescriptorCustodyUnsupportedChirho")
    }
}

/// Inspect a validated bounded identity without creating, repairing, locking, or scanning history.
pub fn inspect_resident_writer_identity_chirho(
    root_chirho: &Path,
) -> Result<ResidentWriterIdentityInspectionChirho> {
    #[cfg(unix)]
    {
        let root_custody_chirho = ResidentWriterRootCustodyChirho::open_path_chirho(root_chirho)?;
        try_inspect_resident_writer_identity_in_custody_chirho(&root_custody_chirho)?
            .ok_or_else(|| anyhow!("ResidentWriterIdentityMissingOrUnreadableChirho"))
    }
    #[cfg(not(unix))]
    {
        let canonical_root_chirho = root_chirho
            .canonicalize()
            .context("canonicalize resident writer root")?;
        if !canonical_root_chirho.is_dir() {
            bail!("ResidentWriterRootNotDirectoryChirho");
        }
        let dir_chirho = existing_resident_writer_dir_chirho(&canonical_root_chirho)?;
        let lock_path_chirho = dir_chirho.join(RESIDENT_WRITER_LOCK_FILE_CHIRHO);
        validate_regular_control_file_chirho(&lock_path_chirho)
            .context("ResidentWriterReservationMissingOrUnsafeChirho: inspect lock marker")?;
        let identity_path_chirho = dir_chirho.join(RESIDENT_WRITER_IDENTITY_FILE_CHIRHO);
        let record_chirho = read_validated_identity_record_chirho(&identity_path_chirho)?;
        let canonical_identity_chirho =
            decode_hex_chirho(&record_chirho.canonical_identity_hex_chirho)
                .context("ResidentWriterIdentityCorruptChirho: invalid identity hex")?;
        Ok(ResidentWriterIdentityInspectionChirho {
            canonical_root_chirho,
            identity_kind_chirho: record_chirho.identity_kind_chirho.clone(),
            canonical_identity_chirho,
            identity_digest_chirho: record_chirho.identity_digest_chirho.clone(),
            record_chirho,
        })
    }
}

/// Inspect optional Pending/Bound state through one retained root descriptor.
///
/// Missing control or marker-only interrupted provisioning returns `None`. Identity without its
/// reservation marker, unsafe aliases, and malformed records fail closed.
pub fn try_inspect_resident_writer_identity_in_custody_chirho(
    root_custody_chirho: &ResidentWriterRootCustodyChirho,
) -> Result<Option<ResidentWriterIdentityInspectionChirho>> {
    #[cfg(unix)]
    {
        let Some(control_chirho) = root_custody_chirho
            .descriptor_root_chirho
            .try_open_control_chirho()?
        else {
            return Ok(None);
        };
        let lock_exists_chirho = control_chirho.lock_exists_chirho()?;
        let identity_exists_chirho = control_chirho.identity_exists_chirho()?;
        if identity_exists_chirho && !lock_exists_chirho {
            bail!("ResidentWriterIdentityWithoutReservationMarkerChirho");
        }
        if !identity_exists_chirho {
            return Ok(None);
        }
        inspect_identity_in_control_chirho(control_chirho).map(Some)
    }
    #[cfg(not(unix))]
    {
        let _root_custody_chirho = root_custody_chirho;
        bail!("ResidentWriterDescriptorCustodyUnsupportedChirho")
    }
}

/// Open an exact existing Bound identity without creating or repairing any control state.
///
/// The low-level primitive cannot interpret opaque state bytes; the composing host must pass only
/// its typed Bound encoding here.
pub fn open_resident_writer_chirho(
    binding_chirho: &ResidentWriterBindingChirho<'_>,
) -> Result<ResidentWriterLeaseChirho> {
    #[cfg(unix)]
    {
        let root_custody_chirho =
            ResidentWriterRootCustodyChirho::open_path_chirho(binding_chirho.root_chirho)?;
        open_resident_writer_in_custody_chirho(&root_custody_chirho, binding_chirho)
    }
    #[cfg(not(unix))]
    {
        let prepared_chirho = PreparedResidentWriterBindingChirho::new_chirho(binding_chirho)?;
        let dir_chirho =
            existing_resident_writer_dir_chirho(&prepared_chirho.canonical_root_chirho)?;
        let lock_path_chirho = dir_chirho.join(RESIDENT_WRITER_LOCK_FILE_CHIRHO);
        let lock_file_chirho = open_existing_resident_lock_chirho(&lock_path_chirho)?;
        let guard_chirho =
            acquire_resident_writer_lock_chirho(lock_file_chirho, &lock_path_chirho)?;
        let identity_path_chirho = dir_chirho.join(RESIDENT_WRITER_IDENTITY_FILE_CHIRHO);
        verify_identity_record_chirho(&identity_path_chirho, &prepared_chirho.record_chirho)?;
        Ok(guard_chirho.into_lease_chirho(
            prepared_chirho.canonical_root_chirho,
            prepared_chirho.record_chirho.identity_digest_chirho,
        ))
    }
}

/// Open an exact Bound identity under one already-retained root descriptor.
pub fn open_resident_writer_in_custody_chirho(
    root_custody_chirho: &ResidentWriterRootCustodyChirho,
    binding_chirho: &ResidentWriterBindingChirho<'_>,
) -> Result<ResidentWriterLeaseChirho> {
    #[cfg(unix)]
    {
        let prepared_chirho = PreparedResidentWriterBindingChirho::new_in_retained_root_chirho(
            binding_chirho,
            root_custody_chirho.canonical_root_chirho(),
            root_custody_chirho
                .descriptor_root_chirho
                .binding_root_matches_chirho(binding_chirho.root_chirho)?,
        )?;
        let control_chirho = root_custody_chirho
            .descriptor_root_chirho
            .open_control_chirho()?;
        let lock_file_chirho = control_chirho.open_lock_chirho()?;
        let guard_chirho = acquire_descriptor_resident_writer_lock_chirho(
            lock_file_chirho,
            Arc::clone(&control_chirho),
        )?;
        verify_identity_record_in_control_chirho(&control_chirho, &prepared_chirho.record_chirho)?;
        guard_chirho.verify_descriptor_custody_chirho()?;
        Ok(guard_chirho.into_lease_chirho(
            prepared_chirho.canonical_root_chirho,
            prepared_chirho.record_chirho.identity_digest_chirho,
        ))
    }
    #[cfg(not(unix))]
    {
        let _root_custody_chirho = root_custody_chirho;
        let _binding_chirho = binding_chirho;
        bail!("ResidentWriterDescriptorCustodyUnsupportedChirho")
    }
}

/// Return a bounded digest for a concrete canonical host filesystem path.
pub fn canonical_filesystem_path_digest_chirho(path_chirho: &Path) -> Result<String> {
    let canonical_chirho = path_chirho
        .canonicalize()
        .context("canonicalize filesystem path")?;
    let bytes_chirho = platform_path_bytes_chirho(&canonical_chirho);
    if bytes_chirho.len() > MAX_CANONICAL_FILESYSTEM_PATH_BYTES_CHIRHO {
        bail!("CanonicalFilesystemPathBoundsChirho");
    }
    Ok(format!(
        "{CANONICAL_PATH_DIGEST_PREFIX_CHIRHO}{}",
        blake3::hash(&bytes_chirho).to_hex()
    ))
}

/// Resolve the fixed identity-record path for diagnostics and offline repair tooling.
pub fn resident_writer_identity_path_chirho(root_chirho: &Path) -> Result<PathBuf> {
    let canonical_root_chirho = root_chirho
        .canonicalize()
        .context("canonicalize resident writer root")?;
    Ok(resident_writer_dir_chirho(&canonical_root_chirho)
        .join(RESIDENT_WRITER_IDENTITY_FILE_CHIRHO))
}

struct PreparedResidentWriterBindingChirho {
    canonical_root_chirho: PathBuf,
    record_chirho: ResidentWriterIdentityRecordChirho,
}

impl PreparedResidentWriterBindingChirho {
    #[cfg(any(test, not(unix)))]
    fn new_chirho(binding_chirho: &ResidentWriterBindingChirho<'_>) -> Result<Self> {
        let canonical_root_chirho = binding_chirho
            .root_chirho
            .canonicalize()
            .context("canonicalize resident writer root")?;
        if !canonical_root_chirho.is_dir() {
            bail!("ResidentWriterRootNotDirectoryChirho");
        }
        Self::new_in_retained_root_chirho(binding_chirho, &canonical_root_chirho, true)
    }

    fn new_in_retained_root_chirho(
        binding_chirho: &ResidentWriterBindingChirho<'_>,
        canonical_root_chirho: &Path,
        root_matches_chirho: bool,
    ) -> Result<Self> {
        if !root_matches_chirho {
            bail!("ResidentWriterIdentityTransitionCoordinateMismatchChirho");
        }
        validate_identity_kind_chirho(binding_chirho.identity_kind_chirho)?;
        if binding_chirho.canonical_identity_chirho.is_empty()
            || binding_chirho.canonical_identity_chirho.len()
                > MAX_RESIDENT_WRITER_IDENTITY_BYTES_CHIRHO
        {
            bail!("ResidentWriterIdentityBoundsChirho");
        }
        let identity_digest_chirho = format!(
            "{RESIDENT_WRITER_IDENTITY_DIGEST_PREFIX_CHIRHO}{}",
            blake3::hash(binding_chirho.canonical_identity_chirho).to_hex()
        );
        let record_chirho = ResidentWriterIdentityRecordChirho {
            schema_chirho: RESIDENT_WRITER_IDENTITY_SCHEMA_CHIRHO.to_string(),
            identity_kind_chirho: binding_chirho.identity_kind_chirho.to_string(),
            canonical_identity_hex_chirho: hex_bytes_chirho(
                binding_chirho.canonical_identity_chirho,
            ),
            identity_digest_chirho,
        };
        let encoded_chirho = serde_json::to_vec(&record_chirho)?;
        if encoded_chirho.len() > MAX_RESIDENT_WRITER_RECORD_BYTES_CHIRHO {
            bail!("ResidentWriterRecordBoundsChirho");
        }
        Ok(Self {
            canonical_root_chirho: canonical_root_chirho.to_path_buf(),
            record_chirho,
        })
    }
}

fn resident_writer_dir_chirho(canonical_root_chirho: &Path) -> PathBuf {
    canonical_root_chirho.join(RESIDENT_WRITER_DIR_CHIRHO)
}

#[cfg(not(unix))]
fn prepare_resident_writer_dir_chirho(canonical_root_chirho: &Path) -> Result<(PathBuf, bool)> {
    let dir_chirho = resident_writer_dir_chirho(canonical_root_chirho);
    let created_chirho = match std::fs::symlink_metadata(&dir_chirho) {
        Ok(metadata_chirho) => {
            validate_resident_writer_dir_metadata_chirho(&metadata_chirho)?;
            false
        }
        Err(error_chirho) if error_chirho.kind() == ErrorKind::NotFound => {
            std::fs::create_dir(&dir_chirho).context("create resident writer directory")?;
            fsync_dir_chirho(canonical_root_chirho)
                .context("durably record resident writer directory creation")?;
            true
        }
        Err(error_chirho) => return Err(error_chirho).context("inspect resident writer directory"),
    };
    Ok((dir_chirho, created_chirho))
}

#[cfg(not(unix))]
fn existing_resident_writer_dir_chirho(canonical_root_chirho: &Path) -> Result<PathBuf> {
    let dir_chirho = resident_writer_dir_chirho(canonical_root_chirho);
    let metadata_chirho = std::fs::symlink_metadata(&dir_chirho)
        .context("ResidentWriterReservationMissingChirho: inspect control directory")?;
    validate_resident_writer_dir_metadata_chirho(&metadata_chirho)?;
    Ok(dir_chirho)
}

#[cfg(not(unix))]
fn validate_resident_writer_dir_metadata_chirho(metadata_chirho: &std::fs::Metadata) -> Result<()> {
    if metadata_chirho.file_type().is_symlink() || !metadata_chirho.is_dir() {
        bail!("ResidentWriterControlDirectoryUnsafeChirho");
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_resident_lock_for_reservation_chirho(lock_path_chirho: &Path) -> Result<File> {
    let file_chirho = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(lock_path_chirho)
        .context("create resident writer reservation marker")?;
    validate_regular_control_file_chirho(lock_path_chirho)?;
    Ok(file_chirho)
}

#[cfg(not(unix))]
fn open_existing_resident_lock_chirho(lock_path_chirho: &Path) -> Result<File> {
    validate_regular_control_file_chirho(lock_path_chirho)
        .context("ResidentWriterReservationMissingOrUnsafeChirho: inspect lock marker")?;
    let file_chirho = OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_path_chirho)
        .context("ResidentWriterReservationMissingChirho: open lock marker")?;
    if !file_chirho.metadata()?.is_file() {
        bail!("ResidentWriterControlFileUnsafeChirho");
    }
    validate_regular_control_file_chirho(lock_path_chirho)?;
    Ok(file_chirho)
}

#[cfg(not(unix))]
fn acquire_resident_writer_lock_chirho(
    lock_file_chirho: File,
    lock_path_chirho: &Path,
) -> Result<ResidentWriterLockGuardChirho> {
    let canonical_lock_path_chirho = lock_path_chirho
        .canonicalize()
        .context("canonicalize resident lock")?;
    let local_key_chirho =
        resident_writer_local_key_chirho(&lock_file_chirho, &canonical_lock_path_chirho)?;
    let local_slot_chirho =
        resident_writer_local_registry_chirho().acquire_chirho(&local_key_chirho)?;
    lock_file_chirho
        .try_lock_exclusive()
        .map_err(|error_chirho| {
            anyhow!("ResidentWriterAlreadyHeldChirho: OS lock refused: {error_chirho}")
        })?;
    Ok(ResidentWriterLockGuardChirho {
        file_chirho: Some(lock_file_chirho),
        local_slot_chirho: Some(local_slot_chirho),
    })
}

#[cfg(unix)]
fn acquire_descriptor_resident_writer_lock_chirho(
    lock_file_chirho: File,
    control_chirho: Arc<DescriptorResidentWriterControlChirho>,
) -> Result<ResidentWriterLockGuardChirho> {
    control_chirho.verify_lock_file_chirho(&lock_file_chirho)?;
    let local_key_chirho = resident_writer_local_key_chirho(&lock_file_chirho, Path::new(""))?;
    let local_slot_chirho =
        resident_writer_local_registry_chirho().acquire_chirho(&local_key_chirho)?;
    lock_file_chirho
        .try_lock_exclusive()
        .map_err(|error_chirho| {
            anyhow!("ResidentWriterAlreadyHeldChirho: OS lock refused: {error_chirho}")
        })?;
    if let Err(error_chirho) = control_chirho.verify_lock_file_chirho(&lock_file_chirho) {
        let _unlock_result_chirho = FileExt::unlock(&lock_file_chirho);
        return Err(error_chirho);
    }
    Ok(ResidentWriterLockGuardChirho {
        file_chirho: Some(lock_file_chirho),
        descriptor_control_chirho: Some(control_chirho),
        local_slot_chirho: Some(local_slot_chirho),
    })
}

#[cfg(unix)]
fn resident_writer_local_key_chirho(
    lock_file_chirho: &File,
    _canonical_lock_path_chirho: &Path,
) -> Result<ResidentWriterLocalKeyChirho> {
    use std::os::unix::fs::MetadataExt;
    let metadata_chirho = lock_file_chirho
        .metadata()
        .context("inspect resident writer lock file identity")?;
    Ok(ResidentWriterLocalKeyChirho::UnixFileChirho {
        device_chirho: metadata_chirho.dev(),
        inode_chirho: metadata_chirho.ino(),
    })
}

#[cfg(not(unix))]
fn resident_writer_local_key_chirho(
    _lock_file_chirho: &File,
    canonical_lock_path_chirho: &Path,
) -> Result<ResidentWriterLocalKeyChirho> {
    Ok(ResidentWriterLocalKeyChirho::CanonicalPathChirho(
        canonical_lock_path_chirho.to_path_buf(),
    ))
}

#[cfg(not(unix))]
fn verify_identity_record_chirho(
    identity_path_chirho: &Path,
    expected_chirho: &ResidentWriterIdentityRecordChirho,
) -> Result<()> {
    let actual_chirho = read_validated_identity_record_chirho(identity_path_chirho)?;
    if actual_chirho != *expected_chirho {
        bail!("ResidentWriterIdentityMismatchChirho");
    }
    Ok(())
}

#[cfg(unix)]
fn verify_identity_record_in_control_chirho(
    control_chirho: &Arc<DescriptorResidentWriterControlChirho>,
    expected_chirho: &ResidentWriterIdentityRecordChirho,
) -> Result<()> {
    let actual_chirho = read_validated_identity_record_in_control_chirho(control_chirho)?;
    if actual_chirho != *expected_chirho {
        bail!("ResidentWriterIdentityMismatchChirho");
    }
    Ok(())
}

#[cfg(unix)]
fn inspect_identity_in_control_chirho(
    control_chirho: Arc<DescriptorResidentWriterControlChirho>,
) -> Result<ResidentWriterIdentityInspectionChirho> {
    let record_chirho = read_validated_identity_record_in_control_chirho(&control_chirho)?;
    let canonical_identity_chirho = decode_hex_chirho(&record_chirho.canonical_identity_hex_chirho)
        .context("ResidentWriterIdentityCorruptChirho: invalid identity hex")?;
    Ok(ResidentWriterIdentityInspectionChirho {
        canonical_root_chirho: control_chirho.canonical_root_chirho().to_path_buf(),
        identity_kind_chirho: record_chirho.identity_kind_chirho.clone(),
        canonical_identity_chirho,
        identity_digest_chirho: record_chirho.identity_digest_chirho.clone(),
        record_chirho,
        descriptor_control_chirho: control_chirho,
    })
}

#[cfg(unix)]
fn read_validated_identity_record_in_control_chirho(
    control_chirho: &Arc<DescriptorResidentWriterControlChirho>,
) -> Result<ResidentWriterIdentityRecordChirho> {
    let bytes_chirho = control_chirho
        .read_identity_bytes_chirho(MAX_RESIDENT_WRITER_RECORD_BYTES_CHIRHO)
        .context("ResidentWriterIdentityMissingOrUnreadableChirho")?;
    decode_validated_identity_record_chirho(&bytes_chirho)
}

#[cfg(unix)]
fn write_identity_record_in_control_chirho(
    control_chirho: &Arc<DescriptorResidentWriterControlChirho>,
    record_chirho: &ResidentWriterIdentityRecordChirho,
) -> Result<()> {
    let bytes_chirho = serde_json::to_vec(record_chirho)?;
    if bytes_chirho.len() > MAX_RESIDENT_WRITER_RECORD_BYTES_CHIRHO {
        bail!("ResidentWriterRecordBoundsChirho");
    }
    control_chirho
        .atomic_write_identity_chirho(&bytes_chirho)
        .context("durably write resident writer identity")
}

#[cfg(any(test, not(unix)))]
fn read_validated_identity_record_chirho(
    identity_path_chirho: &Path,
) -> Result<ResidentWriterIdentityRecordChirho> {
    let bytes_chirho = read_bounded_identity_record_chirho(identity_path_chirho)
        .context("ResidentWriterIdentityMissingOrUnreadableChirho")?;
    decode_validated_identity_record_chirho(&bytes_chirho)
}

fn decode_validated_identity_record_chirho(
    bytes_chirho: &[u8],
) -> Result<ResidentWriterIdentityRecordChirho> {
    let actual_chirho: ResidentWriterIdentityRecordChirho = serde_json::from_slice(bytes_chirho)
        .context("ResidentWriterIdentityCorruptChirho: decode identity record")?;
    if serde_json::to_vec(&actual_chirho)? != bytes_chirho {
        bail!("ResidentWriterIdentityCorruptChirho: non-canonical record bytes");
    }
    validate_stored_identity_record_chirho(&actual_chirho)?;
    Ok(actual_chirho)
}

fn validate_stored_identity_record_chirho(
    record_chirho: &ResidentWriterIdentityRecordChirho,
) -> Result<()> {
    if record_chirho.schema_chirho != RESIDENT_WRITER_IDENTITY_SCHEMA_CHIRHO {
        bail!("ResidentWriterIdentityCorruptChirho: schema mismatch");
    }
    validate_identity_kind_chirho(&record_chirho.identity_kind_chirho)?;
    let identity_bytes_chirho = decode_hex_chirho(&record_chirho.canonical_identity_hex_chirho)
        .context("ResidentWriterIdentityCorruptChirho: invalid identity hex")?;
    if identity_bytes_chirho.is_empty()
        || identity_bytes_chirho.len() > MAX_RESIDENT_WRITER_IDENTITY_BYTES_CHIRHO
    {
        bail!("ResidentWriterIdentityCorruptChirho: identity bounds");
    }
    let expected_digest_chirho = format!(
        "{RESIDENT_WRITER_IDENTITY_DIGEST_PREFIX_CHIRHO}{}",
        blake3::hash(&identity_bytes_chirho).to_hex()
    );
    if record_chirho.identity_digest_chirho != expected_digest_chirho {
        bail!("ResidentWriterIdentityCorruptChirho: digest mismatch");
    }
    Ok(())
}

#[cfg(any(test, not(unix)))]
fn write_identity_record_chirho(
    identity_path_chirho: &Path,
    record_chirho: &ResidentWriterIdentityRecordChirho,
) -> Result<()> {
    if identity_path_chirho.exists() {
        validate_regular_control_file_chirho(identity_path_chirho)?;
    }
    let bytes_chirho = serde_json::to_vec(record_chirho)?;
    if bytes_chirho.len() > MAX_RESIDENT_WRITER_RECORD_BYTES_CHIRHO {
        bail!("ResidentWriterRecordBoundsChirho");
    }
    write_file_durable_chirho(identity_path_chirho, &bytes_chirho)
        .context("durably write resident writer identity")
}

#[cfg(any(test, not(unix)))]
fn read_bounded_identity_record_chirho(path_chirho: &Path) -> Result<Vec<u8>> {
    validate_regular_control_file_chirho(path_chirho)?;
    let mut file_chirho = File::open(path_chirho)?;
    let mut bytes_chirho = Vec::with_capacity(MAX_RESIDENT_WRITER_RECORD_BYTES_CHIRHO.min(4096));
    file_chirho
        .by_ref()
        .take((MAX_RESIDENT_WRITER_RECORD_BYTES_CHIRHO + 1) as u64)
        .read_to_end(&mut bytes_chirho)?;
    if bytes_chirho.len() > MAX_RESIDENT_WRITER_RECORD_BYTES_CHIRHO {
        bail!("ResidentWriterIdentityCorruptChirho: record exceeds byte cap");
    }
    Ok(bytes_chirho)
}

#[cfg(not(unix))]
fn regular_control_file_exists_chirho(path_chirho: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path_chirho) {
        Ok(metadata_chirho) => {
            if metadata_chirho.file_type().is_symlink() || !metadata_chirho.is_file() {
                bail!("ResidentWriterControlFileUnsafeChirho");
            }
            Ok(true)
        }
        Err(error_chirho) if error_chirho.kind() == ErrorKind::NotFound => Ok(false),
        Err(error_chirho) => Err(error_chirho).context("inspect resident writer control file"),
    }
}

#[cfg(any(test, not(unix)))]
fn validate_regular_control_file_chirho(path_chirho: &Path) -> Result<()> {
    let metadata_chirho = std::fs::symlink_metadata(path_chirho)?;
    if metadata_chirho.file_type().is_symlink() || !metadata_chirho.is_file() {
        bail!("ResidentWriterControlFileUnsafeChirho");
    }
    Ok(())
}

fn validate_identity_kind_chirho(identity_kind_chirho: &str) -> Result<()> {
    if identity_kind_chirho.is_empty()
        || identity_kind_chirho.len() > MAX_RESIDENT_WRITER_KIND_BYTES_CHIRHO
        || identity_kind_chirho
            .chars()
            .any(|char_chirho| char_chirho.is_control() || char_chirho.is_whitespace())
    {
        bail!("ResidentWriterIdentityKindInvalidChirho");
    }
    Ok(())
}

fn resident_writer_local_registry_chirho() -> &'static ResidentWriterLocalRegistryChirho {
    RESIDENT_WRITER_LOCAL_REGISTRY_CHIRHO.get_or_init(ResidentWriterLocalRegistryChirho::new_chirho)
}

fn hex_bytes_chirho(bytes_chirho: &[u8]) -> String {
    const HEX_CHIRHO: &[u8; 16] = b"0123456789abcdef";
    let mut encoded_chirho = String::with_capacity(bytes_chirho.len() * 2);
    for byte_chirho in bytes_chirho {
        encoded_chirho.push(HEX_CHIRHO[(byte_chirho >> 4) as usize] as char);
        encoded_chirho.push(HEX_CHIRHO[(byte_chirho & 0x0f) as usize] as char);
    }
    encoded_chirho
}

fn decode_hex_chirho(hex_chirho: &str) -> Result<Vec<u8>> {
    if !hex_chirho.len().is_multiple_of(2) {
        bail!("hex byte length is odd");
    }
    hex_chirho
        .as_bytes()
        .chunks_exact(2)
        .map(|pair_chirho| {
            let high_chirho = hex_nibble_chirho(pair_chirho[0])?;
            let low_chirho = hex_nibble_chirho(pair_chirho[1])?;
            Ok((high_chirho << 4) | low_chirho)
        })
        .collect()
}

fn hex_nibble_chirho(byte_chirho: u8) -> Result<u8> {
    match byte_chirho {
        b'0'..=b'9' => Ok(byte_chirho - b'0'),
        b'a'..=b'f' => Ok(byte_chirho - b'a' + 10),
        _ => bail!("non-canonical hex"),
    }
}

#[cfg(unix)]
fn platform_path_bytes_chirho(path_chirho: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path_chirho.as_os_str().as_bytes().to_vec()
}

#[cfg(windows)]
fn platform_path_bytes_chirho(path_chirho: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    path_chirho
        .as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[cfg(test)]
#[path = "resident_writer_chirho/tests_chirho.rs"]
mod tests_chirho;
