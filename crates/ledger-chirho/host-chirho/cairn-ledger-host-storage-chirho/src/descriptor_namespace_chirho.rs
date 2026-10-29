// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Descriptor-owned Unix ledger namespace.
//!
//! Every component is resolved relative to the retained root descriptor. Pathnames remain useful
//! for operator display and current-path revalidation, but no storage operation reopens through
//! that ambient path. Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/p5-cutover-and-lease-design-chirho.md`.

#[cfg(any(test, feature = "test-hooks-chirho"))]
use super::STABLE_MUTABLE_TARGET_MAX_BYTES_CHIRHO;
use super::{
    is_internal_temp_name_chirho, validate_logical_path_chirho, HostLedgerStorageRefusalChirho,
};
use anyhow::{Context, Result};
use cairn_ledger_log_chirho::ports_chirho::{CreateDurableOutcomeChirho, StoragePathChirho};
use rustix::fs::{
    flock, mkdirat, open, openat, renameat, statat, unlinkat, AtFlags, Dir, FileType,
    FlockOperation, Mode, OFlags,
};
use rustix::io::Errno;
use std::ffi::{CStr, OsStr};
use std::fs::{self, File};
use std::io::{Read, Write};
#[cfg(any(test, feature = "test-hooks-chirho"))]
use std::io::{Seek, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const TEMP_CREATE_ATTEMPTS_CHIRHO: usize = 64;
static TEMP_COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StableFilesystemIdentityChirho {
    pub device_chirho: u64,
    pub inode_chirho: u64,
}

#[derive(Debug)]
pub(super) struct DescriptorLedgerNamespaceChirho {
    canonical_root_chirho: PathBuf,
    root_directory_chirho: File,
    root_identity_chirho: StableFilesystemIdentityChirho,
    owner_uid_chirho: u32,
}

#[derive(Clone, Debug)]
pub struct StableLedgerNamespaceSnapshotChirho {
    namespace_chirho: Arc<DescriptorLedgerNamespaceChirho>,
}

#[derive(Debug)]
struct DescriptorParentTargetChirho {
    parent_directory_chirho: File,
    target_name_chirho: String,
}

#[derive(Clone, Copy, Debug)]
struct StableEntryInspectionChirho {
    identity_chirho: StableFilesystemIdentityChirho,
    file_type_chirho: FileType,
    mode_chirho: u32,
    links_chirho: u64,
    owner_uid_chirho: u32,
    len_chirho: u64,
}

#[derive(Debug)]
pub(super) struct DescriptorLedgerExclusiveLockHandleChirho {
    namespace_chirho: Arc<DescriptorLedgerNamespaceChirho>,
    parent_directory_chirho: File,
    parent_identity_chirho: StableFilesystemIdentityChirho,
    lock_file_chirho: File,
    lock_name_chirho: String,
    lock_identity_chirho: StableFilesystemIdentityChirho,
}

#[derive(Debug)]
pub(super) struct DescriptorLedgerExclusiveLockGuardChirho<'lock_chirho> {
    handle_chirho: &'lock_chirho DescriptorLedgerExclusiveLockHandleChirho,
}

#[cfg(any(test, feature = "test-hooks-chirho"))]
#[derive(Debug)]
pub struct StableLedgerMutableTargetChirho {
    namespace_chirho: Arc<DescriptorLedgerNamespaceChirho>,
    parent_directory_chirho: File,
    parent_identity_chirho: StableFilesystemIdentityChirho,
    target_file_chirho: File,
    target_name_chirho: String,
    target_identity_chirho: StableFilesystemIdentityChirho,
}

impl DescriptorLedgerNamespaceChirho {
    pub(super) fn open_existing_chirho(namespace_root_chirho: &Path) -> Result<Arc<Self>> {
        let path_metadata_chirho = fs::symlink_metadata(namespace_root_chirho)
            .map_err(|_error_chirho| HostLedgerStorageRefusalChirho::NamespaceUnavailableChirho)?;
        if path_metadata_chirho.file_type().is_symlink() {
            return Err(HostLedgerStorageRefusalChirho::SymlinkBoundaryChirho.into());
        }
        if !path_metadata_chirho.is_dir() {
            return Err(HostLedgerStorageRefusalChirho::NamespaceNotDirectoryChirho.into());
        }
        let canonical_root_chirho = namespace_root_chirho
            .canonicalize()
            .map_err(|_error_chirho| HostLedgerStorageRefusalChirho::NamespaceUnavailableChirho)?;
        let root_descriptor_chirho = open(
            &canonical_root_chirho,
            directory_open_flags_chirho(),
            Mode::empty(),
        )
        .map_err(map_open_errno_chirho)?;
        let root_directory_chirho = File::from(root_descriptor_chirho);
        let root_metadata_chirho = root_directory_chirho
            .metadata()
            .context("inspect descriptor-owned ledger namespace")?;
        let path_identity_chirho = identity_from_metadata_chirho(&path_metadata_chirho);
        let root_identity_chirho = identity_from_metadata_chirho(&root_metadata_chirho);
        if path_identity_chirho != root_identity_chirho {
            return Err(HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho.into());
        }
        let owner_uid_chirho = root_metadata_chirho.uid();
        if owner_uid_chirho != rustix::process::geteuid().as_raw() {
            return Err(HostLedgerStorageRefusalChirho::MutableTargetOwnerMismatchChirho.into());
        }
        verify_directory_metadata_chirho(&root_metadata_chirho, owner_uid_chirho)?;
        Ok(Arc::new(Self {
            canonical_root_chirho,
            root_directory_chirho,
            root_identity_chirho,
            owner_uid_chirho,
        }))
    }

    pub(super) fn canonical_root_chirho(&self) -> &Path {
        &self.canonical_root_chirho
    }

    pub(super) fn clone_root_directory_chirho(&self) -> Result<File> {
        self.verify_descriptor_chirho()?;
        self.root_directory_chirho
            .try_clone()
            .context("clone retained ledger namespace root descriptor")
    }

    pub(super) fn stable_snapshot_chirho(
        namespace_chirho: &Arc<Self>,
    ) -> StableLedgerNamespaceSnapshotChirho {
        StableLedgerNamespaceSnapshotChirho {
            namespace_chirho: Arc::clone(namespace_chirho),
        }
    }

    pub(super) fn open_existing_exclusive_lock_handle_chirho(
        namespace_chirho: &Arc<Self>,
        path_chirho: &StoragePathChirho,
    ) -> Result<DescriptorLedgerExclusiveLockHandleChirho> {
        let target_chirho = namespace_chirho
            .open_parent_target_chirho(path_chirho, false)?
            .ok_or(HostLedgerStorageRefusalChirho::MissingObjectChirho)?;
        let lock_file_chirho =
            namespace_chirho.open_existing_file_chirho(&target_chirho, OFlags::RDWR)?;
        let lock_inspection_chirho =
            inspect_open_file_chirho(&lock_file_chirho, namespace_chirho.owner_uid_chirho)?;
        if lock_inspection_chirho.len_chirho != 0 {
            return Err(HostLedgerStorageRefusalChirho::ObjectExceedsBoundChirho.into());
        }
        let lock_identity_chirho = lock_inspection_chirho.identity_chirho;
        namespace_chirho.verify_open_file_entry_chirho(
            &target_chirho,
            &lock_file_chirho,
            lock_identity_chirho,
        )?;
        let parent_identity_chirho = identity_from_metadata_chirho(
            &target_chirho
                .parent_directory_chirho
                .metadata()
                .context("inspect descriptor-owned lock parent")?,
        );
        Ok(DescriptorLedgerExclusiveLockHandleChirho {
            namespace_chirho: Arc::clone(namespace_chirho),
            parent_directory_chirho: target_chirho.parent_directory_chirho,
            parent_identity_chirho,
            lock_file_chirho,
            lock_name_chirho: target_chirho.target_name_chirho,
            lock_identity_chirho,
        })
    }

    pub(super) fn read_bounded_object_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        max_bytes_chirho: u64,
    ) -> Result<Option<Vec<u8>>> {
        let Some(target_chirho) = self.open_parent_target_chirho(path_chirho, false)? else {
            return Ok(None);
        };
        let Some(file_chirho) =
            self.open_optional_existing_file_chirho(&target_chirho, OFlags::RDONLY)?
        else {
            return Ok(None);
        };
        let inspection_chirho = inspect_open_file_chirho(&file_chirho, self.owner_uid_chirho)?;
        if inspection_chirho.len_chirho > max_bytes_chirho {
            return Err(HostLedgerStorageRefusalChirho::ObjectExceedsBoundChirho.into());
        }
        let allocation_len_chirho = usize::try_from(inspection_chirho.len_chirho)
            .map_err(|_error_chirho| HostLedgerStorageRefusalChirho::ObjectExceedsBoundChirho)?;
        let mut bytes_chirho = vec![0_u8; allocation_len_chirho];
        file_chirho
            .read_exact_at(&mut bytes_chirho, 0)
            .context("read bounded descriptor-owned ledger object")?;
        self.verify_open_file_entry_chirho(
            &target_chirho,
            &file_chirho,
            inspection_chirho.identity_chirho,
        )?;
        Ok(Some(bytes_chirho))
    }

    pub(super) fn create_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<CreateDurableOutcomeChirho> {
        let target_chirho = self
            .open_parent_target_chirho(path_chirho, true)?
            .expect("create-parent traversal always returns a target chirho");
        match self.create_new_file_chirho(&target_chirho, false) {
            Ok(mut file_chirho) => {
                file_chirho
                    .write_all(bytes_chirho)
                    .context("write newly claimed ledger storage object")?;
                file_chirho
                    .sync_all()
                    .context("sync newly claimed ledger storage object")?;
                target_chirho
                    .parent_directory_chirho
                    .sync_all()
                    .context("sync newly claimed ledger storage directory entry")?;
                Ok(CreateDurableOutcomeChirho::CreatedChirho)
            }
            Err(error_chirho) if errno_from_anyhow_chirho(&error_chirho) == Some(Errno::EXIST) => {
                self.open_existing_file_chirho(&target_chirho, OFlags::RDONLY)?;
                Ok(CreateDurableOutcomeChirho::AlreadyExistsChirho)
            }
            Err(error_chirho) => Err(error_chirho).context("durably create ledger storage object"),
        }
    }

    pub(super) fn append_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()> {
        let target_chirho = self
            .open_parent_target_chirho(path_chirho, true)?
            .expect("append-parent traversal always returns a target chirho");
        match self.create_new_file_chirho(&target_chirho, true) {
            Ok(mut file_chirho) => {
                file_chirho
                    .write_all(bytes_chirho)
                    .context("append first ledger storage bytes")?;
                file_chirho.sync_all().context("sync new ledger append")?;
                target_chirho
                    .parent_directory_chirho
                    .sync_all()
                    .context("sync new ledger append directory entry")
            }
            Err(error_chirho) if errno_from_anyhow_chirho(&error_chirho) == Some(Errno::EXIST) => {
                let mut file_chirho = self
                    .open_existing_file_chirho(&target_chirho, OFlags::WRONLY | OFlags::APPEND)?;
                file_chirho
                    .write_all(bytes_chirho)
                    .context("append ledger storage bytes")?;
                file_chirho.sync_all().context("sync ledger append")
            }
            Err(error_chirho) => Err(error_chirho).context("open durable ledger append target"),
        }
    }

    pub(super) fn read_all_chirho(
        &self,
        path_chirho: &StoragePathChirho,
    ) -> Result<Option<Vec<u8>>> {
        let Some(target_chirho) = self.open_parent_target_chirho(path_chirho, false)? else {
            return Ok(None);
        };
        let Some(mut file_chirho) =
            self.open_optional_existing_file_chirho(&target_chirho, OFlags::RDONLY)?
        else {
            return Ok(None);
        };
        let before_chirho = inspect_open_file_chirho(&file_chirho, self.owner_uid_chirho)?;
        let mut bytes_chirho = Vec::new();
        file_chirho
            .read_to_end(&mut bytes_chirho)
            .context("read descriptor-owned ledger storage object")?;
        let after_chirho = self.verify_open_file_entry_chirho(
            &target_chirho,
            &file_chirho,
            before_chirho.identity_chirho,
        )?;
        if before_chirho.len_chirho != after_chirho.len_chirho
            || after_chirho.len_chirho != bytes_chirho.len() as u64
        {
            return Err(HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho.into());
        }
        Ok(Some(bytes_chirho))
    }

    pub(super) fn object_len_chirho(&self, path_chirho: &StoragePathChirho) -> Result<Option<u64>> {
        let Some(target_chirho) = self.open_parent_target_chirho(path_chirho, false)? else {
            return Ok(None);
        };
        let Some(file_chirho) =
            self.open_optional_existing_file_chirho(&target_chirho, OFlags::RDONLY)?
        else {
            return Ok(None);
        };
        Ok(Some(
            inspect_open_file_chirho(&file_chirho, self.owner_uid_chirho)?.len_chirho,
        ))
    }

    pub(super) fn read_exact_range_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        offset_chirho: u64,
        len_chirho: u64,
    ) -> Result<Vec<u8>> {
        let end_chirho = offset_chirho
            .checked_add(len_chirho)
            .ok_or(HostLedgerStorageRefusalChirho::InvalidRangeChirho)?;
        let target_chirho = self
            .open_parent_target_chirho(path_chirho, false)?
            .ok_or(HostLedgerStorageRefusalChirho::MissingObjectChirho)?;
        let file_chirho = self.open_existing_file_chirho(&target_chirho, OFlags::RDONLY)?;
        let inspection_chirho = inspect_open_file_chirho(&file_chirho, self.owner_uid_chirho)?;
        if end_chirho > inspection_chirho.len_chirho {
            return Err(HostLedgerStorageRefusalChirho::InvalidRangeChirho.into());
        }
        let allocation_len_chirho = usize::try_from(len_chirho)
            .map_err(|_error_chirho| HostLedgerStorageRefusalChirho::InvalidRangeChirho)?;
        let mut bytes_chirho = vec![0_u8; allocation_len_chirho];
        file_chirho
            .read_exact_at(&mut bytes_chirho, offset_chirho)
            .context("read exact descriptor-owned ledger range")?;
        let after_chirho = self.verify_open_file_entry_chirho(
            &target_chirho,
            &file_chirho,
            inspection_chirho.identity_chirho,
        )?;
        if end_chirho > after_chirho.len_chirho {
            return Err(HostLedgerStorageRefusalChirho::InvalidRangeChirho.into());
        }
        Ok(bytes_chirho)
    }

    pub(super) fn atomic_write_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()> {
        let target_chirho = self
            .open_parent_target_chirho(path_chirho, true)?
            .expect("atomic-write parent traversal always returns a target chirho");
        self.verify_optional_target_chirho(&target_chirho)?;
        let (temp_name_chirho, mut temp_file_chirho) =
            self.create_unique_temp_file_chirho(&target_chirho.parent_directory_chirho)?;
        let write_result_chirho = (|| {
            temp_file_chirho
                .write_all(bytes_chirho)
                .context("write descriptor-owned ledger replacement")?;
            temp_file_chirho
                .sync_all()
                .context("sync descriptor-owned ledger replacement")?;
            renameat(
                &target_chirho.parent_directory_chirho,
                temp_name_chirho.as_str(),
                &target_chirho.parent_directory_chirho,
                target_chirho.target_name_chirho.as_str(),
            )
            .map_err(io_error_from_errno_chirho)
            .context("install descriptor-owned ledger replacement")?;
            target_chirho
                .parent_directory_chirho
                .sync_all()
                .context("sync descriptor-owned ledger replacement directory")
        })();
        if write_result_chirho.is_err() {
            let _ = unlinkat(
                &target_chirho.parent_directory_chirho,
                temp_name_chirho.as_str(),
                AtFlags::empty(),
            );
        }
        write_result_chirho
    }

    pub(super) fn truncate_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        new_len_chirho: u64,
    ) -> Result<()> {
        let target_chirho = self
            .open_parent_target_chirho(path_chirho, false)?
            .ok_or(HostLedgerStorageRefusalChirho::MissingObjectChirho)?;
        let file_chirho = self.open_existing_file_chirho(&target_chirho, OFlags::RDWR)?;
        let before_chirho = inspect_open_file_chirho(&file_chirho, self.owner_uid_chirho)?;
        if new_len_chirho > before_chirho.len_chirho {
            return Err(HostLedgerStorageRefusalChirho::InvalidRangeChirho.into());
        }
        file_chirho
            .set_len(new_len_chirho)
            .context("truncate descriptor-owned ledger object")?;
        file_chirho
            .sync_all()
            .context("sync truncated descriptor-owned ledger object")?;
        let after_chirho = self.verify_open_file_entry_chirho(
            &target_chirho,
            &file_chirho,
            before_chirho.identity_chirho,
        )?;
        if after_chirho.len_chirho != new_len_chirho {
            return Err(HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho.into());
        }
        Ok(())
    }

    pub(super) fn rename_chirho(
        &self,
        from_chirho: &StoragePathChirho,
        to_chirho: &StoragePathChirho,
    ) -> Result<()> {
        let from_target_chirho = self
            .open_parent_target_chirho(from_chirho, false)?
            .ok_or(HostLedgerStorageRefusalChirho::MissingObjectChirho)?;
        let from_file_chirho =
            self.open_existing_file_chirho(&from_target_chirho, OFlags::RDONLY)?;
        let from_identity_chirho =
            inspect_open_file_chirho(&from_file_chirho, self.owner_uid_chirho)?.identity_chirho;
        let to_target_chirho = self
            .open_parent_target_chirho(to_chirho, true)?
            .expect("rename destination traversal always returns a target chirho");
        self.verify_optional_target_chirho(&to_target_chirho)?;
        renameat(
            &from_target_chirho.parent_directory_chirho,
            from_target_chirho.target_name_chirho.as_str(),
            &to_target_chirho.parent_directory_chirho,
            to_target_chirho.target_name_chirho.as_str(),
        )
        .map_err(map_open_errno_chirho)
        .context("rename descriptor-owned ledger object")?;
        let installed_chirho = inspect_entry_at_chirho(
            &to_target_chirho.parent_directory_chirho,
            to_target_chirho.target_name_chirho.as_str(),
        )?
        .ok_or(HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho)?;
        verify_file_inspection_chirho(&installed_chirho, self.owner_uid_chirho)?;
        if installed_chirho.identity_chirho != from_identity_chirho {
            return Err(HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho.into());
        }
        to_target_chirho
            .parent_directory_chirho
            .sync_all()
            .context("sync descriptor-owned ledger rename destination")?;
        if identity_from_metadata_chirho(
            &from_target_chirho
                .parent_directory_chirho
                .metadata()
                .context("inspect ledger rename source parent")?,
        ) != identity_from_metadata_chirho(
            &to_target_chirho
                .parent_directory_chirho
                .metadata()
                .context("inspect ledger rename destination parent")?,
        ) {
            from_target_chirho
                .parent_directory_chirho
                .sync_all()
                .context("sync descriptor-owned ledger rename source")?;
        }
        Ok(())
    }

    pub(super) fn remove_chirho(&self, path_chirho: &StoragePathChirho) -> Result<()> {
        let Some(target_chirho) = self.open_parent_target_chirho(path_chirho, false)? else {
            return Ok(());
        };
        let Some(file_chirho) =
            self.open_optional_existing_file_chirho(&target_chirho, OFlags::RDONLY)?
        else {
            return Ok(());
        };
        self.verify_open_file_entry_chirho(
            &target_chirho,
            &file_chirho,
            inspect_open_file_chirho(&file_chirho, self.owner_uid_chirho)?.identity_chirho,
        )?;
        unlinkat(
            &target_chirho.parent_directory_chirho,
            target_chirho.target_name_chirho.as_str(),
            AtFlags::empty(),
        )
        .map_err(map_open_errno_chirho)
        .context("remove descriptor-owned ledger object")?;
        target_chirho
            .parent_directory_chirho
            .sync_all()
            .context("sync removed ledger directory entry")
    }

    pub(super) fn list_chirho(
        &self,
        prefix_chirho: &StoragePathChirho,
    ) -> Result<Vec<StoragePathChirho>> {
        validate_logical_path_chirho(prefix_chirho.key_chirho(), true)?;
        let prefix_key_chirho = prefix_chirho.key_chirho();
        let trimmed_chirho = prefix_key_chirho.trim_end_matches('/');
        let base_key_chirho = if prefix_key_chirho.ends_with('/') {
            trimmed_chirho
        } else {
            trimmed_chirho
                .rsplit_once('/')
                .map_or("", |(parent_chirho, _leaf_chirho)| parent_chirho)
        };
        let Some(base_directory_chirho) =
            self.open_directory_path_chirho(base_key_chirho, false)?
        else {
            return Ok(Vec::new());
        };
        let mut paths_chirho = Vec::new();
        self.collect_files_chirho(
            &base_directory_chirho,
            base_key_chirho,
            prefix_key_chirho,
            &mut paths_chirho,
        )?;
        paths_chirho.sort_by(|left_chirho, right_chirho| {
            left_chirho.key_chirho().cmp(right_chirho.key_chirho())
        });
        Ok(paths_chirho)
    }

    pub(super) fn exists_chirho(&self, path_chirho: &StoragePathChirho) -> Result<bool> {
        let Some(target_chirho) = self.open_parent_target_chirho(path_chirho, false)? else {
            return Ok(false);
        };
        Ok(self
            .open_optional_existing_file_chirho(&target_chirho, OFlags::RDONLY)?
            .is_some())
    }

    fn verify_descriptor_chirho(&self) -> Result<()> {
        let metadata_chirho = self
            .root_directory_chirho
            .metadata()
            .context("reinspect descriptor-owned ledger namespace")?;
        if identity_from_metadata_chirho(&metadata_chirho) != self.root_identity_chirho {
            return Err(HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho.into());
        }
        verify_directory_metadata_chirho(&metadata_chirho, self.owner_uid_chirho)
    }

    fn open_parent_target_chirho(
        &self,
        logical_path_chirho: &StoragePathChirho,
        create_missing_chirho: bool,
    ) -> Result<Option<DescriptorParentTargetChirho>> {
        validate_logical_path_chirho(logical_path_chirho.key_chirho(), false)?;
        let mut components_chirho = logical_path_chirho
            .key_chirho()
            .split('/')
            .collect::<Vec<_>>();
        let target_name_chirho = components_chirho
            .pop()
            .ok_or(HostLedgerStorageRefusalChirho::UnsafeLogicalPathChirho)?
            .to_owned();
        let parent_key_chirho = components_chirho.join("/");
        let Some(parent_directory_chirho) =
            self.open_directory_path_chirho(&parent_key_chirho, create_missing_chirho)?
        else {
            return Ok(None);
        };
        Ok(Some(DescriptorParentTargetChirho {
            parent_directory_chirho,
            target_name_chirho,
        }))
    }

    fn open_directory_path_chirho(
        &self,
        logical_directory_chirho: &str,
        create_missing_chirho: bool,
    ) -> Result<Option<File>> {
        self.verify_descriptor_chirho()?;
        let mut current_chirho = self
            .root_directory_chirho
            .try_clone()
            .context("duplicate descriptor-owned ledger root")?;
        if logical_directory_chirho.is_empty() {
            return Ok(Some(current_chirho));
        }
        for component_chirho in logical_directory_chirho.split('/') {
            match open_directory_component_chirho(
                &current_chirho,
                component_chirho,
                self.owner_uid_chirho,
            ) {
                Ok(next_chirho) => current_chirho = next_chirho,
                Err(error_chirho)
                    if error_chirho.downcast_ref::<HostLedgerStorageRefusalChirho>()
                        == Some(&HostLedgerStorageRefusalChirho::MissingObjectChirho) =>
                {
                    if !create_missing_chirho {
                        return Ok(None);
                    }
                    match mkdirat(&current_chirho, component_chirho, Mode::RWXU) {
                        Ok(()) | Err(Errno::EXIST) => {}
                        Err(error_chirho) => {
                            return Err(map_open_errno_chirho(error_chirho))
                                .context("create descriptor-relative ledger directory")
                        }
                    }
                    current_chirho
                        .sync_all()
                        .context("sync descriptor-relative ledger directory entry")?;
                    current_chirho = open_directory_component_chirho(
                        &current_chirho,
                        component_chirho,
                        self.owner_uid_chirho,
                    )?;
                }
                Err(error_chirho) => return Err(error_chirho),
            }
        }
        Ok(Some(current_chirho))
    }

    fn create_new_file_chirho(
        &self,
        target_chirho: &DescriptorParentTargetChirho,
        append_chirho: bool,
    ) -> Result<File> {
        let mut flags_chirho = OFlags::WRONLY
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::NOFOLLOW
            | OFlags::CLOEXEC
            | OFlags::NONBLOCK;
        if append_chirho {
            flags_chirho |= OFlags::APPEND;
        }
        let descriptor_chirho = openat(
            &target_chirho.parent_directory_chirho,
            target_chirho.target_name_chirho.as_str(),
            flags_chirho,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|error_chirho| anyhow::Error::new(io_error_from_errno_chirho(error_chirho)))?;
        let file_chirho = File::from(descriptor_chirho);
        inspect_open_file_chirho(&file_chirho, self.owner_uid_chirho)?;
        Ok(file_chirho)
    }

    fn open_existing_file_chirho(
        &self,
        target_chirho: &DescriptorParentTargetChirho,
        access_flags_chirho: OFlags,
    ) -> Result<File> {
        self.open_optional_existing_file_chirho(target_chirho, access_flags_chirho)?
            .ok_or_else(|| HostLedgerStorageRefusalChirho::MissingObjectChirho.into())
    }

    fn open_optional_existing_file_chirho(
        &self,
        target_chirho: &DescriptorParentTargetChirho,
        access_flags_chirho: OFlags,
    ) -> Result<Option<File>> {
        let Some(entry_chirho) = inspect_entry_at_chirho(
            &target_chirho.parent_directory_chirho,
            target_chirho.target_name_chirho.as_str(),
        )?
        else {
            return Ok(None);
        };
        verify_file_inspection_chirho(&entry_chirho, self.owner_uid_chirho)?;
        let flags_chirho =
            access_flags_chirho | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let descriptor_chirho = openat(
            &target_chirho.parent_directory_chirho,
            target_chirho.target_name_chirho.as_str(),
            flags_chirho,
            Mode::empty(),
        )
        .map_err(map_open_errno_chirho)?;
        let file_chirho = File::from(descriptor_chirho);
        let opened_chirho = inspect_open_file_chirho(&file_chirho, self.owner_uid_chirho)?;
        if opened_chirho.identity_chirho != entry_chirho.identity_chirho {
            return Err(HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho.into());
        }
        Ok(Some(file_chirho))
    }

    fn verify_optional_target_chirho(
        &self,
        target_chirho: &DescriptorParentTargetChirho,
    ) -> Result<()> {
        if let Some(inspection_chirho) = inspect_entry_at_chirho(
            &target_chirho.parent_directory_chirho,
            target_chirho.target_name_chirho.as_str(),
        )? {
            verify_file_inspection_chirho(&inspection_chirho, self.owner_uid_chirho)?;
        }
        Ok(())
    }

    fn verify_open_file_entry_chirho(
        &self,
        target_chirho: &DescriptorParentTargetChirho,
        file_chirho: &File,
        expected_identity_chirho: StableFilesystemIdentityChirho,
    ) -> Result<StableEntryInspectionChirho> {
        let entry_chirho = inspect_entry_at_chirho(
            &target_chirho.parent_directory_chirho,
            target_chirho.target_name_chirho.as_str(),
        )?
        .ok_or(HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho)?;
        verify_file_inspection_chirho(&entry_chirho, self.owner_uid_chirho)?;
        let opened_chirho = inspect_open_file_chirho(file_chirho, self.owner_uid_chirho)?;
        if entry_chirho.identity_chirho != expected_identity_chirho
            || opened_chirho.identity_chirho != expected_identity_chirho
        {
            return Err(HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho.into());
        }
        Ok(opened_chirho)
    }

    fn create_unique_temp_file_chirho(&self, parent_chirho: &File) -> Result<(String, File)> {
        for _attempt_chirho in 0..TEMP_CREATE_ATTEMPTS_CHIRHO {
            let counter_chirho = TEMP_COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
            let name_chirho = format!(".ledger.tmp-chirho-{}-{counter_chirho}", std::process::id());
            match openat(
                parent_chirho,
                name_chirho.as_str(),
                OFlags::WRONLY
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(descriptor_chirho) => {
                    let file_chirho = File::from(descriptor_chirho);
                    inspect_open_file_chirho(&file_chirho, self.owner_uid_chirho)?;
                    return Ok((name_chirho, file_chirho));
                }
                Err(Errno::EXIST) => continue,
                Err(error_chirho) => {
                    return Err(io_error_from_errno_chirho(error_chirho))
                        .context("create descriptor-owned ledger temp object")
                }
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "descriptor-owned ledger temp namespace exhausted",
        )
        .into())
    }

    fn collect_files_chirho(
        &self,
        directory_chirho: &File,
        directory_key_chirho: &str,
        prefix_chirho: &str,
        paths_chirho: &mut Vec<StoragePathChirho>,
    ) -> Result<()> {
        let entries_chirho = Dir::read_from(directory_chirho)
            .map_err(io_error_from_errno_chirho)
            .context("open descriptor-owned ledger directory stream")?;
        for entry_result_chirho in entries_chirho {
            let entry_chirho = entry_result_chirho
                .map_err(io_error_from_errno_chirho)
                .context("read descriptor-owned ledger directory entry")?;
            let name_chirho = utf8_name_chirho(entry_chirho.file_name())?;
            if matches!(name_chirho.as_str(), "." | "..") {
                continue;
            }
            let inspection_chirho = inspect_entry_at_chirho(directory_chirho, &name_chirho)?
                .ok_or(HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho)?;
            let logical_chirho = if directory_key_chirho.is_empty() {
                name_chirho.clone()
            } else {
                format!("{directory_key_chirho}/{name_chirho}")
            };
            match inspection_chirho.file_type_chirho {
                FileType::Directory => {
                    verify_directory_inspection_chirho(&inspection_chirho, self.owner_uid_chirho)?;
                    let child_chirho = open_directory_component_chirho(
                        directory_chirho,
                        &name_chirho,
                        self.owner_uid_chirho,
                    )?;
                    self.collect_files_chirho(
                        &child_chirho,
                        &logical_chirho,
                        prefix_chirho,
                        paths_chirho,
                    )?;
                }
                FileType::RegularFile => {
                    verify_file_inspection_chirho(&inspection_chirho, self.owner_uid_chirho)?;
                    if !is_internal_temp_name_chirho(&name_chirho)
                        && logical_chirho.starts_with(prefix_chirho)
                    {
                        paths_chirho.push(StoragePathChirho::new_chirho(logical_chirho));
                    }
                }
                FileType::Symlink => {
                    return Err(HostLedgerStorageRefusalChirho::SymlinkBoundaryChirho.into())
                }
                _ => {
                    return Err(
                        HostLedgerStorageRefusalChirho::MutableTargetNotRegularChirho.into(),
                    )
                }
            }
        }
        Ok(())
    }
}

impl DescriptorLedgerExclusiveLockHandleChirho {
    pub(super) fn try_acquire_chirho(
        &mut self,
    ) -> Result<DescriptorLedgerExclusiveLockGuardChirho<'_>> {
        self.verify_custody_chirho()?;
        match flock(
            &self.lock_file_chirho,
            FlockOperation::NonBlockingLockExclusive,
        ) {
            Ok(()) => {}
            Err(Errno::WOULDBLOCK) => {
                return Err(HostLedgerStorageRefusalChirho::ExclusiveLockBusyChirho.into())
            }
            Err(error_chirho) => {
                return Err(io_error_from_errno_chirho(error_chirho))
                    .context("acquire descriptor-owned exclusive lock")
            }
        }
        if let Err(error_chirho) = self.verify_custody_chirho() {
            let _unlock_result_chirho = flock(&self.lock_file_chirho, FlockOperation::Unlock);
            return Err(error_chirho);
        }
        Ok(DescriptorLedgerExclusiveLockGuardChirho {
            handle_chirho: self,
        })
    }

    pub(super) fn verify_custody_chirho(&self) -> Result<()> {
        self.namespace_chirho.verify_descriptor_chirho()?;
        let parent_metadata_chirho = self
            .parent_directory_chirho
            .metadata()
            .context("inspect held descriptor lock parent")?;
        verify_directory_metadata_chirho(
            &parent_metadata_chirho,
            self.namespace_chirho.owner_uid_chirho,
        )?;
        if identity_from_metadata_chirho(&parent_metadata_chirho) != self.parent_identity_chirho {
            return Err(HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho.into());
        }
        let target_chirho = DescriptorParentTargetChirho {
            parent_directory_chirho: self
                .parent_directory_chirho
                .try_clone()
                .context("clone held descriptor lock parent")?,
            target_name_chirho: self.lock_name_chirho.clone(),
        };
        self.namespace_chirho.verify_open_file_entry_chirho(
            &target_chirho,
            &self.lock_file_chirho,
            self.lock_identity_chirho,
        )?;
        Ok(())
    }
}

impl DescriptorLedgerExclusiveLockGuardChirho<'_> {
    pub(super) fn verify_custody_chirho(&self) -> Result<()> {
        self.handle_chirho.verify_custody_chirho()
    }
}

impl Drop for DescriptorLedgerExclusiveLockGuardChirho<'_> {
    fn drop(&mut self) {
        let _unlock_result_chirho =
            flock(&self.handle_chirho.lock_file_chirho, FlockOperation::Unlock);
    }
}

impl StableLedgerNamespaceSnapshotChirho {
    #[cfg(any(test, not(unix), feature = "test-hooks-chirho"))]
    pub fn acquire_existing_chirho(namespace_root_chirho: &Path) -> Result<Self> {
        Ok(Self {
            namespace_chirho: DescriptorLedgerNamespaceChirho::open_existing_chirho(
                namespace_root_chirho,
            )?,
        })
    }

    pub fn identity_chirho(&self) -> Result<StableFilesystemIdentityChirho> {
        self.namespace_chirho.verify_descriptor_chirho()?;
        Ok(self.namespace_chirho.root_identity_chirho)
    }

    pub fn verify_current_path_chirho(&self, namespace_root_chirho: &Path) -> Result<()> {
        let path_metadata_chirho =
            fs::symlink_metadata(namespace_root_chirho).map_err(|_error_chirho| {
                HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho
            })?;
        if path_metadata_chirho.file_type().is_symlink() {
            return Err(HostLedgerStorageRefusalChirho::SymlinkBoundaryChirho.into());
        }
        if identity_from_metadata_chirho(&path_metadata_chirho)
            != self.namespace_chirho.root_identity_chirho
        {
            return Err(HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho.into());
        }
        self.namespace_chirho.verify_descriptor_chirho()
    }

    #[cfg(any(test, feature = "test-hooks-chirho"))]
    pub fn open_mutable_target_chirho(
        &self,
        logical_path_chirho: &StoragePathChirho,
    ) -> Result<StableLedgerMutableTargetChirho> {
        let target_chirho = self
            .namespace_chirho
            .open_parent_target_chirho(logical_path_chirho, false)?
            .ok_or(HostLedgerStorageRefusalChirho::MissingObjectChirho)?;
        let target_file_chirho = self
            .namespace_chirho
            .open_existing_file_chirho(&target_chirho, OFlags::RDWR)?;
        let target_inspection_chirho =
            inspect_open_file_chirho(&target_file_chirho, self.namespace_chirho.owner_uid_chirho)?;
        if target_inspection_chirho.len_chirho > STABLE_MUTABLE_TARGET_MAX_BYTES_CHIRHO as u64 {
            return Err(HostLedgerStorageRefusalChirho::ObjectExceedsBoundChirho.into());
        }
        let parent_identity_chirho = identity_from_metadata_chirho(
            &target_chirho
                .parent_directory_chirho
                .metadata()
                .context("inspect stable ledger mutable parent")?,
        );
        Ok(StableLedgerMutableTargetChirho {
            namespace_chirho: Arc::clone(&self.namespace_chirho),
            parent_directory_chirho: target_chirho.parent_directory_chirho,
            parent_identity_chirho,
            target_file_chirho,
            target_name_chirho: target_chirho.target_name_chirho,
            target_identity_chirho: target_inspection_chirho.identity_chirho,
        })
    }
}

#[cfg(any(test, feature = "test-hooks-chirho"))]
impl StableLedgerMutableTargetChirho {
    pub fn read_bounded_chirho(&self) -> Result<Vec<u8>> {
        let before_chirho = self.verify_custody_chirho()?;
        let mut bytes_chirho =
            Vec::with_capacity(usize::try_from(before_chirho.len_chirho).map_err(
                |_error_chirho| HostLedgerStorageRefusalChirho::ObjectExceedsBoundChirho,
            )?);
        let mut offset_chirho = 0_u64;
        let mut chunk_chirho = [0_u8; 4096];
        loop {
            let remaining_chirho = STABLE_MUTABLE_TARGET_MAX_BYTES_CHIRHO
                .saturating_add(1)
                .saturating_sub(bytes_chirho.len());
            if remaining_chirho == 0 {
                return Err(HostLedgerStorageRefusalChirho::ObjectExceedsBoundChirho.into());
            }
            let chunk_len_chirho = remaining_chirho.min(chunk_chirho.len());
            let read_chirho = self
                .target_file_chirho
                .read_at(&mut chunk_chirho[..chunk_len_chirho], offset_chirho)
                .context("read stable ledger target through its descriptor")?;
            if read_chirho == 0 {
                break;
            }
            bytes_chirho.extend_from_slice(&chunk_chirho[..read_chirho]);
            offset_chirho = offset_chirho
                .checked_add(read_chirho as u64)
                .ok_or(HostLedgerStorageRefusalChirho::ObjectExceedsBoundChirho)?;
        }
        if bytes_chirho.len() > STABLE_MUTABLE_TARGET_MAX_BYTES_CHIRHO {
            return Err(HostLedgerStorageRefusalChirho::ObjectExceedsBoundChirho.into());
        }
        let after_chirho = self.verify_custody_chirho()?;
        if before_chirho.len_chirho != after_chirho.len_chirho
            || after_chirho.len_chirho != bytes_chirho.len() as u64
        {
            return Err(HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho.into());
        }
        Ok(bytes_chirho)
    }

    pub fn overwrite_bounded_chirho(&mut self, bytes_chirho: &[u8]) -> Result<()> {
        if bytes_chirho.len() > STABLE_MUTABLE_TARGET_MAX_BYTES_CHIRHO {
            return Err(HostLedgerStorageRefusalChirho::ObjectExceedsBoundChirho.into());
        }
        self.verify_custody_chirho()?;
        self.target_file_chirho.set_len(0)?;
        self.target_file_chirho.seek(SeekFrom::Start(0))?;
        self.target_file_chirho
            .write_all(bytes_chirho)
            .context("write stable ledger target through its descriptor")?;
        self.target_file_chirho.sync_all()?;
        let after_chirho = self.verify_custody_chirho()?;
        if after_chirho.len_chirho != bytes_chirho.len() as u64 {
            return Err(HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho.into());
        }
        Ok(())
    }

    fn verify_custody_chirho(&self) -> Result<StableEntryInspectionChirho> {
        self.namespace_chirho.verify_descriptor_chirho()?;
        let parent_metadata_chirho = self
            .parent_directory_chirho
            .metadata()
            .context("reinspect stable ledger parent descriptor")?;
        if identity_from_metadata_chirho(&parent_metadata_chirho) != self.parent_identity_chirho {
            return Err(HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho.into());
        }
        verify_directory_metadata_chirho(
            &parent_metadata_chirho,
            self.namespace_chirho.owner_uid_chirho,
        )?;
        let entry_chirho = inspect_entry_at_chirho(
            &self.parent_directory_chirho,
            self.target_name_chirho.as_str(),
        )?
        .ok_or(HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho)?;
        verify_file_inspection_chirho(&entry_chirho, self.namespace_chirho.owner_uid_chirho)?;
        if entry_chirho.identity_chirho != self.target_identity_chirho
            || entry_chirho.len_chirho > STABLE_MUTABLE_TARGET_MAX_BYTES_CHIRHO as u64
        {
            return Err(HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho.into());
        }
        let opened_chirho = inspect_open_file_chirho(
            &self.target_file_chirho,
            self.namespace_chirho.owner_uid_chirho,
        )?;
        if opened_chirho.identity_chirho != self.target_identity_chirho
            || opened_chirho.len_chirho > STABLE_MUTABLE_TARGET_MAX_BYTES_CHIRHO as u64
        {
            return Err(HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho.into());
        }
        Ok(opened_chirho)
    }
}

fn directory_open_flags_chirho() -> OFlags {
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK
}

fn open_directory_component_chirho(
    parent_chirho: &File,
    component_chirho: &str,
    owner_uid_chirho: u32,
) -> Result<File> {
    let before_chirho = inspect_entry_at_chirho(parent_chirho, component_chirho)?
        .ok_or(HostLedgerStorageRefusalChirho::MissingObjectChirho)?;
    verify_directory_inspection_chirho(&before_chirho, owner_uid_chirho)?;
    let descriptor_chirho = openat(
        parent_chirho,
        component_chirho,
        directory_open_flags_chirho(),
        Mode::empty(),
    )
    .map_err(map_open_errno_chirho)?;
    let directory_chirho = File::from(descriptor_chirho);
    let metadata_chirho = directory_chirho
        .metadata()
        .context("inspect opened descriptor-relative ledger directory")?;
    verify_directory_metadata_chirho(&metadata_chirho, owner_uid_chirho)?;
    if identity_from_metadata_chirho(&metadata_chirho) != before_chirho.identity_chirho {
        return Err(HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho.into());
    }
    Ok(directory_chirho)
}

fn inspect_entry_at_chirho(
    parent_chirho: &File,
    name_chirho: &str,
) -> Result<Option<StableEntryInspectionChirho>> {
    let stat_chirho = match statat(parent_chirho, name_chirho, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat_chirho) => stat_chirho,
        Err(Errno::NOENT) => return Ok(None),
        Err(error_chirho) => return Err(io_error_from_errno_chirho(error_chirho).into()),
    };
    Ok(Some(StableEntryInspectionChirho {
        identity_chirho: StableFilesystemIdentityChirho {
            device_chirho: stable_u64_chirho(stat_chirho.st_dev)?,
            inode_chirho: stable_u64_chirho(stat_chirho.st_ino)?,
        },
        file_type_chirho: FileType::from_raw_mode(stat_chirho.st_mode),
        mode_chirho: stable_u32_chirho(stat_chirho.st_mode)?,
        links_chirho: stable_u64_chirho(stat_chirho.st_nlink)?,
        owner_uid_chirho: stable_u32_chirho(stat_chirho.st_uid)?,
        len_chirho: stable_u64_chirho(stat_chirho.st_size)?,
    }))
}

fn inspect_open_file_chirho(
    file_chirho: &File,
    owner_uid_chirho: u32,
) -> Result<StableEntryInspectionChirho> {
    let metadata_chirho = file_chirho
        .metadata()
        .context("inspect opened descriptor-owned ledger object")?;
    let inspection_chirho = StableEntryInspectionChirho {
        identity_chirho: identity_from_metadata_chirho(&metadata_chirho),
        file_type_chirho: if metadata_chirho.is_file() {
            FileType::RegularFile
        } else if metadata_chirho.is_dir() {
            FileType::Directory
        } else if metadata_chirho.file_type().is_symlink() {
            FileType::Symlink
        } else {
            FileType::Unknown
        },
        mode_chirho: metadata_chirho.mode(),
        links_chirho: metadata_chirho.nlink(),
        owner_uid_chirho: metadata_chirho.uid(),
        len_chirho: metadata_chirho.len(),
    };
    verify_file_inspection_chirho(&inspection_chirho, owner_uid_chirho)?;
    Ok(inspection_chirho)
}

fn verify_file_inspection_chirho(
    inspection_chirho: &StableEntryInspectionChirho,
    owner_uid_chirho: u32,
) -> Result<()> {
    match inspection_chirho.file_type_chirho {
        FileType::Symlink => {
            return Err(HostLedgerStorageRefusalChirho::SymlinkBoundaryChirho.into())
        }
        FileType::RegularFile => {}
        _ => return Err(HostLedgerStorageRefusalChirho::MutableTargetNotRegularChirho.into()),
    }
    if inspection_chirho.links_chirho != 1 {
        return Err(HostLedgerStorageRefusalChirho::MutableTargetAliasedChirho.into());
    }
    if inspection_chirho.owner_uid_chirho != owner_uid_chirho {
        return Err(HostLedgerStorageRefusalChirho::MutableTargetOwnerMismatchChirho.into());
    }
    if inspection_chirho.mode_chirho & 0o022 != 0 {
        return Err(HostLedgerStorageRefusalChirho::MutableTargetModeTooBroadChirho.into());
    }
    Ok(())
}

fn verify_directory_inspection_chirho(
    inspection_chirho: &StableEntryInspectionChirho,
    owner_uid_chirho: u32,
) -> Result<()> {
    match inspection_chirho.file_type_chirho {
        FileType::Symlink => {
            return Err(HostLedgerStorageRefusalChirho::SymlinkBoundaryChirho.into())
        }
        FileType::Directory => {}
        _ => return Err(HostLedgerStorageRefusalChirho::NamespaceNotDirectoryChirho.into()),
    }
    if inspection_chirho.owner_uid_chirho != owner_uid_chirho {
        return Err(HostLedgerStorageRefusalChirho::MutableTargetOwnerMismatchChirho.into());
    }
    if inspection_chirho.mode_chirho & 0o022 != 0 {
        return Err(HostLedgerStorageRefusalChirho::MutableTargetModeTooBroadChirho.into());
    }
    Ok(())
}

fn verify_directory_metadata_chirho(
    metadata_chirho: &fs::Metadata,
    owner_uid_chirho: u32,
) -> Result<()> {
    if !metadata_chirho.is_dir() {
        return Err(HostLedgerStorageRefusalChirho::NamespaceNotDirectoryChirho.into());
    }
    if metadata_chirho.uid() != owner_uid_chirho {
        return Err(HostLedgerStorageRefusalChirho::MutableTargetOwnerMismatchChirho.into());
    }
    if metadata_chirho.mode() & 0o022 != 0 {
        return Err(HostLedgerStorageRefusalChirho::MutableTargetModeTooBroadChirho.into());
    }
    Ok(())
}

fn identity_from_metadata_chirho(metadata_chirho: &fs::Metadata) -> StableFilesystemIdentityChirho {
    StableFilesystemIdentityChirho {
        device_chirho: metadata_chirho.dev(),
        inode_chirho: metadata_chirho.ino(),
    }
}

fn utf8_name_chirho(name_chirho: &CStr) -> Result<String> {
    let os_name_chirho = OsStr::from_bytes(name_chirho.to_bytes());
    os_name_chirho
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| HostLedgerStorageRefusalChirho::NonUtf8ObjectNameChirho.into())
}

fn map_open_errno_chirho(error_chirho: Errno) -> anyhow::Error {
    match error_chirho {
        Errno::LOOP => HostLedgerStorageRefusalChirho::SymlinkBoundaryChirho.into(),
        Errno::NOENT => HostLedgerStorageRefusalChirho::MissingObjectChirho.into(),
        Errno::NOTDIR => HostLedgerStorageRefusalChirho::NamespaceNotDirectoryChirho.into(),
        _ => io_error_from_errno_chirho(error_chirho).into(),
    }
}

fn io_error_from_errno_chirho(error_chirho: Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error_chirho.raw_os_error())
}

fn errno_from_anyhow_chirho(error_chirho: &anyhow::Error) -> Option<Errno> {
    error_chirho
        .downcast_ref::<std::io::Error>()
        .and_then(std::io::Error::raw_os_error)
        .map(Errno::from_raw_os_error)
}

fn stable_u64_chirho<ValueChirho>(value_chirho: ValueChirho) -> Result<u64>
where
    ValueChirho: TryInto<u64>,
{
    value_chirho.try_into().map_err(|_error_chirho| {
        HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho.into()
    })
}

fn stable_u32_chirho<ValueChirho>(value_chirho: ValueChirho) -> Result<u32>
where
    ValueChirho: TryInto<u32>,
{
    value_chirho.try_into().map_err(|_error_chirho| {
        HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho.into()
    })
}
