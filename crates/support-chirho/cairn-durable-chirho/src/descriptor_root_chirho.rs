// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Descriptor-owned resident-writer control state on Unix.
//!
//! The caller may hand in an already-open root directory. Every control-directory, lock, and
//! identity operation then stays relative to that retained descriptor; the canonical pathname is
//! display and coordinate evidence only. Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/p5-cutover-and-lease-design-chirho.md` §4.

use crate::{
    MAX_CANONICAL_FILESYSTEM_PATH_BYTES_CHIRHO, RESIDENT_WRITER_DIR_CHIRHO,
    RESIDENT_WRITER_IDENTITY_FILE_CHIRHO, RESIDENT_WRITER_LOCK_FILE_CHIRHO,
};
use anyhow::{bail, Context, Result};
use rustix::fs::{
    mkdirat, open, openat, renameat, statat, unlinkat, AtFlags, FileType, Mode, OFlags,
};
use rustix::io::Errno;
use std::fs::File;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const RESIDENT_CONTROL_TEMP_ATTEMPTS_CHIRHO: usize = 64;
static RESIDENT_CONTROL_TEMP_COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResidentControlFilesystemIdentityChirho {
    pub(crate) device_chirho: u64,
    pub(crate) inode_chirho: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ResidentControlEntryInspectionChirho {
    pub(crate) identity_chirho: ResidentControlFilesystemIdentityChirho,
    pub(crate) file_type_chirho: FileType,
    pub(crate) mode_chirho: u32,
    pub(crate) links_chirho: u64,
    pub(crate) owner_uid_chirho: u32,
    pub(crate) len_chirho: u64,
}

#[derive(Debug)]
pub struct DescriptorRootCustodyChirho {
    pub(crate) canonical_root_chirho: PathBuf,
    pub(crate) root_directory_chirho: File,
    pub(crate) root_identity_chirho: ResidentControlFilesystemIdentityChirho,
    pub(crate) owner_uid_chirho: u32,
}

#[derive(Debug)]
pub struct DescriptorResidentWriterControlChirho {
    root_chirho: Arc<DescriptorRootCustodyChirho>,
    control_directory_chirho: File,
    control_identity_chirho: ResidentControlFilesystemIdentityChirho,
}

impl DescriptorRootCustodyChirho {
    pub fn open_path_chirho(root_chirho: &Path) -> Result<Arc<Self>> {
        let canonical_root_chirho = root_chirho
            .canonicalize()
            .context("canonicalize resident writer root")?;
        let descriptor_chirho = open(
            &canonical_root_chirho,
            directory_open_flags_chirho(),
            Mode::empty(),
        )
        .map_err(map_open_error_chirho)?;
        Self::from_retained_directory_chirho(canonical_root_chirho, File::from(descriptor_chirho))
    }

    pub fn from_retained_directory_chirho(
        canonical_root_chirho: PathBuf,
        root_directory_chirho: File,
    ) -> Result<Arc<Self>> {
        validate_canonical_display_path_chirho(&canonical_root_chirho)?;
        let metadata_chirho = root_directory_chirho
            .metadata()
            .context("inspect retained resident writer root descriptor")?;
        let owner_uid_chirho = metadata_chirho.uid();
        verify_directory_metadata_chirho(&metadata_chirho, owner_uid_chirho)?;
        if owner_uid_chirho != rustix::process::geteuid().as_raw() {
            bail!("ResidentWriterControlOwnerMismatchChirho");
        }
        Ok(Arc::new(Self {
            canonical_root_chirho,
            root_identity_chirho: identity_from_metadata_chirho(&metadata_chirho),
            root_directory_chirho,
            owner_uid_chirho,
        }))
    }

    pub fn canonical_root_chirho(&self) -> &Path {
        &self.canonical_root_chirho
    }

    /// Domain-separated identity of this retained root descriptor and its canonical coordinate.
    ///
    /// This is local filesystem binding evidence, not a portable content identity. The device and
    /// inode prevent a pathname rebound from retaining the old identity. The canonical path keeps
    /// the protocol coordinate explicit while normalizing ordinary symlink/path aliases.
    pub fn binding_identity_digest_chirho(&self) -> Result<[u8; 32]> {
        self.verify_custody_chirho()?;
        let path_bytes_chirho = self.canonical_root_chirho.as_os_str().as_bytes();
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(b"cairn-descriptor-root-binding-v1-chirho");
        hasher_chirho.update(&self.root_identity_chirho.device_chirho.to_le_bytes());
        hasher_chirho.update(&self.root_identity_chirho.inode_chirho.to_le_bytes());
        hasher_chirho.update(&(path_bytes_chirho.len() as u64).to_le_bytes());
        hasher_chirho.update(path_bytes_chirho);
        Ok(*hasher_chirho.finalize().as_bytes())
    }

    pub fn binding_root_matches_chirho(&self, root_chirho: &Path) -> Result<bool> {
        if root_chirho == self.canonical_root_chirho {
            self.verify_custody_chirho()?;
            return Ok(true);
        }
        let candidate_chirho = root_chirho
            .canonicalize()
            .context("canonicalize resident writer binding root")?;
        let descriptor_chirho = open(
            &candidate_chirho,
            directory_open_flags_chirho(),
            Mode::empty(),
        )
        .map_err(map_open_error_chirho)?;
        let candidate_file_chirho = File::from(descriptor_chirho);
        let candidate_metadata_chirho = candidate_file_chirho
            .metadata()
            .context("inspect resident writer binding root descriptor")?;
        Ok(identity_from_metadata_chirho(&candidate_metadata_chirho) == self.root_identity_chirho)
    }

    /// Reopen the canonical pathname and prove it still names this retained root inode.
    ///
    /// Resident-writer custody deliberately keeps following a renamed inode, so
    /// [`Self::binding_root_matches_chirho`] preserves that older behavior for an exact canonical
    /// coordinate. CAS lifecycle promotion needs the stricter pathname-rebound check instead.
    pub fn canonical_path_still_names_custody_chirho(&self) -> Result<bool> {
        self.verify_custody_chirho()?;
        let descriptor_chirho = match open(
            &self.canonical_root_chirho,
            directory_open_flags_chirho(),
            Mode::empty(),
        ) {
            Ok(descriptor_chirho) => descriptor_chirho,
            Err(Errno::NOENT | Errno::NOTDIR) => return Ok(false),
            Err(error_chirho) => return Err(map_open_error_chirho(error_chirho)),
        };
        let candidate_metadata_chirho = File::from(descriptor_chirho)
            .metadata()
            .context("inspect canonical root pathname for rebound")?;
        Ok(identity_from_metadata_chirho(&candidate_metadata_chirho) == self.root_identity_chirho)
    }

    pub fn prepare_control_chirho(
        self: &Arc<Self>,
    ) -> Result<(Arc<DescriptorResidentWriterControlChirho>, bool)> {
        self.verify_custody_chirho()?;
        let created_chirho =
            match inspect_entry_at_chirho(&self.root_directory_chirho, RESIDENT_WRITER_DIR_CHIRHO)?
            {
                Some(inspection_chirho) => {
                    verify_directory_inspection_chirho(&inspection_chirho, self.owner_uid_chirho)?;
                    false
                }
                None => match mkdirat(
                    &self.root_directory_chirho,
                    RESIDENT_WRITER_DIR_CHIRHO,
                    Mode::RWXU,
                ) {
                    Ok(()) => {
                        self.root_directory_chirho
                            .sync_all()
                            .context("sync resident writer control directory creation")?;
                        true
                    }
                    Err(Errno::EXIST) => false,
                    Err(error_chirho) => {
                        return Err(io_error_from_errno_chirho(error_chirho))
                            .context("create descriptor-owned resident writer control directory")
                    }
                },
            };
        Ok((self.open_control_chirho()?, created_chirho))
    }

    pub fn open_control_chirho(
        self: &Arc<Self>,
    ) -> Result<Arc<DescriptorResidentWriterControlChirho>> {
        self.try_open_control_chirho()?
            .ok_or_else(|| anyhow::anyhow!("ResidentWriterReservationMissingChirho"))
    }

    pub fn try_open_control_chirho(
        self: &Arc<Self>,
    ) -> Result<Option<Arc<DescriptorResidentWriterControlChirho>>> {
        self.verify_custody_chirho()?;
        let Some(before_chirho) =
            inspect_entry_at_chirho(&self.root_directory_chirho, RESIDENT_WRITER_DIR_CHIRHO)?
        else {
            return Ok(None);
        };
        verify_directory_inspection_chirho(&before_chirho, self.owner_uid_chirho)?;
        let descriptor_chirho = openat(
            &self.root_directory_chirho,
            RESIDENT_WRITER_DIR_CHIRHO,
            directory_open_flags_chirho(),
            Mode::empty(),
        )
        .map_err(map_open_error_chirho)?;
        let control_directory_chirho = File::from(descriptor_chirho);
        let metadata_chirho = control_directory_chirho
            .metadata()
            .context("inspect descriptor-owned resident writer control directory")?;
        verify_directory_metadata_chirho(&metadata_chirho, self.owner_uid_chirho)?;
        let control_identity_chirho = identity_from_metadata_chirho(&metadata_chirho);
        if control_identity_chirho != before_chirho.identity_chirho {
            bail!("ResidentWriterControlCustodyChangedChirho");
        }
        Ok(Some(Arc::new(DescriptorResidentWriterControlChirho {
            root_chirho: Arc::clone(self),
            control_directory_chirho,
            control_identity_chirho,
        })))
    }

    pub(crate) fn verify_custody_chirho(&self) -> Result<()> {
        let metadata_chirho = self
            .root_directory_chirho
            .metadata()
            .context("reinspect retained resident writer root descriptor")?;
        verify_directory_metadata_chirho(&metadata_chirho, self.owner_uid_chirho)?;
        if identity_from_metadata_chirho(&metadata_chirho) != self.root_identity_chirho {
            bail!("ResidentWriterControlCustodyChangedChirho");
        }
        Ok(())
    }
}

impl DescriptorResidentWriterControlChirho {
    pub fn canonical_root_chirho(&self) -> &Path {
        self.root_chirho.canonical_root_chirho()
    }

    pub fn binding_root_matches_chirho(&self, root_chirho: &Path) -> Result<bool> {
        self.root_chirho.binding_root_matches_chirho(root_chirho)
    }

    pub fn lock_exists_chirho(&self) -> Result<bool> {
        self.regular_file_exists_chirho(RESIDENT_WRITER_LOCK_FILE_CHIRHO, true)
    }

    pub fn identity_exists_chirho(&self) -> Result<bool> {
        self.regular_file_exists_chirho(RESIDENT_WRITER_IDENTITY_FILE_CHIRHO, false)
    }

    pub fn provision_lock_chirho(&self) -> Result<(File, bool)> {
        self.verify_custody_chirho()?;
        let descriptor_chirho = match openat(
            &self.control_directory_chirho,
            RESIDENT_WRITER_LOCK_FILE_CHIRHO,
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(descriptor_chirho) => descriptor_chirho,
            Err(Errno::EXIST) => return Ok((self.open_lock_chirho()?, false)),
            Err(error_chirho) => return Err(map_open_error_chirho(error_chirho)),
        };
        let lock_file_chirho = File::from(descriptor_chirho);
        let inspection_chirho =
            inspect_open_file_chirho(&lock_file_chirho, self.owner_uid_chirho())?;
        if inspection_chirho.len_chirho != 0 {
            bail!("ResidentWriterControlFileUnsafeChirho");
        }
        lock_file_chirho
            .sync_all()
            .context("sync new resident writer reservation marker")?;
        self.control_directory_chirho
            .sync_all()
            .context("durably record resident writer reservation marker")?;
        self.verify_lock_file_chirho(&lock_file_chirho)?;
        Ok((lock_file_chirho, true))
    }

    pub fn open_lock_chirho(&self) -> Result<File> {
        let lock_file_chirho = self
            .open_optional_file_chirho(RESIDENT_WRITER_LOCK_FILE_CHIRHO, OFlags::RDWR)?
            .ok_or_else(|| anyhow::anyhow!("ResidentWriterReservationMissingChirho"))?;
        let inspection_chirho =
            inspect_open_file_chirho(&lock_file_chirho, self.owner_uid_chirho())?;
        if inspection_chirho.len_chirho != 0 {
            bail!("ResidentWriterControlFileUnsafeChirho");
        }
        Ok(lock_file_chirho)
    }

    pub fn verify_lock_file_chirho(&self, lock_file_chirho: &File) -> Result<()> {
        self.verify_open_file_entry_chirho(RESIDENT_WRITER_LOCK_FILE_CHIRHO, lock_file_chirho)?;
        if lock_file_chirho.metadata()?.len() != 0 {
            bail!("ResidentWriterControlFileUnsafeChirho");
        }
        Ok(())
    }

    pub fn read_identity_bytes_chirho(&self, max_bytes_chirho: usize) -> Result<Vec<u8>> {
        let identity_file_chirho = self
            .open_optional_file_chirho(RESIDENT_WRITER_IDENTITY_FILE_CHIRHO, OFlags::RDONLY)?
            .ok_or_else(|| anyhow::anyhow!("ResidentWriterIdentityMissingOrUnreadableChirho"))?;
        let before_chirho =
            inspect_open_file_chirho(&identity_file_chirho, self.owner_uid_chirho())?;
        if before_chirho.len_chirho > max_bytes_chirho as u64 {
            bail!("ResidentWriterIdentityCorruptChirho: record exceeds byte cap");
        }
        let allocation_chirho =
            usize::try_from(before_chirho.len_chirho).map_err(|_error_chirho| {
                anyhow::anyhow!("ResidentWriterIdentityCorruptChirho: record exceeds byte cap")
            })?;
        let mut bytes_chirho = vec![0_u8; allocation_chirho];
        identity_file_chirho
            .read_exact_at(&mut bytes_chirho, 0)
            .context("read descriptor-owned resident writer identity")?;
        let after_chirho = self.verify_open_file_entry_chirho(
            RESIDENT_WRITER_IDENTITY_FILE_CHIRHO,
            &identity_file_chirho,
        )?;
        if before_chirho.len_chirho != after_chirho.len_chirho
            || after_chirho.len_chirho != bytes_chirho.len() as u64
        {
            bail!("ResidentWriterControlCustodyChangedChirho");
        }
        Ok(bytes_chirho)
    }

    pub fn atomic_write_identity_chirho(&self, bytes_chirho: &[u8]) -> Result<()> {
        self.verify_custody_chirho()?;
        if let Some(inspection_chirho) = inspect_entry_at_chirho(
            &self.control_directory_chirho,
            RESIDENT_WRITER_IDENTITY_FILE_CHIRHO,
        )? {
            verify_file_inspection_chirho(&inspection_chirho, self.owner_uid_chirho())?;
        }
        let (temp_name_chirho, mut temp_file_chirho) = self.create_unique_temp_file_chirho()?;
        let temp_identity_chirho = identity_from_metadata_chirho(&temp_file_chirho.metadata()?);
        let write_result_chirho = (|| {
            temp_file_chirho
                .write_all(bytes_chirho)
                .context("write descriptor-owned resident writer identity")?;
            temp_file_chirho
                .sync_all()
                .context("sync descriptor-owned resident writer identity")?;
            renameat(
                &self.control_directory_chirho,
                temp_name_chirho.as_str(),
                &self.control_directory_chirho,
                RESIDENT_WRITER_IDENTITY_FILE_CHIRHO,
            )
            .map_err(io_error_from_errno_chirho)
            .context("install descriptor-owned resident writer identity")?;
            self.control_directory_chirho
                .sync_all()
                .context("sync descriptor-owned resident writer identity directory")?;
            let installed_chirho = inspect_entry_at_chirho(
                &self.control_directory_chirho,
                RESIDENT_WRITER_IDENTITY_FILE_CHIRHO,
            )?
            .ok_or_else(|| anyhow::anyhow!("ResidentWriterControlCustodyChangedChirho"))?;
            verify_file_inspection_chirho(&installed_chirho, self.owner_uid_chirho())?;
            if installed_chirho.identity_chirho != temp_identity_chirho
                || installed_chirho.len_chirho != bytes_chirho.len() as u64
            {
                bail!("ResidentWriterControlCustodyChangedChirho");
            }
            Ok(())
        })();
        if write_result_chirho.is_err() {
            let _unlink_result_chirho = unlinkat(
                &self.control_directory_chirho,
                temp_name_chirho.as_str(),
                AtFlags::empty(),
            );
        }
        write_result_chirho
    }

    fn regular_file_exists_chirho(
        &self,
        name_chirho: &str,
        require_empty_chirho: bool,
    ) -> Result<bool> {
        self.verify_custody_chirho()?;
        let Some(inspection_chirho) =
            inspect_entry_at_chirho(&self.control_directory_chirho, name_chirho)?
        else {
            return Ok(false);
        };
        verify_file_inspection_chirho(&inspection_chirho, self.owner_uid_chirho())?;
        if require_empty_chirho && inspection_chirho.len_chirho != 0 {
            bail!("ResidentWriterControlFileUnsafeChirho");
        }
        Ok(true)
    }

    fn open_optional_file_chirho(
        &self,
        name_chirho: &str,
        access_chirho: OFlags,
    ) -> Result<Option<File>> {
        self.verify_custody_chirho()?;
        let Some(before_chirho) =
            inspect_entry_at_chirho(&self.control_directory_chirho, name_chirho)?
        else {
            return Ok(None);
        };
        verify_file_inspection_chirho(&before_chirho, self.owner_uid_chirho())?;
        let descriptor_chirho = openat(
            &self.control_directory_chirho,
            name_chirho,
            access_chirho | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(map_open_error_chirho)?;
        let file_chirho = File::from(descriptor_chirho);
        let opened_chirho = inspect_open_file_chirho(&file_chirho, self.owner_uid_chirho())?;
        if opened_chirho.identity_chirho != before_chirho.identity_chirho {
            bail!("ResidentWriterControlCustodyChangedChirho");
        }
        Ok(Some(file_chirho))
    }

    fn verify_open_file_entry_chirho(
        &self,
        name_chirho: &str,
        file_chirho: &File,
    ) -> Result<ResidentControlEntryInspectionChirho> {
        self.verify_custody_chirho()?;
        let entry_chirho = inspect_entry_at_chirho(&self.control_directory_chirho, name_chirho)?
            .ok_or_else(|| anyhow::anyhow!("ResidentWriterControlCustodyChangedChirho"))?;
        verify_file_inspection_chirho(&entry_chirho, self.owner_uid_chirho())?;
        let opened_chirho = inspect_open_file_chirho(file_chirho, self.owner_uid_chirho())?;
        if entry_chirho.identity_chirho != opened_chirho.identity_chirho {
            bail!("ResidentWriterControlCustodyChangedChirho");
        }
        Ok(opened_chirho)
    }

    fn create_unique_temp_file_chirho(&self) -> Result<(String, File)> {
        for _attempt_chirho in 0..RESIDENT_CONTROL_TEMP_ATTEMPTS_CHIRHO {
            let counter_chirho =
                RESIDENT_CONTROL_TEMP_COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
            let name_chirho = format!(
                ".resident-writer.tmp-chirho-{}-{counter_chirho}",
                std::process::id()
            );
            match openat(
                &self.control_directory_chirho,
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
                    inspect_open_file_chirho(&file_chirho, self.owner_uid_chirho())?;
                    return Ok((name_chirho, file_chirho));
                }
                Err(Errno::EXIST) => continue,
                Err(error_chirho) => {
                    return Err(io_error_from_errno_chirho(error_chirho))
                        .context("create descriptor-owned resident writer temp identity")
                }
            }
        }
        bail!("ResidentWriterControlTempNamespaceExhaustedChirho")
    }

    fn verify_custody_chirho(&self) -> Result<()> {
        self.root_chirho.verify_custody_chirho()?;
        let root_entry_chirho = inspect_entry_at_chirho(
            &self.root_chirho.root_directory_chirho,
            RESIDENT_WRITER_DIR_CHIRHO,
        )?
        .ok_or_else(|| anyhow::anyhow!("ResidentWriterControlCustodyChangedChirho"))?;
        verify_directory_inspection_chirho(&root_entry_chirho, self.root_chirho.owner_uid_chirho)?;
        let metadata_chirho = self
            .control_directory_chirho
            .metadata()
            .context("reinspect descriptor-owned resident writer control directory")?;
        verify_directory_metadata_chirho(&metadata_chirho, self.root_chirho.owner_uid_chirho)?;
        if root_entry_chirho.identity_chirho != self.control_identity_chirho
            || identity_from_metadata_chirho(&metadata_chirho) != self.control_identity_chirho
        {
            bail!("ResidentWriterControlCustodyChangedChirho");
        }
        Ok(())
    }

    fn owner_uid_chirho(&self) -> u32 {
        self.root_chirho.owner_uid_chirho
    }
}

fn validate_canonical_display_path_chirho(path_chirho: &Path) -> Result<()> {
    if !path_chirho.is_absolute()
        || path_chirho.as_os_str().as_bytes().len() > MAX_CANONICAL_FILESYSTEM_PATH_BYTES_CHIRHO
        || path_chirho.components().any(|component_chirho| {
            matches!(component_chirho, Component::CurDir | Component::ParentDir)
        })
    {
        bail!("CanonicalFilesystemPathBoundsChirho");
    }
    Ok(())
}

fn directory_open_flags_chirho() -> OFlags {
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK
}

pub(crate) fn inspect_entry_at_chirho(
    parent_chirho: &File,
    name_chirho: &str,
) -> Result<Option<ResidentControlEntryInspectionChirho>> {
    let stat_chirho = match statat(parent_chirho, name_chirho, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat_chirho) => stat_chirho,
        Err(Errno::NOENT) => return Ok(None),
        Err(error_chirho) => return Err(io_error_from_errno_chirho(error_chirho).into()),
    };
    Ok(Some(ResidentControlEntryInspectionChirho {
        identity_chirho: ResidentControlFilesystemIdentityChirho {
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

pub(crate) fn inspect_open_file_chirho(
    file_chirho: &File,
    owner_uid_chirho: u32,
) -> Result<ResidentControlEntryInspectionChirho> {
    let metadata_chirho = file_chirho
        .metadata()
        .context("inspect opened descriptor-owned resident writer file")?;
    let inspection_chirho = ResidentControlEntryInspectionChirho {
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

pub(crate) fn verify_file_inspection_chirho(
    inspection_chirho: &ResidentControlEntryInspectionChirho,
    owner_uid_chirho: u32,
) -> Result<()> {
    if inspection_chirho.file_type_chirho != FileType::RegularFile
        || inspection_chirho.links_chirho != 1
        || inspection_chirho.owner_uid_chirho != owner_uid_chirho
        || inspection_chirho.mode_chirho & 0o022 != 0
    {
        bail!("ResidentWriterControlFileUnsafeChirho");
    }
    Ok(())
}

pub(crate) fn verify_directory_inspection_chirho(
    inspection_chirho: &ResidentControlEntryInspectionChirho,
    owner_uid_chirho: u32,
) -> Result<()> {
    if inspection_chirho.file_type_chirho != FileType::Directory
        || inspection_chirho.owner_uid_chirho != owner_uid_chirho
        || inspection_chirho.mode_chirho & 0o022 != 0
    {
        bail!("ResidentWriterControlDirectoryUnsafeChirho");
    }
    Ok(())
}

fn verify_directory_metadata_chirho(
    metadata_chirho: &std::fs::Metadata,
    owner_uid_chirho: u32,
) -> Result<()> {
    if !metadata_chirho.is_dir()
        || metadata_chirho.uid() != owner_uid_chirho
        || metadata_chirho.mode() & 0o022 != 0
    {
        bail!("ResidentWriterControlDirectoryUnsafeChirho");
    }
    Ok(())
}

pub(crate) fn identity_from_metadata_chirho(
    metadata_chirho: &std::fs::Metadata,
) -> ResidentControlFilesystemIdentityChirho {
    ResidentControlFilesystemIdentityChirho {
        device_chirho: metadata_chirho.dev(),
        inode_chirho: metadata_chirho.ino(),
    }
}

fn map_open_error_chirho(error_chirho: Errno) -> anyhow::Error {
    match error_chirho {
        Errno::LOOP => anyhow::anyhow!("ResidentWriterControlFileUnsafeChirho"),
        Errno::NOENT => anyhow::anyhow!("ResidentWriterReservationMissingChirho"),
        Errno::NOTDIR => anyhow::anyhow!("ResidentWriterControlDirectoryUnsafeChirho"),
        _ => io_error_from_errno_chirho(error_chirho).into(),
    }
}

pub(crate) fn io_error_from_errno_chirho(error_chirho: Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error_chirho.raw_os_error())
}

fn stable_u64_chirho<ValueChirho>(value_chirho: ValueChirho) -> Result<u64>
where
    ValueChirho: TryInto<u64>,
{
    value_chirho
        .try_into()
        .map_err(|_error_chirho| anyhow::anyhow!("ResidentWriterControlCustodyChangedChirho"))
}

fn stable_u32_chirho<ValueChirho>(value_chirho: ValueChirho) -> Result<u32>
where
    ValueChirho: TryInto<u32>,
{
    value_chirho
        .try_into()
        .map_err(|_error_chirho| anyhow::anyhow!("ResidentWriterControlCustodyChangedChirho"))
}
