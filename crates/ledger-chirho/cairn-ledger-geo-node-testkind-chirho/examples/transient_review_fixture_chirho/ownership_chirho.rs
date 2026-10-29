// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Exclusively creates the fixture and retains descriptor-relative tenant custody.

use anyhow::{bail, ensure, Result};
use rustix::fs::{mkdirat, open, openat, Mode, OFlags};
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

fn flags_chirho() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

pub(super) fn private_parent_chirho(path_chirho: &Path) -> Result<(File, PathBuf)> {
    ensure!(
        path_chirho.is_absolute()
            && path_chirho.components().all(|part_chirho| !matches!(
                part_chirho,
                Component::ParentDir | Component::CurDir
            )),
        "fixture path"
    );
    let parent_chirho = path_chirho
        .parent()
        .ok_or_else(|| anyhow::anyhow!("fixture parent"))?;
    let canonical_chirho = parent_chirho.canonicalize()?;
    ensure!(canonical_chirho == parent_chirho, "aliased fixture parent");
    let file_chirho = File::from(open(parent_chirho, flags_chirho(), Mode::empty())?);
    let meta_chirho = file_chirho.metadata()?;
    ensure!(
        meta_chirho.uid() == rustix::process::geteuid().as_raw() && meta_chirho.mode() & 0o077 == 0,
        "private fixture parent required"
    );
    Ok((file_chirho, canonical_chirho))
}

pub(super) fn absent_chirho(path_chirho: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path_chirho) {
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => bail!("fixture output exists or is unreadable"),
    }
}

pub(super) struct OwnedRootChirho {
    platform_chirho: File,
    tenant_chirho: File,
    tenant_id_chirho: String,
    public_chirho: PathBuf,
    public_tenant_chirho: PathBuf,
    _parent_chirho: File,
}

impl OwnedRootChirho {
    pub(super) fn create_chirho(path_chirho: &Path, tenant_chirho: &str) -> Result<Self> {
        ensure!(
            cairn_chirho::tenant_chirho::validate_tenant_id_chirho(tenant_chirho)? == tenant_chirho,
            "tenant id"
        );
        let (parent_chirho, _) = private_parent_chirho(path_chirho)?;
        let leaf_chirho = path_chirho
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("fixture leaf"))?;
        mkdirat(&parent_chirho, leaf_chirho, Mode::RWXU)?;
        let platform_chirho = File::from(openat(
            &parent_chirho,
            leaf_chirho,
            flags_chirho(),
            Mode::empty(),
        )?);
        for entry_chirho in rustix::fs::Dir::read_from(&platform_chirho)? {
            let entry_chirho = entry_chirho?;
            ensure!(
                matches!(entry_chirho.file_name().to_bytes(), b"." | b".."),
                "fixture birth is not empty"
            );
        }
        mkdirat(&platform_chirho, "tenants-chirho", Mode::RWXU)?;
        let tenants_chirho = File::from(openat(
            &platform_chirho,
            "tenants-chirho",
            flags_chirho(),
            Mode::empty(),
        )?);
        mkdirat(&tenants_chirho, tenant_chirho, Mode::RWXU)?;
        let tenant_file_chirho = File::from(openat(
            &tenants_chirho,
            tenant_chirho,
            flags_chirho(),
            Mode::empty(),
        )?);
        let owned_chirho = Self {
            platform_chirho,
            tenant_chirho: tenant_file_chirho,
            tenant_id_chirho: tenant_chirho.to_string(),
            public_chirho: path_chirho.to_path_buf(),
            public_tenant_chirho: path_chirho.join("tenants-chirho").join(tenant_chirho),
            _parent_chirho: parent_chirho,
        };
        owned_chirho.verify_chirho()?;
        Ok(owned_chirho)
    }

    fn verify_chirho(&self) -> Result<()> {
        for (file_chirho, path_chirho) in [
            (&self.platform_chirho, &self.public_chirho),
            (&self.tenant_chirho, &self.public_tenant_chirho),
        ] {
            let held_chirho = file_chirho.metadata()?;
            let named_chirho = std::fs::symlink_metadata(path_chirho)?;
            ensure!(
                named_chirho.is_dir()
                    && held_chirho.dev() == named_chirho.dev()
                    && held_chirho.ino() == named_chirho.ino(),
                "fixture root replaced"
            );
        }
        Ok(())
    }

    // This is a dedicated example PROCESS, never a library entry: cwd is retained inode custody
    // on macOS too, where /dev/fd/<directory>/child is not supported. No serving task exists yet.
    pub(super) fn activate_chirho(self) -> Result<ActiveRootChirho> {
        self.verify_chirho()?;
        let original_cwd_chirho = File::from(open(".", flags_chirho(), Mode::empty())?);
        let active_chirho = ActiveRootChirho {
            root_chirho: self,
            original_cwd_chirho,
            restored_chirho: false,
            runtime_active_chirho: AtomicBool::new(false),
        };
        rustix::process::fchdir(&active_chirho.root_chirho.platform_chirho)?;
        cairn_chirho::tenant_chirho::prepare_tenant_root_chirho(
            Path::new("."),
            &active_chirho.root_chirho.tenant_id_chirho,
        )?;
        rustix::process::fchdir(&active_chirho.root_chirho.tenant_chirho)?;
        active_chirho.verify_chirho()?;
        Ok(active_chirho)
    }
}

pub(super) struct ActiveRootChirho {
    root_chirho: OwnedRootChirho,
    original_cwd_chirho: File,
    restored_chirho: bool,
    runtime_active_chirho: AtomicBool,
}

struct RestoreCwdChirho<'a>(&'a File);

impl Drop for RestoreCwdChirho<'_> {
    fn drop(&mut self) {
        if rustix::process::fchdir(self.0).is_err() {
            eprintln!("TransientReviewCwdRestoreFailedChirho");
            std::process::exit(1);
        }
    }
}

impl Drop for ActiveRootChirho {
    fn drop(&mut self) {
        // An initialization/drain failure may leave blocking work alive. Never redirect its
        // relative I/O by restoring cwd; this dedicated child must die without success frames.
        if self.runtime_active_chirho.load(Ordering::Acquire) {
            eprintln!("TransientReviewBridgeRefusedChirho");
            std::process::exit(1);
        }
        if !self.restored_chirho && rustix::process::fchdir(&self.original_cwd_chirho).is_err() {
            eprintln!("TransientReviewCwdRestoreFailedChirho");
            std::process::exit(1);
        }
    }
}

impl ActiveRootChirho {
    pub(super) fn tenant_chirho(&self) -> PathBuf {
        PathBuf::from(".")
    }

    fn verify_chirho(&self) -> Result<()> {
        self.root_chirho.verify_chirho()?;
        let cwd_chirho = std::fs::metadata(".")?;
        let held_chirho = self.root_chirho.tenant_chirho.metadata()?;
        ensure!(
            cwd_chirho.dev() == held_chirho.dev() && cwd_chirho.ino() == held_chirho.ino(),
            "fixture cwd changed"
        );
        Ok(())
    }

    // Caller must be quiescent: before serve or after the execution-custody drain. The only
    // concurrent watcher uses an absolute outside-root stop path and never accesses cwd.
    pub(super) fn with_platform_chirho<T>(
        &self,
        operation_chirho: impl FnOnce(&Path) -> Result<T>,
    ) -> Result<T> {
        self.verify_chirho()?;
        rustix::process::fchdir(&self.root_chirho.platform_chirho)?;
        let restore_chirho = RestoreCwdChirho(&self.root_chirho.tenant_chirho);
        let result_chirho = operation_chirho(Path::new("."));
        drop(restore_chirho);
        self.verify_chirho()?;
        result_chirho
    }

    pub(super) fn plant_sentinel_chirho(&self) -> Result<()> {
        self.with_platform_chirho(|path_chirho| {
            std::fs::write(
                path_chirho.join(super::snapshot_chirho::SENTINEL_PATH_CHIRHO),
                super::snapshot_chirho::SENTINEL_CHIRHO,
            )?;
            Ok(())
        })
    }

    pub(super) fn latch_chirho(self) -> Result<LatchedRootChirho> {
        self.with_platform_chirho(|path_chirho| {
            std::fs::write(
                path_chirho.join("transient-component-fixture-chirho"),
                b"read-authority-test-double-chirho\n",
            )?;
            Ok(())
        })?;
        self.verify_chirho()?;
        cairn_writer_head_chirho::writer_head_chirho::issue_elected_writer_fence_for_root_chirho(
            Path::new("."),
            7,
        )?;
        self.verify_chirho()?;
        Ok(LatchedRootChirho(self))
    }
}

pub(super) struct LatchedRootChirho(ActiveRootChirho);

impl LatchedRootChirho {
    pub(super) fn begin_runtime_chirho(&self) {
        self.0.runtime_active_chirho.store(true, Ordering::Release);
    }

    pub(super) fn tenant_chirho(&self) -> PathBuf {
        self.0.tenant_chirho()
    }
    pub(super) fn verify_chirho(&self) -> Result<()> {
        self.0.verify_chirho()
    }
    pub(super) fn snapshot_chirho(&self) -> Result<super::snapshot_chirho::SnapshotChirho> {
        self.0
            .with_platform_chirho(super::snapshot_chirho::snapshot_chirho)
    }

    pub(super) fn finish_chirho(mut self) -> Result<()> {
        self.verify_chirho()?;
        self.0.runtime_active_chirho.store(false, Ordering::Release);
        rustix::process::fchdir(&self.0.original_cwd_chirho)?;
        self.0.restored_chirho = true;
        Ok(())
    }
}

pub(super) fn private_input_chirho(path_chirho: &Path, bound_chirho: u64) -> Result<Vec<u8>> {
    let meta_chirho = std::fs::symlink_metadata(path_chirho)?;
    ensure!(
        meta_chirho.uid() == rustix::process::geteuid().as_raw() && meta_chirho.mode() & 0o077 == 0,
        "private input required"
    );
    Ok(
        cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
            path_chirho,
            bound_chirho,
        )?,
    )
}

pub(super) fn session_output_chirho(path_chirho: &Path) -> Result<File> {
    let (parent_chirho, _) = private_parent_chirho(path_chirho)?;
    let leaf_chirho = path_chirho
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("session leaf"))?;
    let file_chirho = File::from(openat(
        &parent_chirho,
        leaf_chirho,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )?);
    Ok(file_chirho)
}

pub(super) fn write_session_chirho(mut file_chirho: File, cookie_chirho: &[u8]) -> Result<()> {
    file_chirho.write_all(cookie_chirho)?;
    file_chirho.sync_all()?;
    Ok(())
}
