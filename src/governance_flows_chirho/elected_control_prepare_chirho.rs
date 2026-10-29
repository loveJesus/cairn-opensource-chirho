// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Shared read-only preparation checks for elected onboarding and agent-authority head commits.
//! Workflow: spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/elected-control-chirho/workflow-chirho.md.

use anyhow::{bail, Context, Result};
use cairn_durable_chirho::cas_lifecycle_chirho::{
    CasLifecycleRootChirho, CasLifecycleSharedGuardChirho, CasLifecycleSnapshotChirho,
};
use cairn_signer_chirho::signer_chirho;
use std::fs::{File, Metadata};
use std::io::{ErrorKind, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[cfg(test)]
#[path = "elected_control_prepare_chirho/test_support_chirho.rs"]
pub(crate) mod test_support_chirho;

pub(crate) struct PreparedControlInputsChirho {
    paths_chirho: Vec<&'static str>,
    files_chirho: Vec<Option<ControlFileChirho>>,
    key_id_chirho: String,
    lifecycle_chirho: CasLifecycleRootChirho,
    generation_chirho: CasLifecycleSnapshotChirho,
}

#[derive(PartialEq, Eq)]
struct ControlFileChirho {
    device_chirho: u64,
    inode_chirho: u64,
    length_chirho: u64,
    seconds_chirho: i64,
    nanos_chirho: i64,
    digest_chirho: blake3::Hash,
}

impl PreparedControlInputsChirho {
    pub(crate) fn capture_chirho(
        root_chirho: &Path,
        paths_chirho: &[&'static str],
    ) -> Result<Self> {
        let key_id_chirho = signer_chirho::existing_keypair_pubkey_hex_chirho(root_chirho)
            .context("ElectedControlExistingSignerUnavailableChirho")?;
        let lifecycle_chirho =
            CasLifecycleRootChirho::open_chirho(root_chirho).map_err(anyhow::Error::new)?;
        let generation_chirho = lifecycle_chirho
            .snapshot_chirho()
            .map_err(anyhow::Error::new)?;
        let files_chirho = capture_files_chirho(root_chirho, paths_chirho)?;
        Ok(Self {
            paths_chirho: paths_chirho.to_vec(),
            files_chirho,
            key_id_chirho,
            lifecycle_chirho,
            generation_chirho,
        })
    }

    pub(crate) fn validate_chirho(&self, root_chirho: &Path) -> Result<()> {
        if signer_chirho::existing_keypair_pubkey_hex_chirho(root_chirho)
            .context("ElectedControlExistingSignerUnavailableChirho")?
            != self.key_id_chirho
        {
            bail!("ElectedControlPreparedSignerChangedChirho");
        }
        if capture_files_chirho(root_chirho, &self.paths_chirho)? != self.files_chirho {
            bail!("ElectedControlPreparedStateChangedChirho");
        }
        Ok(())
    }

    pub(crate) fn hold_for_commit_chirho(
        &self,
        root_chirho: &Path,
    ) -> Result<CasLifecycleSharedGuardChirho> {
        self.validate_chirho(root_chirho)?;
        self.lifecycle_chirho
            .promote_chirho(self.generation_chirho.clone())
            .map_err(anyhow::Error::new)
    }
}

fn same_identity_chirho(left_chirho: &Metadata, right_chirho: &Metadata) -> bool {
    left_chirho.dev() == right_chirho.dev()
        && left_chirho.ino() == right_chirho.ino()
        && left_chirho.len() == right_chirho.len()
        && left_chirho.mtime() == right_chirho.mtime()
        && left_chirho.mtime_nsec() == right_chirho.mtime_nsec()
}

fn capture_files_chirho(
    root_chirho: &Path,
    paths_chirho: &[&str],
) -> Result<Vec<Option<ControlFileChirho>>> {
    paths_chirho
        .iter()
        .map(|name_chirho| {
            let path_chirho = root_chirho.join(name_chirho);
            let before_chirho = match std::fs::symlink_metadata(&path_chirho) {
                Ok(metadata_chirho) => metadata_chirho,
                Err(error_chirho) if error_chirho.kind() == ErrorKind::NotFound => return Ok(None),
                Err(error_chirho) => {
                    return Err(error_chirho).context("ElectedControlInputUnavailableChirho")
                }
            };
            if !before_chirho.file_type().is_file() {
                bail!("ElectedControlInputNotRegularChirho");
            }
            let mut file_chirho =
                File::open(&path_chirho).context("ElectedControlInputUnavailableChirho")?;
            let opened_chirho = file_chirho.metadata()?;
            if !same_identity_chirho(&before_chirho, &opened_chirho) {
                bail!("ElectedControlInputReboundChirho");
            }
            // These are cold operator paths, already verifying their whole signed family history.
            // Stream the byte witness so PREPARE cannot consume memory proportional to that history.
            let mut hash_chirho = blake3::Hasher::new();
            let mut buffer_chirho = [0_u8; 8192];
            loop {
                let read_chirho = file_chirho.read(&mut buffer_chirho)?;
                if read_chirho == 0 {
                    break;
                }
                hash_chirho.update(&buffer_chirho[..read_chirho]);
            }
            let after_chirho = file_chirho.metadata()?;
            let path_after_chirho = std::fs::symlink_metadata(&path_chirho)?;
            if !path_after_chirho.file_type().is_file()
                || !same_identity_chirho(&opened_chirho, &after_chirho)
                || !same_identity_chirho(&after_chirho, &path_after_chirho)
            {
                bail!("ElectedControlInputChangedDuringReadChirho");
            }
            Ok(Some(ControlFileChirho {
                device_chirho: after_chirho.dev(),
                inode_chirho: after_chirho.ino(),
                length_chirho: after_chirho.len(),
                seconds_chirho: after_chirho.mtime(),
                nanos_chirho: after_chirho.mtime_nsec(),
                digest_chirho: hash_chirho.finalize(),
            }))
        })
        .collect()
}
