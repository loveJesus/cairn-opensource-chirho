// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use anyhow::{bail, Result};
use cairn_durable_chirho::cas_lifecycle_chirho::migrate_cas_lifecycle_offline_chirho;
use cairn_writer_head_chirho::{
    head_transition_authority_chirho::{
        with_elected_head_transition_scope_chirho, HeadTransitionAuthorityPortChirho,
        HeadTransitionCommitActionChirho,
    },
    writer_head_chirho::{
        consistency_group_for_root_chirho, issue_elected_writer_fence_for_root_chirho,
        ConsistencyGroupIdChirho,
    },
};
use std::{
    cell::Cell,
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub(crate) struct ControlAuthorityChirho {
    group_chirho: ConsistencyGroupIdChirho,
    pub(crate) refuse_chirho: bool,
    pub(crate) before_chirho: Option<fn(&Path) -> Result<()>>,
    pub(crate) called_chirho: Cell<bool>,
}

impl ControlAuthorityChirho {
    pub(crate) fn new_chirho(root_chirho: &Path) -> Self {
        migrate_cas_lifecycle_offline_chirho(root_chirho).unwrap();
        issue_elected_writer_fence_for_root_chirho(root_chirho, 1).unwrap();
        let mut authority_chirho = Self::refusing_chirho(root_chirho);
        authority_chirho.refuse_chirho = false;
        authority_chirho
    }

    pub(crate) fn refusing_chirho(root_chirho: &Path) -> Self {
        Self {
            group_chirho: consistency_group_for_root_chirho(root_chirho).unwrap(),
            refuse_chirho: true,
            before_chirho: None,
            called_chirho: Cell::new(false),
        }
    }
}

impl HeadTransitionAuthorityPortChirho for ControlAuthorityChirho {
    fn with_elected_head_transition_scope_chirho(
        &self,
        root_chirho: &Path,
        action_chirho: &mut dyn HeadTransitionCommitActionChirho,
    ) -> Result<()> {
        self.called_chirho.set(true);
        if self.refuse_chirho {
            bail!("ElectedAuthorityDeposedChirho");
        }
        if let Some(before_chirho) = self.before_chirho {
            before_chirho(root_chirho)?;
        }
        with_elected_head_transition_scope_chirho(
            root_chirho,
            &self.group_chirho,
            2,
            None,
            |scope_chirho| action_chirho.call_chirho(scope_chirho),
        )
        .into_result_chirho()
    }
}

pub(crate) fn snapshot_chirho(root_chirho: &Path) -> BTreeMap<PathBuf, blake3::Hash> {
    fn walk_chirho(
        root_chirho: &Path,
        current_chirho: &Path,
        out_chirho: &mut BTreeMap<PathBuf, blake3::Hash>,
    ) {
        for entry_chirho in std::fs::read_dir(current_chirho).unwrap() {
            let path_chirho = entry_chirho.unwrap().path();
            if path_chirho.is_dir() {
                walk_chirho(root_chirho, &path_chirho, out_chirho);
            } else {
                out_chirho.insert(
                    path_chirho.strip_prefix(root_chirho).unwrap().to_owned(),
                    blake3::hash(&std::fs::read(path_chirho).unwrap()),
                );
            }
        }
    }
    let mut out_chirho = BTreeMap::new();
    walk_chirho(root_chirho, root_chirho, &mut out_chirho);
    out_chirho
}

pub(crate) fn rewrite_refs_chirho(root_chirho: &Path) -> Result<()> {
    use std::io::Write;
    let path_chirho = root_chirho.join("refs-chirho.json");
    std::fs::OpenOptions::new()
        .append(true)
        .open(path_chirho)?
        .write_all(b" ")?;
    Ok(())
}

pub(crate) fn rebind_root_chirho(root_chirho: &Path) -> Result<()> {
    fn copy_chirho(source_chirho: &Path, target_chirho: &Path) -> Result<()> {
        std::fs::create_dir(target_chirho)?;
        for entry_chirho in std::fs::read_dir(source_chirho)? {
            let entry_chirho = entry_chirho?;
            let path_chirho = target_chirho.join(entry_chirho.file_name());
            if entry_chirho.file_type()?.is_dir() {
                copy_chirho(&entry_chirho.path(), &path_chirho)?;
            } else {
                std::fs::copy(entry_chirho.path(), path_chirho)?;
            }
        }
        Ok(())
    }
    let held_chirho = root_chirho.with_extension("held-chirho");
    if held_chirho.try_exists()? {
        bail!("control fixture held path already exists");
    }
    std::fs::rename(root_chirho, &held_chirho)?;
    copy_chirho(&held_chirho, root_chirho)
}
