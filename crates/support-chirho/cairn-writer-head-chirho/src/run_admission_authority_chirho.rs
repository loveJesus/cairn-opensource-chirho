// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Elected request-storage and pending-intent COMMIT, without holding the append lock.
//! Workflow: spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/run-admission-chirho/workflow-chirho.md.
//! Held-lease amendment: spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/run-admission-chirho/held-lease-chirho/workflow-chirho.md.

use crate::writer_head_chirho::{
    consistency_group_for_root_chirho, verify_writer_fence_for_root_chirho,
    with_reused_or_issued_elected_writer_fence_chirho, writer_authority_era_chirho,
    ConsistencyGroupIdChirho, WriterAuthorityEraChirho, WriterFenceTokenChirho,
};
use anyhow::{bail, Result};
use std::marker::PhantomData;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

/// Borrowed proof of one root's held fence. The host must retain its leadership generation too.
/// It is neither cloneable nor Send, and cannot outlive the host callback.
/// The host's borrowed validator rechecks that held generation's elapsed lease at each sink.
///
/// ```compile_fail,E0277
/// use cairn_writer_head_chirho::run_admission_authority_chirho::RunAdmissionCommitScopeChirho;
/// fn requires_send_chirho<ValueChirho: Send>(_value_chirho: ValueChirho) {}
/// fn transfer_chirho(scope_chirho: RunAdmissionCommitScopeChirho<'_>) {
///     requires_send_chirho(scope_chirho);
/// }
/// ```
///
/// ```compile_fail,E0599
/// use cairn_writer_head_chirho::run_admission_authority_chirho::RunAdmissionCommitScopeChirho;
/// fn duplicate_chirho(scope_chirho: RunAdmissionCommitScopeChirho<'_>) {
///     let _copy_chirho = scope_chirho.clone();
/// }
/// ```
pub struct RunAdmissionCommitScopeChirho<'scope_chirho> {
    canonical_root_chirho: PathBuf,
    root_device_chirho: u64,
    root_inode_chirho: u64,
    fence_chirho: &'scope_chirho WriterFenceTokenChirho,
    validate_authority_chirho: &'scope_chirho dyn Fn() -> Result<()>,
    _thread_affinity_chirho: PhantomData<Rc<()>>,
}

impl RunAdmissionCommitScopeChirho<'_> {
    /// Revalidate at each durable sink, not merely at request preparation.
    pub fn validate_sink_chirho(&self, root_chirho: &Path) -> Result<()> {
        let canonical_root_chirho = root_chirho.canonicalize()?;
        let metadata_chirho = std::fs::metadata(&canonical_root_chirho)?;
        if canonical_root_chirho != self.canonical_root_chirho
            || metadata_chirho.dev() != self.root_device_chirho
            || metadata_chirho.ino() != self.root_inode_chirho
        {
            bail!("RunAdmissionWrongRootChirho");
        }
        if consistency_group_for_root_chirho(root_chirho)? != self.fence_chirho.group_chirho {
            bail!("RunAdmissionWrongGroupChirho");
        }
        verify_writer_fence_for_root_chirho(root_chirho, self.fence_chirho)?;
        // Check time last: root and fence I/O may itself have consumed the remaining lease.
        (self.validate_authority_chirho)()
    }
}

pub trait RunAdmissionCommitActionChirho {
    fn call_chirho(&mut self, scope_chirho: RunAdmissionCommitScopeChirho<'_>) -> Result<()>;
}

/// Only the host joins this port to live election authority. No relay envelope supplies it.
pub trait RunAdmissionAuthorityPortChirho {
    fn with_elected_run_admission_scope_chirho(
        &self,
        root_chirho: &Path,
        action_chirho: &mut dyn RunAdmissionCommitActionChirho,
    ) -> Result<()>;
}

pub struct RunAdmissionScopeOutcomeChirho<ValueChirho> {
    observed_fence_chirho: Option<WriterFenceTokenChirho>,
    result_chirho: Result<ValueChirho>,
}

impl<ValueChirho> RunAdmissionScopeOutcomeChirho<ValueChirho> {
    pub fn observed_fence_chirho(&self) -> Option<&WriterFenceTokenChirho> {
        self.observed_fence_chirho.as_ref()
    }

    pub fn into_result_chirho(self) -> Result<ValueChirho> {
        self.result_chirho
    }
}

/// Host bridge only: hold the generation before entering, and retain it until this returns.
/// Unlike head-transition COMMIT, this does not take append-log; the storage sinks own that lock.
pub fn with_elected_run_admission_scope_chirho<ValueChirho, ActionChirho>(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
    geo_term_chirho: u64,
    current_fence_chirho: Option<&WriterFenceTokenChirho>,
    validate_authority_chirho: &dyn Fn() -> Result<()>,
    action_chirho: ActionChirho,
) -> RunAdmissionScopeOutcomeChirho<ValueChirho>
where
    ActionChirho: for<'scope_chirho> FnOnce(
        RunAdmissionCommitScopeChirho<'scope_chirho>,
    ) -> Result<ValueChirho>,
{
    let mut observed_fence_chirho = None;
    let mut action_result_chirho = None;
    let result_chirho = (|| {
        if writer_authority_era_chirho(root_chirho)? != WriterAuthorityEraChirho::ElectedChirho {
            bail!("RunAdmissionElectedEraRequiredChirho");
        }
        validate_authority_chirho()?;
        with_reused_or_issued_elected_writer_fence_chirho(
            root_chirho,
            group_chirho,
            geo_term_chirho,
            current_fence_chirho,
            |fence_chirho| {
                observed_fence_chirho = Some(fence_chirho.clone());
                let canonical_root_chirho = root_chirho.canonicalize()?;
                let metadata_chirho = std::fs::metadata(&canonical_root_chirho)?;
                let scope_chirho = RunAdmissionCommitScopeChirho {
                    canonical_root_chirho,
                    root_device_chirho: metadata_chirho.dev(),
                    root_inode_chirho: metadata_chirho.ino(),
                    fence_chirho,
                    validate_authority_chirho,
                    _thread_affinity_chirho: PhantomData,
                };
                scope_chirho.validate_sink_chirho(root_chirho)?;
                action_result_chirho = Some(action_chirho(scope_chirho));
                Ok(())
            },
        )?;
        action_result_chirho
            .take()
            .ok_or_else(|| anyhow::anyhow!("RunAdmissionCallbackMissingChirho"))?
    })();
    RunAdmissionScopeOutcomeChirho {
        observed_fence_chirho,
        result_chirho,
    }
}

#[cfg(test)]
#[path = "run_admission_authority_chirho/tests_chirho.rs"]
mod tests_chirho;
