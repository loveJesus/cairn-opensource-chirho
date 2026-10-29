// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Request-admission authority on the same root-bound elector and fence cache as head transitions.
//! Workflow: spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/run-admission-chirho/workflow-chirho.md.
//! Held-lease amendment: spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/run-admission-chirho/held-lease-chirho/workflow-chirho.md.

use super::*;
use cairn_writer_head_chirho::run_admission_authority_chirho::{
    with_elected_run_admission_scope_chirho, RunAdmissionAuthorityPortChirho,
    RunAdmissionCommitActionChirho,
};

impl RunAdmissionAuthorityPortChirho for ElectedHeadTransitionAdapterChirho {
    fn with_elected_run_admission_scope_chirho(
        &self,
        root_chirho: &Path,
        action_chirho: &mut dyn RunAdmissionCommitActionChirho,
    ) -> Result<()> {
        self.validate_call_binding_chirho(root_chirho)?;
        let mut active_fence_chirho = match self.active_fence_chirho.try_lock() {
            Ok(active_fence_chirho) => active_fence_chirho,
            Err(TryLockError::WouldBlock) => {
                return Err(ElectedHeadTransitionRefusalChirho::AuthorityBusyChirho.into())
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(ElectedHeadTransitionRefusalChirho::AuthorityPoisonedChirho.into())
            }
        };
        let generation_guard_chirho = self
            .authority_handle_chirho
            .try_acquire_chirho()
            .map_err(map_local_refusal_chirho)?;
        let published_term_chirho = generation_guard_chirho.published_raft_term_chirho();
        let validate_authority_chirho = || -> Result<()> {
            generation_guard_chirho
                .validate_current_chirho()
                .map_err(map_local_refusal_chirho)?;
            Ok(())
        };
        let outcome_chirho = with_elected_run_admission_scope_chirho(
            &self.canonical_root_chirho,
            &self.group_chirho,
            published_term_chirho,
            active_fence_chirho.as_ref(),
            &validate_authority_chirho,
            |scope_chirho| {
                self.validate_call_binding_chirho(root_chirho)?;
                action_chirho.call_chirho(scope_chirho)
            },
        );
        if let Some(observed_fence_chirho) = outcome_chirho.observed_fence_chirho() {
            *active_fence_chirho = Some(observed_fence_chirho.clone());
        }
        outcome_chirho.into_result_chirho()
    }
}

#[cfg(test)]
#[path = "run_admission_chirho/tests_chirho.rs"]
mod tests_chirho;

#[cfg(test)]
#[path = "run_admission_chirho/lease_tests_chirho.rs"]
mod lease_tests_chirho;
