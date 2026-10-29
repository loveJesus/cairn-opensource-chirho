// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Narrow authority port and dispatcher for positive-head transition COMMIT.

use crate::head_transition_chirho::{
    complete_head_transition_unlocked_chirho, preflight_head_transition_commit_chirho,
    preflight_prepared_fence_commit_chirho, HeadTransitionRecoveryOutcomeChirho,
    PreparedHeadTransitionChirho,
};
use crate::writer_head_chirho::{
    with_head_transition_scope_chirho, with_reused_or_issued_elected_writer_fence_chirho,
    writer_authority_era_chirho, ConsistencyGroupIdChirho, PreparedFenceLowerBoundChirho,
    WriterAuthorityEraChirho, WriterFenceTokenChirho,
};
use anyhow::{bail, Result};
use cairn_seqlog_chirho::seqlog_chirho;
use std::marker::PhantomData;
use std::path::Path;
use std::rc::Rc;

/// By-value, non-cloneable proof that the elected generation and local mutation locks are live.
pub struct HeadTransitionCommitScopeChirho<'scope_chirho> {
    append_capability_chirho: HeadTransitionAppendCapabilityChirho<'scope_chirho>,
    _thread_affinity_chirho: PhantomData<Rc<()>>,
}

struct HeadTransitionAppendCapabilityChirho<'scope_chirho> {
    writer_fence_chirho: &'scope_chirho WriterFenceTokenChirho,
}

impl HeadTransitionCommitScopeChirho<'_> {
    pub fn writer_fence_epoch_chirho(&self) -> u64 {
        self.append_capability_chirho
            .writer_fence_chirho
            .epoch_chirho
    }

    /// Bind recovery admission to the observed root and current fence, including no-op recovery.
    pub fn preflight_prepared_fence_chirho(
        &self,
        root_chirho: &Path,
        prepared_chirho: &PreparedFenceLowerBoundChirho,
    ) -> Result<()> {
        preflight_prepared_fence_commit_chirho(
            root_chirho,
            prepared_chirho,
            self.append_capability_chirho.writer_fence_chirho,
        )
    }

    /// Check the prepared root, group, lower-bound epoch, and current fence before the first write.
    pub fn preflight_head_transition_chirho(
        &self,
        root_chirho: &Path,
        prepared_chirho: &PreparedHeadTransitionChirho,
    ) -> Result<()> {
        preflight_head_transition_commit_chirho(
            root_chirho,
            prepared_chirho,
            self.append_capability_chirho.writer_fence_chirho,
        )
    }

    /// Consume the live append capability to publish one cell transition and its receipt.
    ///
    /// The positive control compiles with one completion:
    ///
    /// ```no_run
    /// use cairn_writer_head_chirho::head_transition_authority_chirho::HeadTransitionCommitScopeChirho;
    /// use cairn_writer_head_chirho::head_transition_chirho::PreparedHeadTransitionChirho;
    /// use std::path::Path;
    ///
    /// fn complete_once_chirho(
    ///     scope_chirho: HeadTransitionCommitScopeChirho<'_>,
    ///     root_chirho: &Path,
    ///     prepared_chirho: &PreparedHeadTransitionChirho,
    /// ) -> anyhow::Result<()> {
    ///     scope_chirho.complete_head_transition_chirho(root_chirho, prepared_chirho)?;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// A second completion fails only because the first consumes the scope:
    ///
    /// ```compile_fail,E0382
    /// use cairn_writer_head_chirho::head_transition_authority_chirho::HeadTransitionCommitScopeChirho;
    /// use cairn_writer_head_chirho::head_transition_chirho::PreparedHeadTransitionChirho;
    /// use std::path::Path;
    ///
    /// fn complete_twice_chirho(
    ///     scope_chirho: HeadTransitionCommitScopeChirho<'_>,
    ///     root_chirho: &Path,
    ///     prepared_chirho: &PreparedHeadTransitionChirho,
    /// ) {
    ///     let _first_chirho =
    ///         scope_chirho.complete_head_transition_chirho(root_chirho, prepared_chirho);
    ///     let _second_chirho =
    ///         scope_chirho.complete_head_transition_chirho(root_chirho, prepared_chirho);
    /// }
    /// ```
    pub fn complete_head_transition_chirho(
        self,
        root_chirho: &Path,
        prepared_chirho: &PreparedHeadTransitionChirho,
    ) -> Result<HeadTransitionRecoveryOutcomeChirho> {
        complete_head_transition_unlocked_chirho(
            root_chirho,
            prepared_chirho,
            self.append_capability_chirho.writer_fence_chirho,
        )
    }
}

/// Host-owned elected-authority bridge. The app/runtime side can consume but cannot mint a scope.
pub trait HeadTransitionAuthorityPortChirho {
    fn with_elected_head_transition_scope_chirho(
        &self,
        root_chirho: &Path,
        action_chirho: &mut dyn HeadTransitionCommitActionChirho,
    ) -> Result<()>;
}

/// Object-safe callback whose only input is one host-minted, lifetime-bound COMMIT scope.
pub trait HeadTransitionCommitActionChirho {
    fn call_chirho(&mut self, scope_chirho: HeadTransitionCommitScopeChirho<'_>) -> Result<()>;
}

pub struct ElectedHeadTransitionScopeOutcomeChirho<ValueChirho> {
    observed_fence_chirho: Option<WriterFenceTokenChirho>,
    result_chirho: Result<ValueChirho>,
}

impl<ValueChirho> ElectedHeadTransitionScopeOutcomeChirho<ValueChirho> {
    pub fn observed_fence_chirho(&self) -> Option<&WriterFenceTokenChirho> {
        self.observed_fence_chirho.as_ref()
    }

    pub fn into_result_chirho(self) -> Result<ValueChirho> {
        self.result_chirho
    }
}

/// Compose an elected writer fence with the append lock and expose one affine COMMIT scope.
///
/// The observed token is retained even when the caller's operation refuses, allowing the host
/// adapter to cache a durably issued token without treating operation success as fence authority.
pub fn with_elected_head_transition_scope_chirho<ValueChirho, ActionChirho>(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
    geo_term_chirho: u64,
    current_token_chirho: Option<&WriterFenceTokenChirho>,
    action_chirho: ActionChirho,
) -> ElectedHeadTransitionScopeOutcomeChirho<ValueChirho>
where
    ActionChirho: for<'scope_chirho> FnOnce(
        HeadTransitionCommitScopeChirho<'scope_chirho>,
    ) -> Result<ValueChirho>,
{
    let mut observed_fence_chirho = None;
    let mut action_chirho = Some(action_chirho);
    let mut action_result_chirho = None;
    let fence_result_chirho = with_reused_or_issued_elected_writer_fence_chirho(
        root_chirho,
        group_chirho,
        geo_term_chirho,
        current_token_chirho,
        |writer_fence_chirho| {
            observed_fence_chirho = Some(writer_fence_chirho.clone());
            seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
                let action_chirho = action_chirho.take().ok_or_else(|| {
                    anyhow::anyhow!("ElectedHeadTransitionCallbackRepeatedChirho")
                })?;
                action_result_chirho = Some(action_chirho(HeadTransitionCommitScopeChirho {
                    append_capability_chirho: HeadTransitionAppendCapabilityChirho {
                        writer_fence_chirho,
                    },
                    _thread_affinity_chirho: PhantomData,
                }));
                Ok(())
            })
        },
    );
    let result_chirho = match fence_result_chirho {
        Err(error_chirho) => Err(error_chirho),
        Ok((_writer_fence_chirho, ())) => action_result_chirho.unwrap_or_else(|| {
            Err(anyhow::anyhow!(
                "ElectedHeadTransitionCallbackMissingChirho"
            ))
        }),
    };
    ElectedHeadTransitionScopeOutcomeChirho {
        observed_fence_chirho,
        result_chirho,
    }
}

/// Route a transition through the byte-identical local path or split elected PREPARE/COMMIT path.
pub fn dispatch_head_transition_chirho<
    ValueChirho,
    PreparedChirho,
    LocalActionChirho,
    PrepareElectedChirho,
    CommitElectedChirho,
>(
    root_chirho: &Path,
    elected_port_chirho: Option<&dyn HeadTransitionAuthorityPortChirho>,
    local_action_chirho: LocalActionChirho,
    prepare_elected_chirho: PrepareElectedChirho,
    commit_elected_chirho: CommitElectedChirho,
) -> Result<ValueChirho>
where
    LocalActionChirho: FnOnce(&WriterFenceTokenChirho) -> Result<ValueChirho>,
    PrepareElectedChirho: FnOnce() -> Result<PreparedChirho>,
    CommitElectedChirho: for<'scope_chirho> FnOnce(
        PreparedChirho,
        HeadTransitionCommitScopeChirho<'scope_chirho>,
    ) -> Result<ValueChirho>,
{
    match writer_authority_era_chirho(root_chirho)? {
        WriterAuthorityEraChirho::LocalChirho => {
            with_head_transition_scope_chirho(root_chirho, local_action_chirho)
        }
        WriterAuthorityEraChirho::ElectedChirho => {
            let port_chirho = elected_port_chirho
                .ok_or_else(|| anyhow::anyhow!("ElectedAuthorityRequiredChirho"))?;
            let prepared_chirho = prepare_elected_chirho()?;
            invoke_elected_port_once_chirho(port_chirho, root_chirho, move |scope_chirho| {
                commit_elected_chirho(prepared_chirho, scope_chirho)
            })
        }
    }
}

fn invoke_elected_port_once_chirho<ValueChirho, ActionChirho>(
    port_chirho: &dyn HeadTransitionAuthorityPortChirho,
    root_chirho: &Path,
    action_chirho: ActionChirho,
) -> Result<ValueChirho>
where
    ActionChirho: for<'scope_chirho> FnOnce(
        HeadTransitionCommitScopeChirho<'scope_chirho>,
    ) -> Result<ValueChirho>,
{
    struct BridgeChirho<ActionChirho, ValueChirho> {
        action_chirho: Option<ActionChirho>,
        result_chirho: Option<Result<ValueChirho>>,
        invocation_count_chirho: u8,
    }

    impl<ActionChirho, ValueChirho> HeadTransitionCommitActionChirho
        for BridgeChirho<ActionChirho, ValueChirho>
    where
        ActionChirho: for<'scope_chirho> FnOnce(
            HeadTransitionCommitScopeChirho<'scope_chirho>,
        ) -> Result<ValueChirho>,
    {
        fn call_chirho(&mut self, scope_chirho: HeadTransitionCommitScopeChirho<'_>) -> Result<()> {
            self.invocation_count_chirho = self.invocation_count_chirho.saturating_add(1);
            let action_chirho = self
                .action_chirho
                .take()
                .ok_or_else(|| anyhow::anyhow!("ElectedAuthorityCallbackRepeatedChirho"))?;
            self.result_chirho = Some(action_chirho(scope_chirho));
            Ok(())
        }
    }

    let mut bridge_chirho = BridgeChirho {
        action_chirho: Some(action_chirho),
        result_chirho: None,
        invocation_count_chirho: 0,
    };
    port_chirho.with_elected_head_transition_scope_chirho(root_chirho, &mut bridge_chirho)?;
    if bridge_chirho.invocation_count_chirho == 0 {
        bail!("ElectedAuthorityCallbackMissingChirho");
    }
    if bridge_chirho.invocation_count_chirho != 1 {
        bail!("ElectedAuthorityCallbackRepeatedChirho");
    }
    bridge_chirho
        .result_chirho
        .ok_or_else(|| anyhow::anyhow!("ElectedAuthorityCallbackMissingChirho"))?
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::writer_head_chirho::consistency_group_for_root_chirho;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    pub(super) fn temp_root_chirho(label_chirho: &str) -> std::path::PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        let root_chirho = std::env::temp_dir().join(format!(
            "cairn-head-transition-authority-{label_chirho}-{nanos_chirho}-{counter_chirho}"
        ));
        std::fs::create_dir_all(&root_chirho).expect("create authority test root");
        root_chirho
    }

    struct MissingCallbackPortChirho;

    impl HeadTransitionAuthorityPortChirho for MissingCallbackPortChirho {
        fn with_elected_head_transition_scope_chirho(
            &self,
            _root_chirho: &Path,
            _action_chirho: &mut dyn HeadTransitionCommitActionChirho,
        ) -> Result<()> {
            Ok(())
        }
    }

    struct RepeatedCallbackPortChirho {
        group_chirho: ConsistencyGroupIdChirho,
    }

    impl HeadTransitionAuthorityPortChirho for RepeatedCallbackPortChirho {
        fn with_elected_head_transition_scope_chirho(
            &self,
            root_chirho: &Path,
            action_chirho: &mut dyn HeadTransitionCommitActionChirho,
        ) -> Result<()> {
            with_elected_head_transition_scope_chirho(
                root_chirho,
                &self.group_chirho,
                7,
                None,
                |scope_chirho| action_chirho.call_chirho(scope_chirho),
            )
            .into_result_chirho()?;
            let second_chirho = with_elected_head_transition_scope_chirho(
                root_chirho,
                &self.group_chirho,
                7,
                None,
                |scope_chirho| action_chirho.call_chirho(scope_chirho),
            );
            assert!(
                second_chirho.into_result_chirho().is_err(),
                "the planted second callback must reach the bridge and be refused"
            );
            Ok(())
        }
    }

    #[test]
    fn dispatcher_named_refuses_a_missing_elected_callback_chirho() {
        let root_chirho = temp_root_chirho("missing");
        let error_chirho = invoke_elected_port_once_chirho(
            &MissingCallbackPortChirho,
            &root_chirho,
            |_scope_chirho| Ok(()),
        )
        .expect_err("a port that returns without a callback must refuse");

        assert_eq!(
            error_chirho.to_string(),
            "ElectedAuthorityCallbackMissingChirho"
        );
        assert_ne!(
            error_chirho.to_string(),
            "ElectedAuthorityCallbackRepeatedChirho"
        );
        std::fs::remove_dir_all(root_chirho).expect("remove authority test root");
    }

    #[test]
    fn dispatcher_named_refuses_a_repeated_elected_callback_chirho() {
        let root_chirho = temp_root_chirho("repeated");
        let port_chirho = RepeatedCallbackPortChirho {
            group_chirho: consistency_group_for_root_chirho(&root_chirho)
                .expect("derive authority test group"),
        };
        let error_chirho =
            invoke_elected_port_once_chirho(&port_chirho, &root_chirho, |_scope_chirho| Ok(()))
                .expect_err("a port that invokes twice must refuse");

        assert_eq!(
            error_chirho.to_string(),
            "ElectedAuthorityCallbackRepeatedChirho"
        );
        assert_ne!(
            error_chirho.to_string(),
            "ElectedAuthorityCallbackMissingChirho"
        );
        std::fs::remove_dir_all(root_chirho).expect("remove authority test root");
    }

    #[test]
    fn issued_fence_survives_an_operation_refusal_for_host_caching_chirho() {
        let root_chirho = temp_root_chirho("cache-on-refusal");
        let group_chirho =
            consistency_group_for_root_chirho(&root_chirho).expect("derive authority test group");
        let outcome_chirho: ElectedHeadTransitionScopeOutcomeChirho<()> =
            with_elected_head_transition_scope_chirho(
                &root_chirho,
                &group_chirho,
                11,
                None,
                |_scope_chirho| Err(anyhow::anyhow!("PlantedOperationRefusalChirho")),
            );

        assert!(
            outcome_chirho.observed_fence_chirho().is_some(),
            "a successfully issued fence must remain available when only the operation refuses"
        );
        assert_eq!(
            outcome_chirho
                .into_result_chirho()
                .expect_err("the planted operation refusal must survive")
                .to_string(),
            "PlantedOperationRefusalChirho"
        );
        std::fs::remove_dir_all(root_chirho).expect("remove authority test root");
    }
}

#[cfg(test)]
#[path = "head_transition_authority_chirho/prepared_fence_tests_chirho.rs"]
mod prepared_fence_tests_chirho;
