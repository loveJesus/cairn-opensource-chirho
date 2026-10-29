// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Production host adapter from local Raft authority to the writer-head elected COMMIT scope.

use anyhow::Result;
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::{
    LocalAppendAuthorityHandleChirho, LocalAppendAuthorityRefusalChirho,
};
use cairn_writer_head_chirho::head_transition_authority_chirho::{
    with_elected_head_transition_scope_chirho, HeadTransitionAuthorityPortChirho,
    HeadTransitionCommitActionChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_for_root_chirho, split_writer_epoch_chirho, ConsistencyGroupIdChirho,
    WriterFenceTokenChirho,
};
use std::error::Error;
use std::fmt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, TryLockError};

mod run_admission_chirho;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants carry the Chirho suffix"
)]
pub enum ElectedHeadTransitionRefusalChirho {
    WrongRootChirho,
    WrongGroupChirho,
    WrongNodeChirho,
    DeposedChirho,
    LeaseExpiredChirho,
    AuthorityUnavailableChirho,
    AuthorityBusyChirho,
    AuthorityPoisonedChirho,
    FenceTermMismatchChirho,
}

impl fmt::Display for ElectedHeadTransitionRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(match self {
            Self::WrongRootChirho => "ElectedAuthorityWrongRootChirho",
            Self::WrongGroupChirho => "ElectedAuthorityWrongGroupChirho",
            Self::WrongNodeChirho => "ElectedAuthorityWrongNodeChirho",
            Self::DeposedChirho => "ElectedAuthorityDeposedChirho",
            Self::LeaseExpiredChirho => "ElectedAuthorityLeaseExpiredChirho",
            Self::AuthorityUnavailableChirho => "ElectedAuthorityUnavailableChirho",
            Self::AuthorityBusyChirho => "ElectedAuthorityBusyChirho",
            Self::AuthorityPoisonedChirho => "ElectedAuthorityPoisonedChirho",
            Self::FenceTermMismatchChirho => "ElectedAuthorityFenceTermMismatchChirho",
        })
    }
}

impl Error for ElectedHeadTransitionRefusalChirho {}

/// One root-bound adapter backed by the exact local append-authority handle of a live elector.
pub struct ElectedHeadTransitionAdapterChirho {
    canonical_root_chirho: PathBuf,
    root_device_chirho: u64,
    root_inode_chirho: u64,
    group_chirho: ConsistencyGroupIdChirho,
    node_chirho: NodeIdChirho,
    authority_handle_chirho: LocalAppendAuthorityHandleChirho,
    active_fence_chirho: Mutex<Option<WriterFenceTokenChirho>>,
}

impl ElectedHeadTransitionAdapterChirho {
    pub fn new_chirho(
        root_chirho: &Path,
        authority_handle_chirho: LocalAppendAuthorityHandleChirho,
    ) -> Result<Self> {
        let canonical_root_chirho = root_chirho.canonicalize()?;
        let metadata_chirho = std::fs::metadata(&canonical_root_chirho)?;
        let group_chirho = consistency_group_for_root_chirho(&canonical_root_chirho)?;
        if authority_handle_chirho.consistency_group_chirho() != &group_chirho {
            return Err(ElectedHeadTransitionRefusalChirho::WrongGroupChirho.into());
        }
        let node_chirho = authority_handle_chirho.node_id_chirho().clone();
        Ok(Self {
            canonical_root_chirho,
            root_device_chirho: metadata_chirho.dev(),
            root_inode_chirho: metadata_chirho.ino(),
            group_chirho,
            node_chirho,
            authority_handle_chirho,
            active_fence_chirho: Mutex::new(None),
        })
    }

    fn validate_call_binding_chirho(&self, root_chirho: &Path) -> Result<()> {
        let canonical_root_chirho = root_chirho
            .canonicalize()
            .map_err(|_| ElectedHeadTransitionRefusalChirho::WrongRootChirho)?;
        let metadata_chirho = std::fs::metadata(&canonical_root_chirho)
            .map_err(|_| ElectedHeadTransitionRefusalChirho::WrongRootChirho)?;
        if canonical_root_chirho != self.canonical_root_chirho
            || metadata_chirho.dev() != self.root_device_chirho
            || metadata_chirho.ino() != self.root_inode_chirho
        {
            return Err(ElectedHeadTransitionRefusalChirho::WrongRootChirho.into());
        }
        let actual_group_chirho = consistency_group_for_root_chirho(&canonical_root_chirho)?;
        if actual_group_chirho != self.group_chirho
            || self.authority_handle_chirho.consistency_group_chirho() != &self.group_chirho
        {
            return Err(ElectedHeadTransitionRefusalChirho::WrongGroupChirho.into());
        }
        if self.authority_handle_chirho.node_id_chirho() != &self.node_chirho {
            return Err(ElectedHeadTransitionRefusalChirho::WrongNodeChirho.into());
        }
        Ok(())
    }

    /// Read-only liveness probe of the local append authority: acquire and immediately
    /// drop the O(1) generation guard. A live current leader returns `Ok`; a deposed,
    /// transferring, or not-yet-warm node returns the same refusal identity the write
    /// path would. This does NOT mutate the writer fence, take the append-log lock, or
    /// touch the filesystem, so it is a cheap readiness gate for the served-LLM dev
    /// dispatch, never a substitute for `with_elected_head_transition_scope_chirho`.
    pub fn probe_local_append_authority_live_chirho(&self) -> Result<()> {
        let _generation_guard_chirho = self
            .authority_handle_chirho
            .try_acquire_chirho()
            .map_err(map_local_refusal_chirho)?;
        Ok(())
    }
}

impl HeadTransitionAuthorityPortChirho for ElectedHeadTransitionAdapterChirho {
    fn with_elected_head_transition_scope_chirho(
        &self,
        root_chirho: &Path,
        action_chirho: &mut dyn HeadTransitionCommitActionChirho,
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
        let published_raft_term_chirho = generation_guard_chirho.published_raft_term_chirho();
        let outcome_chirho = with_elected_head_transition_scope_chirho(
            &self.canonical_root_chirho,
            &self.group_chirho,
            published_raft_term_chirho,
            active_fence_chirho.as_ref(),
            |scope_chirho| {
                let fence_term_chirho = u64::from(
                    split_writer_epoch_chirho(scope_chirho.writer_fence_epoch_chirho())
                        .geo_term_chirho,
                );
                if fence_term_chirho != published_raft_term_chirho {
                    return Err(ElectedHeadTransitionRefusalChirho::FenceTermMismatchChirho.into());
                }
                action_chirho.call_chirho(scope_chirho)
            },
        );
        if let Some(observed_fence_chirho) = outcome_chirho.observed_fence_chirho() {
            *active_fence_chirho = Some(observed_fence_chirho.clone());
        }
        outcome_chirho.into_result_chirho()
    }
}

fn map_local_refusal_chirho(refusal_chirho: LocalAppendAuthorityRefusalChirho) -> anyhow::Error {
    let mapped_chirho = match refusal_chirho {
        LocalAppendAuthorityRefusalChirho::NotLocalLeaderChirho
        | LocalAppendAuthorityRefusalChirho::NotPromotableVoterChirho
        | LocalAppendAuthorityRefusalChirho::LeadershipTransferInProgressChirho
        | LocalAppendAuthorityRefusalChirho::HandoffActiveChirho
        | LocalAppendAuthorityRefusalChirho::HandoffIdentityMismatchChirho => {
            ElectedHeadTransitionRefusalChirho::DeposedChirho
        }
        LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho => {
            ElectedHeadTransitionRefusalChirho::LeaseExpiredChirho
        }
        LocalAppendAuthorityRefusalChirho::GuardBusyChirho
        | LocalAppendAuthorityRefusalChirho::TransitionPendingChirho => {
            ElectedHeadTransitionRefusalChirho::AuthorityBusyChirho
        }
        LocalAppendAuthorityRefusalChirho::AuthorityPoisonedChirho => {
            ElectedHeadTransitionRefusalChirho::AuthorityPoisonedChirho
        }
        // This mapper receives only `try_acquire_chirho` refusals; that path never allocates a
        // handoff generation. Keep the unreachable case explicit so enum growth remains visible.
        LocalAppendAuthorityRefusalChirho::HandoffGenerationExhaustedChirho => {
            ElectedHeadTransitionRefusalChirho::AuthorityUnavailableChirho
        }
        LocalAppendAuthorityRefusalChirho::ElectorDroppedChirho
        | LocalAppendAuthorityRefusalChirho::AuthorityUnavailableChirho
        | LocalAppendAuthorityRefusalChirho::InvalidHandoffIdentityChirho
        | LocalAppendAuthorityRefusalChirho::PublishedRaftTermOutOfRangeChirho => {
            ElectedHeadTransitionRefusalChirho::AuthorityUnavailableChirho
        }
    };
    mapped_chirho.into()
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
    use cairn_writer_head_chirho::head_transition_authority_chirho::HeadTransitionCommitScopeChirho;
    use cairn_writer_head_chirho::writer_head_chirho::{
        issue_elected_writer_fence_for_root_chirho, verify_writer_fence_for_root_chirho,
        CompositeWriterEpochChirho, CompositeWriterEpochRefusalChirho,
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct CountingActionChirho {
        calls_chirho: u8,
        observed_epoch_chirho: Option<u64>,
    }

    impl HeadTransitionCommitActionChirho for CountingActionChirho {
        fn call_chirho(&mut self, scope_chirho: HeadTransitionCommitScopeChirho<'_>) -> Result<()> {
            self.calls_chirho = self.calls_chirho.saturating_add(1);
            self.observed_epoch_chirho = Some(scope_chirho.writer_fence_epoch_chirho());
            Ok(())
        }
    }

    pub(super) fn temp_root_chirho(label_chirho: &str) -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "cairn-elected-head-{label_chirho}-{nanos_chirho}-{counter_chirho}"
        ))
    }

    pub(super) fn elector_for_root_chirho(
        root_chirho: &Path,
        warm_chirho: bool,
    ) -> RaftWriterElectorChirho {
        std::fs::create_dir_all(root_chirho).expect("create elected-head root");
        let group_chirho =
            consistency_group_for_root_chirho(root_chirho).expect("derive consistency group");
        let elector_chirho = RaftWriterElectorChirho::new_single_node_chirho(
            NodeIdChirho("a".repeat(64)),
            group_chirho,
        )
        .expect("build single-node elector")
        .with_leadership_warmup_lease_chirho();
        elector_chirho
            .campaign_chirho()
            .expect("single-node elector campaigns");
        if warm_chirho {
            for _tick_chirho in 0..10 {
                elector_chirho.tick_chirho();
            }
        }
        elector_chirho
    }

    fn install_drill_tenant_marker_chirho(root_chirho: &Path) {
        std::fs::create_dir_all(root_chirho).expect("create tenant-marked elected-head root");
        std::fs::write(
            root_chirho.join("tenant-chirho.json"),
            br#"{"tenant_id_chirho":"item6-drill-chirho"}"#,
        )
        .expect("write drill tenant marker");
    }

    fn durable_elector_at_term_chirho(
        root_chirho: &Path,
        target_term_chirho: u64,
    ) -> RaftWriterElectorChirho {
        assert!(target_term_chirho > 0);
        let group_chirho =
            consistency_group_for_root_chirho(root_chirho).expect("derive durable test group");
        let node_chirho = NodeIdChirho("a".repeat(64));
        let elector_root_chirho = root_chirho.join("writer-election-test-chirho");
        let mut elector_chirho = RaftWriterElectorChirho::new_durable_single_node_chirho(
            elector_root_chirho.clone(),
            node_chirho.clone(),
            group_chirho.clone(),
        )
        .expect("create durable test elector")
        .with_leadership_warmup_lease_chirho();

        for expected_term_chirho in 1..=target_term_chirho {
            elector_chirho
                .campaign_chirho()
                .expect("durable test elector campaigns");
            for _tick_chirho in 0..10 {
                elector_chirho.tick_chirho();
            }
            let leadership_chirho = elector_chirho.current_leadership_chirho();
            assert!(leadership_chirho.is_leader_chirho);
            assert_eq!(leadership_chirho.term_chirho, expected_term_chirho);
            if expected_term_chirho == target_term_chirho {
                return elector_chirho;
            }
            drop(elector_chirho);
            elector_chirho = RaftWriterElectorChirho::open_existing_durable_single_node_chirho(
                elector_root_chirho.clone(),
                node_chirho.clone(),
                group_chirho.clone(),
            )
            .expect("reopen durable test elector")
            .with_leadership_warmup_lease_chirho();
        }
        unreachable!("positive target term always returns a durable elector")
    }

    #[test]
    fn warmed_elector_mints_one_root_bound_commit_scope_chirho() {
        let root_chirho = temp_root_chirho("live");
        let elector_chirho = elector_for_root_chirho(&root_chirho, true);
        let expected_term_chirho = elector_chirho.current_leadership_chirho().term_chirho;
        let adapter_chirho = ElectedHeadTransitionAdapterChirho::new_chirho(
            &root_chirho,
            elector_chirho.local_append_authority_handle_chirho(),
        )
        .expect("bind elected adapter");
        let mut action_chirho = CountingActionChirho {
            calls_chirho: 0,
            observed_epoch_chirho: None,
        };

        adapter_chirho
            .with_elected_head_transition_scope_chirho(&root_chirho, &mut action_chirho)
            .expect("live elected authority reaches one callback");

        assert_eq!(action_chirho.calls_chirho, 1);
        assert_eq!(
            u64::from(
                split_writer_epoch_chirho(
                    action_chirho
                        .observed_epoch_chirho
                        .expect("callback observes a fence")
                )
                .geo_term_chirho
            ),
            expected_term_chirho
        );
        std::fs::remove_dir_all(root_chirho).expect("remove elected-head root");
    }

    // The live-authority readiness probe the served-LLM dev dispatch calls: it must ADMIT a warm
    // leader (acquire+drop cleanly) and REFUSE a leader that is not yet warm, carrying the SAME
    // write-path refusal identity `try_acquire_chirho` produces (WarmupLeaseInvalid -> LeaseExpired).
    // This arms the money/authority gate's refusal branch: a not-live node's served card is refused.
    #[test]
    fn live_authority_probe_admits_warm_leader_and_refuses_not_warm_chirho() {
        // Positive control: a warmed single-node leader's probe acquires (and drops) cleanly.
        let warm_root_chirho = temp_root_chirho("probe-warm");
        let warm_elector_chirho = elector_for_root_chirho(&warm_root_chirho, true);
        let warm_adapter_chirho = ElectedHeadTransitionAdapterChirho::new_chirho(
            &warm_root_chirho,
            warm_elector_chirho.local_append_authority_handle_chirho(),
        )
        .expect("bind the warm elected adapter");
        warm_adapter_chirho
            .probe_local_append_authority_live_chirho()
            .expect("a warm leader's live-authority probe must acquire");

        // The refusal branch: a campaigned-but-not-warm leader is NOT live, so the probe refuses
        // with the write-path lease refusal identity rather than admitting a served paid write.
        let cold_root_chirho = temp_root_chirho("probe-cold");
        let cold_elector_chirho = elector_for_root_chirho(&cold_root_chirho, false);
        let cold_adapter_chirho = ElectedHeadTransitionAdapterChirho::new_chirho(
            &cold_root_chirho,
            cold_elector_chirho.local_append_authority_handle_chirho(),
        )
        .expect("bind the not-warm elected adapter");
        let refusal_chirho = cold_adapter_chirho
            .probe_local_append_authority_live_chirho()
            .expect_err("a not-warm leader's live-authority probe must refuse");
        assert!(
            matches!(
                refusal_chirho.downcast_ref::<ElectedHeadTransitionRefusalChirho>(),
                Some(ElectedHeadTransitionRefusalChirho::LeaseExpiredChirho)
            ),
            "the not-warm probe must carry the write-path lease refusal identity, got: {refusal_chirho:#}"
        );

        std::fs::remove_dir_all(&warm_root_chirho).expect("remove warm probe root");
        std::fs::remove_dir_all(&cold_root_chirho).expect("remove cold probe root");
    }

    #[test]
    fn first_live_scope_regrants_the_equal_term_seed_fence_chirho() {
        let root_chirho = temp_root_chirho("equal-term-seed");
        install_drill_tenant_marker_chirho(&root_chirho);
        let seed_fence_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 1)
            .expect("seed latches the tenant fence at term one");
        assert_eq!(
            split_writer_epoch_chirho(seed_fence_chirho.epoch_chirho),
            CompositeWriterEpochChirho {
                geo_term_chirho: 1,
                local_grant_seq_chirho: 0,
            }
        );

        let elector_chirho = elector_for_root_chirho(&root_chirho, true);
        let published_raft_term_chirho = elector_chirho.current_leadership_chirho().term_chirho;
        assert_eq!(published_raft_term_chirho, 1);
        let adapter_chirho = ElectedHeadTransitionAdapterChirho::new_chirho(
            &root_chirho,
            elector_chirho.local_append_authority_handle_chirho(),
        )
        .expect("bind the live tenant authority");
        let mut action_chirho = CountingActionChirho {
            calls_chirho: 0,
            observed_epoch_chirho: None,
        };

        adapter_chirho
            .with_elected_head_transition_scope_chirho(&root_chirho, &mut action_chirho)
            .expect("equal live term regrants the seed fence");

        assert_eq!(action_chirho.calls_chirho, 1);
        assert_eq!(
            split_writer_epoch_chirho(
                action_chirho
                    .observed_epoch_chirho
                    .expect("callback observes the regranted fence")
            ),
            CompositeWriterEpochChirho {
                geo_term_chirho: 1,
                local_grant_seq_chirho: 1,
            },
            "the first live scope must bump the equal-term grant instead of resetting it"
        );
        std::fs::remove_dir_all(root_chirho).expect("remove equal-term seed root");
    }

    #[test]
    fn lower_live_term_refuses_the_seed_fence_before_callback_chirho() {
        let root_chirho = temp_root_chirho("deposed-seed");
        install_drill_tenant_marker_chirho(&root_chirho);
        let seed_fence_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 2)
            .expect("seed latches the tenant fence at term two");
        let elector_chirho = elector_for_root_chirho(&root_chirho, true);
        assert_eq!(elector_chirho.current_leadership_chirho().term_chirho, 1);
        let adapter_chirho = ElectedHeadTransitionAdapterChirho::new_chirho(
            &root_chirho,
            elector_chirho.local_append_authority_handle_chirho(),
        )
        .expect("bind the lower-term tenant authority");
        let mut action_chirho = CountingActionChirho {
            calls_chirho: 0,
            observed_epoch_chirho: None,
        };

        let error_chirho = adapter_chirho
            .with_elected_head_transition_scope_chirho(&root_chirho, &mut action_chirho)
            .expect_err("a lower live term must not enter the callback");

        assert_eq!(
            error_chirho.downcast_ref::<CompositeWriterEpochRefusalChirho>(),
            Some(&CompositeWriterEpochRefusalChirho::DeposedGeoTermChirho)
        );
        assert!(
            error_chirho
                .downcast_ref::<ElectedHeadTransitionRefusalChirho>()
                .is_none(),
            "the geo-term regression must not be mistaken for an adapter sibling refusal"
        );
        assert_eq!(error_chirho.to_string(), "DeposedWriterGeoTermChirho");
        assert_eq!(action_chirho.calls_chirho, 0);
        assert_eq!(action_chirho.observed_epoch_chirho, None);
        verify_writer_fence_for_root_chirho(&root_chirho, &seed_fence_chirho)
            .expect("the lower-term refusal must leave the seed fence current");
        std::fs::remove_dir_all(root_chirho).expect("remove deposed seed root");
    }

    #[test]
    fn higher_live_term_reissues_the_seed_fence_at_zero_grant_chirho() {
        let root_chirho = temp_root_chirho("higher-term-seed");
        install_drill_tenant_marker_chirho(&root_chirho);
        let seed_fence_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 1)
            .expect("seed latches the tenant fence at term one");
        assert_eq!(
            split_writer_epoch_chirho(seed_fence_chirho.epoch_chirho),
            CompositeWriterEpochChirho {
                geo_term_chirho: 1,
                local_grant_seq_chirho: 0,
            }
        );

        let elector_chirho = durable_elector_at_term_chirho(&root_chirho, 2);
        assert_eq!(elector_chirho.current_leadership_chirho().term_chirho, 2);
        let adapter_chirho = ElectedHeadTransitionAdapterChirho::new_chirho(
            &root_chirho,
            elector_chirho.local_append_authority_handle_chirho(),
        )
        .expect("bind the higher-term tenant authority");
        let mut action_chirho = CountingActionChirho {
            calls_chirho: 0,
            observed_epoch_chirho: None,
        };

        adapter_chirho
            .with_elected_head_transition_scope_chirho(&root_chirho, &mut action_chirho)
            .expect("higher live term reissues the seed fence");

        assert_eq!(action_chirho.calls_chirho, 1);
        assert_eq!(
            split_writer_epoch_chirho(
                action_chirho
                    .observed_epoch_chirho
                    .expect("callback observes the reissued fence")
            ),
            CompositeWriterEpochChirho {
                geo_term_chirho: 2,
                local_grant_seq_chirho: 0,
            },
            "a higher live term must reset the grant sequence at its new term"
        );
        std::fs::remove_dir_all(root_chirho).expect("remove higher-term seed root");
    }

    #[test]
    fn unwarmed_elector_named_refuses_before_callback_chirho() {
        let root_chirho = temp_root_chirho("unwarmed");
        let elector_chirho = elector_for_root_chirho(&root_chirho, false);
        let adapter_chirho = ElectedHeadTransitionAdapterChirho::new_chirho(
            &root_chirho,
            elector_chirho.local_append_authority_handle_chirho(),
        )
        .expect("bind elected adapter");
        let mut action_chirho = CountingActionChirho {
            calls_chirho: 0,
            observed_epoch_chirho: None,
        };

        let error_chirho = adapter_chirho
            .with_elected_head_transition_scope_chirho(&root_chirho, &mut action_chirho)
            .expect_err("unwarmed authority must refuse");

        assert_eq!(
            error_chirho.to_string(),
            "ElectedAuthorityLeaseExpiredChirho"
        );
        assert_ne!(error_chirho.to_string(), "ElectedAuthorityDeposedChirho");
        assert_eq!(action_chirho.calls_chirho, 0);
        std::fs::remove_dir_all(root_chirho).expect("remove elected-head root");
    }

    #[test]
    fn adapter_refuses_wrong_root_before_callback_chirho() {
        let root_chirho = temp_root_chirho("bound");
        let other_root_chirho = temp_root_chirho("other");
        std::fs::create_dir_all(&other_root_chirho).expect("create other root");
        let elector_chirho = elector_for_root_chirho(&root_chirho, true);
        let adapter_chirho = ElectedHeadTransitionAdapterChirho::new_chirho(
            &root_chirho,
            elector_chirho.local_append_authority_handle_chirho(),
        )
        .expect("bind elected adapter");
        let mut action_chirho = CountingActionChirho {
            calls_chirho: 0,
            observed_epoch_chirho: None,
        };

        let error_chirho = adapter_chirho
            .with_elected_head_transition_scope_chirho(&other_root_chirho, &mut action_chirho)
            .expect_err("root substitution must refuse");

        assert_eq!(error_chirho.to_string(), "ElectedAuthorityWrongRootChirho");
        assert_ne!(error_chirho.to_string(), "ElectedAuthorityWrongGroupChirho");
        assert_eq!(action_chirho.calls_chirho, 0);
        std::fs::remove_dir_all(root_chirho).expect("remove bound root");
        std::fs::remove_dir_all(other_root_chirho).expect("remove other root");
    }

    #[test]
    fn adapter_constructor_refuses_a_handle_for_another_group_chirho() {
        let root_chirho = temp_root_chirho("group-a");
        let other_root_chirho = temp_root_chirho("group-b");
        std::fs::create_dir_all(&root_chirho).expect("create group-a root");
        let other_elector_chirho = elector_for_root_chirho(&other_root_chirho, true);

        let error_chirho = match ElectedHeadTransitionAdapterChirho::new_chirho(
            &root_chirho,
            other_elector_chirho.local_append_authority_handle_chirho(),
        ) {
            Ok(_adapter_chirho) => panic!("cross-group handle must refuse"),
            Err(error_chirho) => error_chirho,
        };

        assert_eq!(error_chirho.to_string(), "ElectedAuthorityWrongGroupChirho");
        assert_ne!(error_chirho.to_string(), "ElectedAuthorityWrongRootChirho");
        std::fs::remove_dir_all(root_chirho).expect("remove group-a root");
        std::fs::remove_dir_all(other_root_chirho).expect("remove group-b root");
    }

    #[test]
    fn local_refusal_mapping_keeps_deposed_and_expired_distinct_chirho() {
        let deposed_chirho =
            map_local_refusal_chirho(LocalAppendAuthorityRefusalChirho::NotLocalLeaderChirho);
        let expired_chirho =
            map_local_refusal_chirho(LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho);

        assert_eq!(deposed_chirho.to_string(), "ElectedAuthorityDeposedChirho");
        assert_ne!(
            deposed_chirho.to_string(),
            "ElectedAuthorityLeaseExpiredChirho"
        );
        assert_eq!(
            expired_chirho.to_string(),
            "ElectedAuthorityLeaseExpiredChirho"
        );
        assert_ne!(expired_chirho.to_string(), "ElectedAuthorityDeposedChirho");
    }
}
