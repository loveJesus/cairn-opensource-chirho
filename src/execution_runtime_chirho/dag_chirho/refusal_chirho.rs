// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Detail-free execution-stage identities for served DAG refusals.

use anyhow::Error;
use std::fmt;

pub const DAG_EXECUTION_REFUSAL_LOG_PREFIX_CHIRHO: &str = "CairnAppExecutionRefusalChirho";

macro_rules! dag_execution_refusal_identities_chirho {
    ($( $identity_chirho:ident => $knowledge_chirho:ident ),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum DagExecutionRefusalIdentityChirho {
            $( $identity_chirho, )+
        }

        impl DagExecutionRefusalIdentityChirho {
            pub const ALL_CHIRHO: &'static [Self] = &[
                $( Self::$identity_chirho, )+
            ];

            pub const fn as_str_chirho(self) -> &'static str {
                match self {
                    $( Self::$identity_chirho => stringify!($identity_chirho), )+
                }
            }

            pub fn from_str_chirho(value_chirho: &str) -> Option<Self> {
                match value_chirho {
                    $( stringify!($identity_chirho) => Some(Self::$identity_chirho), )+
                    _ => None,
                }
            }

            pub const fn execution_knowledge_chirho(self) -> DagExecutionKnowledgeChirho {
                match self {
                    $( Self::$identity_chirho => DagExecutionKnowledgeChirho::$knowledge_chirho, )+
                }
            }
        }
    };
}

dag_execution_refusal_identities_chirho!(
    DagExecutionUnclassifiedRefusedChirho => UnknownChirho,
    DagPreEffectRefusedChirho => DefinitelyNotExecutedChirho,
    DagEffectProviderRefusedChirho => MayHaveExecutedChirho,
    DagEffectTerminalAuditRefusedChirho => MayHaveExecutedChirho,
    DagEffectResultAccountingRefusedChirho => MayHaveExecutedChirho,
    DagPostEffectPureNodeRefusedChirho => MayHaveExecutedChirho,
    DagPostEffectSurfaceRefusedChirho => MayHaveExecutedChirho,
    DagPostEffectUnclassifiedRefusedChirho => MayHaveExecutedChirho,
    RunIntentTerminalRecordRefusedChirho => MayHaveExecutedChirho,
    RunIntentFailureRecordRefusedChirho => MayHaveExecutedChirho,
    RunIntentPreviouslyFailedRefusedChirho => PriorAttemptFailedChirho,
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DagExecutionKnowledgeChirho {
    DefinitelyNotExecutedChirho,
    MayHaveExecutedChirho,
    PriorAttemptFailedChirho,
    UnknownChirho,
}

impl DagExecutionKnowledgeChirho {
    pub const fn as_str_chirho(self) -> &'static str {
        match self {
            Self::DefinitelyNotExecutedChirho => "definitely-not-executed-chirho",
            Self::MayHaveExecutedChirho => "may-have-executed-chirho",
            Self::PriorAttemptFailedChirho => "prior-attempt-failed-chirho",
            Self::UnknownChirho => "unknown-chirho",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DagExecutionAttemptOrdinalChirho {
    FirstChirho,
    ResumeChirho,
    CompletedReplayChirho,
    FailedReplayChirho,
    UnclassifiedChirho,
}

impl DagExecutionAttemptOrdinalChirho {
    pub const fn as_str_chirho(self) -> &'static str {
        match self {
            Self::FirstChirho => "first-chirho",
            Self::ResumeChirho => "resume-chirho",
            Self::CompletedReplayChirho => "completed-replay-chirho",
            Self::FailedReplayChirho => "failed-replay-chirho",
            Self::UnclassifiedChirho => "unclassified-chirho",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DagExecutionRefusalObservationChirho {
    identity_chirho: DagExecutionRefusalIdentityChirho,
    attempt_ordinal_chirho: DagExecutionAttemptOrdinalChirho,
    prior_identity_chirho: Option<DagExecutionRefusalIdentityChirho>,
}

impl DagExecutionRefusalObservationChirho {
    pub const fn identity_chirho(self) -> DagExecutionRefusalIdentityChirho {
        self.identity_chirho
    }

    pub const fn attempt_ordinal_chirho(self) -> DagExecutionAttemptOrdinalChirho {
        self.attempt_ordinal_chirho
    }

    pub const fn prior_identity_chirho(self) -> Option<DagExecutionRefusalIdentityChirho> {
        self.prior_identity_chirho
    }

    pub const fn execution_knowledge_chirho(self) -> DagExecutionKnowledgeChirho {
        self.identity_chirho.execution_knowledge_chirho()
    }
}

#[derive(Debug)]
struct DagExecutionStageRefusalChirho {
    identity_chirho: DagExecutionRefusalIdentityChirho,
    source_display_chirho: String,
}

impl fmt::Display for DagExecutionStageRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(&self.source_display_chirho)
    }
}

#[derive(Debug)]
struct DagExecutionAttemptRefusalChirho {
    observation_chirho: DagExecutionRefusalObservationChirho,
    source_display_chirho: String,
}

impl fmt::Display for DagExecutionAttemptRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(&self.source_display_chirho)
    }
}

pub(crate) fn wrap_dag_execution_stage_chirho<SourceChirho>(
    identity_chirho: DagExecutionRefusalIdentityChirho,
    source_chirho: SourceChirho,
) -> Error
where
    SourceChirho: Into<Error>,
{
    let source_chirho = source_chirho.into();
    if dag_execution_refusal_identity_chirho(&source_chirho).is_some() {
        return source_chirho;
    }
    let source_display_chirho = source_chirho.to_string();
    source_chirho.context(DagExecutionStageRefusalChirho {
        identity_chirho,
        source_display_chirho,
    })
}

pub(crate) fn ensure_dag_execution_stage_chirho(
    identity_chirho: DagExecutionRefusalIdentityChirho,
    source_chirho: Error,
) -> Error {
    if dag_execution_refusal_identity_chirho(&source_chirho).is_some() {
        source_chirho
    } else {
        wrap_dag_execution_stage_chirho(identity_chirho, source_chirho)
    }
}

pub(crate) fn wrap_dag_execution_attempt_chirho(
    source_chirho: Error,
    attempt_ordinal_chirho: DagExecutionAttemptOrdinalChirho,
    prior_identity_chirho: Option<DagExecutionRefusalIdentityChirho>,
) -> Error {
    let identity_chirho = dag_execution_refusal_identity_chirho(&source_chirho)
        .unwrap_or(DagExecutionRefusalIdentityChirho::DagExecutionUnclassifiedRefusedChirho);
    let source_display_chirho = source_chirho.to_string();
    source_chirho.context(DagExecutionAttemptRefusalChirho {
        observation_chirho: DagExecutionRefusalObservationChirho {
            identity_chirho,
            attempt_ordinal_chirho,
            prior_identity_chirho,
        },
        source_display_chirho,
    })
}

pub fn dag_execution_refusal_observation_chirho(
    error_chirho: &Error,
) -> DagExecutionRefusalObservationChirho {
    if let Some(attempt_chirho) = error_chirho.downcast_ref::<DagExecutionAttemptRefusalChirho>() {
        return attempt_chirho.observation_chirho;
    }
    DagExecutionRefusalObservationChirho {
        identity_chirho: dag_execution_refusal_identity_chirho(error_chirho)
            .unwrap_or(DagExecutionRefusalIdentityChirho::DagExecutionUnclassifiedRefusedChirho),
        attempt_ordinal_chirho: DagExecutionAttemptOrdinalChirho::UnclassifiedChirho,
        prior_identity_chirho: None,
    }
}

/// Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md`.
pub fn dag_execution_refusal_log_line_chirho(error_chirho: &Error) -> String {
    let observation_chirho = dag_execution_refusal_observation_chirho(error_chirho);
    let prior_identity_chirho = observation_chirho
        .prior_identity_chirho()
        .map(DagExecutionRefusalIdentityChirho::as_str_chirho)
        .unwrap_or("none-chirho");
    format!(
        "{DAG_EXECUTION_REFUSAL_LOG_PREFIX_CHIRHO}:attempt_ordinal_chirho={}:identity_chirho={}:knowledge_chirho={}:prior_identity_chirho={}",
        observation_chirho.attempt_ordinal_chirho().as_str_chirho(),
        observation_chirho.identity_chirho().as_str_chirho(),
        observation_chirho.execution_knowledge_chirho().as_str_chirho(),
        prior_identity_chirho,
    )
}

fn dag_execution_refusal_identity_chirho(
    error_chirho: &Error,
) -> Option<DagExecutionRefusalIdentityChirho> {
    error_chirho
        .downcast_ref::<DagExecutionStageRefusalChirho>()
        .map(|stage_chirho| stage_chirho.identity_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use anyhow::anyhow;
    use std::collections::BTreeSet;

    #[derive(Debug)]
    struct InternalTypedRefusalChirho;

    impl fmt::Display for InternalTypedRefusalChirho {
        fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter_chirho.write_str("/private/internal-typed-detail-chirho")
        }
    }

    impl std::error::Error for InternalTypedRefusalChirho {}

    #[test]
    fn fixed_identity_vocabulary_round_trips_without_duplicates_chirho() {
        let mut observed_chirho = BTreeSet::new();
        for identity_chirho in DagExecutionRefusalIdentityChirho::ALL_CHIRHO {
            assert!(observed_chirho.insert(identity_chirho.as_str_chirho()));
            assert_eq!(
                DagExecutionRefusalIdentityChirho::from_str_chirho(identity_chirho.as_str_chirho()),
                Some(*identity_chirho)
            );
        }
    }

    #[test]
    fn deepest_stage_identity_survives_outer_stage_and_attempt_chirho() {
        let inner_chirho = wrap_dag_execution_stage_chirho(
            DagExecutionRefusalIdentityChirho::DagEffectTerminalAuditRefusedChirho,
            anyhow!("/private/execution-detail-needle-chirho"),
        );
        let outer_chirho = wrap_dag_execution_stage_chirho(
            DagExecutionRefusalIdentityChirho::DagPostEffectUnclassifiedRefusedChirho,
            inner_chirho,
        );
        let error_chirho = wrap_dag_execution_attempt_chirho(
            outer_chirho,
            DagExecutionAttemptOrdinalChirho::FirstChirho,
            None,
        );
        let observation_chirho = dag_execution_refusal_observation_chirho(&error_chirho);
        assert_eq!(
            observation_chirho.identity_chirho(),
            DagExecutionRefusalIdentityChirho::DagEffectTerminalAuditRefusedChirho
        );
        assert_eq!(
            observation_chirho.attempt_ordinal_chirho(),
            DagExecutionAttemptOrdinalChirho::FirstChirho
        );
        assert_eq!(
            dag_execution_refusal_log_line_chirho(&error_chirho),
            "CairnAppExecutionRefusalChirho:attempt_ordinal_chirho=first-chirho:identity_chirho=DagEffectTerminalAuditRefusedChirho:knowledge_chirho=may-have-executed-chirho:prior_identity_chirho=none-chirho"
        );
        assert!(!dag_execution_refusal_log_line_chirho(&error_chirho)
            .contains("/private/execution-detail-needle-chirho"));
    }

    #[test]
    fn stage_context_preserves_internal_typed_error_but_not_boundary_detail_chirho() {
        let error_chirho = wrap_dag_execution_stage_chirho(
            DagExecutionRefusalIdentityChirho::DagEffectResultAccountingRefusedChirho,
            anyhow::Error::new(InternalTypedRefusalChirho),
        );
        assert!(error_chirho
            .downcast_ref::<InternalTypedRefusalChirho>()
            .is_some());
        assert!(error_chirho
            .to_string()
            .contains("/private/internal-typed-detail-chirho"));
        assert!(!dag_execution_refusal_log_line_chirho(&error_chirho)
            .contains("/private/internal-typed-detail-chirho"));
    }
}
