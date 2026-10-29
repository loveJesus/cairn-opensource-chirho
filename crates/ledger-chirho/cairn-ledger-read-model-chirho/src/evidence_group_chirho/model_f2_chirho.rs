// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Model F2: canonical multi-source projection merge under independently delayed verification,
//! crash/restart, equal-HLC ties, and full refold. Each mutation removes one protocol law and uses
//! reachability to prove that the corresponding divergence becomes possible.
//! Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf4-read-model-foundation-chirho.md`.

use crate::{
    canonical_projection_merge_chirho, derive_projection_privacy_evidence_ref_chirho,
    verify_projection_descriptor_chirho, CanonicalProjectionMergeChirho, ProjectionCostClassChirho,
    ProjectionDescriptorChirho, ProjectionMergeEventChirho, ProjectionMergeSourcePrefixChirho,
    ProjectionReadPolicyChirho, ProjectionRebuildLawChirho, ProjectionSourceBindingChirho,
    ProjectionWatermarkChirho, StalenessContractChirho, VerifiedProjectionDescriptorChirho,
    VerifiedProjectionSourceChirho, VerifiedProjectionSourceHeadChirho,
    PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_model_chirho::{ids_chirho::DigestChirho, record_chirho::HlcChirho};
use cairn_model_privacy_chirho::PrivacyClassChirho;
use stateright::{Model, Property};

const SOURCE_A_CHIRHO: &str = "a-model-f2-source-chirho";
const SOURCE_B_CHIRHO: &str = "b-model-f2-source-chirho";
const SOURCE_COUNT_CHIRHO: usize = 2;
const EVENT_COUNT_CHIRHO: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModelF2MutationChirho {
    NoneChirho,
    ArrivalOrderChirho,
    BeyondMinFrontierChirho,
    OmittedSourceChirho,
    MissingTieBreakChirho,
    DuplicateApplyChirho,
    BrokenRefoldChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ModelF2EventIdChirho {
    A1Chirho,
    A2Chirho,
    B1Chirho,
    B2Chirho,
}

impl ModelF2EventIdChirho {
    fn family_chirho(self) -> &'static str {
        match self {
            Self::A1Chirho | Self::A2Chirho => SOURCE_A_CHIRHO,
            Self::B1Chirho | Self::B2Chirho => SOURCE_B_CHIRHO,
        }
    }

    fn seq_chirho(self) -> u8 {
        match self {
            Self::A1Chirho | Self::B1Chirho => 1,
            Self::A2Chirho | Self::B2Chirho => 2,
        }
    }

    fn hlc_ms_chirho(self) -> u64 {
        match self {
            Self::A1Chirho => 10,
            Self::B1Chirho => 20,
            Self::A2Chirho | Self::B2Chirho => 30,
        }
    }

    fn digest_number_chirho(self) -> u64 {
        match self {
            Self::A1Chirho => 101,
            Self::A2Chirho => 102,
            Self::B1Chirho => 201,
            Self::B2Chirho => 202,
        }
    }

    fn index_chirho(self) -> usize {
        match self {
            Self::A1Chirho => 0,
            Self::A2Chirho => 1,
            Self::B1Chirho => 2,
            Self::B2Chirho => 3,
        }
    }

    fn event_chirho(self) -> ProjectionMergeEventChirho {
        ProjectionMergeEventChirho {
            source_family_id_chirho: self.family_chirho().into(),
            source_seq_chirho: u64::from(self.seq_chirho()),
            source_hlc_chirho: hlc_chirho(self.hlc_ms_chirho()),
            signed_line_digest_chirho: digest_chirho(self.digest_number_chirho()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ModelF2StateChirho {
    appended_chirho: [u8; SOURCE_COUNT_CHIRHO],
    verified_chirho: [u8; SOURCE_COUNT_CHIRHO],
    verification_arrival_chirho: Vec<ModelF2EventIdChirho>,
    projector_alive_chirho: bool,
    saw_verification_skew_chirho: bool,
    restarted_after_skew_chirho: bool,
    published_cut_chirho: [u8; SOURCE_COUNT_CHIRHO],
    published_cursors_chirho: [u8; SOURCE_COUNT_CHIRHO],
    previous_published_cursors_chirho: [u8; SOURCE_COUNT_CHIRHO],
    published_frontier_ms_chirho: u64,
    previous_published_frontier_ms_chirho: u64,
    published_trace_chirho: Vec<ModelF2EventIdChirho>,
    apply_counts_chirho: [u8; EVENT_COUNT_CHIRHO],
    completed_refold_chirho: bool,
    refold_matched_previous_chirho: bool,
    duplicate_applied_chirho: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ModelF2ActionChirho {
    AppendAChirho,
    AppendBChirho,
    VerifyAChirho,
    VerifyBChirho,
    PublishChirho,
    CrashChirho,
    RestartChirho,
    RefoldChirho,
    DuplicateLastChirho,
}

struct ModelF2Chirho {
    mutation_chirho: ModelF2MutationChirho,
    verified_descriptor_chirho: VerifiedProjectionDescriptorChirho,
}

impl ModelF2Chirho {
    fn canonical_at_cut_chirho(
        &self,
        cut_chirho: [u8; SOURCE_COUNT_CHIRHO],
    ) -> CanonicalProjectionMergeChirho {
        canonical_projection_merge_chirho(
            &self.verified_descriptor_chirho,
            &source_prefixes_chirho(cut_chirho),
        )
        .expect("bounded model prefixes are valid")
    }

    fn canonical_ids_at_cut_chirho(
        &self,
        cut_chirho: [u8; SOURCE_COUNT_CHIRHO],
    ) -> Vec<ModelF2EventIdChirho> {
        self.canonical_at_cut_chirho(cut_chirho)
            .ordered_events_chirho
            .iter()
            .map(event_id_chirho)
            .collect()
    }

    fn published_is_canonical_chirho(&self, state_chirho: &ModelF2StateChirho) -> bool {
        let expected_chirho = self.canonical_at_cut_chirho(state_chirho.published_cut_chirho);
        let expected_cursors_chirho = [
            expected_chirho.applied_source_cursors_chirho[0].source_seq_chirho as u8,
            expected_chirho.applied_source_cursors_chirho[1].source_seq_chirho as u8,
        ];
        state_chirho.published_trace_chirho
            == expected_chirho
                .ordered_events_chirho
                .iter()
                .map(event_id_chirho)
                .collect::<Vec<_>>()
            && state_chirho.published_cursors_chirho == expected_cursors_chirho
            && state_chirho.published_frontier_ms_chirho
                == expected_chirho.safe_frontier_hlc_chirho.physical_ms_chirho
    }

    fn apply_counts_are_exact_chirho(state_chirho: &ModelF2StateChirho) -> bool {
        let mut expected_chirho = [0_u8; EVENT_COUNT_CHIRHO];
        for event_chirho in &state_chirho.published_trace_chirho {
            expected_chirho[event_chirho.index_chirho()] += 1;
        }
        state_chirho.apply_counts_chirho == expected_chirho
            && expected_chirho
                .iter()
                .all(|count_chirho| *count_chirho <= 1)
    }

    fn published_vectors_are_monotone_chirho(state_chirho: &ModelF2StateChirho) -> bool {
        state_chirho
            .published_cursors_chirho
            .iter()
            .zip(state_chirho.previous_published_cursors_chirho)
            .all(|(cursor_chirho, previous_chirho)| *cursor_chirho >= previous_chirho)
            && state_chirho.published_frontier_ms_chirho
                >= state_chirho.previous_published_frontier_ms_chirho
    }

    fn publication_for_verified_cut_chirho(
        &self,
        state_chirho: &ModelF2StateChirho,
    ) -> (Vec<ModelF2EventIdChirho>, [u8; 2], u64) {
        let canonical_chirho = self.canonical_at_cut_chirho(state_chirho.verified_chirho);
        let canonical_trace_chirho = canonical_chirho
            .ordered_events_chirho
            .iter()
            .map(event_id_chirho)
            .collect::<Vec<_>>();
        let canonical_cursors_chirho = [
            canonical_chirho.applied_source_cursors_chirho[0].source_seq_chirho as u8,
            canonical_chirho.applied_source_cursors_chirho[1].source_seq_chirho as u8,
        ];
        let canonical_frontier_chirho =
            canonical_chirho.safe_frontier_hlc_chirho.physical_ms_chirho;

        match self.mutation_chirho {
            ModelF2MutationChirho::ArrivalOrderChirho => (
                ready_arrival_trace_chirho(
                    &state_chirho.verification_arrival_chirho,
                    state_chirho.verified_chirho,
                    canonical_frontier_chirho,
                ),
                canonical_cursors_chirho,
                canonical_frontier_chirho,
            ),
            ModelF2MutationChirho::BeyondMinFrontierChirho => {
                let mut trace_chirho = verified_event_ids_chirho(state_chirho.verified_chirho);
                trace_chirho
                    .sort_by_key(|event_chirho| event_chirho.event_chirho().merge_key_chirho());
                (
                    trace_chirho,
                    canonical_cursors_chirho,
                    canonical_frontier_chirho,
                )
            }
            ModelF2MutationChirho::OmittedSourceChirho => {
                let mut trace_chirho = source_event_ids_chirho(0)
                    .into_iter()
                    .take(usize::from(state_chirho.verified_chirho[0]))
                    .collect::<Vec<_>>();
                trace_chirho
                    .sort_by_key(|event_chirho| event_chirho.event_chirho().merge_key_chirho());
                let frontier_chirho = source_head_hlc_ms_chirho(0, state_chirho.verified_chirho[0]);
                (
                    trace_chirho,
                    [state_chirho.verified_chirho[0], 0],
                    frontier_chirho,
                )
            }
            ModelF2MutationChirho::MissingTieBreakChirho => {
                let mut trace_chirho = ready_arrival_trace_chirho(
                    &state_chirho.verification_arrival_chirho,
                    state_chirho.verified_chirho,
                    canonical_frontier_chirho,
                );
                trace_chirho.sort_by_key(|event_chirho| event_chirho.hlc_ms_chirho());
                (
                    trace_chirho,
                    canonical_cursors_chirho,
                    canonical_frontier_chirho,
                )
            }
            ModelF2MutationChirho::NoneChirho
            | ModelF2MutationChirho::DuplicateApplyChirho
            | ModelF2MutationChirho::BrokenRefoldChirho => (
                canonical_trace_chirho,
                canonical_cursors_chirho,
                canonical_frontier_chirho,
            ),
        }
    }

    fn publish_chirho(&self, state_chirho: &mut ModelF2StateChirho) {
        let (trace_chirho, cursors_chirho, frontier_chirho) =
            self.publication_for_verified_cut_chirho(state_chirho);
        state_chirho.published_cut_chirho = state_chirho.verified_chirho;
        state_chirho.published_trace_chirho = trace_chirho;
        state_chirho.published_cursors_chirho = cursors_chirho;
        state_chirho.published_frontier_ms_chirho = frontier_chirho;
        state_chirho.apply_counts_chirho =
            apply_counts_chirho(&state_chirho.published_trace_chirho);
    }
}

impl Model for ModelF2Chirho {
    type State = ModelF2StateChirho;
    type Action = ModelF2ActionChirho;

    fn init_states(&self) -> Vec<Self::State> {
        vec![ModelF2StateChirho {
            appended_chirho: [0, 0],
            verified_chirho: [0, 0],
            verification_arrival_chirho: Vec::new(),
            projector_alive_chirho: true,
            saw_verification_skew_chirho: false,
            restarted_after_skew_chirho: false,
            published_cut_chirho: [0, 0],
            published_cursors_chirho: [0, 0],
            previous_published_cursors_chirho: [0, 0],
            published_frontier_ms_chirho: 0,
            previous_published_frontier_ms_chirho: 0,
            published_trace_chirho: Vec::new(),
            apply_counts_chirho: [0; EVENT_COUNT_CHIRHO],
            completed_refold_chirho: false,
            refold_matched_previous_chirho: false,
            duplicate_applied_chirho: false,
        }]
    }

    fn actions(&self, state_chirho: &Self::State, actions_chirho: &mut Vec<Self::Action>) {
        if state_chirho.appended_chirho[0] < 2 {
            actions_chirho.push(ModelF2ActionChirho::AppendAChirho);
        }
        if state_chirho.appended_chirho[1] < 2 {
            actions_chirho.push(ModelF2ActionChirho::AppendBChirho);
        }
        if state_chirho.verified_chirho[0] < state_chirho.appended_chirho[0] {
            actions_chirho.push(ModelF2ActionChirho::VerifyAChirho);
        }
        if state_chirho.verified_chirho[1] < state_chirho.appended_chirho[1] {
            actions_chirho.push(ModelF2ActionChirho::VerifyBChirho);
        }
        if state_chirho.projector_alive_chirho {
            if state_chirho.published_cut_chirho != state_chirho.verified_chirho
                || state_chirho.published_trace_chirho
                    != self.publication_for_verified_cut_chirho(state_chirho).0
            {
                actions_chirho.push(ModelF2ActionChirho::PublishChirho);
            }
            if !state_chirho.completed_refold_chirho
                && !state_chirho.published_trace_chirho.is_empty()
            {
                actions_chirho.push(ModelF2ActionChirho::RefoldChirho);
            }
            if self.mutation_chirho == ModelF2MutationChirho::DuplicateApplyChirho
                && !state_chirho.duplicate_applied_chirho
                && !state_chirho.published_trace_chirho.is_empty()
            {
                actions_chirho.push(ModelF2ActionChirho::DuplicateLastChirho);
            }
            actions_chirho.push(ModelF2ActionChirho::CrashChirho);
        } else {
            actions_chirho.push(ModelF2ActionChirho::RestartChirho);
        }
    }

    fn next_state(
        &self,
        state_chirho: &Self::State,
        action_chirho: Self::Action,
    ) -> Option<Self::State> {
        let mut next_chirho = state_chirho.clone();
        next_chirho.previous_published_cursors_chirho = state_chirho.published_cursors_chirho;
        next_chirho.previous_published_frontier_ms_chirho =
            state_chirho.published_frontier_ms_chirho;
        match action_chirho {
            ModelF2ActionChirho::AppendAChirho => next_chirho.appended_chirho[0] += 1,
            ModelF2ActionChirho::AppendBChirho => next_chirho.appended_chirho[1] += 1,
            ModelF2ActionChirho::VerifyAChirho => {
                next_chirho.verified_chirho[0] += 1;
                next_chirho.verification_arrival_chirho.push(
                    source_event_ids_chirho(0)[usize::from(next_chirho.verified_chirho[0] - 1)],
                );
                next_chirho.saw_verification_skew_chirho |=
                    next_chirho.verified_chirho[0] != next_chirho.verified_chirho[1];
            }
            ModelF2ActionChirho::VerifyBChirho => {
                next_chirho.verified_chirho[1] += 1;
                next_chirho.verification_arrival_chirho.push(
                    source_event_ids_chirho(1)[usize::from(next_chirho.verified_chirho[1] - 1)],
                );
                next_chirho.saw_verification_skew_chirho |=
                    next_chirho.verified_chirho[0] != next_chirho.verified_chirho[1];
            }
            ModelF2ActionChirho::PublishChirho => self.publish_chirho(&mut next_chirho),
            ModelF2ActionChirho::CrashChirho => next_chirho.projector_alive_chirho = false,
            ModelF2ActionChirho::RestartChirho => {
                next_chirho.projector_alive_chirho = true;
                next_chirho.restarted_after_skew_chirho |= next_chirho.saw_verification_skew_chirho;
            }
            ModelF2ActionChirho::RefoldChirho => {
                let previous_trace_chirho = next_chirho.published_trace_chirho.clone();
                let mut refolded_trace_chirho =
                    self.canonical_ids_at_cut_chirho(next_chirho.published_cut_chirho);
                if self.mutation_chirho == ModelF2MutationChirho::BrokenRefoldChirho {
                    refolded_trace_chirho.reverse();
                }
                next_chirho.published_trace_chirho = refolded_trace_chirho;
                next_chirho.apply_counts_chirho =
                    apply_counts_chirho(&next_chirho.published_trace_chirho);
                next_chirho.completed_refold_chirho = true;
                next_chirho.refold_matched_previous_chirho =
                    next_chirho.published_trace_chirho == previous_trace_chirho;
            }
            ModelF2ActionChirho::DuplicateLastChirho => {
                let event_chirho = *next_chirho.published_trace_chirho.last().unwrap();
                next_chirho.published_trace_chirho.push(event_chirho);
                next_chirho.apply_counts_chirho[event_chirho.index_chirho()] += 1;
                next_chirho.duplicate_applied_chirho = true;
            }
        }
        Some(next_chirho)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        match self.mutation_chirho {
            ModelF2MutationChirho::NoneChirho => vec![
                Property::<Self>::always(
                    "rm-f2-canonical-at-published-cut-chirho",
                    |model_chirho, state_chirho| {
                        model_chirho.published_is_canonical_chirho(state_chirho)
                    },
                ),
                Property::<Self>::always(
                    "rm-f2-exactly-once-application-chirho",
                    |_, state_chirho| Self::apply_counts_are_exact_chirho(state_chirho),
                ),
                Property::<Self>::always(
                    "rm-f2-published-vector-monotone-chirho",
                    |_, state_chirho| Self::published_vectors_are_monotone_chirho(state_chirho),
                ),
                Property::<Self>::sometimes(
                    "rm-f2-equal-hlc-tie-reachable-chirho",
                    |_, state_chirho| {
                        state_chirho.published_trace_chirho
                            == vec![
                                ModelF2EventIdChirho::A1Chirho,
                                ModelF2EventIdChirho::B1Chirho,
                                ModelF2EventIdChirho::A2Chirho,
                                ModelF2EventIdChirho::B2Chirho,
                            ]
                    },
                ),
                Property::<Self>::sometimes(
                    "rm-f2-beyond-frontier-remains-pending-chirho",
                    |_, state_chirho| {
                        state_chirho.published_cut_chirho == [2, 1]
                            && state_chirho.published_frontier_ms_chirho == 20
                            && !state_chirho
                                .published_trace_chirho
                                .contains(&ModelF2EventIdChirho::A2Chirho)
                    },
                ),
                Property::<Self>::sometimes(
                    "rm-f2-post-delay-restart-catch-up-chirho",
                    |model_chirho, state_chirho| {
                        state_chirho.restarted_after_skew_chirho
                            && state_chirho.published_cut_chirho == [2, 2]
                            && model_chirho.published_is_canonical_chirho(state_chirho)
                    },
                ),
                Property::<Self>::sometimes(
                    "rm-f2-refold-byte-equivalent-chirho",
                    |model_chirho, state_chirho| {
                        state_chirho.completed_refold_chirho
                            && state_chirho.refold_matched_previous_chirho
                            && model_chirho.published_is_canonical_chirho(state_chirho)
                    },
                ),
            ],
            ModelF2MutationChirho::ArrivalOrderChirho => vec![Property::<Self>::sometimes(
                "arrival-order-divergence-reachable-chirho",
                |model_chirho, state_chirho| {
                    !model_chirho.published_is_canonical_chirho(state_chirho)
                },
            )],
            ModelF2MutationChirho::BeyondMinFrontierChirho => vec![Property::<Self>::sometimes(
                "beyond-min-frontier-read-ahead-reachable-chirho",
                |model_chirho, state_chirho| {
                    !model_chirho.published_is_canonical_chirho(state_chirho)
                        && state_chirho
                            .published_trace_chirho
                            .iter()
                            .any(|event_chirho| {
                                event_chirho.hlc_ms_chirho()
                                    > state_chirho.published_frontier_ms_chirho
                            })
                },
            )],
            ModelF2MutationChirho::OmittedSourceChirho => vec![Property::<Self>::sometimes(
                "omitted-source-subset-merge-reachable-chirho",
                |model_chirho, state_chirho| {
                    state_chirho.published_cut_chirho[1] > 0
                        && !model_chirho.published_is_canonical_chirho(state_chirho)
                },
            )],
            ModelF2MutationChirho::MissingTieBreakChirho => vec![Property::<Self>::sometimes(
                "equal-hlc-order-divergence-reachable-chirho",
                |model_chirho, state_chirho| {
                    !model_chirho.published_is_canonical_chirho(state_chirho)
                        && event_precedes_chirho(
                            &state_chirho.published_trace_chirho,
                            ModelF2EventIdChirho::B2Chirho,
                            ModelF2EventIdChirho::A2Chirho,
                        )
                },
            )],
            ModelF2MutationChirho::DuplicateApplyChirho => vec![Property::<Self>::sometimes(
                "duplicate-application-reachable-chirho",
                |model_chirho, state_chirho| {
                    state_chirho.duplicate_applied_chirho
                        && !Self::apply_counts_are_exact_chirho(state_chirho)
                        && !model_chirho.published_is_canonical_chirho(state_chirho)
                },
            )],
            ModelF2MutationChirho::BrokenRefoldChirho => vec![Property::<Self>::sometimes(
                "non-equivalent-refold-reachable-chirho",
                |model_chirho, state_chirho| {
                    state_chirho.completed_refold_chirho
                        && !state_chirho.refold_matched_previous_chirho
                        && !model_chirho.published_is_canonical_chirho(state_chirho)
                },
            )],
        }
    }
}

fn digest_chirho(number_chirho: u64) -> DigestChirho {
    DigestChirho(format!("{number_chirho:064x}"))
}

fn hlc_chirho(ms_chirho: u64) -> HlcChirho {
    HlcChirho {
        physical_ms_chirho: ms_chirho,
        logical_chirho: 0,
    }
}

fn source_event_ids_chirho(source_index_chirho: usize) -> [ModelF2EventIdChirho; 2] {
    match source_index_chirho {
        0 => [
            ModelF2EventIdChirho::A1Chirho,
            ModelF2EventIdChirho::A2Chirho,
        ],
        1 => [
            ModelF2EventIdChirho::B1Chirho,
            ModelF2EventIdChirho::B2Chirho,
        ],
        _ => unreachable!("bounded model has two sources"),
    }
}

fn verified_event_ids_chirho(
    verified_chirho: [u8; SOURCE_COUNT_CHIRHO],
) -> Vec<ModelF2EventIdChirho> {
    (0..SOURCE_COUNT_CHIRHO)
        .flat_map(|source_chirho| {
            source_event_ids_chirho(source_chirho)
                .into_iter()
                .take(usize::from(verified_chirho[source_chirho]))
        })
        .collect()
}

fn source_head_hlc_ms_chirho(source_index_chirho: usize, verified_chirho: u8) -> u64 {
    if verified_chirho == 0 {
        0
    } else {
        source_event_ids_chirho(source_index_chirho)[usize::from(verified_chirho - 1)]
            .hlc_ms_chirho()
    }
}

fn ready_arrival_trace_chirho(
    arrival_chirho: &[ModelF2EventIdChirho],
    verified_chirho: [u8; SOURCE_COUNT_CHIRHO],
    frontier_chirho: u64,
) -> Vec<ModelF2EventIdChirho> {
    arrival_chirho
        .iter()
        .copied()
        .filter(|event_chirho| {
            let source_chirho = usize::from(event_chirho.family_chirho() == SOURCE_B_CHIRHO);
            event_chirho.seq_chirho() <= verified_chirho[source_chirho]
                && event_chirho.hlc_ms_chirho() <= frontier_chirho
        })
        .collect()
}

fn apply_counts_chirho(trace_chirho: &[ModelF2EventIdChirho]) -> [u8; EVENT_COUNT_CHIRHO] {
    let mut counts_chirho = [0_u8; EVENT_COUNT_CHIRHO];
    for event_chirho in trace_chirho {
        counts_chirho[event_chirho.index_chirho()] += 1;
    }
    counts_chirho
}

fn event_precedes_chirho(
    trace_chirho: &[ModelF2EventIdChirho],
    first_chirho: ModelF2EventIdChirho,
    second_chirho: ModelF2EventIdChirho,
) -> bool {
    let first_index_chirho = trace_chirho
        .iter()
        .position(|event_chirho| *event_chirho == first_chirho);
    let second_index_chirho = trace_chirho
        .iter()
        .position(|event_chirho| *event_chirho == second_chirho);
    matches!((first_index_chirho, second_index_chirho), (Some(first_chirho), Some(second_chirho)) if first_chirho < second_chirho)
}

fn event_id_chirho(event_chirho: &ProjectionMergeEventChirho) -> ModelF2EventIdChirho {
    match (
        event_chirho.source_family_id_chirho.as_str(),
        event_chirho.source_seq_chirho,
    ) {
        (SOURCE_A_CHIRHO, 1) => ModelF2EventIdChirho::A1Chirho,
        (SOURCE_A_CHIRHO, 2) => ModelF2EventIdChirho::A2Chirho,
        (SOURCE_B_CHIRHO, 1) => ModelF2EventIdChirho::B1Chirho,
        (SOURCE_B_CHIRHO, 2) => ModelF2EventIdChirho::B2Chirho,
        _ => unreachable!("bounded model event is known"),
    }
}

fn source_prefixes_chirho(
    verified_chirho: [u8; SOURCE_COUNT_CHIRHO],
) -> [ProjectionMergeSourcePrefixChirho; SOURCE_COUNT_CHIRHO] {
    std::array::from_fn(|source_index_chirho| {
        let family_chirho = if source_index_chirho == 0 {
            SOURCE_A_CHIRHO
        } else {
            SOURCE_B_CHIRHO
        };
        let genesis_chirho = ProjectionWatermarkChirho {
            source_family_id_chirho: family_chirho.into(),
            source_seq_chirho: 0,
            source_hlc_chirho: hlc_chirho(0),
            signed_prefix_digest_chirho: digest_chirho(300 + source_index_chirho as u64),
        };
        let events_chirho = source_event_ids_chirho(source_index_chirho)
            .into_iter()
            .take(usize::from(verified_chirho[source_index_chirho]))
            .map(ModelF2EventIdChirho::event_chirho)
            .collect::<Vec<_>>();
        let verified_head_chirho = events_chirho.last().map_or_else(
            || VerifiedProjectionSourceHeadChirho {
                source_family_id_chirho: family_chirho.into(),
                source_seq_chirho: 0,
                source_hlc_chirho: genesis_chirho.source_hlc_chirho.clone(),
                signed_prefix_digest_chirho: genesis_chirho.signed_prefix_digest_chirho.clone(),
            },
            |event_chirho| VerifiedProjectionSourceHeadChirho {
                source_family_id_chirho: family_chirho.into(),
                source_seq_chirho: event_chirho.source_seq_chirho,
                source_hlc_chirho: event_chirho.source_hlc_chirho.clone(),
                signed_prefix_digest_chirho: event_chirho.signed_line_digest_chirho.clone(),
            },
        );
        ProjectionMergeSourcePrefixChirho {
            genesis_chirho,
            verified_head_chirho,
            events_chirho,
        }
    })
}

fn verified_model_descriptor_chirho() -> VerifiedProjectionDescriptorChirho {
    let sources_chirho = [SOURCE_A_CHIRHO, SOURCE_B_CHIRHO]
        .into_iter()
        .enumerate()
        .map(
            |(index_chirho, family_chirho)| VerifiedProjectionSourceChirho {
                binding_chirho: ProjectionSourceBindingChirho {
                    family_id_chirho: family_chirho.into(),
                    source_schema_ref_chirho: digest_chirho(400 + index_chirho as u64),
                },
                privacy_floor_chirho: PrivacyClassChirho::DirectChirho,
                privacy_evidence_ref_chirho: digest_chirho(410 + index_chirho as u64),
            },
        )
        .collect::<Vec<_>>();
    let privacy_evidence_ref_chirho =
        derive_projection_privacy_evidence_ref_chirho(&sources_chirho).unwrap();
    let descriptor_chirho = ProjectionDescriptorChirho {
        schema_chirho: PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO.into(),
        name_chirho: "model-f2-projection-chirho".into(),
        source_families_chirho: sources_chirho
            .iter()
            .map(|source_chirho| source_chirho.binding_chirho.clone())
            .collect(),
        fold_fn_ref_chirho: digest_chirho(420),
        staleness_contract_chirho: StalenessContractChirho {
            max_owner_hlc_lag_ms_chirho: 0,
            read_policy_chirho: ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        },
        cost_class_chirho: ProjectionCostClassChirho::StandingWriteRateChirho,
        privacy_floor_chirho: PrivacyClassChirho::DirectChirho,
        privacy_floor_evidence_ref_chirho: privacy_evidence_ref_chirho,
        rebuild_law_chirho: ProjectionRebuildLawChirho::DropAndRefoldChirho,
    };
    verify_projection_descriptor_chirho(descriptor_chirho, &sources_chirho).unwrap()
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use stateright::Checker;

    fn model_chirho(mutation_chirho: ModelF2MutationChirho) -> ModelF2Chirho {
        ModelF2Chirho {
            mutation_chirho,
            verified_descriptor_chirho: verified_model_descriptor_chirho(),
        }
    }

    #[test]
    fn model_f2_canonical_merge_survives_delay_crash_and_refold_chirho() {
        model_chirho(ModelF2MutationChirho::NoneChirho)
            .checker()
            .spawn_bfs()
            .join()
            .assert_properties();
    }

    #[test]
    fn model_f2_mutations_each_reach_the_divergence_the_guard_prevents_chirho() {
        for mutation_chirho in [
            ModelF2MutationChirho::ArrivalOrderChirho,
            ModelF2MutationChirho::BeyondMinFrontierChirho,
            ModelF2MutationChirho::OmittedSourceChirho,
            ModelF2MutationChirho::MissingTieBreakChirho,
            ModelF2MutationChirho::DuplicateApplyChirho,
            ModelF2MutationChirho::BrokenRefoldChirho,
        ] {
            model_chirho(mutation_chirho)
                .checker()
                .spawn_bfs()
                .join()
                .assert_properties();
        }
    }
}
