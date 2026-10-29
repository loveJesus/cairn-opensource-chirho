// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Model F: single-source projector/follower safety under append, verification, crash, lag, and
//! drop/refold. Mutation modes expose one removed law at a time and use reachability properties so
//! the RED itself remains a green, load-bearing regression.
//! Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf4-read-model-foundation-chirho.md`.

use crate::{
    classify_follower_read_chirho, derive_projection_privacy_evidence_ref_chirho,
    verify_projection_descriptor_chirho, ProjectionCostClassChirho, ProjectionDescriptorChirho,
    ProjectionReadOutcomeChirho, ProjectionReadPolicyChirho, ProjectionRebuildLawChirho,
    ProjectionSourceBindingChirho, ProjectionWatermarkChirho, PublishedProjectionViewChirho,
    StalenessContractChirho, VerifiedProjectionDescriptorChirho, VerifiedProjectionReadCutChirho,
    VerifiedProjectionSourceChirho, VerifiedProjectionSourceHeadChirho,
    PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_model_chirho::{ids_chirho::DigestChirho, record_chirho::HlcChirho};
use cairn_model_privacy_chirho::PrivacyClassChirho;
use stateright::{Model, Property};

const SOURCE_FAMILY_CHIRHO: &str = "model-f-source-chirho";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModelFMutationChirho {
    NoneChirho,
    ReadAheadChirho,
    DuplicateApplyChirho,
    SilentStaleChirho,
    BrokenRebuildChirho,
    ServeScratchChirho,
    RegressWatermarkChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ModelFReadKindChirho {
    FreshChirho,
    DegradedChirho,
    RefusedChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ModelFReadObservationChirho {
    kind_chirho: ModelFReadKindChirho,
    served_value_chirho: Option<u16>,
    served_watermark_chirho: Option<usize>,
    lag_ms_chirho: u64,
    during_rebuild_chirho: bool,
    from_scratch_chirho: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ModelFRebuildChirho {
    target_watermark_chirho: usize,
    next_index_chirho: usize,
    scratch_value_chirho: u16,
    scratch_apply_counts_chirho: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ModelFStateChirho {
    owner_log_chirho: Vec<u8>,
    verified_prefix_chirho: usize,
    projector_alive_chirho: bool,
    published_value_chirho: u16,
    published_watermark_chirho: usize,
    previous_published_watermark_chirho: usize,
    published_apply_counts_chirho: Vec<u8>,
    rebuild_chirho: Option<ModelFRebuildChirho>,
    completed_rebuild_chirho: bool,
    restarted_after_crash_chirho: bool,
    last_read_chirho: Option<ModelFReadObservationChirho>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ModelFActionChirho {
    AppendChirho,
    VerifyNextChirho,
    ApplyNextChirho,
    DuplicateLastChirho,
    CrashChirho,
    RestartChirho,
    StartRebuildChirho,
    RebuildStepChirho,
    FinishRebuildChirho,
    ReadChirho,
}

struct ModelFChirho {
    max_records_chirho: usize,
    max_lag_ms_chirho: u64,
    read_policy_chirho: ProjectionReadPolicyChirho,
    mutation_chirho: ModelFMutationChirho,
    verified_descriptor_chirho: VerifiedProjectionDescriptorChirho,
}

impl ModelFChirho {
    fn expected_fold_chirho(state_chirho: &ModelFStateChirho, watermark_chirho: usize) -> u16 {
        state_chirho.owner_log_chirho[..watermark_chirho]
            .iter()
            .map(|value_chirho| u16::from(*value_chirho))
            .sum()
    }

    fn published_is_derivable_chirho(state_chirho: &ModelFStateChirho) -> bool {
        state_chirho.published_watermark_chirho <= state_chirho.verified_prefix_chirho
            && state_chirho.published_watermark_chirho <= state_chirho.owner_log_chirho.len()
            && state_chirho.published_value_chirho
                == Self::expected_fold_chirho(state_chirho, state_chirho.published_watermark_chirho)
    }

    fn apply_counts_are_exact_chirho(state_chirho: &ModelFStateChirho) -> bool {
        state_chirho
            .published_apply_counts_chirho
            .iter()
            .enumerate()
            .all(|(index_chirho, count_chirho)| {
                *count_chirho
                    == if index_chirho < state_chirho.published_watermark_chirho {
                        1
                    } else {
                        0
                    }
            })
    }

    fn read_is_derivable_and_disclosed_chirho(&self, state_chirho: &ModelFStateChirho) -> bool {
        let Some(read_chirho) = &state_chirho.last_read_chirho else {
            return true;
        };
        match read_chirho.kind_chirho {
            ModelFReadKindChirho::FreshChirho | ModelFReadKindChirho::DegradedChirho => {
                let Some(watermark_chirho) = read_chirho.served_watermark_chirho else {
                    return false;
                };
                let Some(value_chirho) = read_chirho.served_value_chirho else {
                    return false;
                };
                if watermark_chirho > state_chirho.verified_prefix_chirho
                    || value_chirho != Self::expected_fold_chirho(state_chirho, watermark_chirho)
                {
                    return false;
                }
                match read_chirho.kind_chirho {
                    ModelFReadKindChirho::FreshChirho => {
                        read_chirho.lag_ms_chirho <= self.max_lag_ms_chirho
                    }
                    ModelFReadKindChirho::DegradedChirho => {
                        self.read_policy_chirho
                            == ProjectionReadPolicyChirho::ServeDegradedWithLagChirho
                            && read_chirho.lag_ms_chirho > self.max_lag_ms_chirho
                    }
                    ModelFReadKindChirho::RefusedChirho => unreachable!(),
                }
            }
            ModelFReadKindChirho::RefusedChirho => {
                read_chirho.served_value_chirho.is_none()
                    && read_chirho.served_watermark_chirho.is_none()
            }
        }
    }

    fn old_or_refuse_chirho(state_chirho: &ModelFStateChirho) -> bool {
        state_chirho
            .last_read_chirho
            .as_ref()
            .is_none_or(|read_chirho| {
                !read_chirho.during_rebuild_chirho || !read_chirho.from_scratch_chirho
            })
    }

    fn make_read_observation_chirho(
        &self,
        state_chirho: &ModelFStateChirho,
    ) -> ModelFReadObservationChirho {
        let during_rebuild_chirho = state_chirho.rebuild_chirho.is_some();
        let use_scratch_chirho = self.mutation_chirho == ModelFMutationChirho::ServeScratchChirho
            && state_chirho
                .rebuild_chirho
                .as_ref()
                .is_some_and(|rebuild_chirho| rebuild_chirho.next_index_chirho > 0);
        let (value_chirho, watermark_chirho) = if use_scratch_chirho {
            let rebuild_chirho = state_chirho.rebuild_chirho.as_ref().unwrap();
            (
                rebuild_chirho.scratch_value_chirho,
                rebuild_chirho.next_index_chirho,
            )
        } else {
            (
                state_chirho.published_value_chirho,
                state_chirho.published_watermark_chirho,
            )
        };
        let view_chirho = PublishedProjectionViewChirho {
            descriptor_ref_chirho: self.verified_descriptor_chirho.digest_chirho().clone(),
            watermark_chirho: ProjectionWatermarkChirho {
                source_family_id_chirho: SOURCE_FAMILY_CHIRHO.into(),
                source_seq_chirho: watermark_chirho as u64,
                source_hlc_chirho: hlc_for_prefix_chirho(watermark_chirho),
                signed_prefix_digest_chirho: prefix_digest_chirho(watermark_chirho),
            },
            state_digest_chirho: value_digest_chirho(value_chirho),
        };
        let head_chirho = VerifiedProjectionSourceHeadChirho {
            source_family_id_chirho: SOURCE_FAMILY_CHIRHO.into(),
            source_seq_chirho: state_chirho.verified_prefix_chirho as u64,
            source_hlc_chirho: hlc_for_prefix_chirho(state_chirho.verified_prefix_chirho),
            signed_prefix_digest_chirho: prefix_digest_chirho(state_chirho.verified_prefix_chirho),
        };
        let verified_cut_chirho = VerifiedProjectionReadCutChirho {
            descriptor_ref_chirho: view_chirho.descriptor_ref_chirho.clone(),
            view_prefix_chirho: view_chirho.watermark_chirho.clone(),
            current_head_chirho: head_chirho,
        };
        let outcome_chirho = classify_follower_read_chirho(
            &view_chirho,
            &verified_cut_chirho,
            &self.verified_descriptor_chirho,
        );
        let actual_lag_chirho = (state_chirho
            .verified_prefix_chirho
            .saturating_sub(watermark_chirho) as u64)
            * 10;

        if self.mutation_chirho == ModelFMutationChirho::SilentStaleChirho
            && actual_lag_chirho > self.max_lag_ms_chirho
        {
            return ModelFReadObservationChirho {
                kind_chirho: ModelFReadKindChirho::FreshChirho,
                served_value_chirho: Some(value_chirho),
                served_watermark_chirho: Some(watermark_chirho),
                lag_ms_chirho: actual_lag_chirho,
                during_rebuild_chirho,
                from_scratch_chirho: use_scratch_chirho,
            };
        }

        match outcome_chirho {
            ProjectionReadOutcomeChirho::FreshChirho { lag_ms_chirho, .. } => {
                ModelFReadObservationChirho {
                    kind_chirho: ModelFReadKindChirho::FreshChirho,
                    served_value_chirho: Some(value_chirho),
                    served_watermark_chirho: Some(watermark_chirho),
                    lag_ms_chirho,
                    during_rebuild_chirho,
                    from_scratch_chirho: use_scratch_chirho,
                }
            }
            ProjectionReadOutcomeChirho::DegradedChirho { lag_ms_chirho, .. } => {
                ModelFReadObservationChirho {
                    kind_chirho: ModelFReadKindChirho::DegradedChirho,
                    served_value_chirho: Some(value_chirho),
                    served_watermark_chirho: Some(watermark_chirho),
                    lag_ms_chirho,
                    during_rebuild_chirho,
                    from_scratch_chirho: use_scratch_chirho,
                }
            }
            ProjectionReadOutcomeChirho::RefusedChirho(_) => ModelFReadObservationChirho {
                kind_chirho: ModelFReadKindChirho::RefusedChirho,
                served_value_chirho: None,
                served_watermark_chirho: None,
                lag_ms_chirho: actual_lag_chirho,
                during_rebuild_chirho,
                from_scratch_chirho: false,
            },
        }
    }
}

impl Model for ModelFChirho {
    type State = ModelFStateChirho;
    type Action = ModelFActionChirho;

    fn init_states(&self) -> Vec<Self::State> {
        vec![ModelFStateChirho {
            owner_log_chirho: Vec::new(),
            verified_prefix_chirho: 0,
            projector_alive_chirho: true,
            published_value_chirho: 0,
            published_watermark_chirho: 0,
            previous_published_watermark_chirho: 0,
            published_apply_counts_chirho: Vec::new(),
            rebuild_chirho: None,
            completed_rebuild_chirho: false,
            restarted_after_crash_chirho: false,
            last_read_chirho: None,
        }]
    }

    fn actions(&self, state_chirho: &Self::State, actions_chirho: &mut Vec<Self::Action>) {
        if state_chirho.owner_log_chirho.len() < self.max_records_chirho {
            actions_chirho.push(ModelFActionChirho::AppendChirho);
        }
        if state_chirho.verified_prefix_chirho < state_chirho.owner_log_chirho.len() {
            actions_chirho.push(ModelFActionChirho::VerifyNextChirho);
        }
        if state_chirho.projector_alive_chirho && state_chirho.rebuild_chirho.is_none() {
            let apply_limit_chirho =
                if self.mutation_chirho == ModelFMutationChirho::ReadAheadChirho {
                    state_chirho.owner_log_chirho.len()
                } else {
                    state_chirho.verified_prefix_chirho
                };
            if state_chirho.published_watermark_chirho < apply_limit_chirho {
                actions_chirho.push(ModelFActionChirho::ApplyNextChirho);
            }
            if self.mutation_chirho == ModelFMutationChirho::DuplicateApplyChirho
                && state_chirho.published_watermark_chirho > 0
            {
                actions_chirho.push(ModelFActionChirho::DuplicateLastChirho);
            }
            actions_chirho.push(ModelFActionChirho::StartRebuildChirho);
        }
        if state_chirho.projector_alive_chirho {
            actions_chirho.push(ModelFActionChirho::CrashChirho);
            if let Some(rebuild_chirho) = &state_chirho.rebuild_chirho {
                if rebuild_chirho.next_index_chirho < rebuild_chirho.target_watermark_chirho {
                    actions_chirho.push(ModelFActionChirho::RebuildStepChirho);
                } else {
                    actions_chirho.push(ModelFActionChirho::FinishRebuildChirho);
                }
            }
        } else {
            actions_chirho.push(ModelFActionChirho::RestartChirho);
        }
        actions_chirho.push(ModelFActionChirho::ReadChirho);
    }

    fn next_state(
        &self,
        state_chirho: &Self::State,
        action_chirho: Self::Action,
    ) -> Option<Self::State> {
        let mut next_chirho = state_chirho.clone();
        next_chirho.previous_published_watermark_chirho = state_chirho.published_watermark_chirho;
        match action_chirho {
            ModelFActionChirho::AppendChirho => {
                next_chirho
                    .owner_log_chirho
                    .push((next_chirho.owner_log_chirho.len() + 1) as u8);
                next_chirho.published_apply_counts_chirho.push(0);
                if let Some(rebuild_chirho) = &mut next_chirho.rebuild_chirho {
                    rebuild_chirho.scratch_apply_counts_chirho.push(0);
                }
            }
            ModelFActionChirho::VerifyNextChirho => {
                next_chirho.verified_prefix_chirho += 1;
            }
            ModelFActionChirho::ApplyNextChirho => {
                let index_chirho = next_chirho.published_watermark_chirho;
                next_chirho.published_value_chirho +=
                    u16::from(next_chirho.owner_log_chirho[index_chirho]);
                next_chirho.published_apply_counts_chirho[index_chirho] += 1;
                next_chirho.published_watermark_chirho += 1;
            }
            ModelFActionChirho::DuplicateLastChirho => {
                let index_chirho = next_chirho.published_watermark_chirho - 1;
                next_chirho.published_value_chirho +=
                    u16::from(next_chirho.owner_log_chirho[index_chirho]);
                next_chirho.published_apply_counts_chirho[index_chirho] += 1;
            }
            ModelFActionChirho::CrashChirho => {
                next_chirho.projector_alive_chirho = false;
            }
            ModelFActionChirho::RestartChirho => {
                next_chirho.projector_alive_chirho = true;
                next_chirho.restarted_after_crash_chirho = true;
            }
            ModelFActionChirho::StartRebuildChirho => {
                next_chirho.rebuild_chirho = Some(ModelFRebuildChirho {
                    target_watermark_chirho: if self.mutation_chirho
                        == ModelFMutationChirho::RegressWatermarkChirho
                        && next_chirho.published_watermark_chirho > 0
                    {
                        0
                    } else {
                        next_chirho.verified_prefix_chirho
                    },
                    next_index_chirho: 0,
                    scratch_value_chirho: 0,
                    scratch_apply_counts_chirho: vec![0; next_chirho.owner_log_chirho.len()],
                });
            }
            ModelFActionChirho::RebuildStepChirho => {
                let rebuild_chirho = next_chirho.rebuild_chirho.as_mut().unwrap();
                let index_chirho = rebuild_chirho.next_index_chirho;
                let multiplier_chirho =
                    if self.mutation_chirho == ModelFMutationChirho::BrokenRebuildChirho {
                        2
                    } else {
                        1
                    };
                rebuild_chirho.scratch_value_chirho +=
                    u16::from(next_chirho.owner_log_chirho[index_chirho]) * multiplier_chirho;
                rebuild_chirho.scratch_apply_counts_chirho[index_chirho] += multiplier_chirho as u8;
                rebuild_chirho.next_index_chirho += 1;
            }
            ModelFActionChirho::FinishRebuildChirho => {
                let rebuild_chirho = next_chirho.rebuild_chirho.take().unwrap();
                next_chirho.published_value_chirho = rebuild_chirho.scratch_value_chirho;
                next_chirho.published_watermark_chirho = rebuild_chirho.target_watermark_chirho;
                next_chirho.published_apply_counts_chirho =
                    rebuild_chirho.scratch_apply_counts_chirho;
                next_chirho.completed_rebuild_chirho = true;
            }
            ModelFActionChirho::ReadChirho => {
                next_chirho.last_read_chirho =
                    Some(self.make_read_observation_chirho(state_chirho));
            }
        }
        Some(next_chirho)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        match self.mutation_chirho {
            ModelFMutationChirho::NoneChirho => vec![
                Property::<Self>::always("rm1-published-derivable-chirho", |_, state_chirho| {
                    Self::published_is_derivable_chirho(state_chirho)
                }),
                Property::<Self>::always("rm2-no-double-apply-chirho", |_, state_chirho| {
                    Self::apply_counts_are_exact_chirho(state_chirho)
                }),
                Property::<Self>::always("rm2-watermark-monotone-chirho", |_, state_chirho| {
                    state_chirho.published_watermark_chirho
                        >= state_chirho.previous_published_watermark_chirho
                }),
                Property::<Self>::always(
                    "rm3-read-disclosure-chirho",
                    |model_chirho, state_chirho| {
                        model_chirho.read_is_derivable_and_disclosed_chirho(state_chirho)
                    },
                ),
                Property::<Self>::always("rm5-old-or-refuse-chirho", |_, state_chirho| {
                    Self::old_or_refuse_chirho(state_chirho)
                }),
                Property::<Self>::sometimes("fresh-read-reachable-chirho", |_, state_chirho| {
                    state_chirho
                        .last_read_chirho
                        .as_ref()
                        .is_some_and(|read_chirho| {
                            read_chirho.kind_chirho == ModelFReadKindChirho::FreshChirho
                        })
                }),
                Property::<Self>::sometimes(
                    "stale-outcome-reachable-chirho",
                    |model_chirho, state_chirho| {
                        state_chirho
                            .last_read_chirho
                            .as_ref()
                            .is_some_and(|read_chirho| match model_chirho.read_policy_chirho {
                                ProjectionReadPolicyChirho::RefuseWhenStaleChirho => {
                                    read_chirho.kind_chirho == ModelFReadKindChirho::RefusedChirho
                                        && read_chirho.lag_ms_chirho
                                            > model_chirho.max_lag_ms_chirho
                                }
                                ProjectionReadPolicyChirho::ServeDegradedWithLagChirho => {
                                    read_chirho.kind_chirho == ModelFReadKindChirho::DegradedChirho
                                }
                            })
                    },
                ),
                Property::<Self>::sometimes("rebuild-byte-equivalent-chirho", |_, state_chirho| {
                    state_chirho.completed_rebuild_chirho
                        && Self::published_is_derivable_chirho(state_chirho)
                        && Self::apply_counts_are_exact_chirho(state_chirho)
                }),
                Property::<Self>::sometimes(
                    "post-restart-catch-up-reachable-chirho",
                    |_, state_chirho| {
                        state_chirho.restarted_after_crash_chirho
                            && state_chirho.verified_prefix_chirho > 0
                            && state_chirho.published_watermark_chirho
                                == state_chirho.verified_prefix_chirho
                            && Self::published_is_derivable_chirho(state_chirho)
                    },
                ),
                Property::<Self>::sometimes(
                    "read-during-rebuild-is-old-or-refused-chirho",
                    |_, state_chirho| {
                        state_chirho
                            .last_read_chirho
                            .as_ref()
                            .is_some_and(|read_chirho| {
                                read_chirho.during_rebuild_chirho
                                    && !read_chirho.from_scratch_chirho
                            })
                    },
                ),
            ],
            ModelFMutationChirho::ReadAheadChirho => vec![Property::<Self>::sometimes(
                "read-ahead-beyond-verified-prefix-reachable-chirho",
                |_, state_chirho| {
                    state_chirho.published_watermark_chirho > state_chirho.verified_prefix_chirho
                },
            )],
            ModelFMutationChirho::DuplicateApplyChirho => vec![Property::<Self>::sometimes(
                "duplicate-apply-divergence-reachable-chirho",
                |_, state_chirho| {
                    !Self::published_is_derivable_chirho(state_chirho)
                        && !Self::apply_counts_are_exact_chirho(state_chirho)
                },
            )],
            ModelFMutationChirho::SilentStaleChirho => vec![Property::<Self>::sometimes(
                "silent-stale-fresh-label-reachable-chirho",
                |model_chirho, state_chirho| {
                    state_chirho
                        .last_read_chirho
                        .as_ref()
                        .is_some_and(|read_chirho| {
                            read_chirho.kind_chirho == ModelFReadKindChirho::FreshChirho
                                && read_chirho.lag_ms_chirho > model_chirho.max_lag_ms_chirho
                        })
                },
            )],
            ModelFMutationChirho::BrokenRebuildChirho => vec![Property::<Self>::sometimes(
                "non-equivalent-rebuild-reachable-chirho",
                |_, state_chirho| {
                    state_chirho.completed_rebuild_chirho
                        && !Self::published_is_derivable_chirho(state_chirho)
                },
            )],
            ModelFMutationChirho::ServeScratchChirho => vec![Property::<Self>::sometimes(
                "partial-rebuild-read-reachable-chirho",
                |_, state_chirho| {
                    state_chirho
                        .last_read_chirho
                        .as_ref()
                        .is_some_and(|read_chirho| {
                            read_chirho.during_rebuild_chirho && read_chirho.from_scratch_chirho
                        })
                },
            )],
            ModelFMutationChirho::RegressWatermarkChirho => vec![Property::<Self>::sometimes(
                "published-watermark-regression-reachable-chirho",
                |_, state_chirho| {
                    state_chirho.published_watermark_chirho
                        < state_chirho.previous_published_watermark_chirho
                },
            )],
        }
    }
}

fn hlc_for_prefix_chirho(prefix_chirho: usize) -> HlcChirho {
    HlcChirho {
        physical_ms_chirho: (prefix_chirho as u64) * 10,
        logical_chirho: 0,
    }
}

fn prefix_digest_chirho(prefix_chirho: usize) -> DigestChirho {
    DigestChirho(format!("{:064x}", prefix_chirho + 1))
}

fn value_digest_chirho(value_chirho: u16) -> DigestChirho {
    DigestChirho(format!("{:064x}", u64::from(value_chirho) + 1_000))
}

fn verified_model_descriptor_chirho(
    max_lag_ms_chirho: u64,
    read_policy_chirho: ProjectionReadPolicyChirho,
) -> VerifiedProjectionDescriptorChirho {
    let sources_chirho = vec![VerifiedProjectionSourceChirho {
        binding_chirho: ProjectionSourceBindingChirho {
            family_id_chirho: SOURCE_FAMILY_CHIRHO.into(),
            source_schema_ref_chirho: prefix_digest_chirho(90),
        },
        privacy_floor_chirho: PrivacyClassChirho::SafeChirho,
        privacy_evidence_ref_chirho: prefix_digest_chirho(91),
    }];
    let privacy_evidence_ref_chirho =
        derive_projection_privacy_evidence_ref_chirho(&sources_chirho).unwrap();
    let descriptor_chirho = ProjectionDescriptorChirho {
        schema_chirho: PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO.into(),
        name_chirho: "model-f-projection-chirho".into(),
        source_families_chirho: sources_chirho
            .iter()
            .map(|source_chirho| source_chirho.binding_chirho.clone())
            .collect(),
        fold_fn_ref_chirho: prefix_digest_chirho(92),
        staleness_contract_chirho: StalenessContractChirho {
            max_owner_hlc_lag_ms_chirho: max_lag_ms_chirho,
            read_policy_chirho,
        },
        cost_class_chirho: ProjectionCostClassChirho::StandingWriteRateChirho,
        privacy_floor_chirho: PrivacyClassChirho::SafeChirho,
        privacy_floor_evidence_ref_chirho: privacy_evidence_ref_chirho,
        rebuild_law_chirho: ProjectionRebuildLawChirho::DropAndRefoldChirho,
    };
    verify_projection_descriptor_chirho(descriptor_chirho, &sources_chirho).unwrap()
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use stateright::Checker;

    fn model_chirho(
        read_policy_chirho: ProjectionReadPolicyChirho,
        mutation_chirho: ModelFMutationChirho,
    ) -> ModelFChirho {
        ModelFChirho {
            max_records_chirho: 3,
            max_lag_ms_chirho: 0,
            read_policy_chirho,
            mutation_chirho,
            verified_descriptor_chirho: verified_model_descriptor_chirho(0, read_policy_chirho),
        }
    }

    #[test]
    fn model_f_refuse_when_stale_satisfies_rm1_through_rm5_chirho() {
        model_chirho(
            ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
            ModelFMutationChirho::NoneChirho,
        )
        .checker()
        .spawn_bfs()
        .join()
        .assert_properties();
    }

    #[test]
    fn model_f_degraded_reads_are_explicit_and_exact_chirho() {
        model_chirho(
            ProjectionReadPolicyChirho::ServeDegradedWithLagChirho,
            ModelFMutationChirho::NoneChirho,
        )
        .checker()
        .spawn_bfs()
        .join()
        .assert_properties();
    }

    #[test]
    fn model_f_mutations_each_reach_the_violation_the_guard_prevents_chirho() {
        for mutation_chirho in [
            ModelFMutationChirho::ReadAheadChirho,
            ModelFMutationChirho::DuplicateApplyChirho,
            ModelFMutationChirho::SilentStaleChirho,
            ModelFMutationChirho::BrokenRebuildChirho,
            ModelFMutationChirho::ServeScratchChirho,
            ModelFMutationChirho::RegressWatermarkChirho,
        ] {
            model_chirho(
                ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
                mutation_chirho,
            )
            .checker()
            .spawn_bfs()
            .join()
            .assert_properties();
        }
    }
}
