// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Canonical multi-source projection merge protocol.
//!
//! This module is a full-prefix correctness oracle, not the production hot-path adapter. The
//! adapter may stream or batch the same ordering law, but its output must equal this oracle at the
//! same exact source-vector cut.
//! Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf4-read-model-foundation-chirho.md`.

use crate::{
    descriptor_chirho::validate_digest_chirho, ProjectionWatermarkChirho,
    VerifiedProjectionDescriptorChirho, VerifiedProjectionSourceHeadChirho,
};
use anyhow::{bail, Result};
use cairn_ledger_model_chirho::{ids_chirho::DigestChirho, record_chirho::HlcChirho};

pub const PROJECTION_MERGE_PROTOCOL_V1_CHIRHO: &str = "merge-protocol-v1-chirho";

/// Metadata-only coordinate for one already verified signed source record.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProjectionMergeEventChirho {
    pub source_family_id_chirho: String,
    pub source_seq_chirho: u64,
    pub source_hlc_chirho: HlcChirho,
    pub signed_line_digest_chirho: DigestChirho,
}

/// The one total ordering key used by every multi-source projection.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProjectionMergeKeyChirho {
    pub source_hlc_chirho: HlcChirho,
    pub source_family_id_chirho: String,
    pub source_seq_chirho: u64,
    pub signed_line_digest_chirho: DigestChirho,
}

impl ProjectionMergeEventChirho {
    pub fn merge_key_chirho(&self) -> ProjectionMergeKeyChirho {
        ProjectionMergeKeyChirho {
            source_hlc_chirho: self.source_hlc_chirho.clone(),
            source_family_id_chirho: self.source_family_id_chirho.clone(),
            source_seq_chirho: self.source_seq_chirho,
            signed_line_digest_chirho: self.signed_line_digest_chirho.clone(),
        }
    }

    fn watermark_chirho(&self) -> ProjectionWatermarkChirho {
        ProjectionWatermarkChirho {
            source_family_id_chirho: self.source_family_id_chirho.clone(),
            source_seq_chirho: self.source_seq_chirho,
            source_hlc_chirho: self.source_hlc_chirho.clone(),
            signed_prefix_digest_chirho: self.signed_line_digest_chirho.clone(),
        }
    }
}

/// One complete verified record prefix for a descriptor source.
///
/// The production adapter owns signature, source-identity, segmented-seam RC.4b, and registry
/// verification. This pure oracle checks the exact descriptor set plus dense sequence, strict HLC,
/// digest grammar, and head equality before ordering records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionMergeSourcePrefixChirho {
    pub genesis_chirho: ProjectionWatermarkChirho,
    pub verified_head_chirho: VerifiedProjectionSourceHeadChirho,
    pub events_chirho: Vec<ProjectionMergeEventChirho>,
}

/// Canonical merged prefix at one exact vector of verified source heads.
///
/// This remains derived evidence and never becomes money authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalProjectionMergeChirho {
    pub protocol_chirho: &'static str,
    pub safe_frontier_hlc_chirho: HlcChirho,
    pub ordered_events_chirho: Vec<ProjectionMergeEventChirho>,
    pub applied_source_cursors_chirho: Vec<ProjectionWatermarkChirho>,
}

/// Merge complete source prefixes using the fixed closed-frontier protocol.
pub fn canonical_projection_merge_chirho(
    verified_descriptor_chirho: &VerifiedProjectionDescriptorChirho,
    source_prefixes_chirho: &[ProjectionMergeSourcePrefixChirho],
) -> Result<CanonicalProjectionMergeChirho> {
    let descriptor_sources_chirho = &verified_descriptor_chirho
        .descriptor_chirho()
        .source_families_chirho;
    if source_prefixes_chirho.len() != descriptor_sources_chirho.len() {
        bail!("merge source prefixes must exactly cover the descriptor source set");
    }

    for (binding_chirho, prefix_chirho) in
        descriptor_sources_chirho.iter().zip(source_prefixes_chirho)
    {
        validate_complete_source_prefix_chirho(&binding_chirho.family_id_chirho, prefix_chirho)?;
    }

    let safe_frontier_hlc_chirho = source_prefixes_chirho
        .iter()
        .map(|prefix_chirho| prefix_chirho.verified_head_chirho.source_hlc_chirho.clone())
        .min()
        .ok_or_else(|| anyhow::anyhow!("merge source set must be nonempty"))?;

    let mut ordered_events_chirho = source_prefixes_chirho
        .iter()
        .flat_map(|prefix_chirho| prefix_chirho.events_chirho.iter())
        .filter(|event_chirho| event_chirho.source_hlc_chirho <= safe_frontier_hlc_chirho)
        .cloned()
        .collect::<Vec<_>>();
    ordered_events_chirho.sort_by_key(ProjectionMergeEventChirho::merge_key_chirho);

    let applied_source_cursors_chirho = source_prefixes_chirho
        .iter()
        .map(|prefix_chirho| {
            prefix_chirho
                .events_chirho
                .iter()
                .take_while(|event_chirho| {
                    event_chirho.source_hlc_chirho <= safe_frontier_hlc_chirho
                })
                .last()
                .map_or_else(
                    || prefix_chirho.genesis_chirho.clone(),
                    ProjectionMergeEventChirho::watermark_chirho,
                )
        })
        .collect();

    Ok(CanonicalProjectionMergeChirho {
        protocol_chirho: PROJECTION_MERGE_PROTOCOL_V1_CHIRHO,
        safe_frontier_hlc_chirho,
        ordered_events_chirho,
        applied_source_cursors_chirho,
    })
}

fn validate_complete_source_prefix_chirho(
    expected_family_chirho: &str,
    prefix_chirho: &ProjectionMergeSourcePrefixChirho,
) -> Result<()> {
    if prefix_chirho.genesis_chirho.source_family_id_chirho != expected_family_chirho
        || prefix_chirho.verified_head_chirho.source_family_id_chirho != expected_family_chirho
    {
        bail!("merge source family does not match the descriptor");
    }
    if prefix_chirho.genesis_chirho.source_seq_chirho != 0 {
        bail!("merge source genesis cursor must have sequence zero");
    }
    validate_digest_chirho(
        "merge source genesis",
        &prefix_chirho.genesis_chirho.signed_prefix_digest_chirho,
    )?;
    validate_digest_chirho(
        "merge source verified head",
        &prefix_chirho
            .verified_head_chirho
            .signed_prefix_digest_chirho,
    )?;

    let expected_head_seq_chirho = u64::try_from(prefix_chirho.events_chirho.len())
        .map_err(|_| anyhow::anyhow!("merge source prefix length exceeds u64"))?;
    if prefix_chirho.verified_head_chirho.source_seq_chirho != expected_head_seq_chirho {
        bail!("merge source prefix is not complete through its verified head");
    }

    let mut previous_hlc_chirho = prefix_chirho.genesis_chirho.source_hlc_chirho.clone();
    for (index_chirho, event_chirho) in prefix_chirho.events_chirho.iter().enumerate() {
        let expected_seq_chirho = u64::try_from(index_chirho)
            .ok()
            .and_then(|index_chirho| index_chirho.checked_add(1))
            .ok_or_else(|| anyhow::anyhow!("merge source sequence exceeds u64"))?;
        if event_chirho.source_family_id_chirho != expected_family_chirho
            || event_chirho.source_seq_chirho != expected_seq_chirho
        {
            bail!("merge source events must be dense and family-bound");
        }
        if event_chirho.source_hlc_chirho <= previous_hlc_chirho {
            bail!("merge source HLC must be strictly monotone");
        }
        validate_digest_chirho(
            "merge source event",
            &event_chirho.signed_line_digest_chirho,
        )?;
        previous_hlc_chirho = event_chirho.source_hlc_chirho.clone();
    }

    if let Some(last_chirho) = prefix_chirho.events_chirho.last() {
        if last_chirho.source_hlc_chirho != prefix_chirho.verified_head_chirho.source_hlc_chirho
            || last_chirho.signed_line_digest_chirho
                != prefix_chirho
                    .verified_head_chirho
                    .signed_prefix_digest_chirho
        {
            bail!("merge source tail does not equal the verified head");
        }
    } else if prefix_chirho.genesis_chirho.source_hlc_chirho
        != prefix_chirho.verified_head_chirho.source_hlc_chirho
        || prefix_chirho.genesis_chirho.signed_prefix_digest_chirho
            != prefix_chirho
                .verified_head_chirho
                .signed_prefix_digest_chirho
    {
        bail!("empty merge source head must equal its genesis cursor");
    }
    Ok(())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::{
        derive_projection_privacy_evidence_ref_chirho, verify_projection_descriptor_chirho,
        ProjectionCostClassChirho, ProjectionDescriptorChirho, ProjectionReadPolicyChirho,
        ProjectionRebuildLawChirho, ProjectionSourceBindingChirho, StalenessContractChirho,
        VerifiedProjectionSourceChirho, PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO,
    };
    use cairn_model_privacy_chirho::PrivacyClassChirho;

    fn digest_chirho(number_chirho: u64) -> DigestChirho {
        DigestChirho(format!("{number_chirho:064x}"))
    }

    fn hlc_chirho(ms_chirho: u64) -> HlcChirho {
        HlcChirho {
            physical_ms_chirho: ms_chirho,
            logical_chirho: 0,
        }
    }

    fn verified_descriptor_chirho() -> VerifiedProjectionDescriptorChirho {
        let sources_chirho = ["a-source-chirho", "b-source-chirho"]
            .into_iter()
            .enumerate()
            .map(
                |(index_chirho, family_chirho)| VerifiedProjectionSourceChirho {
                    binding_chirho: ProjectionSourceBindingChirho {
                        family_id_chirho: family_chirho.into(),
                        source_schema_ref_chirho: digest_chirho(10 + index_chirho as u64),
                    },
                    privacy_floor_chirho: PrivacyClassChirho::SafeChirho,
                    privacy_evidence_ref_chirho: digest_chirho(20 + index_chirho as u64),
                },
            )
            .collect::<Vec<_>>();
        let privacy_ref_chirho =
            derive_projection_privacy_evidence_ref_chirho(&sources_chirho).unwrap();
        let descriptor_chirho = ProjectionDescriptorChirho {
            schema_chirho: PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO.into(),
            name_chirho: "merge-test-chirho".into(),
            source_families_chirho: sources_chirho
                .iter()
                .map(|source_chirho| source_chirho.binding_chirho.clone())
                .collect(),
            fold_fn_ref_chirho: digest_chirho(30),
            staleness_contract_chirho: StalenessContractChirho {
                max_owner_hlc_lag_ms_chirho: 5,
                read_policy_chirho: ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
            },
            cost_class_chirho: ProjectionCostClassChirho::StandingWriteRateChirho,
            privacy_floor_chirho: PrivacyClassChirho::SafeChirho,
            privacy_floor_evidence_ref_chirho: privacy_ref_chirho,
            rebuild_law_chirho: ProjectionRebuildLawChirho::DropAndRefoldChirho,
        };
        verify_projection_descriptor_chirho(descriptor_chirho, &sources_chirho).unwrap()
    }

    fn event_chirho(
        family_chirho: &str,
        seq_chirho: u64,
        ms_chirho: u64,
        digest_number_chirho: u64,
    ) -> ProjectionMergeEventChirho {
        ProjectionMergeEventChirho {
            source_family_id_chirho: family_chirho.into(),
            source_seq_chirho: seq_chirho,
            source_hlc_chirho: hlc_chirho(ms_chirho),
            signed_line_digest_chirho: digest_chirho(digest_number_chirho),
        }
    }

    fn prefix_chirho(
        family_chirho: &str,
        genesis_digest_chirho: u64,
        events_chirho: Vec<ProjectionMergeEventChirho>,
    ) -> ProjectionMergeSourcePrefixChirho {
        let genesis_chirho = ProjectionWatermarkChirho {
            source_family_id_chirho: family_chirho.into(),
            source_seq_chirho: 0,
            source_hlc_chirho: hlc_chirho(0),
            signed_prefix_digest_chirho: digest_chirho(genesis_digest_chirho),
        };
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
    }

    #[test]
    fn canonical_merge_closes_at_min_head_and_breaks_equal_hlc_by_family_chirho() {
        let descriptor_chirho = verified_descriptor_chirho();
        let prefixes_chirho = vec![
            prefix_chirho(
                "a-source-chirho",
                100,
                vec![
                    event_chirho("a-source-chirho", 1, 10, 101),
                    event_chirho("a-source-chirho", 2, 30, 102),
                ],
            ),
            prefix_chirho(
                "b-source-chirho",
                200,
                vec![
                    event_chirho("b-source-chirho", 1, 20, 201),
                    event_chirho("b-source-chirho", 2, 30, 202),
                ],
            ),
        ];
        let merged_chirho =
            canonical_projection_merge_chirho(&descriptor_chirho, &prefixes_chirho).unwrap();
        assert_eq!(merged_chirho.protocol_chirho, "merge-protocol-v1-chirho");
        assert_eq!(merged_chirho.safe_frontier_hlc_chirho, hlc_chirho(30));
        assert_eq!(
            merged_chirho
                .ordered_events_chirho
                .iter()
                .map(|event_chirho| (
                    event_chirho.source_family_id_chirho.as_str(),
                    event_chirho.source_seq_chirho
                ))
                .collect::<Vec<_>>(),
            vec![
                ("a-source-chirho", 1),
                ("b-source-chirho", 1),
                ("a-source-chirho", 2),
                ("b-source-chirho", 2),
            ]
        );
    }

    #[test]
    fn slow_or_empty_source_holds_the_closed_frontier_chirho() {
        let descriptor_chirho = verified_descriptor_chirho();
        let prefixes_chirho = vec![
            prefix_chirho(
                "a-source-chirho",
                100,
                vec![event_chirho("a-source-chirho", 1, 10, 101)],
            ),
            prefix_chirho("b-source-chirho", 200, vec![]),
        ];
        let merged_chirho =
            canonical_projection_merge_chirho(&descriptor_chirho, &prefixes_chirho).unwrap();
        assert_eq!(merged_chirho.safe_frontier_hlc_chirho, hlc_chirho(0));
        assert!(merged_chirho.ordered_events_chirho.is_empty());
        assert!(merged_chirho
            .applied_source_cursors_chirho
            .iter()
            .all(|cursor_chirho| cursor_chirho.source_seq_chirho == 0));
    }

    #[test]
    fn merge_refuses_missing_nondense_nonmonotone_or_head_divergent_sources_chirho() {
        let descriptor_chirho = verified_descriptor_chirho();
        let valid_a_chirho = prefix_chirho(
            "a-source-chirho",
            100,
            vec![event_chirho("a-source-chirho", 1, 10, 101)],
        );
        assert!(canonical_projection_merge_chirho(
            &descriptor_chirho,
            std::slice::from_ref(&valid_a_chirho)
        )
        .is_err());

        let mut bad_b_chirho = prefix_chirho(
            "b-source-chirho",
            200,
            vec![
                event_chirho("b-source-chirho", 1, 20, 201),
                event_chirho("b-source-chirho", 2, 30, 202),
            ],
        );
        bad_b_chirho.events_chirho[1].source_seq_chirho = 3;
        assert!(canonical_projection_merge_chirho(
            &descriptor_chirho,
            &[valid_a_chirho.clone(), bad_b_chirho]
        )
        .is_err());

        let mut bad_b_chirho = prefix_chirho(
            "b-source-chirho",
            200,
            vec![
                event_chirho("b-source-chirho", 1, 20, 201),
                event_chirho("b-source-chirho", 2, 30, 202),
            ],
        );
        bad_b_chirho.events_chirho[1].source_hlc_chirho = hlc_chirho(20);
        assert!(canonical_projection_merge_chirho(
            &descriptor_chirho,
            &[valid_a_chirho.clone(), bad_b_chirho]
        )
        .is_err());

        let mut bad_b_chirho = prefix_chirho(
            "b-source-chirho",
            200,
            vec![event_chirho("b-source-chirho", 1, 20, 201)],
        );
        bad_b_chirho
            .verified_head_chirho
            .signed_prefix_digest_chirho = digest_chirho(999);
        assert!(canonical_projection_merge_chirho(
            &descriptor_chirho,
            &[valid_a_chirho, bad_b_chirho]
        )
        .is_err());
    }
}
