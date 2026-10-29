// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The composition surfaces: WRITE (journal open with the optional F3a finality seam) and READ
//! (registries → evidence resolution → feed → publish → load → serve, with the config and feeder
//! authorities held as distinct injected identities).

use anyhow::{bail, Context, Result};
use cairn_ledger_conservation_monitor_chirho::model_chirho::{
    ConservationDomainIdChirho, ConservationHeadCoordinateChirho,
    HeadConsistentConservationSnapshotChirho,
};
use cairn_ledger_conservation_monitor_chirho::ports_chirho::VerifiedConservationSnapshotPortChirho;
use cairn_ledger_log_chirho::admission_chirho::FinalityAdmissionViewsChirho;
use cairn_ledger_log_chirho::journal_chirho::{
    JournalErrorChirho, JournalPortsChirho, LedgerJournalChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{LedgerSignerPortChirho, StoragePathChirho};
use cairn_ledger_log_chirho::recompose_chirho::read_recomposed_journal_lines_chirho;
use cairn_ledger_model_chirho::ids_chirho::{ClusterIdChirho, DigestChirho, MoneyGroupIdChirho};
use cairn_ledger_model_chirho::wire_chirho::{
    parse_canonical_ledger_journal_line_chirho, LedgerJournalLineChirho,
};
use cairn_ledger_money_audit_chirho::snapshot_adapter_chirho::derive_conservation_snapshot_chirho;
use cairn_ledger_read_model_chirho::feeder_chirho::{
    feed_projection_once_chirho, MaterializedProjectionChirho, ProjectionFoldPortChirho,
    ProjectionSourceChirho,
};
use cairn_ledger_read_model_chirho::publication_chirho::{
    load_published_projection_chirho, publish_projection_chirho,
};
use cairn_ledger_read_model_chirho::registry_chirho::{
    append_projection_registry_op_chirho, load_verified_projection_registry_chirho,
    ProjectionRegistryOpChirho, VerifiedProjectionRegistryChirho,
};
use cairn_ledger_read_model_chirho::serving_chirho::{
    serve_effect_host_follower_read_chirho, serve_follower_read_chirho, FollowerServeOutcomeChirho,
};
use cairn_ledger_read_model_chirho::source_registry_chirho::{
    append_source_registry_op_chirho, load_verified_source_registry_chirho,
    resolve_projection_sources_chirho, SourceRegistryOpChirho,
};
use cairn_ledger_read_model_chirho::ProjectionCostClassChirho;

/// The WRITE-side composition: the journal ports plus the OPTIONAL F3a finality views. An
/// un-wired composition (`finality_chirho: None`) keeps the counterpart Transfer row
/// ExplicitlyUnsupported at admission (law v) — the seam's absence refuses, never default-opens.
pub struct LedgerWriteCompositionChirho<'ports_chirho> {
    pub journal_ports_chirho: JournalPortsChirho<'ports_chirho>,
    pub finality_chirho: Option<FinalityAdmissionViewsChirho<'ports_chirho>>,
}

impl<'ports_chirho> LedgerWriteCompositionChirho<'ports_chirho> {
    /// Open (verified) an existing cluster journal, wiring the finality seam when composed.
    pub fn open_journal_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        cluster_chirho: &ClusterIdChirho,
    ) -> Result<LedgerJournalChirho<'ports_chirho>> {
        let journal_chirho = LedgerJournalChirho::open_chirho(
            self.journal_ports_chirho,
            path_chirho.clone(),
            cluster_chirho,
        )
        .map_err(|error_chirho| anyhow::anyhow!("verified open failed: {error_chirho:?}"))?;
        Ok(match self.finality_chirho {
            Some(views_chirho) => journal_chirho.with_finality_views_chirho(views_chirho),
            None => journal_chirho,
        })
    }

    /// Create a fresh cluster journal (genesis), wiring the finality seam when composed.
    pub fn create_journal_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        cluster_chirho: ClusterIdChirho,
        epoch_chirho: u64,
    ) -> Result<LedgerJournalChirho<'ports_chirho>> {
        let journal_chirho = LedgerJournalChirho::create_chirho(
            self.journal_ports_chirho,
            path_chirho.clone(),
            cluster_chirho,
            epoch_chirho,
        )
        .map_err(|error_chirho| anyhow::anyhow!("genesis create failed: {error_chirho:?}"))?;
        Ok(match self.finality_chirho {
            Some(views_chirho) => journal_chirho.with_finality_views_chirho(views_chirho),
            None => journal_chirho,
        })
    }
}

/// The READ-side composition: the two config chains under the CONFIG root, the feeder root, and
/// the paths/identities that name them. Evidence is always RESOLVED from the signed source
/// registry — no caller-supplied privacy floors exist on this surface at all.
pub struct LedgerReadCompositionChirho<'ports_chirho> {
    pub journal_ports_chirho: JournalPortsChirho<'ports_chirho>,
    pub config_root_chirho: &'ports_chirho dyn LedgerSignerPortChirho,
    pub feeder_root_chirho: &'ports_chirho dyn LedgerSignerPortChirho,
    pub projection_registry_path_chirho: StoragePathChirho,
    pub projection_registry_id_chirho: String,
    pub source_registry_path_chirho: StoragePathChirho,
    pub source_registry_id_chirho: String,
}

#[derive(Clone, Copy)]
enum ProjectionReadFreshnessPostureChirho {
    LagWindowChirho,
    EffectHostExactCutChirho,
}

/// One composed published-projection observation after the full CF4 verification ladder.
///
/// View bytes exist only for Fresh/Degraded reads. Both classifier and gate refusals carry no
/// bytes, so a caller cannot accidentally serve data the read law refused. The cost class exists
/// only after the descriptor reached the verified classifier path; it is never inferred for a
/// pre-classifier gate refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComposedProjectionReadChirho {
    pub view_bytes_chirho: Option<Vec<u8>>,
    pub verified_cost_class_chirho: Option<ProjectionCostClassChirho>,
    pub outcome_chirho: FollowerServeOutcomeChirho,
}

impl LedgerReadCompositionChirho<'_> {
    /// Append one PROJECTION registry op under the config root.
    pub fn append_projection_op_chirho(&self, op_chirho: ProjectionRegistryOpChirho) -> Result<()> {
        append_projection_registry_op_chirho(
            self.journal_ports_chirho.storage_chirho,
            self.config_root_chirho,
            &self.projection_registry_path_chirho,
            &self.projection_registry_id_chirho,
            op_chirho,
        )
        .map(|_| ())
    }

    /// Append one SOURCE registry op under the config root.
    pub fn append_source_op_chirho(&self, op_chirho: SourceRegistryOpChirho) -> Result<()> {
        append_source_registry_op_chirho(
            self.journal_ports_chirho.storage_chirho,
            self.config_root_chirho,
            &self.source_registry_path_chirho,
            &self.source_registry_id_chirho,
            op_chirho,
        )
        .map(|_| ())
    }

    fn load_projection_registry_chirho(&self) -> Result<VerifiedProjectionRegistryChirho> {
        load_verified_projection_registry_chirho(
            self.journal_ports_chirho.storage_chirho,
            self.config_root_chirho,
            &self.projection_registry_path_chirho,
            &self.projection_registry_id_chirho,
        )
    }

    /// FEED one registered state projection from its live verified source and PUBLISH it
    /// (old-or-refuse: CAS bytes then the atomic receipt commit). Evidence is resolved from the
    /// signed source registry and the descriptor re-verified against it before any fold runs.
    pub fn feed_and_publish_chirho(
        &self,
        projection_name_chirho: &str,
        descriptor_digest_chirho: &DigestChirho,
        fold_chirho: &dyn ProjectionFoldPortChirho,
        source_chirho: ProjectionSourceChirho<'_>,
        head_path_chirho: &StoragePathChirho,
    ) -> Result<MaterializedProjectionChirho> {
        let projection_registry_chirho = self.load_projection_registry_chirho()?;
        let materialized_chirho = feed_projection_once_chirho(
            &projection_registry_chirho,
            projection_name_chirho,
            descriptor_digest_chirho,
            fold_chirho,
            source_chirho,
            self.feeder_root_chirho,
        )?;
        publish_projection_chirho(
            self.journal_ports_chirho.storage_chirho,
            &materialized_chirho,
            head_path_chirho,
        )
        .context("publish after feed")?;
        Ok(materialized_chirho)
    }

    /// LOAD the published head and SERVE it through the full gate ladder, resolving descriptor
    /// evidence from the signed source registry (never caller-supplied).
    pub fn load_and_serve_chirho(
        &self,
        head_path_chirho: &StoragePathChirho,
        source_chirho: ProjectionSourceChirho<'_>,
    ) -> Result<FollowerServeOutcomeChirho> {
        self.load_and_serve_with_view_chirho(head_path_chirho, source_chirho)
            .map(|read_chirho| read_chirho.outcome_chirho)
    }

    /// LOAD the published head and return the exact view bytes only when the full serve ladder
    /// classifies them Fresh/Degraded. This is the root-runtime port seam: verdicts stay typed,
    /// refusals carry no view, and the verified descriptor cost class accompanies classifier
    /// outcomes so the caller can allowlist its read-time charging posture without inference.
    pub fn load_and_serve_with_view_chirho(
        &self,
        head_path_chirho: &StoragePathChirho,
        source_chirho: ProjectionSourceChirho<'_>,
    ) -> Result<ComposedProjectionReadChirho> {
        self.load_and_serve_with_expected_name_chirho(
            None,
            head_path_chirho,
            source_chirho,
            ProjectionReadFreshnessPostureChirho::LagWindowChirho,
        )
    }

    /// The host-owned route variant. A configured projection name may open only a head whose
    /// signed receipt names that same projection; a valid foreign head is not a route alias.
    pub fn load_named_and_serve_with_view_chirho(
        &self,
        expected_projection_name_chirho: &str,
        head_path_chirho: &StoragePathChirho,
        source_chirho: ProjectionSourceChirho<'_>,
    ) -> Result<ComposedProjectionReadChirho> {
        self.load_and_serve_with_expected_name_chirho(
            Some(expected_projection_name_chirho),
            head_path_chirho,
            source_chirho,
            ProjectionReadFreshnessPostureChirho::LagWindowChirho,
        )
    }

    /// The effect-enabled host variant. Only a would-be Fresh result is tightened: its published
    /// cut must exactly equal the durable journal cut because this same host owns local writes.
    pub fn load_named_and_serve_with_view_exact_cut_chirho(
        &self,
        expected_projection_name_chirho: &str,
        head_path_chirho: &StoragePathChirho,
        source_chirho: ProjectionSourceChirho<'_>,
    ) -> Result<ComposedProjectionReadChirho> {
        self.load_and_serve_with_expected_name_chirho(
            Some(expected_projection_name_chirho),
            head_path_chirho,
            source_chirho,
            ProjectionReadFreshnessPostureChirho::EffectHostExactCutChirho,
        )
    }

    fn load_and_serve_with_expected_name_chirho(
        &self,
        expected_projection_name_chirho: Option<&str>,
        head_path_chirho: &StoragePathChirho,
        source_chirho: ProjectionSourceChirho<'_>,
        freshness_posture_chirho: ProjectionReadFreshnessPostureChirho,
    ) -> Result<ComposedProjectionReadChirho> {
        let materialized_chirho = load_published_projection_chirho(
            self.journal_ports_chirho.storage_chirho,
            head_path_chirho,
            self.feeder_root_chirho,
        )?;
        if expected_projection_name_chirho.is_some_and(|expected_chirho| {
            expected_chirho != materialized_chirho.receipt_chirho.projection_name_chirho
        }) {
            bail!("configured projection route does not match the published head receipt");
        }
        let projection_registry_chirho = self.load_projection_registry_chirho()?;
        let source_registry_chirho = load_verified_source_registry_chirho(
            self.journal_ports_chirho.storage_chirho,
            self.config_root_chirho,
            &self.source_registry_path_chirho,
            &self.source_registry_id_chirho,
        )?;
        // Resolve evidence for the RECEIPT's descriptor as the registry currently resolves it;
        // the serve gates then re-verify descriptor identity, evidence binding, and staleness.
        let receipt_name_chirho = &materialized_chirho.receipt_chirho.projection_name_chirho;
        let receipt_digest_chirho = &materialized_chirho.receipt_chirho.descriptor_digest_chirho;
        let descriptor_chirho = match projection_registry_chirho
            .resolve_chirho(receipt_name_chirho, receipt_digest_chirho)
        {
            cairn_ledger_read_model_chirho::registry_chirho::ProjectionResolutionChirho::CurrentChirho {
                descriptor_chirho,
            } => descriptor_chirho,
            _ => {
                // Let the serve gates own the typed refusal; resolution here only needs to know
                // there is no CURRENT descriptor to resolve evidence FOR.
                let outcome_chirho = match freshness_posture_chirho {
                    ProjectionReadFreshnessPostureChirho::LagWindowChirho => {
                        serve_follower_read_chirho(
                            &projection_registry_chirho,
                            &materialized_chirho,
                            self.feeder_root_chirho,
                            &[],
                            source_chirho,
                        )?
                    }
                    ProjectionReadFreshnessPostureChirho::EffectHostExactCutChirho => {
                        serve_effect_host_follower_read_chirho(
                            &projection_registry_chirho,
                            &materialized_chirho,
                            self.feeder_root_chirho,
                            &[],
                            source_chirho,
                        )?
                    }
                };
                return Ok(composed_projection_read_chirho(
                    &materialized_chirho,
                    None,
                    outcome_chirho,
                ));
            }
        };
        let cost_class_chirho = descriptor_chirho.cost_class_chirho;
        let resolved_chirho =
            resolve_projection_sources_chirho(&source_registry_chirho, &descriptor_chirho)?;
        let outcome_chirho = match freshness_posture_chirho {
            ProjectionReadFreshnessPostureChirho::LagWindowChirho => serve_follower_read_chirho(
                &projection_registry_chirho,
                &materialized_chirho,
                self.feeder_root_chirho,
                &resolved_chirho,
                source_chirho,
            )?,
            ProjectionReadFreshnessPostureChirho::EffectHostExactCutChirho => {
                serve_effect_host_follower_read_chirho(
                    &projection_registry_chirho,
                    &materialized_chirho,
                    self.feeder_root_chirho,
                    &resolved_chirho,
                    source_chirho,
                )?
            }
        };
        Ok(composed_projection_read_chirho(
            &materialized_chirho,
            Some(cost_class_chirho),
            outcome_chirho,
        ))
    }
}

fn composed_projection_read_chirho(
    materialized_chirho: &MaterializedProjectionChirho,
    current_cost_class_chirho: Option<ProjectionCostClassChirho>,
    outcome_chirho: FollowerServeOutcomeChirho,
) -> ComposedProjectionReadChirho {
    let classifier_ran_chirho = matches!(outcome_chirho, FollowerServeOutcomeChirho::ReadChirho(_));
    let serves_view_chirho = matches!(
        outcome_chirho,
        FollowerServeOutcomeChirho::ReadChirho(
            cairn_ledger_read_model_chirho::follower_chirho::ProjectionReadOutcomeChirho::FreshChirho { .. }
                | cairn_ledger_read_model_chirho::follower_chirho::ProjectionReadOutcomeChirho::DegradedChirho { .. }
        )
    );
    ComposedProjectionReadChirho {
        view_bytes_chirho: serves_view_chirho
            .then(|| materialized_chirho.view_bytes_chirho.clone()),
        verified_cost_class_chirho: classifier_ran_chirho
            .then_some(current_cost_class_chirho)
            .flatten(),
        outcome_chirho,
    }
}

/// Pairwise KEY-EXCLUSIVITY check over a set of named signer identities: every identity's
/// signature must verify under ITSELF and refuse under EVERY other. The composition demo calls
/// this across journal/config/feeder(/finality-source) roots at startup — a shared or copied key
/// is a composition defect caught before any record is written.
pub fn assert_distinct_key_identities_chirho(
    identities_chirho: &[(&str, &dyn LedgerSignerPortChirho)],
) -> Result<()> {
    for (name_chirho, signer_chirho) in identities_chirho {
        let probe_chirho = format!("key-identity-probe:{name_chirho}");
        let sig_chirho = signer_chirho
            .sign_chirho(&probe_chirho)
            .map_err(|error_chirho| anyhow::anyhow!("probe sign failed: {error_chirho}"))?;
        if !signer_chirho.verify_chirho(&probe_chirho, &sig_chirho) {
            bail!("identity {name_chirho} does not verify its own signature");
        }
        for (other_name_chirho, other_chirho) in identities_chirho {
            if name_chirho == other_name_chirho {
                continue;
            }
            if other_chirho.verify_chirho(&probe_chirho, &sig_chirho) {
                bail!(
                    "identity {other_name_chirho} verifies a signature by {name_chirho} — \
                     distinct authorities must never share keys"
                );
            }
        }
    }
    Ok(())
}

/// The §4 canary-and-heal outcome: every path is TYPED evidence, and a divergence is never left
/// serving (the "rebuild + alarm, never serve" law operationalized at the composition level).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanaryOutcomeChirho {
    /// The published view byte-equals the independent re-fold at the same cut.
    CleanChirho,
    /// The source moved past the published cut (or nothing was published yet): a fresh feed was
    /// published — the honest refresh, not a divergence.
    RefreshedChirho { published_seq_chirho: u64 },
    /// THE CANARY FIRED: the published view diverged from the independent re-fold at the SAME
    /// cut. The divergent view was replaced by the honest re-fold and both digests are evidence
    /// for the alarm the caller must raise (observational boundary: halt/page, never gate money).
    HealedDivergenceChirho {
        divergent_view_digest_chirho: String,
        healed_view_digest_chirho: String,
        at_seq_chirho: u64,
    },
}

impl LedgerReadCompositionChirho<'_> {
    /// Run the equivalence canary against the PUBLISHED head and HEAL what it finds: a clean
    /// match reports Clean; a moved source re-feeds and re-publishes (Refreshed); a divergence at
    /// the same cut re-publishes the honest re-fold and reports the alarm evidence
    /// (HealedDivergence). A missing published head is first publication (Refreshed).
    pub fn canary_and_heal_chirho(
        &self,
        projection_name_chirho: &str,
        descriptor_digest_chirho: &DigestChirho,
        fold_chirho: &dyn ProjectionFoldPortChirho,
        source_chirho: ProjectionSourceChirho<'_>,
        head_path_chirho: &StoragePathChirho,
    ) -> Result<CanaryOutcomeChirho> {
        let published_chirho = match load_published_projection_chirho(
            self.journal_ports_chirho.storage_chirho,
            head_path_chirho,
            self.feeder_root_chirho,
        ) {
            Ok(materialized_chirho) => Some(materialized_chirho),
            // No head object yet = first publication; every OTHER load failure is evidence
            // breakage and must surface, never be silently healed over.
            Err(error_chirho)
                if error_chirho.to_string().contains("missing")
                    || error_chirho
                        .chain()
                        .any(|cause_chirho| cause_chirho.to_string().contains("missing")) =>
            {
                None
            }
            Err(error_chirho) => return Err(error_chirho.context("published head load")),
        };
        let fresh_chirho = self.feed_and_publish_chirho(
            projection_name_chirho,
            descriptor_digest_chirho,
            fold_chirho,
            source_chirho,
            head_path_chirho,
        )?;
        let Some(published_chirho) = published_chirho else {
            return Ok(CanaryOutcomeChirho::RefreshedChirho {
                published_seq_chirho: fresh_chirho.receipt_chirho.source_tail_seq_chirho,
            });
        };
        if published_chirho.receipt_chirho.source_tail_seq_chirho
            != fresh_chirho.receipt_chirho.source_tail_seq_chirho
            || published_chirho.receipt_chirho.source_genesis_digest_chirho
                != fresh_chirho.receipt_chirho.source_genesis_digest_chirho
        {
            return Ok(CanaryOutcomeChirho::RefreshedChirho {
                published_seq_chirho: fresh_chirho.receipt_chirho.source_tail_seq_chirho,
            });
        }
        if published_chirho.view_bytes_chirho == fresh_chirho.view_bytes_chirho {
            return Ok(CanaryOutcomeChirho::CleanChirho);
        }
        // SAME cut, DIFFERENT bytes: the published view was lying. The honest re-fold is already
        // republished (feed_and_publish above overwrote the head — heal preceded the verdict by
        // construction), so report the alarm evidence.
        Ok(CanaryOutcomeChirho::HealedDivergenceChirho {
            divergent_view_digest_chirho: published_chirho
                .receipt_chirho
                .view_digest_hex_chirho
                .clone(),
            healed_view_digest_chirho: fresh_chirho.receipt_chirho.view_digest_hex_chirho.clone(),
            at_seq_chirho: fresh_chirho.receipt_chirho.source_tail_seq_chirho,
        })
    }
}

/// Conservation snapshot source over ONE verified cluster journal — the #5298 wiring split made
/// concrete: audit DERIVES (pure, two independent paths), the monitor CHECKS, and this newtype
/// only wires. The port's verify-before-return contract is met by pairing the journal's VERIFIED
/// open (chain/signature/canonical law over the whole log) with the recomposed line walk
/// re-parsed through the canonical router (every record re-passes the J0a byte law), and a
/// count-vs-verified-tail-seq equality that refuses a mixed cut between the two reads.
pub struct JournalConservationSourceChirho<'ports_chirho> {
    pub journal_ports_chirho: JournalPortsChirho<'ports_chirho>,
    pub journal_path_chirho: StoragePathChirho,
    pub cluster_chirho: ClusterIdChirho,
    pub money_group_chirho: MoneyGroupIdChirho,
}

/// Typed failure at the journal-backed conservation boundary. In particular, the read-only
/// journal refusal stays distinguishable from malformed source data so operators know that the
/// write lane must recover storage before monitoring can continue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JournalConservationSourceErrorChirho {
    JournalOpenChirho(JournalErrorChirho),
    JournalLineReadChirho(String),
    JournalLineParseChirho(String),
    MixedCutChirho {
        records_chirho: u64,
        verified_tail_seq_chirho: u64,
    },
    SnapshotDerivationChirho(String),
}

impl VerifiedConservationSnapshotPortChirho for JournalConservationSourceChirho<'_> {
    type ErrorChirho = JournalConservationSourceErrorChirho;

    fn load_verified_head_consistent_snapshot_chirho(
        &self,
    ) -> Result<HeadConsistentConservationSnapshotChirho, Self::ErrorChirho> {
        let journal_chirho = LedgerJournalChirho::open_read_only_full_chirho(
            self.journal_ports_chirho,
            self.journal_path_chirho.clone(),
            &self.cluster_chirho,
        )
        .map_err(JournalConservationSourceErrorChirho::JournalOpenChirho)?;
        let head_chirho = ConservationHeadCoordinateChirho {
            epoch_chirho: journal_chirho.current_epoch_chirho(),
            checkpoint_digest_chirho: journal_chirho.tail_line_digest_chirho().clone(),
            covered_record_count_chirho: journal_chirho.tail_seq_chirho(),
        };
        let lines_chirho = read_recomposed_journal_lines_chirho(
            self.journal_ports_chirho,
            &self.journal_path_chirho,
            &self.cluster_chirho,
        )
        .map_err(|error_chirho| {
            JournalConservationSourceErrorChirho::JournalLineReadChirho(format!("{error_chirho:?}"))
        })?;
        let mut records_chirho = Vec::new();
        for line_chirho in &lines_chirho {
            match parse_canonical_ledger_journal_line_chirho(line_chirho).map_err(
                |error_chirho| {
                    JournalConservationSourceErrorChirho::JournalLineParseChirho(format!(
                        "{error_chirho:?}"
                    ))
                },
            )? {
                LedgerJournalLineChirho::GenesisChirho(_) => {}
                LedgerJournalLineChirho::RecordChirho(record_chirho) => {
                    records_chirho.push(record_chirho)
                }
            }
        }
        if records_chirho.len() as u64 != journal_chirho.tail_seq_chirho() {
            return Err(JournalConservationSourceErrorChirho::MixedCutChirho {
                records_chirho: records_chirho.len() as u64,
                verified_tail_seq_chirho: journal_chirho.tail_seq_chirho(),
            });
        }
        derive_conservation_snapshot_chirho(
            &records_chirho,
            ConservationDomainIdChirho {
                money_group_chirho: self.money_group_chirho.clone(),
                cluster_chirho: self.cluster_chirho.clone(),
            },
            head_chirho,
        )
        .map_err(|error_chirho| {
            JournalConservationSourceErrorChirho::SnapshotDerivationChirho(format!(
                "{error_chirho:?}"
            ))
        })
    }
}

pub mod gd7_conservation_adapter_chirho;

#[cfg(test)]
mod composition_tests_chirho;
