// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Schema-tagged report/evidence types for the credits-demo LocalPhaseB PASS packet (the four legs,
//! the coordinate chain, external preconditions, and the honesty/claim-scope fields).

use cairn_chirho::model_chirho::HashChirho;
use serde::Serialize;

pub const PASS_PACKET_SCHEMA_CHIRHO: &str = "credits-demo-localphaseb-pass-packet-v2-chirho";
pub const COORDINATE_CHAIN_SCHEMA_CHIRHO: &str =
    "credits-demo-localphaseb-coordinate-chain-v2-chirho";
pub const AUTHORITY_COORDINATES_SCHEMA_CHIRHO: &str =
    "credits-demo-localphaseb-authority-coordinates-v1-chirho";
pub const EXTERNAL_PRECONDITIONS_SCHEMA_CHIRHO: &str =
    "localphaseb-external-preconditions-v1-chirho";
pub const CONSERVATION_LEG_SCHEMA_CHIRHO: &str =
    "credits-demo-localphaseb-conservation-leg-v1-chirho";
pub const VERIFIER_SUITE_LEG_SCHEMA_CHIRHO: &str =
    "credits-demo-localphaseb-verifier-suite-leg-v1-chirho";
pub const NO_LEGACY_LEG_SCHEMA_CHIRHO: &str = "credits-demo-localphaseb-no-legacy-leg-v1-chirho";
pub const CREDITS_SMOKE_LEG_SCHEMA_CHIRHO: &str =
    "credits-demo-localphaseb-credits-smoke-leg-v1-chirho";
pub const DORMANCY_POSTURE_SCHEMA_CHIRHO: &str =
    "credits-demo-localphaseb-dormancy-posture-v1-chirho";
pub const AUTHORING_PROVENANCE_SCHEMA_CHIRHO: &str =
    "credits-demo-localphaseb-authoring-provenance-v2-chirho";
pub const AUTHORING_GATE_REPORT_SCHEMA_CHIRHO: &str =
    "credits-demo-authoring-gate-report-v2-chirho";

/// Fixed bounded labels for the delete gates that remain UNMET after this local PASS; the packet
/// self-documents that Phase-B green is only the cax11 precondition, not delete authorization.
pub const REMAINING_DELETE_GATES_CHIRHO: [&str; 3] = [
    "cax11-hosted-phase-b-packet-chirho",
    "reviewed-public-cutover-chirho",
    "pre-delete-source-sweep-chirho",
];

#[derive(Clone, Debug, Serialize)]
pub struct CreditsDemoLocalPhaseBPassPacketChirho {
    pub schema_chirho: &'static str,
    /// True only when every required leg is green; the command refuses to emit a PASS packet with
    /// any red leg and exits non-zero.
    pub pass_chirho: bool,
    /// This local packet unlocks Phase C / satisfies the cax11 precondition. It does NOT authorize
    /// any wave-1 legacy deletion.
    pub delete_authorized_chirho: bool,
    pub phase_c_precondition_chirho: bool,
    pub remaining_delete_gates_chirho: Vec<&'static str>,
    pub root_scope_chirho: String,
    pub app_root_scope_chirho: String,
    pub coordinate_chain_chirho: CoordinateChainChirho,
    pub authority_coordinates_chirho: AuthorityCoordinatesChirho,
    pub external_preconditions_chirho: ExternalPreconditionsChirho,
    pub dormancy_chirho: DormancyPostureChirho,
    pub authoring_chirho: AuthoringProvenanceChirho,
    pub conservation_chirho: ConservationLegChirho,
    pub verifier_suite_chirho: VerifierSuiteLegChirho,
    pub no_legacy_chirho: NoLegacyLegChirho,
    pub credits_smoke_chirho: CreditsSmokeLegChirho,
}

#[derive(Clone, Debug, Serialize)]
pub struct CoordinateChainChirho {
    pub schema_chirho: &'static str,
    pub principal_chirho: String,
    pub control_plane_owner_chirho: String,
    pub owner_distinct_from_principal_chirho: bool,
    /// The FIVE payer coordinates, each sourced from its OWN independent evidence: the verified
    /// identity record (exact-selected from the one verified load), the config payer member
    /// (exact-selected by principal), the plan initial_owner, the VERIFIED H3 packet balance
    /// account owner (through the packet-provenance-sealed evidence object), and the authenticated
    /// served viewer — all equal, with the control-plane owner DISTINCT.
    pub identity_record_payer_chirho: String,
    pub config_payer_member_chirho: String,
    pub plan_initial_owner_chirho: String,
    pub packet_account_owner_chirho: String,
    pub served_viewer_principal_chirho: String,
    pub regenesis_binds_plan_initial_owner_chirho: bool,
    pub identity_config_plan_packet_viewer_same_chirho: bool,
    pub plan_digest_chirho: String,
    pub regenesis_packet_digest_chirho: String,
    pub regenesis_publication_manifest_digest_chirho: String,
    pub source_review_report_chirho: String,
    pub source_review_report_bound_by_compensation_chirho: bool,
    /// VERIFIED cut coordinates from the by-construction evidence object (sole packet-sealed
    /// constructor; every coordinate verified-or-refused against signed artifacts): the regenesis
    /// (pre-L2, mint-only) cut and the final (post-compensation) cut of the SAME projection AND
    /// descriptor revision, ancestry-bound to one verified chain.
    pub verified_projection_name_chirho: String,
    pub verified_descriptor_digest_chirho: String,
    pub verified_source_family_id_chirho: String,
    /// The SHARED journal instance digest both cuts bind (#6061 — each cut fork-resistant in its
    /// own bytes: shared genesis + per-cut {seq, HLC, prefix/tail digest, view digest}).
    pub verified_genesis_digest_chirho: String,
    pub regenesis_view_digest_chirho: String,
    pub regenesis_source_seq_chirho: u64,
    pub regenesis_source_hlc_physical_ms_chirho: u64,
    pub regenesis_source_hlc_logical_chirho: u32,
    pub regenesis_signed_prefix_digest_chirho: String,
    pub regenesis_account_net_chirho: u64,
    pub final_view_digest_chirho: String,
    pub final_source_seq_chirho: u64,
    pub final_source_hlc_physical_ms_chirho: u64,
    pub final_source_hlc_logical_chirho: u32,
    pub final_tail_line_digest_chirho: String,
    pub final_account_net_chirho: u64,
    pub genesis_and_final_views_distinct_chirho: bool,
    pub raw_manifest_hash_chirho: HashChirho,
    pub effective_manifest_hash_chirho: HashChirho,
    pub l4_committed_and_restored_no_refund_chirho: bool,
    /// #12 (corrected on source): the L4 compensation authority's plan digest is the reviewed
    /// UNDO-PLAN digest — closed against the independently selected spend-route binding plus membership in the complete reviewed binding set (the
    /// regenesis plan digest is a different artifact and is carried separately above).
    pub l4_plan_chain_closed_chirho: bool,
}

/// The three DISTINCT authority chains the production command consumes, each grounded separately so
/// the packet substantiates its real-input + secret-store-custody posture (never a single conflated
/// "reviewed inputs" claim). Digests / bools / bounded names / counts only — no host paths, DSN
/// values, or secret bytes.
#[derive(Clone, Debug, Serialize)]
pub struct AuthorityCoordinatesChirho {
    pub schema_chirho: &'static str,
    pub plan_chirho: PlanAuthorityChirho,
    pub config_chirho: ConfigAuthorityChirho,
    pub app_chirho: AppAuthorityChirho,
}

#[derive(Clone, Debug, Serialize)]
pub struct PlanAuthorityChirho {
    pub plan_digest_chirho: String,
    pub plan_digest_matches_expected_chirho: bool,
    pub issuer_secret_ref_name_chirho: String,
    pub issuer_binding_verified_chirho: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConfigAuthorityChirho {
    pub config_digest_chirho: HashChirho,
    pub config_validated_chirho: bool,
    pub config_root_bound_chirho: bool,
    pub custody_verified_chirho: bool,
    /// DERIVED from the actual config/protocol secret-ref sets (#3): the six pairwise-distinct
    /// signer refs and the provider refs (connection secret + adapter-evidence secret).
    pub signer_secret_ref_count_chirho: usize,
    pub provider_secret_ref_count_chirho: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct AppAuthorityChirho {
    pub source_review_report_chirho: String,
    /// The verified APP-RECORD (Deploy) seq and the review-log Promote record seq — DISTINCT
    /// coordinates, never relabeled into one (#6061).
    pub reviewed_app_record_seq_chirho: u64,
    pub reviewed_promote_review_seq_chirho: u64,
    pub accepted_capability_escalation_chirho: bool,
    pub accepted_cost_increase_chirho: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExternalPreconditionsChirho {
    pub schema_chirho: &'static str,
    pub operator_established_chirho: bool,
    pub cairn_minted_chirho: bool,
    pub pg_schema_installed_chirho: bool,
    pub pg_tables_chirho: Vec<&'static str>,
    pub seed_subject_chirho: String,
    pub seed_row_key_chirho: String,
    pub seed_value_utf8_chirho: String,
    /// RECOMPUTED under the CONFIGURED operator adapter key at preflight (#6046) — never a
    /// constant expectation; key rotation changes this recorded value and the smoke still runs.
    pub seed_before_state_fingerprint_chirho: String,
    pub l2_spend_concurrency_token_chirho: String,
    pub l2_token_bound_to_seed_fingerprint_chirho: bool,
    /// DERIVED from the actual fingerprint (first hex flipped) with an explicit distinctness
    /// check — never a constant assumed distinct from every real key's fingerprint.
    pub r4b_distinct_token_chirho: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DormancyPostureChirho {
    pub schema_chirho: &'static str,
    pub idempotency_window_present_chirho: bool,
    pub retry_finality_horizon_ms_chirho: u64,
    pub mint_age_exceeds_horizon_chirho: bool,
    pub dormant_beyond_horizon_chirho: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuthoringProvenanceChirho {
    pub schema_chirho: &'static str,
    pub app_chirho: String,
    pub emitted_not_accepted_chirho: bool,
    pub manifest_regenerated_and_matched_chirho: Option<bool>,
    pub authoring_gate_chirho: AuthoringGateReportChirho,
    pub raw_manifest_hash_chirho: HashChirho,
    pub effective_manifest_hash_chirho: HashChirho,
    pub candidate_root_dag_chirho: HashChirho,
    pub source_review_report_chirho: String,
    /// The owner principal substituted into the EFFECTIVE reviewed manifest during review-first, and
    /// a VERIFIED equality that it is the app's control-plane owner (closing raw-emit → effective →
    /// owner provenance). Sourced from the review candidate owner, not copied from one --owner input.
    pub reviewed_owner_substitution_chirho: String,
    pub owner_matches_control_plane_owner_chirho: bool,
    /// The verified APP-RECORD (Deploy) seq from `app_record_seq_chirho`, not the review-log seq.
    pub reviewed_app_record_seq_chirho: u64,
    /// The review-log Promote record's own seq (distinct from the Deploy app-record seq).
    pub reviewed_promote_review_seq_chirho: u64,
    /// The reviewed undo-plan digests from the promoted candidate (one per executable dag), plus
    /// the INDEPENDENTLY re-selected eligible binding (the spend route's dag) — the L4
    /// compensation authority must present exactly the selected digest, with set membership as
    /// the consistency check (#6100/#6101 re-ruled law; distinct from the ISSUER-chain regenesis
    /// plan digest).
    pub reviewed_undo_plan_digests_chirho: Vec<HashChirho>,
    pub reviewed_selected_undo_plan_digest_chirho: HashChirho,
    pub accepted_capability_escalation_chirho: bool,
    pub accepted_cost_increase_chirho: bool,
    pub cost_delta_token_chirho: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuthoringGateReportChirho {
    pub schema_chirho: &'static str,
    pub source_tree_blake3_chirho: String,
    pub source_entry_count_chirho: usize,
    pub local_package_count_chirho: usize,
    pub cargo_executable_blake3_chirho: String,
    pub emitted_manifest_blake3_chirho: String,
    pub artifact_dispositions_chirho: Vec<AuthoringGateArtifactDispositionChirho>,
    pub steps_chirho: Vec<AuthoringGateStepEvidenceChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuthoringGateArtifactDispositionChirho {
    pub node_id_chirho: String,
    pub node_identity_chirho: String,
    pub artifact_path_chirho: String,
    pub artifact_blake3_chirho: String,
    pub artifact_bytes_chirho: usize,
    pub fixture_count_chirho: usize,
    pub disposition_chirho: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "step_chirho")]
pub enum AuthoringGateStepEvidenceChirho {
    #[serde(rename = "check-chirho")]
    CheckChirho {
        source_tree_blake3_chirho: String,
        finding_count_chirho: usize,
    },
    #[serde(rename = "guest-tests-chirho")]
    GuestTestsChirho {
        source_tree_blake3_chirho: String,
        exit_code_chirho: i32,
        test_count_chirho: usize,
    },
    #[serde(rename = "wasm-examples-build-chirho")]
    WasmExamplesBuildChirho {
        source_tree_blake3_chirho: String,
        exit_code_chirho: i32,
        artifact_count_chirho: usize,
    },
    #[serde(rename = "node-fixtures-chirho")]
    NodeFixturesChirho {
        source_tree_blake3_chirho: String,
        fixture_count_chirho: usize,
        pure_node_count_chirho: usize,
        disposition_count_chirho: usize,
        failure_count_chirho: usize,
    },
    #[serde(rename = "emit-chirho")]
    EmitChirho {
        source_tree_blake3_chirho: String,
        emitted_manifest_blake3_chirho: String,
        emitted_manifest_bytes_chirho: usize,
    },
}

impl AuthoringGateStepEvidenceChirho {
    pub fn label_chirho(&self) -> &'static str {
        match self {
            Self::CheckChirho { .. } => "check-chirho",
            Self::GuestTestsChirho { .. } => "guest-tests-chirho",
            Self::WasmExamplesBuildChirho { .. } => "wasm-examples-build-chirho",
            Self::NodeFixturesChirho { .. } => "node-fixtures-chirho",
            Self::EmitChirho { .. } => "emit-chirho",
        }
    }

    pub fn source_tree_blake3_chirho(&self) -> &str {
        match self {
            Self::CheckChirho {
                source_tree_blake3_chirho,
                ..
            }
            | Self::GuestTestsChirho {
                source_tree_blake3_chirho,
                ..
            }
            | Self::WasmExamplesBuildChirho {
                source_tree_blake3_chirho,
                ..
            }
            | Self::NodeFixturesChirho {
                source_tree_blake3_chirho,
                ..
            }
            | Self::EmitChirho {
                source_tree_blake3_chirho,
                ..
            } => source_tree_blake3_chirho,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ConservationLegChirho {
    pub schema_chirho: &'static str,
    pub green_chirho: bool,
    pub minted_chirho: u64,
    pub balance_l1_chirho: u64,
    pub balance_after_l2_chirho: u64,
    pub balance_final_chirho: u64,
    pub settlement_after_l2_chirho: u64,
    pub settlement_final_chirho: u64,
    pub charge_per_spend_chirho: u64,
    pub no_refund_chirho: bool,
    pub payer_net_final_chirho: u64,
    pub settlement_net_final_chirho: u64,
    pub held_sum_final_chirho: u64,
    pub conservation_holds_chirho: bool,
    /// #6073/#6077: the verified initial mint plus its three independent source coordinates —
    /// the digest-bound plan amount (initial_minted), the census Mint-record amount, and the
    /// regenesis-cut net (in the coordinate chain) — with the cross-equality emitted.
    pub initial_minted_chirho: u64,
    pub census_mint_amount_chirho: u64,
    pub initial_mint_sources_match_chirho: bool,
    /// #6072: the journal's own supply coordinate, exact-selected by billing kind from the
    /// authoritative fold — REQUIRED equal to the verified initial mint AND the account-net sum;
    /// carried distinctly (net supply is never called "minted").
    pub final_net_supply_chirho: u64,
    pub supply_conserved_chirho: bool,
    /// The verified per-record op census (from the ONE packet-sealed evidence object): the
    /// whole-arc mint count, escrow record count, distinct control-saga count, and the settlement
    /// CREDIT meter sum, plus the wire's structural pin (exact Hold→Finalize / Hold→Release /
    /// Hold→Finalize saga pairs at the signed price on the payer account).
    pub census_mint_count_chirho: u64,
    pub census_escrow_record_count_chirho: usize,
    pub census_saga_count_chirho: usize,
    pub census_settlement_meter_sum_chirho: u64,
    pub census_structure_bound_chirho: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "status_chirho")]
pub enum VerifierStatusChirho {
    #[serde(rename = "green-chirho")]
    GreenChirho { records_chirho: usize },
    /// Verifier-confirmed empty: the real verifier returned Ok with zero applicable records. The
    /// zero count is carried explicitly so an N/A leg is visibly a successful empty verify, never an
    /// unquantified skip. (Any verifier ERROR is RED, never recast as N/A.)
    #[serde(rename = "not-applicable-empty-chirho")]
    NotApplicableEmptyChirho { records_chirho: usize },
}

#[derive(Clone, Debug, Serialize)]
pub struct VerifierSuiteLegChirho {
    pub schema_chirho: &'static str,
    pub green_chirho: bool,
    pub ledger_substrate_chirho: LedgerSubstrateVerifyChirho,
    pub run_cache_chirho: RunCacheVerifyChirho,
    pub volatile_effects_chirho: VolatileEffectsVerifyChirho,
    pub privacy_verify_chirho: PrivacyVerifyChirho,
    pub privacy_scan_findings_chirho: usize,
    pub residency_chirho: VerifierStatusChirho,
    pub compliance_chirho: VerifierStatusChirho,
    pub pg_provider_outcome_chirho: PgProviderOutcomeVerifyChirho,
}

#[derive(Clone, Debug, Serialize)]
pub struct LedgerSubstrateVerifyChirho {
    pub reopen_full_replay_ok_chirho: bool,
    pub conservation_cycle_green_chirho: bool,
    /// #9: the immutable H3 packet file re-read + canonical re-digest EQUALS the regenesis
    /// receipt's recorded packet digest (an equality re-verified here, never a non-empty check).
    pub packet_reopen_digest_matches_chirho: bool,
    /// The host-bound publication manifest is independently re-read under its fixed byte limit and
    /// its digest equals the published receipt coordinate.
    pub publication_manifest_reopen_digest_matches_chirho: bool,
    pub initial_minted_chirho: u64,
    /// #6072: the journal's own supply coordinate (distinct from the initial mint above).
    pub final_net_supply_chirho: u64,
    pub payer_net_chirho: u64,
    pub settlement_net_chirho: u64,
    pub payer_held_zero_chirho: bool,
    pub conservation_holds_chirho: bool,
}

/// #13: the external provider's own outcome tables, pinned EXACTLY — decision rows by kind (the
/// committed L2 spend and the definite-no-effect R4b retry), the single compensation receipt, the
/// single restored value row, and a CONTENT check: the restored row's keyed fingerprint recomputed
/// under the configured adapter key equals the preflight-recorded fingerprint (row count alone
/// cannot prove the seed VALUE was restored).
#[derive(Clone, Debug, Serialize)]
pub struct PgProviderOutcomeVerifyChirho {
    pub forward_decision_rows_chirho: u64,
    pub committed_decisions_chirho: u64,
    pub definite_no_effect_decisions_chirho: u64,
    pub comp_receipt_rows_chirho: u64,
    /// #6082-C: the WHOLE values-table cardinality and the exact target-coordinate row count,
    /// emitted distinctly (total==1 AND target==1 are both required).
    pub total_values_rows_chirho: u64,
    pub target_values_rows_chirho: u64,
    pub restored_row_fingerprint_matches_chirho: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RunCacheVerifyChirho {
    pub runs_chirho: usize,
    pub runkeys_chirho: usize,
    pub runseals_chirho: usize,
    pub clean_chirho: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct VolatileEffectsVerifyChirho {
    pub records_chirho: usize,
    pub objects_chirho: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct PrivacyVerifyChirho {
    pub blob_records_chirho: usize,
    pub erasure_records_chirho: usize,
    pub access_records_chirho: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct NoLegacyLegChirho {
    pub schema_chirho: &'static str,
    pub green_chirho: bool,
    pub credential_inventory_chirho: CredentialInventoryLegChirho,
    pub artifact_census_chirho: ArtifactCensusChirho,
}

#[derive(Clone, Debug, Serialize)]
pub struct CredentialInventoryLegChirho {
    pub identity_records_chirho: usize,
    pub argon2id_credentials_chirho: usize,
    pub legacy_blake3_credentials_chirho: usize,
    pub credentialless_keys_chirho: usize,
    pub legacy_zero_chirho: bool,
}

/// Fresh-root artifact identity census under the sealed three-part law (9afeb514/d7e7f270): (a)
/// the credential inventory above is ALWAYS required; (b) the exact Gate-1 / economic money-spine
/// delete-candidate markers are ALWAYS required zero; (c) the run/node census is
/// `not-applicable-pre-law-chirho` while the binary carries no Packet-4 marker law (a binary
/// inapplicability claim, never a root-absence proof), with the anomaly scan never supplying
/// activation authority. Counts + fixed class labels ONLY (never paths, offsets, or content).
#[derive(Clone, Debug, Serialize)]
pub struct ArtifactCensusChirho {
    pub gate1_marker_files_chirho: usize,
    pub economic_spine_marker_files_chirho: usize,
    pub money_spine_zero_chirho: bool,
    pub run_node_migration_chirho: RunNodeMigrationCensusChirho,
    pub census_green_chirho: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "status_chirho")]
pub enum RunNodeMigrationCensusChirho {
    /// PRE-LAW (sealed three-seat #6066/#6068/#6069): no v2 marker type, codec, canonical path,
    /// sink, or verifier exists in this build (Packet-4 deferred; CF7 ships on v1), so no artifact
    /// can be RECOGNIZED as a valid activation marker — the migration gate is not applicable to
    /// this binary. This is a source-absence fact, NOT a fabricated "verified-marker-absent"
    /// claim about root bytes. The anomaly scan may RED suspicious residue but is never authority
    /// and never this arm's source. When Packet-4 lands, the authority-owned verifier owns this
    /// branch (a contract guard fails the build path that keeps pre-law past that landing).
    #[serde(rename = "not-applicable-pre-law-chirho")]
    NotApplicablePreLawChirho {
        v2_activation_authority_deployed_chirho: bool,
    },
    /// Producible ONLY by the authority-owned v2 activation verifier once landed: a VERIFIED
    /// signed marker exists and the v1 node/run residue count is zero.
    #[serde(rename = "green-chirho")]
    GreenChirho { v1_residue_chirho: usize },
    /// Producible ONLY by the authority-owned v2 activation verifier once landed: an invalid
    /// marker or present v1 residue — RED, never recast.
    #[serde(rename = "red-chirho")]
    RedChirho {
        v1_residue_chirho: usize,
        invalid_marker_chirho: bool,
    },
    /// PRE-LAW anomaly (#6082-B): unexpected marker-ish artifacts on a fresh root. This arm makes
    /// NO activation or marker-validity claim and carries no activation-shaped residue — it only
    /// reports that unexpected artifacts exist and blocks green until an operator adjudicates.
    #[serde(rename = "unexpected-artifact-pre-law-red-chirho")]
    UnexpectedArtifactPreLawRedChirho {
        unexpected_artifact_files_chirho: usize,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct CreditsSmokeLegChirho {
    pub schema_chirho: &'static str,
    pub green_chirho: bool,
    pub server_chirho: String,
    pub anonymous_viewer_refusal_chirho: ViewerScopeEvidenceChirho,
    pub l1_balance_chirho: ViewerScopeEvidenceChirho,
    pub l2_spend_chirho: SpendEvidenceChirho,
    pub same_k_replay_chirho: ReplayEvidenceChirho,
    pub r4b_distinct_retry_chirho: DistinctRetryEvidenceChirho,
    pub compensation_chirho: CompensationEvidenceChirho,
    pub l5_balance_chirho: ViewerScopeEvidenceChirho,
    /// Fresh-never-lies viewer binding: the served L1/L5 route-parsed balances equal the VERIFIED
    /// regenesis/final cut nets exact-selected from the canonical published views.
    pub l1_matches_verified_regenesis_net_chirho: bool,
    pub l5_matches_verified_final_net_chirho: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ViewerScopeEvidenceChirho {
    pub method_chirho: String,
    pub path_chirho: String,
    pub status_chirho: u16,
    pub body_chirho: HashChirho,
    pub parsed_balance_chirho: Option<u64>,
    pub fresh_chirho: bool,
    pub viewer_rows_chirho: usize,
    pub settlement_rows_in_body_chirho: usize,
    /// The AUTHENTICATED payer principal's occurrence count in the rendered body (#6061): the
    /// viewer-scoped row must carry exactly the session payer once (anonymous: zero) — a
    /// token-to-wrong-owner regression cannot pass on row-count alone.
    pub viewer_principal_occurrences_chirho: usize,
    /// #6082-E: the TYPED missing-viewer refusal discriminator was present in the body — the
    /// anonymous negative never accepts a generic 400.
    pub missing_viewer_refusal_chirho: bool,
    /// The SERVED authenticated cut coordinates parsed from the rendered page (#6071): the wire
    /// requires exact equality to the named verified cut (regenesis for L1, final for L5) — a
    /// Fresh response from a different cut/revision with the same balance value refuses.
    pub served_descriptor_chirho: Option<String>,
    pub served_family_chirho: Option<String>,
    pub served_seq_chirho: Option<u64>,
    pub served_hlc_physical_ms_chirho: Option<u64>,
    pub served_hlc_logical_chirho: Option<u32>,
    pub served_prefix_digest_chirho: Option<String>,
    pub served_state_digest_chirho: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SpendEvidenceChirho {
    pub method_chirho: String,
    pub path_chirho: String,
    pub status_chirho: u16,
    pub body_chirho: HashChirho,
    pub committed_chirho: bool,
    pub hostile_body_ignored_chirho: bool,
    pub verified_payer_charged_exactly_price_chirho: bool,
    pub balance_before_chirho: u64,
    pub balance_after_chirho: u64,
    pub settlement_after_chirho: u64,
    /// A single metered charge of the signed price, proven by verified net deltas: the payer net
    /// fell by exactly the price and the settlement net rose by exactly the price (a 999 body or a
    /// spoofed principal would break these), with the verified journal tail advanced.
    pub single_signed_price_charge_chirho: bool,
    pub journal_tail_advanced_chirho: bool,
    /// Read from the AUTHORITATIVE ledger after L2: the CANONICAL-SHAPED spoofed principal in the
    /// hostile body (#6054 — a valid `user/<16-hex>` coordinate, so a body-authority regression
    /// cannot hide behind shape validation) has NO account — the composed engine neither debited
    /// nor created a spoof account.
    pub attacker_account_absent_or_uncharged_chirho: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReplayEvidenceChirho {
    pub status_chirho: u16,
    pub body_chirho: HashChirho,
    pub byte_identical_response_chirho: bool,
    pub no_double_charge_chirho: bool,
    /// The verified escrow held is unchanged (no leaked Hold) and the verified journal cut is
    /// unchanged — the idempotent replay appended no new record: the full (seq, tail-line digest)
    /// tuple is compared, not the seq alone (#6050 HOLD B).
    pub no_new_hold_chirho: bool,
    pub journal_cut_unchanged_chirho: bool,
    pub balance_after_chirho: u64,
    pub settlement_after_chirho: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct DistinctRetryEvidenceChirho {
    pub status_chirho: u16,
    pub body_chirho: HashChirho,
    pub definite_no_effect_chirho: bool,
    pub no_amplification_chirho: bool,
    /// The escrow invariant: after the definite-no-effect Hold→Release the payer held returns to 0,
    /// read DIRECTLY from the verified fold (net cannot prove a Release — net is identical whether
    /// the Hold released or leaked).
    pub payer_held_zero_chirho: bool,
    /// The verified journal tail advanced by exactly two records (the net-zero Hold→Release pair)
    /// while every account net stayed unchanged — a real journal transition, not a summary label.
    pub journal_tail_advanced_by_two_chirho: bool,
    pub net_money_unchanged_chirho: bool,
    pub balance_after_chirho: u64,
    pub settlement_after_chirho: u64,
    pub pg_values_row_count_chirho: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct CompensationEvidenceChirho {
    pub preview_verdict_executable_chirho: bool,
    pub source_review_report_chirho: String,
    pub bound_to_reviewed_report_chirho: bool,
    /// #6100 re-rule (money/model concurred): the SELECTED L4 compensation UNDO-PLAN digest —
    /// a different authority coordinate than the regenesis plan digest, never equated to it; the
    /// chain closes it by membership in the reviewed candidate's undo-binding set.
    pub undo_plan_digest_chirho: String,
    pub committed_chirho: bool,
    pub provider_restored_chirho: bool,
    pub comp_receipt_count_chirho: i64,
    pub pg_values_row_count_chirho: i64,
    pub payer_held_zero_chirho: bool,
    pub no_refund_chirho: bool,
    pub payer_net_after_chirho: u64,
    pub settlement_net_after_chirho: u64,
}
