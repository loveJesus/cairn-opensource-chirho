// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Orchestrates the credits-demo LocalPhaseB PASS packet: it consumes operator-reviewed inputs
//! (config / plan / expected-digest / issuer secret / app root + secret-store custody), drives the
//! LIVE served money arc, builds the ONE packet-provenance-sealed verified cut/census evidence
//! object, runs the fresh-root verifier suite and the sealed three-part no-legacy gate, and emits
//! ONE schema-tagged packet. A complete local Phase-B PASS unlocks Phase C and satisfies the cax11
//! precondition; it does NOT authorize any wave-1 legacy deletion.
//!
//! Workflow: `spec-chirho/workflows-chirho/reversible-postgres-effect-chirho/credits-demo-localphaseb-smoke-chirho.md`.

mod authoring_gate_chirho;
pub mod concurrency_token_chirho;
pub mod constants_chirho;
pub mod continuation_chirho;
pub mod evidence_chirho;
#[cfg(test)]
pub mod fixture_chirho;
pub mod http_smoke_chirho;
pub mod operator_prepare_chirho;
pub mod setup_chirho;
pub mod types_chirho;
pub mod wire_smoke_chirho;

use anyhow::{bail, Result};

pub use concurrency_token_chirho::{
    read_credits_demo_concurrency_token_chirho, CreditsDemoConcurrencyTokenRequestChirho,
};
pub use operator_prepare_chirho::{
    author_credits_demo_inputs_chirho, prepare_credits_demo_provider_chirho,
    CreditsDemoInputsAuthorReportChirho, CreditsDemoInputsAuthorRequestChirho,
    CreditsDemoProviderPrepareReportChirho, CreditsDemoProviderPrepareRequestChirho,
};
pub use setup_chirho::{CreditsDemoResidentOpenerChirho, CreditsDemoSmokeInputsChirho};

use setup_chirho::CreditsDemoSetupChirho;
use types_chirho::{
    ConservationLegChirho, CoordinateChainChirho, CreditsDemoLocalPhaseBPassPacketChirho,
    CreditsSmokeLegChirho, CONSERVATION_LEG_SCHEMA_CHIRHO, COORDINATE_CHAIN_SCHEMA_CHIRHO,
    CREDITS_SMOKE_LEG_SCHEMA_CHIRHO, PASS_PACKET_SCHEMA_CHIRHO, REMAINING_DELETE_GATES_CHIRHO,
};
use wire_smoke_chirho::WireOutcomeChirho;

pub const CREDITS_DEMO_GEO_SEED_REPORT_SCHEMA_CHIRHO: &str =
    "credits-demo-geo-seed-report-v1-chirho";

/// Bounded operator evidence for preparing a synthetic geo root without pretending that the
/// LocalPhaseB served-money smoke ran in elected era. The later relay drill owns that served arc.
#[derive(Debug, serde::Serialize)]
pub struct CreditsDemoGeoSeedReportChirho {
    pub schema_chirho: &'static str,
    pub geo_seeded_chirho: bool,
    pub served_money_arc_executed_chirho: bool,
    pub writer_authority_era_chirho: &'static str,
    pub payer_chirho: String,
    pub plan_mint_amount_chirho: u64,
    pub source_review_report_chirho: String,
    pub projection_name_chirho: String,
    pub projection_head_path_chirho: String,
    pub regenesis_packet_digest_chirho: String,
    pub regenesis_publication_manifest_digest_chirho: String,
}

/// Prepare the H3/app/route/price state consumed by a geo drill, but do not drive the local served
/// money arc. Elected-era SSR remains closed until its own forwarding/read-effect composition lands.
///
/// `resident_opener_chirho` is the E1-e-2 injection seam (see
/// [`CreditsDemoResidentOpenerChirho`]). The shipping CLI passes `None` — which keeps the refusing
/// production door and the early test-kind refusal. A hosted test-kind drill passes its own opener;
/// the door symbol that opener reaches lives in the drill's crate, never in this one.
pub fn run_credits_demo_geo_seed_chirho(
    inputs_chirho: &CreditsDemoSmokeInputsChirho<'_>,
    resident_opener_chirho: Option<CreditsDemoResidentOpenerChirho<'_>>,
) -> Result<CreditsDemoGeoSeedReportChirho> {
    let setup_chirho =
        setup_chirho::run_credits_demo_setup_chirho(inputs_chirho, resident_opener_chirho)?;
    let era_chirho = cairn_writer_head_chirho::writer_head_chirho::writer_authority_era_chirho(
        &setup_chirho.root_chirho,
    )?;
    let writer_authority_era_chirho = match era_chirho {
        cairn_writer_head_chirho::writer_head_chirho::WriterAuthorityEraChirho::LocalChirho => {
            "LocalChirho"
        }
        cairn_writer_head_chirho::writer_head_chirho::WriterAuthorityEraChirho::ElectedChirho => {
            "ElectedChirho"
        }
    };
    if era_chirho
        != cairn_writer_head_chirho::writer_head_chirho::WriterAuthorityEraChirho::ElectedChirho
    {
        bail!("CreditsDemoGeoSeedWriterEraNotElectedChirho");
    }
    Ok(CreditsDemoGeoSeedReportChirho {
        schema_chirho: CREDITS_DEMO_GEO_SEED_REPORT_SCHEMA_CHIRHO,
        geo_seeded_chirho: true,
        served_money_arc_executed_chirho: false,
        writer_authority_era_chirho,
        payer_chirho: setup_chirho.payer_chirho,
        plan_mint_amount_chirho: setup_chirho.plan_mint_amount_chirho,
        source_review_report_chirho: setup_chirho.source_review_report_chirho,
        projection_name_chirho: setup_chirho.balance_projection_name_chirho,
        projection_head_path_chirho: setup_chirho.balance_head_path_chirho,
        regenesis_packet_digest_chirho: setup_chirho.regenesis_packet_digest_chirho,
        regenesis_publication_manifest_digest_chirho: setup_chirho
            .regenesis_publication_manifest_digest_chirho,
    })
}

/// Drive the whole credits-demo LocalPhaseB arc + verifier suite and emit the PASS packet. The
/// command FAILS (this returns Err → non-zero exit, no PASS packet) if any required leg is red.
pub fn run_credits_demo_smoke_chirho(
    inputs_chirho: &CreditsDemoSmokeInputsChirho<'_>,
) -> Result<CreditsDemoLocalPhaseBPassPacketChirho> {
    // DELIBERATELY NOT WIDENED. The E1-e-2 injection seam exists for the geo-seed road a hosted
    // test-kind drill consumes; this is the LocalPhaseB served-money PASS packet — production
    // evidence — so it hard-codes the refusing default and a test-kind config is refused early.
    let setup_chirho = setup_chirho::run_credits_demo_setup_chirho(inputs_chirho, None)?;

    let wire_chirho = wire_smoke_chirho::run_credits_demo_wire_chirho(&setup_chirho)?;
    let verifier_suite_chirho = evidence_chirho::run_verifier_suite_chirho(&setup_chirho)?;
    let no_legacy_chirho = evidence_chirho::run_no_legacy_chirho(&setup_chirho)?;

    let conservation_chirho = build_conservation_leg_chirho(&setup_chirho, &wire_chirho)?;
    let credits_smoke_chirho = build_credits_smoke_leg_chirho(&wire_chirho);
    let coordinate_chain_chirho = build_coordinate_chain_chirho(&setup_chirho, &wire_chirho);

    let pass_chirho = conservation_chirho.green_chirho
        && verifier_suite_chirho.green_chirho
        && no_legacy_chirho.green_chirho
        && credits_smoke_chirho.green_chirho
        && coordinate_closed_chirho(&coordinate_chain_chirho);

    let packet_chirho = CreditsDemoLocalPhaseBPassPacketChirho {
        schema_chirho: PASS_PACKET_SCHEMA_CHIRHO,
        pass_chirho,
        delete_authorized_chirho: false,
        phase_c_precondition_chirho: pass_chirho,
        remaining_delete_gates_chirho: REMAINING_DELETE_GATES_CHIRHO.to_vec(),
        root_scope_chirho: cairn_chirho::operator_evidence_chirho::redacted_local_root_scope_chirho(
            &setup_chirho.root_chirho,
        ),
        app_root_scope_chirho: "credits-demo-app-root-chirho".to_string(),
        coordinate_chain_chirho,
        authority_coordinates_chirho: setup_chirho.authority_coordinates_chirho.clone(),
        external_preconditions_chirho: setup_chirho.external_preconditions_chirho.clone(),
        dormancy_chirho: setup_chirho.dormancy_chirho.clone(),
        authoring_chirho: setup_chirho.authoring_chirho.clone(),
        conservation_chirho,
        verifier_suite_chirho,
        no_legacy_chirho,
        credits_smoke_chirho,
    };

    let packet_json_chirho = serde_json::to_string(&packet_chirho)?;
    // #6067: the no-leak scan needles include the ACTUAL configured production secret set,
    // re-resolved at emission (raw UTF-8 where valid + lowercase hex of the bytes), the DSN, and
    // the arc's ephemeral session tokens — a rotated real operator key can never pass on
    // fixture-pattern needles alone.
    let mut dynamic_needles_chirho = zeroize::Zeroizing::new(Vec::<String>::new());
    for name_chirho in &setup_chirho.secret_ref_names_chirho {
        let secret_chirho = cairn_chirho::secret_chirho::resolve_secret_ref_chirho(
            &setup_chirho.root_chirho,
            &cairn_chirho::secret_chirho::secret_ref_chirho(name_chirho)?,
        )?;
        let bytes_chirho = secret_chirho.as_bytes_chirho();
        if let Ok(text_chirho) = std::str::from_utf8(bytes_chirho) {
            dynamic_needles_chirho.push(text_chirho.to_string());
        }
        dynamic_needles_chirho.push(
            bytes_chirho
                .iter()
                .map(|byte_chirho| format!("{byte_chirho:02x}"))
                .collect(),
        );
    }
    dynamic_needles_chirho.push(setup_chirho.dsn_chirho.clone());
    dynamic_needles_chirho.extend(wire_chirho.session_tokens_chirho.iter().cloned());
    evidence_chirho::assert_no_secret_or_path_leak_chirho(
        &packet_json_chirho,
        &dynamic_needles_chirho,
    )?;

    if !packet_chirho.pass_chirho {
        let chain_chirho = &packet_chirho.coordinate_chain_chirho;
        // Operator diagnosability: name the red leg + the chain sub-predicates (bounded booleans
        // only — never values) so a refused packet is actionable without spelunking.
        bail!(
            "credits-demo LocalPhaseB PASS packet has a red leg; refusing to emit a PASS packet \
             (conservation={} verifier_suite={} no_legacy={} credits_smoke={} coordinate_closed={} \
             | chain: owner_distinct={} five_same={} regenesis_binds={} review_bound={} \
             views_distinct={} l4_committed={} l4_plan_chain={})",
            packet_chirho.conservation_chirho.green_chirho,
            packet_chirho.verifier_suite_chirho.green_chirho,
            packet_chirho.no_legacy_chirho.green_chirho,
            packet_chirho.credits_smoke_chirho.green_chirho,
            coordinate_closed_chirho(chain_chirho),
            chain_chirho.owner_distinct_from_principal_chirho,
            chain_chirho.identity_config_plan_packet_viewer_same_chirho,
            chain_chirho.regenesis_binds_plan_initial_owner_chirho,
            chain_chirho.source_review_report_bound_by_compensation_chirho,
            chain_chirho.genesis_and_final_views_distinct_chirho,
            chain_chirho.l4_committed_and_restored_no_refund_chirho,
            chain_chirho.l4_plan_chain_closed_chirho
        );
    }
    Ok(packet_chirho)
}

fn build_conservation_leg_chirho(
    setup_chirho: &CreditsDemoSetupChirho,
    wire_chirho: &WireOutcomeChirho,
) -> anyhow::Result<ConservationLegChirho> {
    let census_chirho = wire_chirho
        .packet_evidence_chirho
        .evidence_chirho()
        .op_census_chirho();
    // Derive-or-bail arithmetic in PASS construction (#6061): no zero defaults, no unchecked adds.
    let charge_per_spend_chirho = u64::try_from(constants_chirho::POSTGRES_REVERSIBLE_PRICE_CHIRHO)
        .map_err(|_error_chirho| anyhow::anyhow!("signed price is negative"))?;
    let payer_plus_settlement_chirho = wire_chirho
        .payer_net_final_chirho
        .checked_add(wire_chirho.settlement_net_final_chirho)
        .ok_or_else(|| anyhow::anyhow!("payer+settlement net overflow"))?;
    let conservation_holds_chirho = payer_plus_settlement_chirho == wire_chirho.minted_chirho
        && wire_chirho.held_sum_final_chirho == 0;
    let minted_chirho = setup_chirho.plan_mint_amount_chirho;
    // #6072: the journal's own supply coordinate must equal the verified initial mint AND the
    // account-net sum (each read from its own authority; never conflated, never renamed).
    let supply_conserved_chirho = wire_chirho.final_net_supply_chirho == minted_chirho
        && wire_chirho.final_net_supply_chirho == payer_plus_settlement_chirho;
    // #6073/#6077: the three INDEPENDENT initial-minted sources, emitted so the packet bytes can
    // substantiate the equality (wire already bailed on divergence; the packet still shows it).
    let census_mint_amount_chirho = census_chirho.mint_total_amount_chirho;
    let initial_mint_sources_match_chirho = census_mint_amount_chirho == minted_chirho
        && wire_chirho
            .packet_evidence_chirho
            .evidence_chirho()
            .regenesis_account_net_chirho()
            == minted_chirho;
    let green_chirho = wire_chirho.balance_l1_chirho == 750
        && wire_chirho.balance_after_l2_chirho == 740
        && wire_chirho.balance_final_chirho == 730
        && wire_chirho.settlement_after_l2_chirho == 10
        && wire_chirho.settlement_final_chirho == 20
        && minted_chirho == 750
        && wire_chirho.minted_chirho == minted_chirho
        && wire_chirho.compensation_chirho.no_refund_chirho
        && conservation_holds_chirho
        && wire_chirho.census_structure_bound_chirho
        && wire_chirho.census_settlement_meter_sum_chirho
            == wire_chirho.settlement_net_final_chirho
        && supply_conserved_chirho
        && initial_mint_sources_match_chirho;
    Ok(ConservationLegChirho {
        schema_chirho: CONSERVATION_LEG_SCHEMA_CHIRHO,
        green_chirho,
        minted_chirho,
        balance_l1_chirho: wire_chirho.balance_l1_chirho,
        balance_after_l2_chirho: wire_chirho.balance_after_l2_chirho,
        balance_final_chirho: wire_chirho.balance_final_chirho,
        settlement_after_l2_chirho: wire_chirho.settlement_after_l2_chirho,
        settlement_final_chirho: wire_chirho.settlement_final_chirho,
        charge_per_spend_chirho,
        no_refund_chirho: wire_chirho.compensation_chirho.no_refund_chirho,
        payer_net_final_chirho: wire_chirho.payer_net_final_chirho,
        settlement_net_final_chirho: wire_chirho.settlement_net_final_chirho,
        held_sum_final_chirho: wire_chirho.held_sum_final_chirho,
        conservation_holds_chirho,
        initial_minted_chirho: minted_chirho,
        census_mint_amount_chirho,
        initial_mint_sources_match_chirho,
        final_net_supply_chirho: wire_chirho.final_net_supply_chirho,
        supply_conserved_chirho,
        census_mint_count_chirho: census_chirho.mint_count_chirho,
        census_escrow_record_count_chirho: census_chirho.escrow_records_chirho.len(),
        census_saga_count_chirho: wire_chirho.census_saga_count_chirho,
        census_settlement_meter_sum_chirho: wire_chirho.census_settlement_meter_sum_chirho,
        census_structure_bound_chirho: wire_chirho.census_structure_bound_chirho,
    })
}

fn build_credits_smoke_leg_chirho(wire_chirho: &WireOutcomeChirho) -> CreditsSmokeLegChirho {
    let green_chirho = wire_chirho.anonymous_refusal_chirho.status_chirho == 400
        && wire_chirho.anonymous_refusal_chirho.viewer_rows_chirho == 0
        && wire_chirho.l1_chirho.status_chirho == 200
        && wire_chirho.l1_chirho.parsed_balance_chirho == Some(750)
        && wire_chirho.l1_chirho.fresh_chirho
        && wire_chirho.l1_chirho.viewer_rows_chirho == 1
        && wire_chirho.l1_chirho.settlement_rows_in_body_chirho == 0
        && wire_chirho.l2_chirho.committed_chirho
        && wire_chirho
            .l2_chirho
            .verified_payer_charged_exactly_price_chirho
        && wire_chirho
            .l2_chirho
            .attacker_account_absent_or_uncharged_chirho
        && wire_chirho.l2_chirho.hostile_body_ignored_chirho
        && wire_chirho.replay_chirho.byte_identical_response_chirho
        && wire_chirho.replay_chirho.no_double_charge_chirho
        && wire_chirho.replay_chirho.journal_cut_unchanged_chirho
        && wire_chirho.r4b_chirho.definite_no_effect_chirho
        && wire_chirho.r4b_chirho.payer_held_zero_chirho
        && wire_chirho.r4b_chirho.journal_tail_advanced_by_two_chirho
        && wire_chirho.r4b_chirho.pg_values_row_count_chirho == 0
        && wire_chirho
            .compensation_chirho
            .preview_verdict_executable_chirho
        && wire_chirho
            .compensation_chirho
            .bound_to_reviewed_report_chirho
        && wire_chirho.compensation_chirho.committed_chirho
        && wire_chirho.compensation_chirho.provider_restored_chirho
        && wire_chirho.compensation_chirho.comp_receipt_count_chirho == 1
        && wire_chirho.compensation_chirho.payer_held_zero_chirho
        && wire_chirho.compensation_chirho.no_refund_chirho
        && wire_chirho.l5_chirho.status_chirho == 200
        && wire_chirho.l5_chirho.parsed_balance_chirho == Some(730)
        && wire_chirho.l5_chirho.fresh_chirho
        && wire_chirho.l5_chirho.viewer_rows_chirho == 1
        && wire_chirho.l5_chirho.settlement_rows_in_body_chirho == 0
        && wire_chirho.l1_matches_verified_regenesis_net_chirho
        && wire_chirho.l5_matches_verified_final_net_chirho;
    CreditsSmokeLegChirho {
        schema_chirho: CREDITS_SMOKE_LEG_SCHEMA_CHIRHO,
        green_chirho,
        // Bounded local posture label — never the ephemeral loopback address/port.
        server_chirho: "loopback-ephemeral-chirho".to_string(),
        anonymous_viewer_refusal_chirho: wire_chirho.anonymous_refusal_chirho.clone(),
        l1_balance_chirho: wire_chirho.l1_chirho.clone(),
        l2_spend_chirho: wire_chirho.l2_chirho.clone(),
        same_k_replay_chirho: wire_chirho.replay_chirho.clone(),
        r4b_distinct_retry_chirho: wire_chirho.r4b_chirho.clone(),
        compensation_chirho: wire_chirho.compensation_chirho.clone(),
        l5_balance_chirho: wire_chirho.l5_chirho.clone(),
        l1_matches_verified_regenesis_net_chirho: wire_chirho
            .l1_matches_verified_regenesis_net_chirho,
        l5_matches_verified_final_net_chirho: wire_chirho.l5_matches_verified_final_net_chirho,
    }
}

fn build_coordinate_chain_chirho(
    setup_chirho: &CreditsDemoSetupChirho,
    wire_chirho: &WireOutcomeChirho,
) -> CoordinateChainChirho {
    let evidence_chirho = wire_chirho.packet_evidence_chirho.evidence_chirho();
    let owner_distinct_chirho = setup_chirho.owner_chirho != setup_chirho.payer_chirho;
    // The FIVE payer coordinates, each from its OWN independent evidence (#4): the verified
    // identity record, the config member, the plan, the VERIFIED packet-sealed evidence object's
    // regenesis account owner, and the authenticated served viewer.
    let identity_record_payer_chirho = setup_chirho.identity_record_payer_chirho.clone();
    let config_payer_member_chirho = setup_chirho.config_payer_member_chirho.clone();
    let plan_initial_owner_chirho = setup_chirho.plan_initial_owner_chirho.clone();
    let packet_account_owner_chirho = evidence_chirho.regenesis_account_owner_chirho().to_string();
    let served_viewer_principal_chirho = wire_chirho.served_viewer_principal_chirho.clone();
    let five_same_chirho = identity_record_payer_chirho == config_payer_member_chirho
        && config_payer_member_chirho == plan_initial_owner_chirho
        && plan_initial_owner_chirho == packet_account_owner_chirho
        && packet_account_owner_chirho == served_viewer_principal_chirho;
    let regenesis_binds_plan_initial_owner_chirho = packet_account_owner_chirho
        == plan_initial_owner_chirho
        && evidence_chirho.regenesis_account_kind_chirho() == setup_chirho.billing_kind_chirho;
    let regenesis_view_digest_chirho = evidence_chirho
        .regenesis_view_digest_hex_chirho()
        .to_string();
    let final_view_digest_chirho = evidence_chirho.final_view_digest_hex_chirho().to_string();
    CoordinateChainChirho {
        schema_chirho: COORDINATE_CHAIN_SCHEMA_CHIRHO,
        principal_chirho: setup_chirho.payer_chirho.clone(),
        control_plane_owner_chirho: setup_chirho.owner_chirho.clone(),
        owner_distinct_from_principal_chirho: owner_distinct_chirho,
        identity_record_payer_chirho,
        config_payer_member_chirho,
        plan_initial_owner_chirho,
        packet_account_owner_chirho,
        served_viewer_principal_chirho,
        regenesis_binds_plan_initial_owner_chirho,
        identity_config_plan_packet_viewer_same_chirho: five_same_chirho,
        plan_digest_chirho: setup_chirho.plan_digest_chirho.clone(),
        regenesis_packet_digest_chirho: setup_chirho.regenesis_packet_digest_chirho.clone(),
        regenesis_publication_manifest_digest_chirho: setup_chirho
            .regenesis_publication_manifest_digest_chirho
            .clone(),
        source_review_report_chirho: setup_chirho.source_review_report_chirho.clone(),
        source_review_report_bound_by_compensation_chirho: wire_chirho
            .compensation_chirho
            .bound_to_reviewed_report_chirho,
        verified_projection_name_chirho: evidence_chirho.projection_name_chirho().to_string(),
        verified_descriptor_digest_chirho: evidence_chirho.descriptor_digest_chirho().0.clone(),
        verified_genesis_digest_chirho: evidence_chirho.genesis_digest_chirho().0.clone(),
        verified_source_family_id_chirho: wire_chirho
            .packet_evidence_chirho
            .source_family_id_chirho()
            .to_string(),
        genesis_and_final_views_distinct_chirho: regenesis_view_digest_chirho
            != final_view_digest_chirho,
        regenesis_view_digest_chirho,
        regenesis_source_seq_chirho: evidence_chirho.regenesis_source_seq_chirho(),
        regenesis_source_hlc_physical_ms_chirho: evidence_chirho
            .regenesis_source_hlc_chirho()
            .physical_ms_chirho,
        regenesis_source_hlc_logical_chirho: evidence_chirho
            .regenesis_source_hlc_chirho()
            .logical_chirho,
        regenesis_signed_prefix_digest_chirho: evidence_chirho
            .regenesis_signed_prefix_digest_chirho()
            .0
            .clone(),
        regenesis_account_net_chirho: evidence_chirho.regenesis_account_net_chirho(),
        final_view_digest_chirho,
        final_source_seq_chirho: evidence_chirho.final_source_seq_chirho(),
        final_source_hlc_physical_ms_chirho: evidence_chirho
            .final_source_hlc_chirho()
            .physical_ms_chirho,
        final_source_hlc_logical_chirho: evidence_chirho.final_source_hlc_chirho().logical_chirho,
        final_tail_line_digest_chirho: evidence_chirho.tail_line_digest_chirho().0.clone(),
        final_account_net_chirho: evidence_chirho.final_account_net_chirho(),
        raw_manifest_hash_chirho: setup_chirho
            .authoring_chirho
            .raw_manifest_hash_chirho
            .clone(),
        effective_manifest_hash_chirho: setup_chirho
            .authoring_chirho
            .effective_manifest_hash_chirho
            .clone(),
        l4_committed_and_restored_no_refund_chirho: wire_chirho
            .compensation_chirho
            .committed_chirho
            && wire_chirho.compensation_chirho.provider_restored_chirho
            && wire_chirho.compensation_chirho.no_refund_chirho,
        // #12 (corrected on source): the compensation authority's plan digest is the reviewed
        // UNDO-PLAN digest — closed against the independently selected spend-route binding plus
        // membership in the complete reviewed binding set.
        l4_plan_chain_closed_chirho: wire_chirho.compensation_chirho.undo_plan_digest_chirho
            == setup_chirho
                .authoring_chirho
                .reviewed_selected_undo_plan_digest_chirho
                .0
            && setup_chirho
                .authoring_chirho
                .reviewed_undo_plan_digests_chirho
                .iter()
                .any(|digest_chirho| {
                    digest_chirho.0 == wire_chirho.compensation_chirho.undo_plan_digest_chirho
                }),
    }
}

fn coordinate_closed_chirho(coordinate_chain_chirho: &CoordinateChainChirho) -> bool {
    coordinate_chain_chirho.owner_distinct_from_principal_chirho
        && coordinate_chain_chirho.identity_config_plan_packet_viewer_same_chirho
        && coordinate_chain_chirho.regenesis_binds_plan_initial_owner_chirho
        && coordinate_chain_chirho.source_review_report_bound_by_compensation_chirho
        && coordinate_chain_chirho.genesis_and_final_views_distinct_chirho
        && coordinate_chain_chirho.l4_committed_and_restored_no_refund_chirho
        && coordinate_chain_chirho.l4_plan_chain_closed_chirho
}

#[cfg(test)]
#[path = "credits_demo_smoke_chirho/operator_prepare_tests_chirho.rs"]
mod operator_prepare_tests_chirho;
#[cfg(test)]
#[path = "credits_demo_smoke_chirho/tests_chirho.rs"]
mod tests_chirho;
