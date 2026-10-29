// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Fresh-root verifier suite (leg 2), the no-legacy-identity gate (leg 3) under the sealed
//! three-part census law, the external-provider outcome evidence, and the no-secret /
//! no-host-coordinate assertion over the emitted packet. Every verifier is CALLED on the fresh root;
//! N/A is VERIFIER-CONFIRMED (a real scan/verify returned zero applicable records), never an error
//! recast or an assumed skip.
//!
//! Workflow: `spec-chirho/workflows-chirho/reversible-postgres-effect-chirho/credits-demo-localphaseb-smoke-chirho.md`.

use anyhow::{bail, Context, Result};
use cairn_chirho::model_chirho::HashChirho;
use cairn_chirho::{
    compliance_evidence_chirho, data_residency_chirho, identity_chirho, privacy_chirho,
    verify_chirho,
};
use cairn_ledger_regenesis_chirho::{
    load_canonical_ledger_regenesis_evidence_packet_chirho,
    load_canonical_ledger_regenesis_publication_manifest_chirho,
};
use cairn_postgres_effect_chirho::crypto_chirho::row_fingerprint_chirho;
use cairn_postgres_effect_chirho::evidence_inventory_chirho::verified_provider_outcome_inventory_chirho;
use cairn_serve_runtime_chirho::{
    LedgerConservationCycleOutcomeChirho, LedgerHostProjectionReadPortChirho,
};
use std::path::Path;

use super::constants_chirho;
use super::setup_chirho::{connect_pg_chirho, CreditsDemoSetupChirho};
use super::types_chirho::{
    ArtifactCensusChirho, CredentialInventoryLegChirho, LedgerSubstrateVerifyChirho,
    NoLegacyLegChirho, PgProviderOutcomeVerifyChirho, PrivacyVerifyChirho, RunCacheVerifyChirho,
    RunNodeMigrationCensusChirho, VerifierStatusChirho, VerifierSuiteLegChirho,
    VolatileEffectsVerifyChirho, NO_LEGACY_LEG_SCHEMA_CHIRHO, VERIFIER_SUITE_LEG_SCHEMA_CHIRHO,
};

/// Run the fresh-root LocalPhaseB / Phase-C-precondition verifier suite (leg 2). Any verifier ERROR
/// propagates as RED (the command fails); the leg's `green_chirho` is only true when every sub-check
/// is clean. This is a Phase-C precondition, not delete authorization.
pub fn run_verifier_suite_chirho(
    setup_chirho: &CreditsDemoSetupChirho,
) -> Result<VerifierSuiteLegChirho> {
    let root_chirho = setup_chirho.root_chirho.as_path();

    let ledger_substrate_chirho = verify_ledger_substrate_chirho(setup_chirho)?;
    let run_cache_report_chirho = verify_chirho::inspect_run_cache_chirho(root_chirho)?;
    let run_cache_clean_chirho =
        verify_chirho::ensure_run_cache_report_clean_chirho(&run_cache_report_chirho).is_ok();
    let run_cache_chirho = RunCacheVerifyChirho {
        runs_chirho: run_cache_report_chirho.runs_chirho,
        runkeys_chirho: run_cache_report_chirho.runkeys_chirho,
        runseals_chirho: run_cache_report_chirho.runseals_chirho,
        clean_chirho: run_cache_clean_chirho,
    };

    let volatile_report_chirho = verify_chirho::verify_volatile_effect_records_chirho(root_chirho)?;
    let volatile_effects_chirho = VolatileEffectsVerifyChirho {
        records_chirho: volatile_report_chirho.records_chirho,
        objects_chirho: volatile_report_chirho.objects_chirho,
    };

    let privacy_report_chirho = privacy_chirho::verify_privacy_logs_chirho(root_chirho)?;
    let privacy_verify_chirho = PrivacyVerifyChirho {
        blob_records_chirho: privacy_report_chirho.blob_records_chirho,
        erasure_records_chirho: privacy_report_chirho.erasure_records_chirho,
        access_records_chirho: privacy_report_chirho.access_records_chirho,
    };
    let privacy_scan_chirho = privacy_chirho::scan_privacy_surfaces_chirho(root_chirho)?;
    let privacy_scan_findings_chirho = privacy_scan_chirho.findings_chirho.len();

    let residency_chirho = residency_status_chirho(root_chirho)?;
    let compliance_chirho = compliance_status_chirho(root_chirho)?;
    let pg_provider_outcome_chirho = verify_pg_provider_outcome_chirho(setup_chirho)?;

    let green_chirho = ledger_substrate_chirho.reopen_full_replay_ok_chirho
        && ledger_substrate_chirho.conservation_cycle_green_chirho
        && ledger_substrate_chirho.packet_reopen_digest_matches_chirho
        && ledger_substrate_chirho.publication_manifest_reopen_digest_matches_chirho
        && ledger_substrate_chirho.conservation_holds_chirho
        && ledger_substrate_chirho.payer_held_zero_chirho
        && run_cache_clean_chirho
        && privacy_scan_findings_chirho == 0
        && pg_provider_outcome_chirho.restored_row_fingerprint_matches_chirho;

    Ok(VerifierSuiteLegChirho {
        schema_chirho: VERIFIER_SUITE_LEG_SCHEMA_CHIRHO,
        green_chirho,
        ledger_substrate_chirho,
        run_cache_chirho,
        volatile_effects_chirho,
        privacy_verify_chirho,
        privacy_scan_findings_chirho,
        residency_chirho,
        compliance_chirho,
        pg_provider_outcome_chirho,
    })
}

fn verify_ledger_substrate_chirho(
    setup_chirho: &CreditsDemoSetupChirho,
) -> Result<LedgerSubstrateVerifyChirho> {
    // H2/H3 reopen: open_existing fully replays + revalidates the signed journal + every route.
    let config_chirho = cairn_chirho::config_chirho::load_digest_bound_config_chirho(
        &setup_chirho.config_path_chirho,
        &setup_chirho.expected_config_digest_chirho,
    )?;
    let ledger_host_chirho = config_chirho
        .ledger_host_chirho
        .ok_or_else(|| anyhow::anyhow!("config lost its ledger_host block"))?;
    let host_chirho = LedgerHostProjectionReadPortChirho::open_existing_chirho(
        &setup_chirho.root_chirho,
        &setup_chirho.config_path_chirho,
        &ledger_host_chirho,
    )?;
    let cycle_chirho = host_chirho.run_conservation_cycle_once_chirho()?;
    let conservation_cycle_green_chirho = matches!(
        cycle_chirho.outcome_chirho,
        LedgerConservationCycleOutcomeChirho::GreenChirho { .. }
    );
    let balances_chirho = host_chirho.read_substrate_balances_chirho()?;
    // #9: independently RE-READ the immutable H3 packet and require its canonical re-digest to
    // EQUAL the regenesis receipt's recorded packet digest — an equality, never a non-empty check.
    let (_packet_chirho, packet_digest_chirho) =
        load_canonical_ledger_regenesis_evidence_packet_chirho(&setup_chirho.h3_packet_path_chirho)
            .context("re-read immutable H3 evidence packet for the verifier leg")?;
    let packet_reopen_digest_matches_chirho =
        packet_digest_chirho == setup_chirho.regenesis_packet_digest_chirho;
    if !packet_reopen_digest_matches_chirho {
        bail!("H3 packet re-digest no longer equals the regenesis receipt packet digest");
    }
    let (_publication_manifest_chirho, publication_manifest_digest_chirho) =
        load_canonical_ledger_regenesis_publication_manifest_chirho(
            &setup_chirho.h3_publication_manifest_path_chirho,
        )
        .context("re-read immutable H3 publication manifest for the verifier leg")?;
    let publication_manifest_reopen_digest_matches_chirho = publication_manifest_digest_chirho
        == setup_chirho.regenesis_publication_manifest_digest_chirho;
    if !publication_manifest_reopen_digest_matches_chirho {
        bail!("H3 publication manifest re-digest no longer equals the regenesis receipt");
    }
    // Both money accounts MUST be present in the verified fold — a missing account is a refusal,
    // never a silent zero.
    let payer_key_chirho = (
        setup_chirho.payer_chirho.clone(),
        setup_chirho.billing_kind_chirho.clone(),
    );
    let settlement_key_chirho = (
        setup_chirho.settlement_owner_chirho.clone(),
        setup_chirho.billing_kind_chirho.clone(),
    );
    let payer_net_chirho = *balances_chirho
        .account_nets_chirho
        .get(&payer_key_chirho)
        .ok_or_else(|| anyhow::anyhow!("payer account absent from the verified substrate fold"))?;
    let settlement_net_chirho = *balances_chirho
        .account_nets_chirho
        .get(&settlement_key_chirho)
        .ok_or_else(|| {
            anyhow::anyhow!("settlement account absent from the verified substrate fold")
        })?;
    let payer_held_chirho = *balances_chirho
        .account_held_chirho
        .get(&payer_key_chirho)
        .unwrap_or(&0);
    let payer_held_zero_chirho = payer_held_chirho == 0;
    let all_held_zero_chirho = balances_chirho
        .account_held_chirho
        .values()
        .all(|held_chirho| *held_chirho == 0);
    // Conservation with CHECKED arithmetic: initial mint (bound from the verified plan) == sum of
    // account nets, and the two money accounts sum to it at exactly 730 / 20.
    let mut sum_nets_chirho: u64 = 0;
    for net_chirho in balances_chirho.account_nets_chirho.values() {
        sum_nets_chirho = sum_nets_chirho
            .checked_add(*net_chirho)
            .ok_or_else(|| anyhow::anyhow!("account-net sum overflow"))?;
    }
    let payer_plus_settlement_chirho = payer_net_chirho
        .checked_add(settlement_net_chirho)
        .ok_or_else(|| anyhow::anyhow!("payer+settlement net overflow"))?;
    // #6072: the journal's OWN supply coordinate, exact-selected by billing kind (absence
    // REFUSES), must equal the verified initial mint.
    let final_net_supply_chirho = *balances_chirho
        .net_supply_by_kind_chirho
        .get(&setup_chirho.billing_kind_chirho)
        .ok_or_else(|| anyhow::anyhow!("billing kind absent from the verified net-supply fold"))?;
    let conservation_holds_chirho = sum_nets_chirho == setup_chirho.plan_mint_amount_chirho
        && payer_plus_settlement_chirho == setup_chirho.plan_mint_amount_chirho
        && final_net_supply_chirho == setup_chirho.plan_mint_amount_chirho
        && payer_net_chirho == 730
        && settlement_net_chirho == 20
        && all_held_zero_chirho;

    Ok(LedgerSubstrateVerifyChirho {
        reopen_full_replay_ok_chirho: true,
        conservation_cycle_green_chirho,
        packet_reopen_digest_matches_chirho,
        publication_manifest_reopen_digest_matches_chirho,
        initial_minted_chirho: setup_chirho.plan_mint_amount_chirho,
        final_net_supply_chirho,
        payer_net_chirho,
        settlement_net_chirho,
        payer_held_zero_chirho,
        conservation_holds_chirho,
    })
}

/// #13/#6058: pin the external provider's own outcome tables EXACTLY through the ADAPTER-OWNED
/// verified inventory — every counted forward decision / compensation receipt passed canonical
/// parse + MAC + embedded-K/row binding (the stored kind column is only a dispatch label and is
/// never trusted raw) — and prove the restored seed row's CONTENT by recomputing its keyed
/// fingerprint under the configured adapter key against the preflight-recorded fingerprint.
fn verify_pg_provider_outcome_chirho(
    setup_chirho: &CreditsDemoSetupChirho,
) -> Result<PgProviderOutcomeVerifyChirho> {
    let mut client_chirho = connect_pg_chirho(&setup_chirho.dsn_chirho)?;
    let adapter_key_chirho = super::concurrency_token_chirho::load_adapter_evidence_key_chirho(
        &setup_chirho.root_chirho,
    )?;
    let inventory_chirho =
        verified_provider_outcome_inventory_chirho(&mut client_chirho, &adapter_key_chirho)
            .map_err(|error_chirho| anyhow::anyhow!("{error_chirho}"))?;
    // The live arc writes exactly: one committed forward decision (L2), one definite-no-effect
    // forward decision (R4b), one compensation receipt (L4). Compensation writes NO forward
    // decision. The fresh-root preflight proved both tables empty, so these verified rows are
    // THIS arc's.
    if inventory_chirho.committed_decisions_chirho != 1
        || inventory_chirho.definite_no_effect_decisions_chirho != 1
        || inventory_chirho.compensation_receipts_chirho != 1
    {
        bail!(
            "verified provider outcome census mismatch: committed={} definite_no_effect={} \
             compensation_receipts={} (expected 1/1/1)",
            inventory_chirho.committed_decisions_chirho,
            inventory_chirho.definite_no_effect_decisions_chirho,
            inventory_chirho.compensation_receipts_chirho
        );
    }
    // TOTAL table cardinality first (#6067): the restored table must hold EXACTLY the one seed
    // row — a stray extra row is a provider-state violation even when the target row matches.
    let total_values_chirho: i64 = client_chirho
        .query_one(
            "SELECT count(*)::bigint FROM cairn_reversible_values_chirho",
            &[],
        )
        .context("count restored provider values")?
        .get(0);
    if total_values_chirho != 1 {
        bail!(
            "restored provider values table holds {total_values_chirho} rows, expected exactly 1"
        );
    }
    let value_rows_chirho = client_chirho
        .query(
            "SELECT value_chirho FROM cairn_reversible_values_chirho \
             WHERE subject_chirho = $1 AND row_key_chirho = $2",
            &[
                &constants_chirho::FIXED_SUBJECT_CHIRHO,
                &constants_chirho::FIXED_ROW_KEY_CHIRHO,
            ],
        )
        .context("read restored provider seed row")?;
    if value_rows_chirho.len() != 1 {
        bail!(
            "expected exactly one restored provider seed row, found {}",
            value_rows_chirho.len()
        );
    }
    let restored_value_chirho: Vec<u8> = value_rows_chirho[0].get(0);
    let restored_fingerprint_chirho = row_fingerprint_chirho(
        &adapter_key_chirho,
        &HashChirho(constants_chirho::FIXED_SUBJECT_CHIRHO.to_string()),
        &HashChirho(constants_chirho::FIXED_ROW_KEY_CHIRHO.to_string()),
        &restored_value_chirho,
    );
    // CONTENT check against the ACTUAL preflight-recorded fingerprint (#6046/#6047 — never the
    // fixture constant): the restored row re-fingerprints to the same keyed before-state.
    let restored_row_fingerprint_matches_chirho = restored_fingerprint_chirho.0
        == setup_chirho
            .external_preconditions_chirho
            .seed_before_state_fingerprint_chirho;
    if !restored_row_fingerprint_matches_chirho {
        bail!("restored provider seed row does not re-fingerprint to the preflight-recorded value");
    }
    Ok(PgProviderOutcomeVerifyChirho {
        forward_decision_rows_chirho: inventory_chirho
            .committed_decisions_chirho
            .checked_add(inventory_chirho.definite_no_effect_decisions_chirho)
            .ok_or_else(|| anyhow::anyhow!("forward decision count overflow"))?,
        committed_decisions_chirho: inventory_chirho.committed_decisions_chirho,
        definite_no_effect_decisions_chirho: inventory_chirho.definite_no_effect_decisions_chirho,
        comp_receipt_rows_chirho: inventory_chirho.compensation_receipts_chirho,
        total_values_rows_chirho: u64::try_from(total_values_chirho)
            .map_err(|_error_chirho| anyhow::anyhow!("negative values cardinality"))?,
        target_values_rows_chirho: u64::try_from(value_rows_chirho.len())
            .map_err(|_error_chirho| anyhow::anyhow!("target row count overflow"))?,
        restored_row_fingerprint_matches_chirho,
    })
}

fn residency_status_chirho(root_chirho: &Path) -> Result<VerifierStatusChirho> {
    let report_chirho = data_residency_chirho::verify_data_residency_chirho(root_chirho)?;
    if report_chirho.noncompliant_attestations_chirho > 0 {
        bail!(
            "data-residency-verify found {} noncompliant attestation(s)",
            report_chirho.noncompliant_attestations_chirho
        );
    }
    let records_chirho = report_chirho
        .policy_records_chirho
        .checked_add(report_chirho.attestation_records_chirho)
        .ok_or_else(|| anyhow::anyhow!("residency record count overflow"))?;
    Ok(if records_chirho == 0 {
        VerifierStatusChirho::NotApplicableEmptyChirho { records_chirho: 0 }
    } else {
        VerifierStatusChirho::GreenChirho { records_chirho }
    })
}

fn compliance_status_chirho(root_chirho: &Path) -> Result<VerifierStatusChirho> {
    let report_chirho =
        compliance_evidence_chirho::verify_compliance_evidence_chirho(root_chirho, None)?;
    if report_chirho.failed_sources_chirho > 0
        || report_chirho.coverage_gaps_chirho > 0
        || report_chirho.manual_controls_chirho > 0
    {
        bail!(
            "compliance-evidence-verify found {} failed source(s), {} coverage gap(s), {} manual control(s)",
            report_chirho.failed_sources_chirho,
            report_chirho.coverage_gaps_chirho,
            report_chirho.manual_controls_chirho
        );
    }
    Ok(if report_chirho.records_chirho == 0 {
        VerifierStatusChirho::NotApplicableEmptyChirho { records_chirho: 0 }
    } else {
        VerifierStatusChirho::GreenChirho {
            records_chirho: report_chirho.records_chirho,
        }
    })
}

/// Leg 3 under the sealed three-part census law (9afeb514/d7e7f270): (a) verified legacy
/// credentials = zero ALWAYS; (b) the FROZEN exact Gate-1 / economic money-spine delete-candidate
/// markers in the fresh root = zero ALWAYS; (c) run/node status is `not-applicable-pre-law-chirho`
/// while this binary carries no Packet-4 marker law (a BINARY inapplicability claim, never a
/// root-absence proof); the anomaly scan never supplies activation authority — a marker-ish
/// artifact is an UNEXPECTED-ARTIFACT red with no validity claim. Never green-by-skip; current v1
/// identities are never mislabeled as legacy. Counts + fixed class labels only.
pub fn run_no_legacy_chirho(setup_chirho: &CreditsDemoSetupChirho) -> Result<NoLegacyLegChirho> {
    let root_chirho = setup_chirho.root_chirho.as_path();
    let inventory_chirho = identity_chirho::credential_inventory_chirho(root_chirho)?;
    let credential_inventory_chirho = CredentialInventoryLegChirho {
        identity_records_chirho: inventory_chirho.identity_records_chirho,
        argon2id_credentials_chirho: inventory_chirho.argon2id_credentials_chirho,
        legacy_blake3_credentials_chirho: inventory_chirho.legacy_blake3_credentials_chirho,
        credentialless_keys_chirho: inventory_chirho.credentialless_keys_chirho,
        legacy_zero_chirho: inventory_chirho.legacy_blake3_credentials_chirho == 0
            && inventory_chirho.legacy_principal_hashes_chirho.is_empty(),
    };

    // (b) ALWAYS: the FROZEN exact-name money-spine delete-candidate markers (#6058/#6060) —
    // never substrings, never imports of the live legacy path helpers (the census must outlive
    // the deleted code; the cfg(test) superset pin binds the frozen list to the live names).
    let gate1_marker_files_chirho = count_marker_files_chirho(root_chirho, &|name_chirho| {
        name_chirho == "gate1-authority-head-chirho"
            || name_chirho == "gate1-authority-log-chirho.jsonl"
    })?;
    let economic_spine_marker_files_chirho =
        count_marker_files_chirho(root_chirho, &|name_chirho| {
            constants_chirho::MONEY_SPINE_MARKER_NAMES_CHIRHO.contains(&name_chirho)
                && !name_chirho.starts_with("gate1-")
        })?;
    let money_spine_zero_chirho =
        gate1_marker_files_chirho == 0 && economic_spine_marker_files_chirho == 0;

    // (c) PRE-LAW (sealed #6066/#6068/#6069 + #6082-B claim-shape): no Packet-4 marker law exists
    // in this binary, so the status is not-applicable-pre-law — a BINARY inapplicability claim,
    // never a root-absence proof. The scan below is ONLY an anomaly detector: a marker-ish
    // artifact on a fresh root is unexpected and blocks green as an UNEXPECTED-ARTIFACT red that
    // makes NO activation or marker-validity claim. When Packet-4 lands its law, the
    // authority-owned verifier owns this branch.
    let v2_anomaly_files_chirho = count_marker_files_chirho(root_chirho, &|name_chirho| {
        name_chirho.contains("cairn-runtime-contract-v2-chirho")
    })?;
    let run_node_migration_chirho = if v2_anomaly_files_chirho == 0 {
        RunNodeMigrationCensusChirho::NotApplicablePreLawChirho {
            v2_activation_authority_deployed_chirho: false,
        }
    } else {
        RunNodeMigrationCensusChirho::UnexpectedArtifactPreLawRedChirho {
            unexpected_artifact_files_chirho: v2_anomaly_files_chirho,
        }
    };
    let migration_not_red_chirho = !matches!(
        run_node_migration_chirho,
        RunNodeMigrationCensusChirho::RedChirho { .. }
            | RunNodeMigrationCensusChirho::UnexpectedArtifactPreLawRedChirho { .. }
    );
    let census_green_chirho = money_spine_zero_chirho && migration_not_red_chirho;
    let artifact_census_chirho = ArtifactCensusChirho {
        gate1_marker_files_chirho,
        economic_spine_marker_files_chirho,
        money_spine_zero_chirho,
        run_node_migration_chirho,
        census_green_chirho,
    };

    let green_chirho = credential_inventory_chirho.legacy_zero_chirho
        && artifact_census_chirho.census_green_chirho;
    Ok(NoLegacyLegChirho {
        schema_chirho: NO_LEGACY_LEG_SCHEMA_CHIRHO,
        green_chirho,
        credential_inventory_chirho,
        artifact_census_chirho,
    })
}

/// #6082-A: key-aware structural path policy over the emitted packet value.
fn assert_no_structural_path_leak_chirho(
    value_chirho: &serde_json::Value,
    key_chirho: Option<&str>,
) -> Result<()> {
    match value_chirho {
        serde_json::Value::String(text_chirho) => {
            // #6106/#6117: URI-shaped and loopback-host coordinates refuse REGARDLESS of key —
            // the bounded-route allowance below can never override them.
            let uri_or_loopback_chirho = text_chirho.contains("://")
                || text_chirho.to_ascii_lowercase().contains("localhost")
                || text_chirho.contains("[::1]")
                || text_chirho.contains("::1");
            if uri_or_loopback_chirho {
                bail!("emitted packet carries a URI/loopback host coordinate (key {key_chirho:?})");
            }
            let path_shaped_chirho = text_chirho.starts_with('/')
                || text_chirho.starts_with("\\\\")
                || (text_chirho.len() >= 3 && text_chirho.as_bytes()[1] == b':');
            if path_shaped_chirho {
                // Only a CLEAN bounded route path may use the path_chirho exception: bounded
                // prefix, no traversal, no embedded host coordinates (already refused above).
                let allowed_chirho = key_chirho == Some("path_chirho")
                    && (text_chirho.starts_with("/ssr-chirho/")
                        || text_chirho.starts_with("/app-chirho/"))
                    && !text_chirho
                        .split('/')
                        .any(|part_chirho| part_chirho == "..");
                if !allowed_chirho {
                    bail!(
                        "emitted packet carries a path-shaped string outside the bounded HTTP \
                         path fields (key {key_chirho:?})"
                    );
                }
            }
        }
        serde_json::Value::Object(map_chirho) => {
            for (inner_key_chirho, inner_chirho) in map_chirho {
                assert_no_structural_path_leak_chirho(inner_chirho, Some(inner_key_chirho))?;
            }
        }
        serde_json::Value::Array(items_chirho) => {
            for inner_chirho in items_chirho {
                assert_no_structural_path_leak_chirho(inner_chirho, key_chirho)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Real bounded scan of the fresh runtime root for marker FILES matching a fixed name predicate.
/// Counts only; never records paths or matched content.
fn count_marker_files_chirho(
    root_chirho: &Path,
    matches_chirho: &dyn Fn(&str) -> bool,
) -> Result<usize> {
    fn walk_chirho(
        dir_chirho: &Path,
        matches_chirho: &dyn Fn(&str) -> bool,
        count_chirho: &mut usize,
        depth_chirho: usize,
    ) -> Result<()> {
        if !dir_chirho.is_dir() {
            return Ok(());
        }
        // A depth beyond the bound REFUSES (#6065) — a silently unscanned deep artifact would be
        // a false-green census, never acceptable for a delete precondition.
        if depth_chirho > 16 {
            bail!("marker census exceeded the depth bound (root nesting deeper than 16)");
        }
        for entry_chirho in std::fs::read_dir(dir_chirho)? {
            let entry_chirho = entry_chirho?;
            let path_chirho = entry_chirho.path();
            if let Some(name_chirho) = path_chirho
                .file_name()
                .and_then(|name_chirho| name_chirho.to_str())
            {
                // A marker DIRECTORY counts too (e.g. the gate1 authority head), then descend.
                if matches_chirho(name_chirho) {
                    *count_chirho = count_chirho
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("marker count overflow"))?;
                }
            }
            if entry_chirho.file_type()?.is_dir() {
                let next_depth_chirho = depth_chirho
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("marker walk depth overflow"))?;
                walk_chirho(
                    &path_chirho,
                    matches_chirho,
                    count_chirho,
                    next_depth_chirho,
                )?;
            }
        }
        Ok(())
    }
    let mut count_chirho = 0usize;
    walk_chirho(root_chirho, matches_chirho, &mut count_chirho, 0)?;
    Ok(count_chirho)
}

/// Scan the emitted packet JSON for absolute host paths, DSN connection strings/values, secret bytes,
/// and session token values — INCLUDING the caller-supplied dynamic needles resolved from the ACTUAL
/// configured production secret set (#6067: fixture seed patterns alone would pass a rotated real
/// operator key). Bounded logical gate labels (cax11-hosted-phase-b-packet-chirho, etc.) are
/// EXPLICITLY allowed — the invariant is "no host coordinates / no secrets", not "no mention of a
/// Phase-C gate".
pub fn assert_no_secret_or_path_leak_chirho(
    packet_json_chirho: &str,
    dynamic_secret_needles_chirho: &[String],
) -> Result<()> {
    for needle_chirho in dynamic_secret_needles_chirho {
        if needle_chirho.len() >= 8 && packet_json_chirho.contains(needle_chirho.as_str()) {
            bail!("emitted packet leaked a resolved production secret/token value");
        }
    }
    // #6082-A STRUCTURAL policy: parse the packet VALUE and walk every (key, string) pair —
    // path-shaped strings are permitted ONLY in the explicit HTTP path fields with the bounded
    // route prefixes; every other absolute or drive/UNC-shaped coordinate refuses (a flat prefix
    // list cannot enumerate /opt, /srv, /root, or Windows forms).
    let packet_value_chirho: serde_json::Value = serde_json::from_str(packet_json_chirho)
        .context("re-parse emitted packet for the structural path policy")?;
    assert_no_structural_path_leak_chirho(&packet_value_chirho, None)?;
    for needle_chirho in [
        "/Users/",
        "/private/tmp/",
        "/var/lib/",
        "/var/backups/",
        "/etc/",
        "/tmp/",
        "/home/",
    ] {
        if packet_json_chirho.contains(needle_chirho) {
            bail!("emitted packet leaked an absolute host path ('{needle_chirho}')");
        }
    }
    for needle_chirho in [
        "host=/tmp",
        "dbname=",
        "port=5432",
        "connection_secret",
        "password=",
        "127.0.0.1",
        "postgres://",
        "postgresql://",
    ] {
        if packet_json_chirho.contains(needle_chirho) {
            bail!("emitted packet leaked a DSN / connection / loopback coordinate ('{needle_chirho}')");
        }
    }
    if packet_json_chirho.contains('@') {
        bail!("emitted packet contained an '@' (possible address/credential leak)");
    }
    // Deterministic demo secret seed bytes must never appear (32-byte repeats of the seed values).
    for seed_chirho in [0x2bu8, 0x33, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86] {
        let hex_chirho = format!("{seed_chirho:02x}").repeat(32);
        if packet_json_chirho.contains(&hex_chirho) {
            bail!("emitted packet leaked a 32-byte secret seed value");
        }
    }
    Ok(())
}
