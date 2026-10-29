// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Runs the complete credits-demo authoring rail against one immutable local-Cargo source closure.
//!
//! Workflow: `spec-chirho/workflows-chirho/reversible-postgres-effect-chirho/credits-demo-localphaseb-smoke-chirho.md`.

mod command_chirho;
mod fixture_chirho;
mod snapshot_chirho;
#[cfg(test)]
mod tests_chirho;

use anyhow::{bail, Context, Result};
use cairn_chirho::{app_source_manifest_chirho, cas_chirho};
use cairn_tree_build_chirho::check_chirho::check_app_tree_with_descriptor_chirho;
use cairn_tree_build_chirho::emit_chirho::{
    emit_manifest_bytes_chirho, load_app_descriptor_chirho,
};
use cairn_tree_build_chirho::tree_chirho::walk_app_tree_chirho;
use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

use self::command_chirho::{run_trusted_cargo_chirho, trusted_cargo_chirho};
use self::fixture_chirho::{
    capture_emitted_node_artifacts_chirho, parse_emitted_manifest_chirho,
    prepared_artifacts_chirho, run_exact_node_fixtures_chirho,
};
use self::snapshot_chirho::SourceSnapshotChirho;
use super::types_chirho::{
    AuthoringGateArtifactDispositionChirho, AuthoringGateReportChirho,
    AuthoringGateStepEvidenceChirho, AUTHORING_GATE_REPORT_SCHEMA_CHIRHO,
};

const MAX_PROVIDED_MANIFEST_BYTES_CHIRHO: u64 = 1024 * 1024;

pub(super) struct VerifiedAuthoringGateChirho {
    snapshot_chirho: SourceSnapshotChirho,
    pub emit_bytes_chirho: Vec<u8>,
    pub manifest_regenerated_and_matched_chirho: Option<bool>,
    pub prepared_inputs_chirho: app_source_manifest_chirho::AppSourcePreparedInputsChirho,
    pub report_chirho: AuthoringGateReportChirho,
}

impl VerifiedAuthoringGateChirho {
    pub fn snapshot_root_chirho(&self) -> &Path {
        self.snapshot_chirho.root_chirho()
    }
}

/// Execute the documented authoring sequence against one complete immutable source closure. The
/// returned prepared inputs hold the exact node artifact bytes the fixtures executed.
pub(super) fn preflight_authoring_gate_chirho(
    app_root_chirho: &Path,
    manifest_path_chirho: Option<&Path>,
) -> Result<VerifiedAuthoringGateChirho> {
    let cargo_chirho = trusted_cargo_chirho()?;
    let snapshot_chirho =
        snapshot_chirho::snapshot_source_closure_chirho(app_root_chirho, &cargo_chirho)?;
    let snapshot_root_chirho = snapshot_chirho.root_chirho();
    let fingerprint_chirho = snapshot_chirho.fingerprint_chirho().clone();
    let mut steps_chirho = Vec::with_capacity(5);

    let tree_chirho = walk_app_tree_chirho(snapshot_root_chirho);
    let descriptor_chirho = load_app_descriptor_chirho(snapshot_root_chirho)
        .map_err(|error_chirho| anyhow::anyhow!("load app descriptor: {error_chirho}"))?;
    let findings_chirho =
        check_app_tree_with_descriptor_chirho(&tree_chirho, Some(&descriptor_chirho));
    if !findings_chirho.is_empty() {
        bail!(
            "credits-demo authoring check failed: {}",
            serde_json::to_string(&findings_chirho)
                .context("serialize credits-demo authoring findings")?
        );
    }
    snapshot_chirho.assert_unchanged_chirho("check")?;
    steps_chirho.push(AuthoringGateStepEvidenceChirho::CheckChirho {
        source_tree_blake3_chirho: fingerprint_chirho.blake3_chirho.clone(),
        finding_count_chirho: findings_chirho.len(),
    });

    let guest_output_chirho = run_trusted_cargo_chirho(
        &cargo_chirho,
        snapshot_root_chirho,
        Some(snapshot_chirho.target_dir_chirho()),
        "guest-tests-chirho",
        &["test", "--locked", "--offline", "--quiet"],
    )?;
    let guest_test_count_chirho = cargo_test_count_chirho(&guest_output_chirho.stdout_chirho)?;
    if guest_test_count_chirho == 0 {
        bail!("credits-demo guest test command succeeded but executed zero tests");
    }
    snapshot_chirho.assert_unchanged_chirho("guest tests")?;
    steps_chirho.push(AuthoringGateStepEvidenceChirho::GuestTestsChirho {
        source_tree_blake3_chirho: fingerprint_chirho.blake3_chirho.clone(),
        exit_code_chirho: guest_output_chirho.status_chirho.code().unwrap_or(-1),
        test_count_chirho: guest_test_count_chirho,
    });

    // A planning emit identifies the artifacts to build. The final emit still occurs after
    // fixtures, and immutable-closure equality below makes any planning/final drift a refusal.
    let planned_emit_bytes_chirho = emit_manifest_bytes_chirho(&tree_chirho, &descriptor_chirho)
        .map_err(|error_chirho| anyhow::anyhow!("plan app source manifest emit: {error_chirho}"))?;
    let planned_manifest_chirho = parse_emitted_manifest_chirho(&planned_emit_bytes_chirho)?;
    let wasm_output_chirho = run_trusted_cargo_chirho(
        &cargo_chirho,
        snapshot_root_chirho,
        Some(snapshot_chirho.target_dir_chirho()),
        "wasm-examples-build-chirho",
        &[
            "build",
            "--locked",
            "--offline",
            "--quiet",
            "--target",
            "wasm32-unknown-unknown",
            "--examples",
        ],
    )?;
    let artifacts_chirho = capture_emitted_node_artifacts_chirho(
        snapshot_root_chirho,
        snapshot_chirho.target_dir_chirho(),
        &planned_manifest_chirho,
    )?;
    snapshot_chirho.assert_unchanged_chirho("WASM examples build and artifact capture")?;
    steps_chirho.push(AuthoringGateStepEvidenceChirho::WasmExamplesBuildChirho {
        source_tree_blake3_chirho: fingerprint_chirho.blake3_chirho.clone(),
        exit_code_chirho: wasm_output_chirho.status_chirho.code().unwrap_or(-1),
        artifact_count_chirho: artifacts_chirho.len(),
    });

    let fixture_report_chirho =
        run_exact_node_fixtures_chirho(snapshot_root_chirho, &artifacts_chirho)?;
    snapshot_chirho.assert_unchanged_chirho("node fixtures")?;
    steps_chirho.push(AuthoringGateStepEvidenceChirho::NodeFixturesChirho {
        source_tree_blake3_chirho: fingerprint_chirho.blake3_chirho.clone(),
        fixture_count_chirho: fixture_report_chirho.fixture_count_chirho,
        pure_node_count_chirho: fixture_report_chirho.pure_node_count_chirho,
        disposition_count_chirho: fixture_report_chirho.dispositions_chirho.len(),
        failure_count_chirho: 0,
    });

    let emit_bytes_chirho = emit_manifest_bytes_chirho(&tree_chirho, &descriptor_chirho)
        .map_err(|error_chirho| anyhow::anyhow!("emit app source manifest: {error_chirho}"))?;
    if emit_bytes_chirho != planned_emit_bytes_chirho {
        bail!("final app source emit diverged from the artifact-planning emit");
    }
    let emitted_manifest_blake3_chirho = hash_bytes_chirho(&emit_bytes_chirho);
    snapshot_chirho.assert_unchanged_chirho("emit")?;
    steps_chirho.push(AuthoringGateStepEvidenceChirho::EmitChirho {
        source_tree_blake3_chirho: fingerprint_chirho.blake3_chirho.clone(),
        emitted_manifest_blake3_chirho: emitted_manifest_blake3_chirho.clone(),
        emitted_manifest_bytes_chirho: emit_bytes_chirho.len(),
    });

    let prepared_artifacts_chirho = prepared_artifacts_chirho(&artifacts_chirho);
    let prepared_inputs_chirho =
        app_source_manifest_chirho::preflight_app_source_manifest_inputs_with_captured_node_artifacts_chirho(
            snapshot_root_chirho,
            &emit_bytes_chirho,
            &prepared_artifacts_chirho,
        )?;
    snapshot_chirho.assert_unchanged_chirho("prepared input capture")?;

    let report_chirho = AuthoringGateReportChirho {
        schema_chirho: AUTHORING_GATE_REPORT_SCHEMA_CHIRHO,
        source_tree_blake3_chirho: fingerprint_chirho.blake3_chirho.clone(),
        source_entry_count_chirho: fingerprint_chirho.entry_count_chirho,
        local_package_count_chirho: snapshot_chirho.local_package_count_chirho,
        cargo_executable_blake3_chirho: cargo_chirho.blake3_chirho.clone(),
        emitted_manifest_blake3_chirho,
        artifact_dispositions_chirho: fixture_report_chirho.dispositions_chirho,
        steps_chirho,
    };
    verify_authoring_gate_report_chirho(
        &report_chirho,
        &fingerprint_chirho.blake3_chirho,
        &cargo_chirho.blake3_chirho,
        &emit_bytes_chirho,
        artifacts_chirho.len(),
    )?;

    let manifest_regenerated_and_matched_chirho = match manifest_path_chirho {
        Some(path_chirho) => {
            let provided_chirho = read_bounded_manifest_chirho(path_chirho)?;
            if provided_chirho != emit_bytes_chirho {
                bail!(
                    "provided --manifest bytes diverged from the bound authoring-gate emit; a \
                     hand-authored manifest that does not reproduce the checked tree is refused"
                );
            }
            Some(true)
        }
        None => None,
    };

    Ok(VerifiedAuthoringGateChirho {
        snapshot_chirho,
        emit_bytes_chirho,
        manifest_regenerated_and_matched_chirho,
        prepared_inputs_chirho,
        report_chirho,
    })
}

fn verify_authoring_gate_report_chirho(
    report_chirho: &AuthoringGateReportChirho,
    expected_source_tree_blake3_chirho: &str,
    expected_cargo_blake3_chirho: &str,
    emit_bytes_chirho: &[u8],
    expected_artifact_count_chirho: usize,
) -> Result<()> {
    if report_chirho.schema_chirho != AUTHORING_GATE_REPORT_SCHEMA_CHIRHO {
        bail!("authoring gate report schema mismatch");
    }
    if report_chirho.source_tree_blake3_chirho != expected_source_tree_blake3_chirho
        || report_chirho.source_entry_count_chirho == 0
        || report_chirho.local_package_count_chirho == 0
    {
        bail!("authoring gate report references incomplete or different source-closure bytes");
    }
    if report_chirho.cargo_executable_blake3_chirho != expected_cargo_blake3_chirho {
        bail!("authoring gate report references different Cargo executable bytes");
    }
    let expected_manifest_blake3_chirho = hash_bytes_chirho(emit_bytes_chirho);
    if report_chirho.emitted_manifest_blake3_chirho != expected_manifest_blake3_chirho {
        bail!("authoring gate report references different emitted manifest bytes");
    }
    verify_artifact_dispositions_chirho(&report_chirho.artifact_dispositions_chirho)?;

    let mut check_seen_chirho = false;
    let mut guest_tests_seen_chirho = false;
    let mut wasm_build_seen_chirho = false;
    let mut fixtures_seen_chirho = false;
    let mut emit_seen_chirho = false;
    for step_chirho in &report_chirho.steps_chirho {
        if step_chirho.source_tree_blake3_chirho() != expected_source_tree_blake3_chirho {
            bail!(
                "authoring gate step '{}' references different source-tree bytes",
                step_chirho.label_chirho()
            );
        }
        match step_chirho {
            AuthoringGateStepEvidenceChirho::CheckChirho {
                finding_count_chirho,
                ..
            } => {
                if std::mem::replace(&mut check_seen_chirho, true) {
                    bail!("duplicate authoring gate step 'check-chirho'");
                }
                if *finding_count_chirho != 0 {
                    bail!("authoring gate check carried findings");
                }
            }
            AuthoringGateStepEvidenceChirho::GuestTestsChirho {
                exit_code_chirho,
                test_count_chirho,
                ..
            } => {
                if std::mem::replace(&mut guest_tests_seen_chirho, true) {
                    bail!("duplicate authoring gate step 'guest-tests-chirho'");
                }
                if *exit_code_chirho != 0 || *test_count_chirho == 0 {
                    bail!("authoring gate guest tests were unsuccessful or empty");
                }
            }
            AuthoringGateStepEvidenceChirho::WasmExamplesBuildChirho {
                exit_code_chirho,
                artifact_count_chirho,
                ..
            } => {
                if std::mem::replace(&mut wasm_build_seen_chirho, true) {
                    bail!("duplicate authoring gate step 'wasm-examples-build-chirho'");
                }
                if *exit_code_chirho != 0
                    || *artifact_count_chirho != expected_artifact_count_chirho
                    || *artifact_count_chirho == 0
                {
                    bail!("authoring gate WASM artifact build evidence was incomplete");
                }
            }
            AuthoringGateStepEvidenceChirho::NodeFixturesChirho {
                fixture_count_chirho,
                pure_node_count_chirho,
                disposition_count_chirho,
                failure_count_chirho,
                ..
            } => {
                if std::mem::replace(&mut fixtures_seen_chirho, true) {
                    bail!("duplicate authoring gate step 'node-fixtures-chirho'");
                }
                if *fixture_count_chirho == 0
                    || *failure_count_chirho != 0
                    || *pure_node_count_chirho != report_chirho.artifact_dispositions_chirho.len()
                    || *disposition_count_chirho != *pure_node_count_chirho
                {
                    bail!("authoring gate node fixtures were empty, failed, or incomplete");
                }
            }
            AuthoringGateStepEvidenceChirho::EmitChirho {
                emitted_manifest_blake3_chirho,
                emitted_manifest_bytes_chirho,
                ..
            } => {
                if std::mem::replace(&mut emit_seen_chirho, true) {
                    bail!("duplicate authoring gate step 'emit-chirho'");
                }
                if emitted_manifest_blake3_chirho != &expected_manifest_blake3_chirho
                    || *emitted_manifest_bytes_chirho != emit_bytes_chirho.len()
                {
                    bail!("authoring gate emit step references different manifest bytes");
                }
            }
        }
    }

    for (label_chirho, seen_chirho) in [
        ("check-chirho", check_seen_chirho),
        ("guest-tests-chirho", guest_tests_seen_chirho),
        ("wasm-examples-build-chirho", wasm_build_seen_chirho),
        ("node-fixtures-chirho", fixtures_seen_chirho),
        ("emit-chirho", emit_seen_chirho),
    ] {
        if !seen_chirho {
            bail!("missing authoring gate step '{label_chirho}'");
        }
    }
    Ok(())
}

fn verify_artifact_dispositions_chirho(
    dispositions_chirho: &[AuthoringGateArtifactDispositionChirho],
) -> Result<()> {
    if dispositions_chirho.is_empty() {
        bail!("authoring gate carried no pure-node artifact dispositions");
    }
    let mut node_ids_chirho = BTreeSet::new();
    let mut paths_chirho = BTreeSet::new();
    for disposition_chirho in dispositions_chirho {
        if !node_ids_chirho.insert(&disposition_chirho.node_id_chirho)
            || !paths_chirho.insert(&disposition_chirho.artifact_path_chirho)
        {
            bail!("authoring gate carried duplicate node or artifact dispositions");
        }
        if disposition_chirho.node_identity_chirho.is_empty()
            || disposition_chirho.artifact_bytes_chirho == 0
            || disposition_chirho.fixture_count_chirho == 0
            || disposition_chirho.disposition_chirho != "fixture-executed-exact-bytes-chirho"
            || !is_hash_chirho(&disposition_chirho.artifact_blake3_chirho)
        {
            bail!("authoring gate carried an incomplete artifact disposition");
        }
    }
    Ok(())
}

fn cargo_test_count_chirho(stdout_chirho: &[u8]) -> Result<usize> {
    let text_chirho = std::str::from_utf8(stdout_chirho)
        .context("trusted Cargo guest-test stdout was not UTF-8")?;
    let mut total_chirho = 0_usize;
    for line_chirho in text_chirho.lines() {
        let Some(summary_chirho) = line_chirho.strip_prefix("test result: ok. ") else {
            continue;
        };
        let Some((passed_chirho, _tail_chirho)) = summary_chirho.split_once(" passed;") else {
            continue;
        };
        total_chirho = total_chirho
            .checked_add(
                passed_chirho
                    .trim()
                    .parse::<usize>()
                    .context("parse Cargo test passed count")?,
            )
            .ok_or_else(|| anyhow::anyhow!("Cargo test count overflow"))?;
    }
    Ok(total_chirho)
}

fn read_bounded_manifest_chirho(path_chirho: &Path) -> Result<Vec<u8>> {
    let file_chirho = std::fs::File::open(path_chirho)
        .with_context(|| format!("open provided manifest {}", path_chirho.display()))?;
    let mut bytes_chirho = Vec::new();
    file_chirho
        .take(MAX_PROVIDED_MANIFEST_BYTES_CHIRHO.saturating_add(1))
        .read_to_end(&mut bytes_chirho)
        .with_context(|| format!("read provided manifest {}", path_chirho.display()))?;
    if bytes_chirho.len() as u64 > MAX_PROVIDED_MANIFEST_BYTES_CHIRHO {
        bail!(
            "provided manifest {} exceeds the {} byte limit",
            path_chirho.display(),
            MAX_PROVIDED_MANIFEST_BYTES_CHIRHO
        );
    }
    Ok(bytes_chirho)
}

fn hash_bytes_chirho(bytes_chirho: &[u8]) -> String {
    cas_chirho::hash_chirho(bytes_chirho).0
}

fn is_hash_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_hexdigit())
}
