// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Verifies a staged artifact manifest as CF8 clause 12 deploy evidence.
//!
//! The clause asks that deploy evidence bind source commit, target triple, architecture, and binary
//! hash, including one reviewed aarch64/x86_64 pair. `DeployEvidenceChirho` already expresses that
//! contract; until now nothing outside its own crate consumed it, so the contract was reusable and
//! unused. This binary is the shipping consumer: it reads the manifest produced from installed bytes
//! and drives the typed verifier rather than re-checking the fields by hand.
//!
//! **Only HOSTED artifacts are deploy evidence.** Rows built for the operator's own machine carry the
//! architecture label `native`, which names no target; counting them would let a local build help
//! satisfy a cross-architecture pair that is supposed to be about what reached the fleet.
//!
//! **Evidence is grouped PER BINARY, and that grouping is the whole correctness of this check.** The
//! set verifier refuses the same commit and triple carrying different bytes — true for one program
//! across hosts, and nonsense across a fleet of different programs, which naturally have different
//! hashes. Verifying all rows as one set reports a defect that is not one; verifying per binary asks
//! the real question, which is whether one program was installed as different bytes in two places.
//! A reviewed pair is likewise per binary: the SAME program built for both architectures from one
//! commit, not two unrelated binaries that happen to cover both.

use cairn_placement_chirho::deploy_evidence_chirho::{
    is_reviewed_arch_pair_chirho, verify_deploy_set_chirho, DeployEvidenceChirho,
};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE_REFUSAL_CHIRHO: &str = "DeployEvidenceVerifyUsageRefusedChirho";
const MANIFEST_READ_REFUSAL_CHIRHO: &str = "DeployEvidenceManifestReadRefusedChirho";
const MANIFEST_SCHEMA_REFUSAL_CHIRHO: &str = "DeployEvidenceManifestSchemaRefusedChirho";
const MANIFEST_SHAPE_REFUSAL_CHIRHO: &str = "DeployEvidenceManifestShapeRefusedChirho";
const ARCH_PAIR_REFUSAL_CHIRHO: &str = "DeployEvidenceReviewedArchPairRefusedChirho";
const EMPTY_POPULATION_REFUSAL_CHIRHO: &str = "DeployEvidenceHostedPopulationEmptyChirho";

/// The manifest schema that carries all four clause-12 fields. v1 omitted the target triple, so it
/// cannot satisfy the contract and is refused by name rather than read leniently.
const REQUIRED_MANIFEST_SCHEMA_CHIRHO: &str = "cf7-r4c-artifact-manifest-v2-chirho";
const HOSTED_ARCHITECTURES_CHIRHO: [&str; 2] = ["x86_64", "aarch64"];

fn next_utf8_chirho(
    arguments_chirho: &mut impl Iterator<Item = OsString>,
) -> Result<String, &'static str> {
    arguments_chirho
        .next()
        .ok_or(USAGE_REFUSAL_CHIRHO)?
        .into_string()
        .map_err(|_value_chirho| USAGE_REFUSAL_CHIRHO)
}

fn string_field_chirho(row_chirho: &serde_json::Value, key_chirho: &str) -> Result<String, String> {
    row_chirho
        .get(key_chirho)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| MANIFEST_SHAPE_REFUSAL_CHIRHO.to_owned())
}

fn hosted_records_by_binary_chirho(
    manifest_chirho: &serde_json::Value,
) -> Result<BTreeMap<String, Vec<DeployEvidenceChirho>>, String> {
    let schema_chirho = manifest_chirho
        .get("schema_chirho")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| MANIFEST_SHAPE_REFUSAL_CHIRHO.to_owned())?;
    if schema_chirho != REQUIRED_MANIFEST_SCHEMA_CHIRHO {
        return Err(MANIFEST_SCHEMA_REFUSAL_CHIRHO.to_owned());
    }
    let source_commit_chirho = string_field_chirho(manifest_chirho, "reviewed_commit_chirho")?;
    let artifacts_chirho = manifest_chirho
        .get("artifacts_chirho")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| MANIFEST_SHAPE_REFUSAL_CHIRHO.to_owned())?;

    let mut by_binary_chirho: BTreeMap<String, Vec<DeployEvidenceChirho>> = BTreeMap::new();
    for row_chirho in artifacts_chirho {
        let architecture_chirho = string_field_chirho(row_chirho, "arch_chirho")?;
        if !HOSTED_ARCHITECTURES_CHIRHO.contains(&architecture_chirho.as_str()) {
            continue;
        }
        let source_name_chirho = string_field_chirho(row_chirho, "source_name_chirho")?;
        by_binary_chirho
            .entry(source_name_chirho)
            .or_default()
            .push(DeployEvidenceChirho {
                source_commit_chirho: source_commit_chirho.clone(),
                target_triple_chirho: string_field_chirho(row_chirho, "target_triple_chirho")?,
                host_architecture_chirho: architecture_chirho,
                binary_sha256_chirho: string_field_chirho(row_chirho, "sha256_chirho")?,
            });
    }
    Ok(by_binary_chirho)
}

fn run_chirho() -> Result<String, String> {
    let mut arguments_chirho = std::env::args_os();
    let _program_chirho = arguments_chirho.next();
    let manifest_path_chirho = PathBuf::from(next_utf8_chirho(&mut arguments_chirho)?);
    if arguments_chirho.next().is_some() {
        return Err(USAGE_REFUSAL_CHIRHO.to_string());
    }

    let bytes_chirho = std::fs::read(&manifest_path_chirho)
        .map_err(|_error_chirho| MANIFEST_READ_REFUSAL_CHIRHO.to_owned())?;
    let manifest_chirho: serde_json::Value = serde_json::from_slice(&bytes_chirho)
        .map_err(|_error_chirho| MANIFEST_READ_REFUSAL_CHIRHO.to_owned())?;

    let by_binary_chirho = hosted_records_by_binary_chirho(&manifest_chirho)?;
    if by_binary_chirho.is_empty() {
        return Err(EMPTY_POPULATION_REFUSAL_CHIRHO.to_owned());
    }
    let mut record_count_chirho = 0_usize;
    let mut triples_chirho: BTreeSet<String> = BTreeSet::new();
    let mut architectures_chirho: BTreeSet<String> = BTreeSet::new();
    let mut reviewed_pair_binaries_chirho: Vec<&str> = Vec::new();
    let mut source_commit_chirho = String::new();
    for (binary_chirho, records_chirho) in &by_binary_chirho {
        verify_deploy_set_chirho(records_chirho)
            .map_err(|refusal_chirho| format!("{refusal_chirho:?}"))?;
        record_count_chirho += records_chirho.len();
        for record_chirho in records_chirho {
            triples_chirho.insert(record_chirho.target_triple_chirho.clone());
            architectures_chirho.insert(record_chirho.host_architecture_chirho.clone());
            source_commit_chirho.clone_from(&record_chirho.source_commit_chirho);
        }
        if is_reviewed_arch_pair_chirho(records_chirho) {
            reviewed_pair_binaries_chirho.push(binary_chirho.as_str());
        }
    }
    // One reviewed pair is the clause's bar, and it must be ONE program spanning both architectures.
    if reviewed_pair_binaries_chirho.is_empty() {
        return Err(ARCH_PAIR_REFUSAL_CHIRHO.to_owned());
    }

    let rendered_chirho = serde_json::json!({
        "schema_chirho": "cf8-deploy-evidence-verdict-v1-chirho",
        "source_commit_chirho": source_commit_chirho,
        "hosted_binary_count_chirho": by_binary_chirho.len(),
        "hosted_record_count_chirho": record_count_chirho,
        "target_triples_chirho": triples_chirho.iter().collect::<Vec<_>>(),
        "host_architectures_chirho": architectures_chirho.iter().collect::<Vec<_>>(),
        "reviewed_arch_pair_binaries_chirho": reviewed_pair_binaries_chirho,
        "verdict_chirho": "green-chirho",
    });
    serde_json::to_string(&rendered_chirho)
        .map_err(|_error_chirho| MANIFEST_SHAPE_REFUSAL_CHIRHO.to_owned())
}

fn main() -> ExitCode {
    match run_chirho() {
        Ok(rendered_chirho) => {
            println!("{rendered_chirho}");
            ExitCode::SUCCESS
        }
        Err(identity_chirho) => {
            eprintln!("{identity_chirho}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod deploy_evidence_verify_tests_chirho {
    use super::*;

    fn manifest_chirho(rows_chirho: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "schema_chirho": REQUIRED_MANIFEST_SCHEMA_CHIRHO,
            "reviewed_commit_chirho": "a".repeat(40),
            "artifacts_chirho": rows_chirho,
        })
    }

    fn row_chirho(
        name_chirho: &str,
        arch_chirho: &str,
        triple_chirho: &str,
        sha_chirho: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "host_chirho": "boaz1",
            "arch_chirho": arch_chirho,
            "target_triple_chirho": triple_chirho,
            "source_name_chirho": name_chirho,
            "installed_name_chirho": name_chirho,
            "sha256_chirho": sha_chirho,
        })
    }

    fn pair_chirho() -> serde_json::Value {
        serde_json::json!([
            row_chirho(
                "one-chirho",
                "x86_64",
                "x86_64-unknown-linux-gnu",
                &"1".repeat(64)
            ),
            row_chirho(
                "one-chirho",
                "aarch64",
                "aarch64-unknown-linux-gnu",
                &"2".repeat(64)
            ),
        ])
    }

    #[test]
    fn v1_schema_is_refused_because_it_cannot_carry_a_triple_chirho() {
        let mut manifest_value_chirho = manifest_chirho(pair_chirho());
        manifest_value_chirho["schema_chirho"] =
            serde_json::json!("cf7-r4c-artifact-manifest-v1-chirho");
        assert_eq!(
            hosted_records_by_binary_chirho(&manifest_value_chirho).unwrap_err(),
            MANIFEST_SCHEMA_REFUSAL_CHIRHO
        );
    }

    #[test]
    fn a_row_missing_its_triple_is_refused_rather_than_defaulted_chirho() {
        let mut rows_chirho = pair_chirho();
        rows_chirho[0]
            .as_object_mut()
            .unwrap()
            .remove("target_triple_chirho");
        assert_eq!(
            hosted_records_by_binary_chirho(&manifest_chirho(rows_chirho)).unwrap_err(),
            MANIFEST_SHAPE_REFUSAL_CHIRHO
        );
    }

    /// A local build must not help satisfy a claim about what reached the fleet.
    #[test]
    fn native_rows_are_excluded_from_deploy_evidence_chirho() {
        let mut rows_chirho = pair_chirho();
        rows_chirho.as_array_mut().unwrap().push(row_chirho(
            "local-tool-chirho",
            "native",
            "aarch64-apple-darwin",
            &"3".repeat(64),
        ));
        let grouped_chirho =
            hosted_records_by_binary_chirho(&manifest_chirho(rows_chirho)).unwrap();
        assert!(!grouped_chirho.contains_key("local-tool-chirho"));
        assert_eq!(grouped_chirho.len(), 1);
    }

    /// The grouping IS the correctness: different programs legitimately differ in bytes, so verifying
    /// them as one set would report a defect that is not one.
    #[test]
    fn distinct_binaries_are_grouped_separately_and_do_not_collide_chirho() {
        let rows_chirho = serde_json::json!([
            row_chirho(
                "one-chirho",
                "x86_64",
                "x86_64-unknown-linux-gnu",
                &"1".repeat(64)
            ),
            row_chirho(
                "two-chirho",
                "x86_64",
                "x86_64-unknown-linux-gnu",
                &"4".repeat(64)
            ),
        ]);
        let grouped_chirho =
            hosted_records_by_binary_chirho(&manifest_chirho(rows_chirho)).unwrap();
        assert_eq!(grouped_chirho.len(), 2);
        for records_chirho in grouped_chirho.values() {
            verify_deploy_set_chirho(records_chirho).expect("one program per group verifies");
        }
    }

    /// The same program installed as different bytes for the same target IS the hazard.
    #[test]
    fn one_binary_with_two_byte_sets_for_one_triple_is_refused_chirho() {
        let rows_chirho = serde_json::json!([
            row_chirho(
                "one-chirho",
                "x86_64",
                "x86_64-unknown-linux-gnu",
                &"1".repeat(64)
            ),
            row_chirho(
                "one-chirho",
                "x86_64",
                "x86_64-unknown-linux-gnu",
                &"5".repeat(64)
            ),
        ]);
        let grouped_chirho =
            hosted_records_by_binary_chirho(&manifest_chirho(rows_chirho)).unwrap();
        let records_chirho = grouped_chirho.get("one-chirho").unwrap();
        assert!(verify_deploy_set_chirho(records_chirho).is_err());
    }

    #[test]
    fn a_reviewed_pair_needs_one_program_spanning_both_architectures_chirho() {
        let grouped_chirho =
            hosted_records_by_binary_chirho(&manifest_chirho(pair_chirho())).unwrap();
        assert!(is_reviewed_arch_pair_chirho(
            grouped_chirho.get("one-chirho").unwrap()
        ));

        // Two different programs covering one architecture each is NOT a pair.
        let split_chirho = serde_json::json!([
            row_chirho(
                "one-chirho",
                "x86_64",
                "x86_64-unknown-linux-gnu",
                &"1".repeat(64)
            ),
            row_chirho(
                "two-chirho",
                "aarch64",
                "aarch64-unknown-linux-gnu",
                &"2".repeat(64)
            ),
        ]);
        let split_grouped_chirho =
            hosted_records_by_binary_chirho(&manifest_chirho(split_chirho)).unwrap();
        assert!(split_grouped_chirho
            .values()
            .all(|records_chirho| !is_reviewed_arch_pair_chirho(records_chirho)));
    }
}
