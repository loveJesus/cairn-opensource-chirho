// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Local backup/restore drill evidence for the production operations blocker.
//!
//! The command copies the configured root into a private temporary restore root, verifies the
//! restored copy with the existing verifier families, and reports fixed redaction labels plus
//! counts. It deliberately does not touch live hosts or retire the hosted ops blocker.

use crate::{
    compliance_evidence_chirho, data_residency_chirho, operator_evidence_chirho,
    privacy_backup_chirho, privacy_chirho, refs_chirho, verify_chirho, versioned_chirho,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

// TEST-ONLY after the (a2-3) repoint: production here now reads through the RETAINED evidence
// modules. The only remaining reach into the dying tree is `post_entry_chirho` in the cfg(test)
// fixture at `seed_restore_root_chirho`, which seeds a root -- it is a test, not a production
// write, and the deletion map recorded it as production until the cfg boundary was resolved.
pub const OPS_RESTORE_DRILL_REPORT_SCHEMA_CHIRHO: &str = "ops-restore-drill-report-v1-chirho";
const RESTORE_ROOT_REDACTED_CHIRHO: &str = "local-restore-root-redacted-chirho";
const VERSIONED_STORE_FILE_CHIRHO: &str = "versioned-chirho.redb";
const VIEWER_STATE_STORE_FILE_CHIRHO: &str = "viewer-state-chirho.redb";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsRestoreCopiedSurfacesChirho {
    pub cas_objects_chirho: usize,
    pub signed_jsonl_logs_chirho: usize,
    pub private_blob_key_files_chirho: usize,
    pub signing_key_present_chirho: bool,
    pub versioned_store_present_chirho: bool,
    #[serde(default)]
    pub viewer_state_store_present_chirho: bool,
    pub refs_present_chirho: bool,
    pub reflog_present_chirho: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsRestoreVerifierCountsChirho {
    pub run_cache_runs_chirho: usize,
    pub run_cache_runkeys_chirho: usize,
    pub run_cache_runseals_chirho: usize,
    pub volatile_effect_records_chirho: usize,
    pub volatile_effect_objects_chirho: usize,
    pub privacy_blob_records_chirho: usize,
    pub privacy_erasure_records_chirho: usize,
    pub privacy_access_records_chirho: usize,
    pub privacy_scan_findings_chirho: usize,
    pub privacy_backup_policy_records_chirho: usize,
    pub privacy_replica_targets_chirho: usize,
    pub privacy_erasure_propagation_records_chirho: usize,
    pub data_residency_policy_records_chirho: usize,
    pub data_residency_attestation_records_chirho: usize,
    pub data_residency_noncompliant_attestations_chirho: usize,
    pub ledger_entries_chirho: usize,
    pub versioned_current_entries_chirho: usize,
    #[serde(default)]
    pub viewer_state_store_readable_chirho: bool,
    pub refs_branches_chirho: usize,
    pub reflog_entries_chirho: usize,
    pub compliance_pack_chirho: crate::model_chirho::HashChirho,
    pub compliance_records_chirho: usize,
    pub compliance_packs_chirho: usize,
    pub compliance_failed_sources_chirho: usize,
    pub compliance_coverage_gaps_chirho: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsRestoreDrillReportChirho {
    pub schema_chirho: &'static str,
    pub source_root_scope_chirho: String,
    pub restore_root_scope_chirho: String,
    pub copied_surfaces_chirho: OpsRestoreCopiedSurfacesChirho,
    pub verifier_counts_chirho: OpsRestoreVerifierCountsChirho,
    pub private_blob_roundtrip_chirho: bool,
    pub restore_verified_chirho: bool,
    pub hosted_ops_blocker_closed_chirho: bool,
    pub honest_scope_chirho: Vec<String>,
}

pub fn run_ops_restore_drill_chirho(root_chirho: &Path) -> Result<OpsRestoreDrillReportChirho> {
    if !root_chirho.exists() {
        bail!("ops restore drill root does not exist");
    }
    let restore_chirho = TempRestoreRootChirho::create_chirho()?;
    let source_canonical_chirho = root_chirho
        .canonicalize()
        .with_context(|| "canonicalize ops restore drill source root")?;
    let restore_canonical_chirho = restore_chirho
        .path_chirho
        .canonicalize()
        .with_context(|| "canonicalize ops restore drill restore root")?;
    if restore_canonical_chirho.starts_with(&source_canonical_chirho) {
        bail!("ops restore drill restore root must not be inside the source root");
    }

    copy_root_tree_chirho(root_chirho, &restore_chirho.path_chirho)?;
    let copied_surfaces_chirho = copied_surfaces_chirho(&restore_chirho.path_chirho)?;
    let verifier_counts_chirho = verify_restored_root_chirho(&restore_chirho.path_chirho)?;
    let private_blob_roundtrip_chirho =
        restored_private_blob_roundtrip_chirho(&restore_chirho.path_chirho)?;
    let restore_verified_chirho = private_blob_roundtrip_chirho
        && verifier_counts_chirho.privacy_scan_findings_chirho == 0
        && verifier_counts_chirho.data_residency_noncompliant_attestations_chirho == 0
        && verifier_counts_chirho.compliance_failed_sources_chirho == 0
        && verifier_counts_chirho.compliance_coverage_gaps_chirho == 0;

    Ok(OpsRestoreDrillReportChirho {
        schema_chirho: OPS_RESTORE_DRILL_REPORT_SCHEMA_CHIRHO,
        source_root_scope_chirho: operator_evidence_chirho::redacted_local_root_scope_chirho(
            root_chirho,
        ),
        restore_root_scope_chirho: RESTORE_ROOT_REDACTED_CHIRHO.to_string(),
        copied_surfaces_chirho,
        verifier_counts_chirho,
        private_blob_roundtrip_chirho,
        restore_verified_chirho,
        hosted_ops_blocker_closed_chirho: false,
        honest_scope_chirho: vec![
            "local restore drill only; no live host, SSH, DNS, TLS, provider, Stripe, or user-traffic action was performed".to_string(),
            "source and restore filesystem paths are fixed redaction labels; counts and content hashes are the evidence".to_string(),
            "the hosted ops blocker remains open until this drill plus custody, token, TLS/DNS, and hosted verifier evidence run on the hosted root".to_string(),
            "compliance evidence is generated and verified only inside the temporary restored copy, not in the source root".to_string(),
        ],
    })
}

fn verify_restored_root_chirho(root_chirho: &Path) -> Result<OpsRestoreVerifierCountsChirho> {
    let run_cache_chirho = verify_chirho::verify_run_cache_chirho(root_chirho)?;
    let volatile_chirho = verify_chirho::verify_volatile_effect_records_chirho(root_chirho)?;
    let privacy_chirho = privacy_chirho::verify_privacy_logs_chirho(root_chirho)?;
    let privacy_scan_chirho = privacy_chirho::scan_privacy_surfaces_chirho(root_chirho)?;
    let privacy_backup_chirho = privacy_backup_chirho::verify_privacy_backups_chirho(root_chirho)?;
    let data_residency_chirho = data_residency_chirho::verify_data_residency_chirho(root_chirho)?;
    let ledger_entries_chirho =
        crate::legacy_ledger_evidence_chirho::verify_ledger_chirho(root_chirho)?;
    let versioned_current_entries_chirho = restored_versioned_current_entries_chirho(root_chirho)?;
    let viewer_state_store_readable_chirho =
        restored_viewer_state_store_readable_chirho(root_chirho)?;
    let refs_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    let reflog_chirho = refs_chirho::reflog_chirho(root_chirho)?;
    let frameworks_chirho = vec![
        "iso27001-chirho".to_string(),
        "iso27017-chirho".to_string(),
        "iso27018-chirho".to_string(),
        "iso27701-chirho".to_string(),
        "soc2-chirho".to_string(),
    ];
    let receipt_chirho = compliance_evidence_chirho::generate_compliance_evidence_pack_chirho(
        root_chirho,
        &frameworks_chirho,
        0,
        now_ms_chirho().saturating_add(1),
        "ops-restore-drill-chirho",
    )?;
    let compliance_chirho = compliance_evidence_chirho::verify_compliance_evidence_chirho(
        root_chirho,
        Some(&receipt_chirho.pack_chirho),
    )?;
    Ok(OpsRestoreVerifierCountsChirho {
        run_cache_runs_chirho: run_cache_chirho.runs_chirho,
        run_cache_runkeys_chirho: run_cache_chirho.runkeys_chirho,
        run_cache_runseals_chirho: run_cache_chirho.runseals_chirho,
        volatile_effect_records_chirho: volatile_chirho.records_chirho,
        volatile_effect_objects_chirho: volatile_chirho.objects_chirho,
        privacy_blob_records_chirho: privacy_chirho.blob_records_chirho,
        privacy_erasure_records_chirho: privacy_chirho.erasure_records_chirho,
        privacy_access_records_chirho: privacy_chirho.access_records_chirho,
        privacy_scan_findings_chirho: privacy_scan_chirho.findings_chirho.len(),
        privacy_backup_policy_records_chirho: privacy_backup_chirho
            .backup_key_policy_records_chirho,
        privacy_replica_targets_chirho: privacy_backup_chirho.replica_targets_chirho,
        privacy_erasure_propagation_records_chirho: privacy_backup_chirho
            .erasure_propagation_records_chirho,
        data_residency_policy_records_chirho: data_residency_chirho.policy_records_chirho,
        data_residency_attestation_records_chirho: data_residency_chirho.attestation_records_chirho,
        data_residency_noncompliant_attestations_chirho: data_residency_chirho
            .noncompliant_attestations_chirho,
        ledger_entries_chirho,
        versioned_current_entries_chirho,
        viewer_state_store_readable_chirho,
        refs_branches_chirho: refs_chirho.branches_chirho.len(),
        reflog_entries_chirho: reflog_chirho.len(),
        compliance_pack_chirho: receipt_chirho.pack_chirho,
        compliance_records_chirho: compliance_chirho.records_chirho,
        compliance_packs_chirho: compliance_chirho.packs_chirho,
        compliance_failed_sources_chirho: compliance_chirho.failed_sources_chirho,
        compliance_coverage_gaps_chirho: compliance_chirho.coverage_gaps_chirho,
    })
}

fn copied_surfaces_chirho(root_chirho: &Path) -> Result<OpsRestoreCopiedSurfacesChirho> {
    Ok(OpsRestoreCopiedSurfacesChirho {
        cas_objects_chirho: count_regular_files_chirho(&root_chirho.join("objects-chirho"))?,
        signed_jsonl_logs_chirho: count_extension_files_chirho(root_chirho, "jsonl")?,
        private_blob_key_files_chirho: count_regular_files_chirho(
            &root_chirho.join("privacy-keys-chirho"),
        )?,
        signing_key_present_chirho: root_chirho.join("signing-key-chirho.bin").is_file(),
        versioned_store_present_chirho: root_chirho.join(VERSIONED_STORE_FILE_CHIRHO).is_file(),
        viewer_state_store_present_chirho: root_chirho
            .join(VIEWER_STATE_STORE_FILE_CHIRHO)
            .is_file(),
        refs_present_chirho: root_chirho.join("refs-chirho.json").is_file(),
        reflog_present_chirho: root_chirho.join("reflog-chirho.jsonl").is_file(),
    })
}

fn restored_versioned_current_entries_chirho(root_chirho: &Path) -> Result<usize> {
    let path_chirho = root_chirho.join(VERSIONED_STORE_FILE_CHIRHO);
    if !path_chirho.is_file() {
        return Ok(0);
    }
    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(&path_chirho)?;
    Ok(store_chirho.current_entries_chirho()?.len())
}

fn restored_viewer_state_store_readable_chirho(root_chirho: &Path) -> Result<bool> {
    let path_chirho = root_chirho.join(VIEWER_STATE_STORE_FILE_CHIRHO);
    if !path_chirho.is_file() {
        return Ok(true);
    }
    let _store_chirho =
        cairn_store_redb_chirho::viewer_state_chirho::ViewerStateStoreChirho::open_existing_chirho(
            &path_chirho,
        )?;
    Ok(true)
}

fn restored_private_blob_roundtrip_chirho(root_chirho: &Path) -> Result<bool> {
    let records_chirho = privacy_chirho::load_privacy_blob_records_chirho(root_chirho)?;
    let Some(record_chirho) = records_chirho.first() else {
        return Ok(true);
    };
    let plaintext_chirho =
        privacy_chirho::load_private_blob_chirho(root_chirho, &record_chirho.blob_chirho)?;
    Ok(plaintext_chirho.len() == record_chirho.bytes_chirho)
}

fn copy_root_tree_chirho(source_chirho: &Path, destination_chirho: &Path) -> Result<()> {
    for entry_chirho in
        std::fs::read_dir(source_chirho).with_context(|| "read ops restore drill source root")?
    {
        let entry_chirho = entry_chirho?;
        let from_chirho = entry_chirho.path();
        let to_chirho = destination_chirho.join(entry_chirho.file_name());
        copy_entry_chirho(&from_chirho, &to_chirho)?;
    }
    Ok(())
}

fn copy_entry_chirho(source_chirho: &Path, destination_chirho: &Path) -> Result<()> {
    let metadata_chirho = std::fs::symlink_metadata(source_chirho)
        .with_context(|| "inspect ops restore drill source entry")?;
    if metadata_chirho.file_type().is_symlink() {
        bail!("ops restore drill refuses to copy symlink entries");
    }
    if metadata_chirho.is_dir() {
        std::fs::create_dir_all(destination_chirho)
            .with_context(|| "create ops restore drill restore directory")?;
        set_permissions_like_source_chirho(source_chirho, destination_chirho)?;
        for entry_chirho in std::fs::read_dir(source_chirho)
            .with_context(|| "read ops restore drill source directory")?
        {
            let entry_chirho = entry_chirho?;
            copy_entry_chirho(
                &entry_chirho.path(),
                &destination_chirho.join(entry_chirho.file_name()),
            )?;
        }
        return Ok(());
    }
    if metadata_chirho.is_file() {
        if let Some(parent_chirho) = destination_chirho.parent() {
            std::fs::create_dir_all(parent_chirho)
                .with_context(|| "create ops restore drill restore file parent")?;
        }
        std::fs::copy(source_chirho, destination_chirho)
            .with_context(|| "copy ops restore drill source file")?;
        set_permissions_like_source_chirho(source_chirho, destination_chirho)?;
        return Ok(());
    }
    bail!("ops restore drill refuses to copy special filesystem entries")
}

fn count_extension_files_chirho(root_chirho: &Path, extension_chirho: &str) -> Result<usize> {
    if !root_chirho.exists() {
        return Ok(0);
    }
    let mut count_chirho = 0usize;
    count_extension_files_inner_chirho(root_chirho, extension_chirho, &mut count_chirho)?;
    Ok(count_chirho)
}

fn count_extension_files_inner_chirho(
    root_chirho: &Path,
    extension_chirho: &str,
    count_chirho: &mut usize,
) -> Result<()> {
    for entry_chirho in std::fs::read_dir(root_chirho)? {
        let path_chirho = entry_chirho?.path();
        let metadata_chirho = std::fs::symlink_metadata(&path_chirho)?;
        if metadata_chirho.file_type().is_symlink() {
            bail!("ops restore drill inventory refuses symlink entries");
        }
        if metadata_chirho.is_dir() {
            count_extension_files_inner_chirho(&path_chirho, extension_chirho, count_chirho)?;
        } else if metadata_chirho.is_file()
            && path_chirho
                .extension()
                .and_then(|ext_chirho| ext_chirho.to_str())
                == Some(extension_chirho)
        {
            *count_chirho += 1;
        }
    }
    Ok(())
}

fn count_regular_files_chirho(path_chirho: &Path) -> Result<usize> {
    if !path_chirho.exists() {
        return Ok(0);
    }
    let metadata_chirho = std::fs::symlink_metadata(path_chirho)?;
    if metadata_chirho.file_type().is_symlink() {
        bail!("ops restore drill inventory refuses symlink entries");
    }
    if metadata_chirho.is_file() {
        return Ok(1);
    }
    if !metadata_chirho.is_dir() {
        return Ok(0);
    }
    let mut count_chirho = 0usize;
    for entry_chirho in std::fs::read_dir(path_chirho)? {
        count_chirho += count_regular_files_chirho(&entry_chirho?.path())?;
    }
    Ok(count_chirho)
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_millis() as u64)
        .unwrap_or(0)
}

fn unique_temp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_nanos())
        .unwrap_or(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!("cairn-ops-restore-drill-{nanos_chirho}-{n_chirho}"))
}

fn set_private_dir_permissions_chirho(path_chirho: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn set_permissions_like_source_chirho(
    source_chirho: &Path,
    destination_chirho: &Path,
) -> Result<()> {
    let permissions_chirho = std::fs::symlink_metadata(source_chirho)?.permissions();
    std::fs::set_permissions(destination_chirho, permissions_chirho)?;
    Ok(())
}

struct TempRestoreRootChirho {
    path_chirho: PathBuf,
}

impl TempRestoreRootChirho {
    fn create_chirho() -> Result<Self> {
        let path_chirho = unique_temp_root_chirho();
        std::fs::create_dir(&path_chirho).with_context(|| "create ops restore drill temp root")?;
        set_private_dir_permissions_chirho(&path_chirho)?;
        Ok(Self { path_chirho })
    }
}

impl Drop for TempRestoreRootChirho {
    fn drop(&mut self) {
        let file_name_chirho = self
            .path_chirho
            .file_name()
            .and_then(|name_chirho| name_chirho.to_str())
            .unwrap_or("");
        if file_name_chirho.starts_with("cairn-ops-restore-drill-") {
            let _ = std::fs::remove_dir_all(&self.path_chirho);
        }
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::{cas_chirho, model_chirho::HashChirho, refs_chirho};
    use cairn_store_redb_chirho::viewer_state_chirho::{
        ViewerStateHeadChirho, ViewerStateHeadTransitionChirho, ViewerStateStoreChirho,
    };

    fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        std::env::temp_dir().join(format!("cairn-{label_chirho}-{nanos_chirho}-{n_chirho}"))
    }

    fn seed_restore_root_chirho() -> (PathBuf, Vec<u8>) {
        let root_chirho = tmp_root_chirho("ops-restore-source");
        std::fs::create_dir_all(&root_chirho).unwrap();
        let cas_hash_chirho = cas_chirho::add_chirho(&root_chirho, b"restore-drill-cas").unwrap();
        refs_chirho::set_branch_chirho(&root_chirho, "restore/drill", cas_hash_chirho).unwrap();
        let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
            &root_chirho.join(VERSIONED_STORE_FILE_CHIRHO),
        )
        .unwrap();
        store_chirho
            .put_chirho("restore/drill/key", b"restore-drill-value")
            .unwrap();
        drop(store_chirho);
        let viewer_state_chirho =
            ViewerStateStoreChirho::open_chirho(&root_chirho.join(VIEWER_STATE_STORE_FILE_CHIRHO))
                .unwrap();
        viewer_state_chirho
            .append_bounded_chirho(
                "viewer-state-chirho/restore-app-chirho/actor-chirho/",
                "viewer-state-chirho/restore-app-chirho/actor-chirho/profile-chirho",
                &ViewerStateHeadTransitionChirho {
                    expected_chirho: None,
                    next_chirho: ViewerStateHeadChirho {
                        version_chirho: 1,
                        receipt_digest_chirho: HashChirho(
                            blake3::hash(b"restore-drill-viewer-receipt-chirho")
                                .to_hex()
                                .to_string(),
                        ),
                    },
                },
                b"sealed-row-fixture-chirho",
                4,
                8,
            )
            .unwrap();
        drop(viewer_state_chirho);
        let private_payload_chirho = b"restore-drill-private-payload".to_vec();
        privacy_chirho::store_private_blob_chirho(
            &root_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                "user/restore-drill",
            ),
            "user/restore-drill",
            &private_payload_chirho,
        )
        .unwrap();
        (root_chirho, private_payload_chirho)
    }

    #[test]
    fn ops_restore_drill_copies_and_verifies_redacted_surfaces_chirho() {
        let (root_chirho, private_payload_chirho) = seed_restore_root_chirho();
        let report_chirho = run_ops_restore_drill_chirho(&root_chirho).unwrap();

        assert_eq!(
            report_chirho.schema_chirho,
            OPS_RESTORE_DRILL_REPORT_SCHEMA_CHIRHO
        );
        assert_eq!(
            report_chirho.source_root_scope_chirho,
            operator_evidence_chirho::LOCAL_ROOT_REDACTED_CHIRHO
        );
        assert_eq!(
            report_chirho.restore_root_scope_chirho,
            RESTORE_ROOT_REDACTED_CHIRHO
        );
        assert!(report_chirho.restore_verified_chirho);
        assert!(!report_chirho.hosted_ops_blocker_closed_chirho);
        assert!(report_chirho.copied_surfaces_chirho.cas_objects_chirho >= 2);
        assert!(
            report_chirho
                .copied_surfaces_chirho
                .signed_jsonl_logs_chirho
                >= 2
        );
        assert_eq!(
            report_chirho
                .copied_surfaces_chirho
                .private_blob_key_files_chirho,
            1
        );
        assert!(
            report_chirho
                .copied_surfaces_chirho
                .signing_key_present_chirho
        );
        assert!(
            report_chirho
                .copied_surfaces_chirho
                .versioned_store_present_chirho
        );
        assert!(
            report_chirho
                .copied_surfaces_chirho
                .viewer_state_store_present_chirho
        );
        assert!(report_chirho.copied_surfaces_chirho.refs_present_chirho);
        assert!(report_chirho.copied_surfaces_chirho.reflog_present_chirho);
        assert_eq!(
            report_chirho
                .verifier_counts_chirho
                .privacy_blob_records_chirho,
            1
        );
        assert_eq!(
            report_chirho.verifier_counts_chirho.ledger_entries_chirho,
            // Zero, not one: the V1 ledger writer died with the money spine, so the drill's
            // fixture seeds no entries. The drill still proves it COPIES and VERIFIES the
            // ledger surface -- over an empty log, which is the honest post-wave-1 state.
            0
        );
        assert_eq!(
            report_chirho
                .verifier_counts_chirho
                .versioned_current_entries_chirho,
            1
        );
        assert!(
            report_chirho
                .verifier_counts_chirho
                .viewer_state_store_readable_chirho
        );
        assert_eq!(report_chirho.verifier_counts_chirho.refs_branches_chirho, 1);
        assert_eq!(
            report_chirho.verifier_counts_chirho.reflog_entries_chirho,
            1
        );
        assert_eq!(
            report_chirho
                .verifier_counts_chirho
                .compliance_failed_sources_chirho,
            0
        );
        assert!(report_chirho.private_blob_roundtrip_chirho);

        let json_chirho = serde_json::to_string_pretty(&report_chirho).unwrap();
        assert!(!json_chirho.contains(root_chirho.to_string_lossy().as_ref()));
        assert!(!json_chirho.contains(std::env::temp_dir().to_string_lossy().as_ref()));
        assert!(!json_chirho.contains(std::str::from_utf8(&private_payload_chirho).unwrap()));
    }

    #[test]
    fn ops_restore_drill_rejects_tampered_restored_signed_logs_chirho() {
        let (root_chirho, _private_payload_chirho) = seed_restore_root_chirho();
        let restore_chirho = tmp_root_chirho("ops-restore-tampered");
        std::fs::create_dir_all(&restore_chirho).unwrap();
        copy_root_tree_chirho(&root_chirho, &restore_chirho).unwrap();
        // RETARGETED AT CF6 WAVE-1. This tampered the ledger log, which the fixture no longer
        // seeds because the V1 writer died with the money spine. The property under test is "a
        // tampered restored SIGNED LOG is rejected" -- the ledger was one instance, not the
        // subject -- so it now tampers a signed log the fixture still writes. If this goes red,
        // read whether the log still exists before assuming the rejection broke.
        let signed_log_chirho = restore_chirho.join("privacy-blob-records-chirho.jsonl");
        let mut text_chirho = std::fs::read_to_string(&signed_log_chirho).unwrap();
        text_chirho = text_chirho.replace("\"seq_chirho\":0", "\"seq_chirho\":7");
        std::fs::write(&signed_log_chirho, text_chirho).unwrap();

        let err_chirho = verify_restored_root_chirho(&restore_chirho).unwrap_err();
        // "ledger" dropped from the accepted reasons with the ledger log itself. Kept as a
        // disjunction rather than pinned to one string because the point is that verification
        // REFUSES a tampered restored log, not which layer notices first.
        assert!(
            err_chirho.to_string().contains("signature")
                || err_chirho.to_string().contains("privacy")
                || err_chirho.to_string().contains("seq")
                || err_chirho.to_string().contains("source"),
            "a tampered restored signed log must be refused: {err_chirho}"
        );
    }

    #[test]
    fn ops_restore_drill_rejects_symlink_entries_chirho() {
        let root_chirho = tmp_root_chirho("ops-restore-symlink");
        std::fs::create_dir_all(&root_chirho).unwrap();
        let target_chirho = root_chirho.join("target-chirho.txt");
        std::fs::write(&target_chirho, b"target").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&target_chirho, root_chirho.join("link-chirho")).unwrap();
            let err_chirho = run_ops_restore_drill_chirho(&root_chirho).unwrap_err();
            assert!(err_chirho.to_string().contains("symlink"));
        }
    }

    #[test]
    fn ops_restore_drill_keeps_empty_private_blob_roundtrip_valid_chirho() {
        let root_chirho = tmp_root_chirho("ops-restore-empty");
        std::fs::create_dir_all(&root_chirho).unwrap();
        let object_chirho = cas_chirho::add_chirho(&root_chirho, b"empty-root-object").unwrap();
        refs_chirho::set_branch_chirho(&root_chirho, "restore/empty", object_chirho).unwrap();
        let report_chirho = run_ops_restore_drill_chirho(&root_chirho).unwrap();
        assert!(report_chirho.private_blob_roundtrip_chirho);
        assert!(report_chirho.restore_verified_chirho);
    }

    #[test]
    fn ops_restore_drill_report_uses_hash_not_paths_for_compliance_pack_chirho() {
        let (root_chirho, _private_payload_chirho) = seed_restore_root_chirho();
        let report_chirho = run_ops_restore_drill_chirho(&root_chirho).unwrap();
        let pack_chirho = &report_chirho
            .verifier_counts_chirho
            .compliance_pack_chirho
            .0;
        assert_eq!(pack_chirho.len(), 64);
        assert!(pack_chirho
            .chars()
            .all(|c_chirho| c_chirho.is_ascii_hexdigit()));
        assert_ne!(HashChirho(pack_chirho.clone()), HashChirho(String::new()));
    }
}
