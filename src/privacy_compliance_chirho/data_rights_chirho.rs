// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Builds portable subject exports across safe signed logs plus private blob records.

use crate::effect_chirho::{self, run_intent_chirho};
use crate::verify_chirho;
use crate::{
    agent_authority_chirho, agent_report_chirho, app_build_request_chirho, app_chirho,
    attenuation_chirho, compliance_evidence_chirho, data_residency_chirho, effect_pricing_chirho,
    head_removal_chirho, identity_chirho, legal_hold_chirho, oauth_chirho, onboarding_chirho,
    privacy_backup_chirho, privacy_chirho, realtime_ledger_bound_evidence_chirho, resource_chirho,
    retention_chirho, reversion_legacy_evidence_chirho, review_chirho, seqlog_chirho,
};
use anyhow::{bail, Context, Result};
use cairn_gate1_authority_log_chirho::authority_log_chirho;
use cairn_seqlog_chirho::jsonl_read_chirho::read_log_text_chirho;
use cairn_signer_chirho::signer_chirho;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const SUBJECT_EXPORT_EVIDENCE_LOCK_CHIRHO: &str = "subject-export-evidence-chirho";
const SUBJECT_EXPORT_EVIDENCE_RECORD_SCHEMA_CHIRHO: &str =
    "subject-export-evidence-record-v1-chirho";
const REALTIME_TRANSCRIPT_ARTIFACT_EXPORT_SOURCE_CHIRHO: &str =
    "realtime.transcript-artifacts-chirho";
const SUBJECT_EXPORT_BACKUP_PROPAGATION_SCHEMA_CHIRHO: &str =
    "subject-export-backup-erasure-propagation-v1-chirho";
const SUBJECT_EXPORT_REPLICA_TARGET_SCHEMA_CHIRHO: &str =
    "subject-export-privacy-replica-target-v1-chirho";
const SUBJECT_EXPORT_REPLICA_ROOT_REDACTED_CHIRHO: &str = "local-replica-root-redacted-chirho";

#[path = "data_rights_chirho/source_collectors_chirho.rs"]
mod source_collectors_chirho;
#[path = "data_rights_chirho/support_realtime_sources_chirho.rs"]
mod support_realtime_sources_chirho;
use source_collectors_chirho::{
    export_change_control_records_chirho, export_finance_records_chirho,
    export_governance_records_chirho, export_oversight_records_chirho,
    export_product_records_chirho,
};
use support_realtime_sources_chirho::export_realtime_records_chirho;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectRecordExportChirho {
    pub source_chirho: String,
    pub matched_by_chirho: Vec<String>,
    pub retention_policy_chirho: retention_chirho::DataRetentionPolicyChirho,
    pub record_chirho: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectExportSourceCountChirho {
    pub source_chirho: String,
    pub records_chirho: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectExportBackupErasurePropagationChirho {
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub source_erasure_seq_chirho: u64,
    pub subject_chirho: String,
    pub replica_chirho: String,
    pub replica_root_scope_chirho: String,
    pub requested_by_chirho: String,
    pub key_ids_chirho: Vec<String>,
    pub removed_key_ids_chirho: Vec<String>,
    pub already_missing_key_ids_chirho: Vec<String>,
    pub at_ms_chirho: u64,
    pub source_record_verified_chirho: bool,
    pub redacted_fields_chirho: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectExportPrivacyReplicaTargetChirho {
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub replica_chirho: String,
    pub root_scope_chirho: String,
    pub registered_by_chirho: String,
    pub at_ms_chirho: u64,
    pub source_record_verified_chirho: bool,
    pub redacted_fields_chirho: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectExportEvidenceRecordChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub subject_chirho: String,
    pub requested_by_chirho: String,
    pub include_private_chirho: bool,
    pub private_blob_key_ids_chirho: Vec<String>,
    pub erasure_record_seqs_chirho: Vec<u64>,
    #[serde(default)]
    pub backup_propagation_record_seqs_chirho: Vec<u64>,
    #[serde(default)]
    pub legal_hold_record_seqs_chirho: Vec<u64>,
    pub source_counts_chirho: Vec<SubjectExportSourceCountChirho>,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectPortableDataExportChirho {
    pub subject_chirho: String,
    pub generated_ms_chirho: u64,
    pub include_private_chirho: bool,
    pub private_blobs_chirho: Vec<privacy_chirho::SubjectPrivateBlobExportChirho>,
    pub private_blob_retention_policy_chirho: retention_chirho::DataRetentionPolicyChirho,
    pub erasures_chirho: Vec<privacy_chirho::PrivacyErasureRecordChirho>,
    pub privacy_access_records_chirho: Vec<privacy_chirho::PrivacyAccessRecordChirho>,
    pub backup_erasure_propagations_chirho: Vec<SubjectExportBackupErasurePropagationChirho>,
    pub legal_holds_chirho: Vec<legal_hold_chirho::LegalHoldRecordChirho>,
    pub records_chirho: Vec<SubjectRecordExportChirho>,
    pub source_counts_chirho: Vec<SubjectExportSourceCountChirho>,
    pub scope_notes_chirho: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_evidence_chirho: Option<SubjectExportEvidenceRecordChirho>,
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d_chirho| d_chirho.as_millis() as u64)
        .unwrap_or(0)
}

fn subject_export_evidence_records_path_chirho(root_chirho: &Path) -> std::path::PathBuf {
    root_chirho.join("privacy-export-records-chirho.jsonl")
}

pub fn reviewed_subject_export_log_files_chirho() -> BTreeSet<&'static str> {
    privacy_chirho::reviewed_signed_log_files_chirho()
}

pub fn export_subject_portable_data_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    include_private_chirho: bool,
) -> Result<SubjectPortableDataExportChirho> {
    let privacy_export_chirho = privacy_chirho::export_subject_data_chirho(
        root_chirho,
        subject_chirho,
        include_private_chirho,
    )?;
    let subject_key_ids_chirho: BTreeSet<String> = privacy_export_chirho
        .private_blobs_chirho
        .iter()
        .map(|item_chirho| item_chirho.record_chirho.blob_chirho.key_id_chirho.clone())
        .collect();
    verify_subject_portable_export_source_logs_chirho(root_chirho)?;
    let mut records_chirho = Vec::new();

    push_matching_records_chirho(
        "identity.records-chirho",
        // The PAYLOAD verifies its own bytes. Scope honestly: the preflight above already verifies
        // this log, so a forged row was refused before this line too — what changes is that the
        // export no longer trusts a label earned by a DIFFERENT read. That closes the TOCTOU window
        // between preflight and payload, which on a subject-export path decides what a person is
        // told is their own data. The raw loader checks only the schema string, which is why
        // `load_verified_identities_chirho` is documented as the single source of verified records.
        identity_chirho::load_verified_identities_chirho(root_chirho)?,
        subject_chirho,
        &mut records_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            let mut matches_chirho = Vec::new();
            match_exact_chirho(
                "principal_chirho",
                &record_chirho.principal_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            match_account_chirho(
                "wallet_chirho",
                &record_chirho.wallet_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            matches_chirho
        },
        &subject_key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "identity.sessions-chirho",
        identity_chirho::load_sessions_chirho(root_chirho)?,
        subject_chirho,
        &mut records_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "principal_chirho",
                &record_chirho.principal_chirho,
                subject_chirho,
            )
        },
        &subject_key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "identity.session-revocations-chirho",
        identity_chirho::load_session_revocations_chirho(root_chirho)?,
        subject_chirho,
        &mut records_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "principal_chirho",
                &record_chirho.principal_chirho,
                subject_chirho,
            )
        },
        &subject_key_ids_chirho,
    )?;
    // Publication intents name the viewer by principal and are her data (what she asked to
    // publish, when, of which version). Applied records live at the platform level and name her
    // only by digest, so they are matched on that digest — never on a principal string.
    push_matching_records_chirho(
        "publication.intents-chirho",
        crate::publication_chirho::load_publication_intents_chirho(root_chirho)?,
        subject_chirho,
        &mut records_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "user_principal_chirho",
                &record_chirho.user_principal_chirho,
                subject_chirho,
            )
        },
        &subject_key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "publication.applied-chirho",
        crate::publication_chirho::load_publication_applied_chirho(root_chirho)?,
        subject_chirho,
        &mut records_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "user_digest_chirho",
                &record_chirho.user_digest_chirho.0,
                &crate::publication_chirho::publication_user_digest_chirho(subject_chirho).0,
            )
        },
        &subject_key_ids_chirho,
    )?;
    // Her owner binding and her slug claims are hers by the same digest. Reserved slugs are an
    // operator act with no subject and a closed reason vocabulary; they are verified in the
    // preflight below and never matched into anyone's export. Deliberate asymmetry (claude2
    // #21816): intents carry her principal STRING and match on it; the three platform-level
    // publication logs carry only her DIGEST and match on that — do not "fix" either direction.
    push_matching_records_chirho(
        "publication.owners-chirho",
        crate::publication_chirho::apply_chirho::load_publication_owners_chirho(root_chirho)?,
        subject_chirho,
        &mut records_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "user_digest_chirho",
                &record_chirho.user_digest_chirho.0,
                &crate::publication_chirho::publication_user_digest_chirho(subject_chirho).0,
            )
        },
        &subject_key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "publication.slug-claims-chirho",
        crate::publication_chirho::apply_chirho::load_slug_claims_chirho(root_chirho)?,
        subject_chirho,
        &mut records_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "user_digest_chirho",
                &record_chirho.user_digest_chirho.0,
                &crate::publication_chirho::publication_user_digest_chirho(subject_chirho).0,
            )
        },
        &subject_key_ids_chirho,
    )?;
    // A reset record names the principal whose credential changed and the operator who did it;
    // it is the PRINCIPAL's data. Matching on the actor would hand an operator another person's
    // principal id inside their own export.
    // A code event names the principal whose code it is, and the operator or the principal as its actor; like a
    // reset record, it is the PRINCIPAL's data, matched on the principal and never on the actor.
    push_matching_records_chirho(
        "identity.recovery-code-events-chirho",
        identity_chirho::load_recovery_code_events_chirho(root_chirho)?,
        subject_chirho,
        &mut records_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "principal_chirho",
                &record_chirho.principal_chirho,
                subject_chirho,
            )
        },
        &subject_key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "identity.credential-resets-chirho",
        identity_chirho::load_credential_resets_chirho(root_chirho)?,
        subject_chirho,
        &mut records_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "principal_chirho",
                &record_chirho.principal_chirho,
                subject_chirho,
            )
        },
        &subject_key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "oauth.clients-chirho",
        oauth_chirho::load_clients_chirho(root_chirho)?,
        subject_chirho,
        &mut records_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "owner_principal_chirho",
                &record_chirho.owner_principal_chirho,
                subject_chirho,
            )
        },
        &subject_key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "oauth.connection-clients-chirho",
        oauth_chirho::load_connection_clients_chirho(root_chirho)?,
        subject_chirho,
        &mut records_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "owner_principal_chirho",
                &record_chirho.owner_principal_chirho,
                subject_chirho,
            )
        },
        &subject_key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "oauth.scoped-tokens-chirho",
        oauth_chirho::load_scoped_tokens_chirho(root_chirho)?,
        subject_chirho,
        &mut records_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "principal_chirho",
                &record_chirho.principal_chirho,
                subject_chirho,
            )
        },
        &subject_key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "oauth.scoped-token-uses-chirho",
        oauth_chirho::load_scoped_token_uses_chirho(root_chirho)?,
        subject_chirho,
        &mut records_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "principal_chirho",
                &record_chirho.principal_chirho,
                subject_chirho,
            )
        },
        &subject_key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "oauth.connection-tokens-chirho",
        oauth_chirho::load_connection_tokens_chirho(root_chirho)?,
        subject_chirho,
        &mut records_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "principal_chirho",
                &record_chirho.principal_chirho,
                subject_chirho,
            )
        },
        &subject_key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "oauth.connection-token-uses-chirho",
        oauth_chirho::load_connection_token_uses_chirho(root_chirho)?,
        subject_chirho,
        &mut records_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "principal_chirho",
                &record_chirho.principal_chirho,
                subject_chirho,
            )
        },
        &subject_key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "effects.volatile-records-chirho",
        effect_chirho::load_volatile_effect_records_chirho(root_chirho)?,
        subject_chirho,
        &mut records_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            let mut matches_chirho = Vec::new();
            match_capability_chirho(
                "effect_chirho.capability_chirho",
                &record_chirho.effect_chirho.capability_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            matches_chirho
        },
        &subject_key_ids_chirho,
    )?;

    export_governance_records_chirho(
        root_chirho,
        subject_chirho,
        &subject_key_ids_chirho,
        &mut records_chirho,
    )?;
    export_product_records_chirho(
        root_chirho,
        subject_chirho,
        &subject_key_ids_chirho,
        &mut records_chirho,
    )?;
    export_finance_records_chirho(
        root_chirho,
        subject_chirho,
        &subject_key_ids_chirho,
        &mut records_chirho,
    )?;
    export_realtime_records_chirho(
        root_chirho,
        subject_chirho,
        &subject_key_ids_chirho,
        &mut records_chirho,
    )?;
    export_change_control_records_chirho(
        root_chirho,
        subject_chirho,
        &subject_key_ids_chirho,
        &mut records_chirho,
    )?;
    export_oversight_records_chirho(
        root_chirho,
        subject_chirho,
        &subject_key_ids_chirho,
        &mut records_chirho,
    )?;
    push_matching_records_chirho(
        "legal-holds.records-chirho",
        legal_hold_chirho::load_legal_hold_records_chirho(root_chirho)?,
        subject_chirho,
        &mut records_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "subject_chirho",
                &record_chirho.subject_chirho,
                subject_chirho,
            )
        },
        &subject_key_ids_chirho,
    )?;

    records_chirho.sort_by(|left_chirho, right_chirho| {
        left_chirho
            .source_chirho
            .cmp(&right_chirho.source_chirho)
            .then_with(|| {
                left_chirho
                    .record_chirho
                    .to_string()
                    .cmp(&right_chirho.record_chirho.to_string())
            })
    });
    let source_counts_chirho = source_counts_chirho(&records_chirho);
    let private_blob_retention_policy_chirho =
        retention_chirho::private_blob_retention_policy_chirho();
    let backup_erasure_propagations_chirho =
        privacy_backup_chirho::load_privacy_erasure_propagation_records_chirho(root_chirho)?
            .into_iter()
            .filter(|record_chirho| record_chirho.subject_chirho == subject_chirho)
            .map(|record_chirho| {
                redacted_backup_propagation_for_subject_export_chirho(&record_chirho)
            })
            .collect();
    let legal_holds_chirho = legal_hold_chirho::load_legal_hold_records_chirho(root_chirho)?
        .into_iter()
        .filter(|record_chirho| record_chirho.subject_chirho == subject_chirho)
        .collect();
    Ok(SubjectPortableDataExportChirho {
        subject_chirho: privacy_export_chirho.subject_chirho,
        generated_ms_chirho: now_ms_chirho(),
        include_private_chirho,
        private_blobs_chirho: privacy_export_chirho.private_blobs_chirho,
        private_blob_retention_policy_chirho,
        erasures_chirho: privacy_export_chirho.erasures_chirho,
        privacy_access_records_chirho: privacy_export_chirho.access_records_chirho,
        backup_erasure_propagations_chirho,
        legal_holds_chirho,
        records_chirho,
        source_counts_chirho,
        scope_notes_chirho: vec![
            "Portable export covers known safe signed-log records, signed head-removal evidence matched by owner principal, privacy blob records, signed backup-erasure propagation evidence, and signed legal-hold evidence for this subject; writer-fences-chirho mutable-head control files are retained root-scope inventory, not subject records; gate1-authority-head-chirho mutable-head control files are also retained root-scope inventory, not subject records; Gate 1 authority-log envelopes are verifier-covered but not subject records; data residency and ISO/SOC evidence are covered by their own signed evidence modules.".to_string(),
        ],
        export_evidence_chirho: None,
    })
}

pub fn export_subject_portable_data_with_evidence_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    include_private_chirho: bool,
    requested_by_chirho: &str,
) -> Result<SubjectPortableDataExportChirho> {
    let export_chirho =
        export_subject_portable_data_chirho(root_chirho, subject_chirho, include_private_chirho)?;
    finalize_subject_portable_data_export_with_evidence_chirho(
        root_chirho,
        export_chirho,
        requested_by_chirho,
    )
}

pub fn finalize_subject_portable_data_export_with_evidence_chirho(
    root_chirho: &Path,
    mut export_chirho: SubjectPortableDataExportChirho,
    requested_by_chirho: &str,
) -> Result<SubjectPortableDataExportChirho> {
    export_chirho
        .records_chirho
        .sort_by(|left_chirho, right_chirho| {
            left_chirho
                .source_chirho
                .cmp(&right_chirho.source_chirho)
                .then_with(|| {
                    left_chirho
                        .record_chirho
                        .to_string()
                        .cmp(&right_chirho.record_chirho.to_string())
                })
        });
    export_chirho.source_counts_chirho = source_counts_chirho(&export_chirho.records_chirho);
    export_chirho.export_evidence_chirho = None;
    let evidence_chirho = append_subject_export_evidence_record_chirho(
        root_chirho,
        &export_chirho,
        requested_by_chirho,
    )?;
    export_chirho.export_evidence_chirho = Some(evidence_chirho);
    Ok(export_chirho)
}

pub fn load_subject_export_evidence_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<SubjectExportEvidenceRecordChirho>> {
    load_jsonl_chirho(&subject_export_evidence_records_path_chirho(root_chirho))
}

pub fn verify_subject_export_evidence_chirho(root_chirho: &Path) -> Result<usize> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let records_chirho = load_subject_export_evidence_records_chirho(root_chirho)?;
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "privacy export seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        validate_export_token_chirho("subject_chirho", &record_chirho.subject_chirho)?;
        validate_export_token_chirho("requested_by_chirho", &record_chirho.requested_by_chirho)?;
        if !record_chirho.schema_chirho.is_empty()
            && record_chirho.schema_chirho != SUBJECT_EXPORT_EVIDENCE_RECORD_SCHEMA_CHIRHO
        {
            bail!(
                "unsupported subject export evidence schema '{}'",
                record_chirho.schema_chirho
            );
        }
        if !subject_export_evidence_signature_valid_chirho(&pubkey_chirho, record_chirho)? {
            bail!(
                "privacy export evidence {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(records_chirho.len())
}

fn append_subject_export_evidence_record_chirho(
    root_chirho: &Path,
    export_chirho: &SubjectPortableDataExportChirho,
    requested_by_chirho: &str,
) -> Result<SubjectExportEvidenceRecordChirho> {
    validate_export_token_chirho("subject_chirho", &export_chirho.subject_chirho)?;
    validate_export_token_chirho("requested_by_chirho", requested_by_chirho)?;
    seqlog_chirho::with_named_lock_chirho(root_chirho, SUBJECT_EXPORT_EVIDENCE_LOCK_CHIRHO, || {
        let path_chirho = subject_export_evidence_records_path_chirho(root_chirho);
        let seq_chirho = load_subject_export_evidence_records_chirho(root_chirho)?.len() as u64;
        let mut record_chirho = SubjectExportEvidenceRecordChirho {
            schema_chirho: SUBJECT_EXPORT_EVIDENCE_RECORD_SCHEMA_CHIRHO.to_string(),
            seq_chirho,
            subject_chirho: export_chirho.subject_chirho.clone(),
            requested_by_chirho: requested_by_chirho.to_string(),
            include_private_chirho: export_chirho.include_private_chirho,
            private_blob_key_ids_chirho: sorted_private_blob_key_ids_chirho(export_chirho),
            erasure_record_seqs_chirho: sorted_erasure_record_seqs_chirho(export_chirho),
            backup_propagation_record_seqs_chirho: sorted_backup_propagation_record_seqs_chirho(
                export_chirho,
            ),
            legal_hold_record_seqs_chirho: sorted_legal_hold_record_seqs_chirho(export_chirho),
            source_counts_chirho: export_chirho.source_counts_chirho.clone(),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho = subject_export_evidence_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
            &path_chirho,
            record_chirho.seq_chirho,
            &record_chirho,
        )?;
        Ok(record_chirho)
    })
}

fn verify_subject_portable_export_source_logs_chirho(root_chirho: &Path) -> Result<()> {
    verify_export_source_chirho("identity.records-chirho", || {
        identity_chirho::verify_identities_chirho(root_chirho)
    })?;
    verify_export_source_chirho("identity.sessions-chirho", || {
        identity_chirho::verify_sessions_chirho(root_chirho)
    })?;
    // Both logs below are matched into the export above; a log the export reads must be verified
    // by this preflight, or a forged row would be exported as the subject's own data.
    verify_export_source_chirho("identity.session-revocations-chirho", || {
        identity_chirho::verify_session_revocations_chirho(root_chirho)
    })?;
    verify_export_source_chirho("identity.credential-resets-chirho", || {
        identity_chirho::verify_credential_resets_chirho(root_chirho)
    })?;
    verify_export_source_chirho("identity.recovery-code-events-chirho", || {
        identity_chirho::verify_recovery_code_events_chirho(root_chirho)
    })?;
    verify_export_source_chirho("publication.intents-chirho", || {
        crate::publication_chirho::verify_publication_intents_chirho(root_chirho)
    })?;
    verify_export_source_chirho("publication.applied-chirho", || {
        crate::publication_chirho::verify_publication_applied_chirho(root_chirho)
    })?;
    verify_export_source_chirho("publication.owners-chirho", || {
        crate::publication_chirho::apply_chirho::verify_publication_owners_chirho(root_chirho)
    })?;
    verify_export_source_chirho("publication.slug-claims-chirho", || {
        crate::publication_chirho::apply_chirho::verify_slug_claims_chirho(root_chirho)
    })?;
    verify_export_source_chirho("publication.reserved-slugs-chirho", || {
        crate::publication_chirho::apply_chirho::verify_reserved_slugs_chirho(root_chirho)
    })?;
    verify_export_source_chirho("identity.auth-attempts-chirho", || {
        identity_chirho::verify_auth_attempts_chirho(root_chirho)
    })?;
    verify_export_source_chirho("identity.credential-change-attempts-chirho", || {
        identity_chirho::verify_credential_change_attempts_chirho(root_chirho)
    })?;
    verify_export_source_chirho("oauth.clients-chirho", || {
        oauth_chirho::verify_clients_chirho(root_chirho)
    })?;
    verify_export_source_chirho("oauth.connection-clients-chirho", || {
        oauth_chirho::verify_connection_clients_chirho(root_chirho)
    })?;
    verify_export_source_chirho("oauth.scoped-tokens-chirho", || {
        oauth_chirho::verify_scoped_tokens_chirho(root_chirho)
    })?;
    verify_export_source_chirho("oauth.scoped-token-uses-chirho", || {
        oauth_chirho::verify_scoped_token_uses_chirho(root_chirho)
    })?;
    verify_export_source_chirho("oauth.connection-tokens-chirho", || {
        oauth_chirho::verify_connection_tokens_chirho(root_chirho)
    })?;
    verify_export_source_chirho("oauth.connection-token-uses-chirho", || {
        oauth_chirho::verify_connection_token_uses_chirho(root_chirho)
    })?;
    verify_export_source_chirho("volatile-effects-chirho", || {
        verify_chirho::verify_volatile_effect_records_chirho(root_chirho)
    })?;
    verify_export_source_chirho("run-intents.records-chirho", || {
        run_intent_chirho::verify_run_intent_records_chirho(root_chirho)
    })?;
    verify_export_source_chirho("attenuation.grants-chirho", || {
        attenuation_chirho::verify_grants_chirho(root_chirho)
    })?;
    verify_export_source_chirho("agent-authority.responses-chirho", || {
        agent_authority_chirho::verify_agent_authority_responses_chirho(root_chirho)
    })?;
    verify_export_source_chirho("privacy.export-evidence-chirho", || {
        verify_subject_export_evidence_chirho(root_chirho)
    })?;
    verify_export_source_chirho("privacy.backup/replica/propagation-chirho", || {
        privacy_backup_chirho::verify_privacy_backups_chirho(root_chirho)
    })?;
    verify_export_source_chirho("privacy.retention-records-chirho", || {
        retention_chirho::verify_private_blob_retention_chirho(root_chirho)
    })?;
    verify_export_source_chirho("legal-holds.records-chirho", || {
        legal_hold_chirho::verify_legal_holds_chirho(root_chirho)
    })?;
    verify_export_source_chirho("data-residency.records-chirho", || {
        data_residency_chirho::verify_data_residency_chirho(root_chirho)
    })?;
    verify_export_source_chirho("compliance-evidence.records-chirho", || {
        compliance_evidence_chirho::verify_compliance_evidence_chirho(root_chirho, None)
    })?;
    verify_export_source_chirho("apps.records-chirho", || {
        app_chirho::verify_apps_chirho(root_chirho)
    })?;
    verify_export_source_chirho("apps.routes-chirho", || {
        app_chirho::verify_app_routes_chirho(root_chirho)
    })?;
    verify_export_source_chirho("apps.params-chirho", || {
        app_chirho::verify_app_params_chirho(root_chirho)
    })?;
    verify_export_source_chirho("apps.static-assets-chirho", || {
        app_chirho::verify_app_static_assets_chirho(root_chirho)
    })?;
    verify_export_source_chirho("apps.client-owner-bindings-chirho", || {
        app_chirho::verify_client_owner_bindings_chirho(root_chirho)
    })?;
    verify_export_source_chirho("apps.template-registry-chirho", || {
        app_chirho::verify_template_registry_chirho(root_chirho)
    })?;
    verify_export_source_chirho("apps.template-deploys-chirho", || {
        app_chirho::verify_template_app_deploy_records_chirho(root_chirho)
    })?;
    verify_export_source_chirho("apps.build-requests-chirho", || {
        let records_chirho =
            app_build_request_chirho::load_app_build_request_records_chirho(root_chirho)?;
        app_build_request_chirho::verify_app_build_request_records_chirho(
            root_chirho,
            &records_chirho,
        )?;
        Ok(records_chirho.len())
    })?;
    verify_export_source_chirho("refs.head-removals-chirho", || {
        head_removal_chirho::verify_head_removal_records_chirho(root_chirho)
    })?;
    verify_export_source_chirho("gate1.authority-log-chirho", || {
        authority_log_chirho::verify_gate1_authority_log_chirho(root_chirho)
    })?;
    verify_export_source_chirho("pricebook.records-chirho", || {
        effect_pricing_chirho::verify_price_books_chirho(root_chirho)
    })?;
    verify_export_source_chirho("billing.policies-chirho", || {
        crate::legacy_billing_evidence_chirho::verify_billing_policies_single_road_chirho(
            root_chirho,
        )
    })?;
    verify_export_source_chirho("resource.policies-chirho", || {
        resource_chirho::verify_resource_policies_chirho(root_chirho)
    })?;
    verify_export_source_chirho("onboarding.records-chirho", || {
        onboarding_chirho::verify_onboarding_chirho(root_chirho)
    })?;
    verify_export_source_chirho("ledger.entries-chirho", || {
        crate::legacy_ledger_evidence_chirho::verify_ledger_chirho(root_chirho)
    })?;
    verify_export_source_chirho("billing.usage-chirho", || {
        crate::legacy_billing_evidence_chirho::verify_billing_usage_single_road_chirho(root_chirho)
    })?;
    verify_export_source_chirho("billing.compensations-chirho", || {
        crate::legacy_billing_evidence_chirho::verify_billing_compensations_single_road_chirho(
            root_chirho,
        )
    })?;
    verify_export_source_chirho("resource.usage-chirho", || {
        resource_chirho::verify_resource_usage_chirho(root_chirho)
    })?;
    verify_export_source_chirho("credit-holds.records-chirho", || {
        crate::legacy_holds_evidence_chirho::verify_credit_holds_single_road_chirho(root_chirho)
    })?;
    verify_export_source_chirho("realtime.sessions/events-chirho", || {
        realtime_ledger_bound_evidence_chirho::verify_realtime_chirho(root_chirho)
    })?;
    verify_export_source_chirho("realtime.epilogues-chirho", || {
        realtime_ledger_bound_evidence_chirho::verify_realtime_epilogues_chirho(root_chirho)
    })?;
    verify_export_source_chirho("review.records-chirho", || {
        review_chirho::verify_review_records_chirho(root_chirho)
    })?;
    // Intentional singular: export labels use `review.*` for SecurityChangeAudit retention; compliance labels use plural `reviews.*`.
    verify_export_source_chirho("review.policy-envelopes-chirho", || {
        review_chirho::verify_review_policy_envelopes_chirho(root_chirho)
    })?;
    verify_export_source_chirho("reversion.records-chirho", || {
        reversion_legacy_evidence_chirho::verify_reversion_evidence_chirho(root_chirho)
    })?;
    verify_export_source_chirho("agent-reports.records-chirho", || {
        agent_report_chirho::verify_agent_report_records_chirho(root_chirho)
    })?;
    verify_export_source_chirho("agent-reports.accounting-chirho", || {
        agent_report_chirho::verify_agent_report_accounting_chirho(root_chirho)
    })?;
    Ok(())
}

fn verify_export_source_chirho<T, F>(source_chirho: &str, verifier_chirho: F) -> Result<()>
where
    F: FnOnce() -> Result<T>,
{
    verifier_chirho()
        .map(|_report_chirho| ())
        .with_context(|| format!("verify {source_chirho} before subject portable export"))
}

fn push_matching_records_chirho<T, F>(
    source_chirho: &str,
    records_chirho: Vec<T>,
    subject_chirho: &str,
    out_chirho: &mut Vec<SubjectRecordExportChirho>,
    matcher_chirho: F,
    key_ids_chirho: &BTreeSet<String>,
) -> Result<()>
where
    T: Serialize,
    F: Fn(&T, &str, &BTreeSet<String>) -> Vec<String>,
{
    for record_chirho in records_chirho {
        let matches_chirho = matcher_chirho(&record_chirho, subject_chirho, key_ids_chirho);
        push_if_matched_chirho(source_chirho, matches_chirho, record_chirho, out_chirho)?;
    }
    Ok(())
}

fn push_if_matched_chirho<T: Serialize>(
    source_chirho: &str,
    matches_chirho: Vec<String>,
    record_chirho: T,
    out_chirho: &mut Vec<SubjectRecordExportChirho>,
) -> Result<()> {
    let matched_by_chirho = dedupe_matches_chirho(matches_chirho);
    if matched_by_chirho.is_empty() {
        return Ok(());
    }
    out_chirho.push(SubjectRecordExportChirho {
        source_chirho: source_chirho.to_string(),
        matched_by_chirho,
        retention_policy_chirho: retention_chirho::signed_log_retention_policy_chirho(
            source_chirho,
        ),
        record_chirho: serde_json::to_value(record_chirho)?,
    });
    Ok(())
}

fn match_exact_chirho(
    label_chirho: &str,
    value_chirho: &str,
    subject_chirho: &str,
    matches_chirho: &mut Vec<String>,
) {
    if value_chirho == subject_chirho {
        matches_chirho.push(label_chirho.to_string());
    }
}

fn exact_matches_chirho(
    label_chirho: &str,
    value_chirho: &str,
    subject_chirho: &str,
) -> Vec<String> {
    let mut matches_chirho = Vec::new();
    match_exact_chirho(
        label_chirho,
        value_chirho,
        subject_chirho,
        &mut matches_chirho,
    );
    matches_chirho
}

fn match_optional_account_chirho(
    label_chirho: &str,
    value_chirho: Option<&str>,
    subject_chirho: &str,
    matches_chirho: &mut Vec<String>,
) {
    if let Some(value_chirho) = value_chirho {
        match_account_chirho(label_chirho, value_chirho, subject_chirho, matches_chirho);
    }
}

fn match_account_chirho(
    label_chirho: &str,
    value_chirho: &str,
    subject_chirho: &str,
    matches_chirho: &mut Vec<String>,
) {
    if account_mentions_subject_chirho(value_chirho, subject_chirho) {
        matches_chirho.push(label_chirho.to_string());
    }
}

fn account_mentions_subject_chirho(value_chirho: &str, subject_chirho: &str) -> bool {
    value_chirho == subject_chirho
        || value_chirho.starts_with(&format!("{subject_chirho}/"))
        || value_chirho.contains(&format!("/{subject_chirho}/"))
        || value_chirho.ends_with(&format!("/{subject_chirho}"))
}

fn match_billing_tags_chirho(
    label_chirho: &str,
    tags_chirho: &crate::economic_model_chirho::BillingTagsChirho,
    subject_chirho: &str,
    matches_chirho: &mut Vec<String>,
) {
    if tags_chirho.user_id_chirho.as_deref() == Some(subject_chirho) {
        matches_chirho.push(format!("{label_chirho}.user_id_chirho"));
    }
}

fn match_capability_chirho(
    label_chirho: &str,
    capability_chirho: &crate::model_chirho::CapabilityChirho,
    subject_chirho: &str,
    matches_chirho: &mut Vec<String>,
) {
    match capability_chirho {
        crate::model_chirho::CapabilityChirho::ReadStoreChirho { prefix_chirho }
        | crate::model_chirho::CapabilityChirho::WriteStoreChirho { prefix_chirho } => {
            match_account_chirho(
                &format!("{label_chirho}.prefix_chirho"),
                prefix_chirho,
                subject_chirho,
                matches_chirho,
            );
        }
        crate::model_chirho::CapabilityChirho::PaidEffectChirho {
            effect_chirho: _,
            caller_chirho,
        }
        | crate::model_chirho::CapabilityChirho::RealtimeSessionChirho {
            app_chirho: _,
            caller_chirho,
        } => {
            match_exact_chirho(
                &format!("{label_chirho}.caller_chirho"),
                caller_chirho,
                subject_chirho,
                matches_chirho,
            );
        }
        crate::model_chirho::CapabilityChirho::UserIdentityChirho {
            principal_chirho,
            client_id_chirho: _,
            token_hash_chirho: _,
        } => {
            match_exact_chirho(
                &format!("{label_chirho}.principal_chirho"),
                principal_chirho,
                subject_chirho,
                matches_chirho,
            );
        }
        crate::model_chirho::CapabilityChirho::AppContextChirho {
            app_chirho: _,
            owner_principal_chirho,
            price_book_chirho: _,
            billing_policy_chirho: _,
        } => {
            match_exact_chirho(
                &format!("{label_chirho}.owner_principal_chirho"),
                owner_principal_chirho,
                subject_chirho,
                matches_chirho,
            );
        }
        crate::model_chirho::CapabilityChirho::SupportIssueChirho {
            issue_chirho,
            actions_chirho: _,
        } => {
            match_account_chirho(
                &format!("{label_chirho}.issue_chirho"),
                issue_chirho,
                subject_chirho,
                matches_chirho,
            );
        }
        crate::model_chirho::CapabilityChirho::CausalReversionChirho { branch_chirho } => {
            match_account_chirho(
                &format!("{label_chirho}.branch_chirho"),
                branch_chirho,
                subject_chirho,
                matches_chirho,
            );
        }
        crate::model_chirho::CapabilityChirho::QueryChirho {
            prefix_chirho,
            caller_chirho,
            max_rows_chirho: _,
        } => {
            match_account_chirho(
                &format!("{label_chirho}.prefix_chirho"),
                prefix_chirho,
                subject_chirho,
                matches_chirho,
            );
            match_exact_chirho(
                &format!("{label_chirho}.caller_chirho"),
                caller_chirho,
                subject_chirho,
                matches_chirho,
            );
        }
        crate::model_chirho::CapabilityChirho::SecretRefChirho { name_chirho } => {
            match_account_chirho(
                &format!("{label_chirho}.name_chirho"),
                name_chirho,
                subject_chirho,
                matches_chirho,
            );
        }
        crate::model_chirho::CapabilityChirho::NetChirho { allowlist_chirho } => {
            for url_chirho in allowlist_chirho {
                match_account_chirho(
                    &format!("{label_chirho}.allowlist_chirho"),
                    url_chirho,
                    subject_chirho,
                    matches_chirho,
                );
            }
        }
        crate::model_chirho::CapabilityChirho::InvokeChirho { node_chirho } => {
            match_exact_chirho(
                &format!("{label_chirho}.node_chirho"),
                &node_chirho.0,
                subject_chirho,
                matches_chirho,
            );
        }
        crate::model_chirho::CapabilityChirho::TemplateAppDeployChirho { template_id_chirho } => {
            match_account_chirho(
                &format!("{label_chirho}.template_id_chirho"),
                template_id_chirho,
                subject_chirho,
                matches_chirho,
            );
        }
        crate::model_chirho::CapabilityChirho::ClockChirho
        | crate::model_chirho::CapabilityChirho::RandomChirho => {}
    }
}

fn match_agent_report_hash_chirho(
    root_chirho: &Path,
    label_chirho: &str,
    report_hash_chirho: &crate::model_chirho::HashChirho,
    subject_chirho: &str,
    matches_chirho: &mut Vec<String>,
) -> Result<()> {
    let report_chirho =
        agent_report_chirho::load_agent_report_chirho(root_chirho, report_hash_chirho)
            .with_context(|| format!("load agent report {}", report_hash_chirho.0))?;
    match_agent_report_body_chirho(label_chirho, &report_chirho, subject_chirho, matches_chirho);
    Ok(())
}

fn match_agent_report_body_chirho(
    label_chirho: &str,
    report_chirho: &agent_report_chirho::AgentReportChirho,
    subject_chirho: &str,
    matches_chirho: &mut Vec<String>,
) {
    match_exact_chirho(
        &format!("{label_chirho}.producer_principal_chirho"),
        &report_chirho.producer_principal_chirho,
        subject_chirho,
        matches_chirho,
    );
    for effect_chirho in &report_chirho.related_effect_ids_chirho {
        match_exact_chirho(
            &format!("{label_chirho}.related_effect_ids_chirho"),
            effect_chirho,
            subject_chirho,
            matches_chirho,
        );
    }
    for evidence_chirho in &report_chirho.evidence_refs_chirho {
        match_exact_chirho(
            &format!("{label_chirho}.evidence_refs_chirho.ref_chirho"),
            &evidence_chirho.ref_chirho,
            subject_chirho,
            matches_chirho,
        );
    }
    if let Some(action_chirho) = &report_chirho.requested_action_chirho {
        match_account_chirho(
            &format!("{label_chirho}.requested_action_chirho.target_chirho"),
            &action_chirho.target_chirho,
            subject_chirho,
            matches_chirho,
        );
    }
}

fn match_private_blob_chirho(
    label_chirho: &str,
    blob_chirho: &privacy_chirho::PrivateBlobRefChirho,
    key_ids_chirho: &BTreeSet<String>,
    matches_chirho: &mut Vec<String>,
) {
    match_key_id_chirho(
        label_chirho,
        &blob_chirho.key_id_chirho,
        key_ids_chirho,
        matches_chirho,
    );
}

fn match_key_id_chirho(
    label_chirho: &str,
    key_id_chirho: &str,
    key_ids_chirho: &BTreeSet<String>,
    matches_chirho: &mut Vec<String>,
) {
    if key_ids_chirho.contains(key_id_chirho) {
        matches_chirho.push(label_chirho.to_string());
    }
}

fn dedupe_matches_chirho(matches_chirho: Vec<String>) -> Vec<String> {
    let mut seen_chirho = BTreeSet::new();
    let mut out_chirho = Vec::new();
    for match_chirho in matches_chirho {
        if seen_chirho.insert(match_chirho.clone()) {
            out_chirho.push(match_chirho);
        }
    }
    out_chirho
}

fn source_counts_chirho(
    records_chirho: &[SubjectRecordExportChirho],
) -> Vec<SubjectExportSourceCountChirho> {
    let mut counts_chirho: BTreeMap<String, usize> = BTreeMap::new();
    for record_chirho in records_chirho {
        *counts_chirho
            .entry(record_chirho.source_chirho.clone())
            .or_default() += 1;
    }
    counts_chirho
        .into_iter()
        .map(
            |(source_chirho, records_chirho)| SubjectExportSourceCountChirho {
                source_chirho,
                records_chirho,
            },
        )
        .collect()
}

fn redacted_backup_propagation_for_subject_export_chirho(
    record_chirho: &privacy_backup_chirho::PrivacyErasurePropagationRecordChirho,
) -> SubjectExportBackupErasurePropagationChirho {
    SubjectExportBackupErasurePropagationChirho {
        schema_chirho: SUBJECT_EXPORT_BACKUP_PROPAGATION_SCHEMA_CHIRHO.to_string(),
        seq_chirho: record_chirho.seq_chirho,
        source_erasure_seq_chirho: record_chirho.source_erasure_seq_chirho,
        subject_chirho: record_chirho.subject_chirho.clone(),
        replica_chirho: record_chirho.replica_chirho.clone(),
        replica_root_scope_chirho: SUBJECT_EXPORT_REPLICA_ROOT_REDACTED_CHIRHO.to_string(),
        requested_by_chirho: record_chirho.requested_by_chirho.clone(),
        key_ids_chirho: record_chirho.key_ids_chirho.clone(),
        removed_key_ids_chirho: record_chirho.removed_key_ids_chirho.clone(),
        already_missing_key_ids_chirho: record_chirho.already_missing_key_ids_chirho.clone(),
        at_ms_chirho: record_chirho.at_ms_chirho,
        source_record_verified_chirho: true,
        redacted_fields_chirho: vec!["replica_root_chirho".to_string()],
    }
}

fn redacted_replica_target_for_subject_export_chirho(
    record_chirho: &privacy_backup_chirho::PrivacyReplicaTargetChirho,
) -> SubjectExportPrivacyReplicaTargetChirho {
    SubjectExportPrivacyReplicaTargetChirho {
        schema_chirho: SUBJECT_EXPORT_REPLICA_TARGET_SCHEMA_CHIRHO.to_string(),
        seq_chirho: record_chirho.seq_chirho,
        replica_chirho: record_chirho.replica_chirho.clone(),
        root_scope_chirho: SUBJECT_EXPORT_REPLICA_ROOT_REDACTED_CHIRHO.to_string(),
        registered_by_chirho: record_chirho.registered_by_chirho.clone(),
        at_ms_chirho: record_chirho.at_ms_chirho,
        source_record_verified_chirho: true,
        redacted_fields_chirho: vec!["root_chirho".to_string()],
    }
}

fn sorted_private_blob_key_ids_chirho(
    export_chirho: &SubjectPortableDataExportChirho,
) -> Vec<String> {
    export_chirho
        .private_blobs_chirho
        .iter()
        .map(|item_chirho| item_chirho.record_chirho.blob_chirho.key_id_chirho.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn sorted_erasure_record_seqs_chirho(export_chirho: &SubjectPortableDataExportChirho) -> Vec<u64> {
    export_chirho
        .erasures_chirho
        .iter()
        .map(|record_chirho| record_chirho.seq_chirho)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn sorted_backup_propagation_record_seqs_chirho(
    export_chirho: &SubjectPortableDataExportChirho,
) -> Vec<u64> {
    export_chirho
        .backup_erasure_propagations_chirho
        .iter()
        .map(|record_chirho| record_chirho.seq_chirho)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn sorted_legal_hold_record_seqs_chirho(
    export_chirho: &SubjectPortableDataExportChirho,
) -> Vec<u64> {
    export_chirho
        .legal_holds_chirho
        .iter()
        .map(|record_chirho| record_chirho.seq_chirho)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn subject_export_evidence_message_chirho(
    record_chirho: &SubjectExportEvidenceRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct MessageChirho<'a> {
        schema_chirho: &'a str,
        seq_chirho: u64,
        subject_chirho: &'a str,
        requested_by_chirho: &'a str,
        include_private_chirho: bool,
        private_blob_key_ids_chirho: &'a [String],
        erasure_record_seqs_chirho: &'a [u64],
        backup_propagation_record_seqs_chirho: &'a [u64],
        legal_hold_record_seqs_chirho: &'a [u64],
        source_counts_chirho: &'a [SubjectExportSourceCountChirho],
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(&MessageChirho {
        schema_chirho: &record_chirho.schema_chirho,
        seq_chirho: record_chirho.seq_chirho,
        subject_chirho: &record_chirho.subject_chirho,
        requested_by_chirho: &record_chirho.requested_by_chirho,
        include_private_chirho: record_chirho.include_private_chirho,
        private_blob_key_ids_chirho: &record_chirho.private_blob_key_ids_chirho,
        erasure_record_seqs_chirho: &record_chirho.erasure_record_seqs_chirho,
        backup_propagation_record_seqs_chirho: &record_chirho.backup_propagation_record_seqs_chirho,
        legal_hold_record_seqs_chirho: &record_chirho.legal_hold_record_seqs_chirho,
        source_counts_chirho: &record_chirho.source_counts_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    })?)
}

fn subject_export_evidence_no_schema_message_chirho(
    record_chirho: &SubjectExportEvidenceRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct MessageChirho<'a> {
        seq_chirho: u64,
        subject_chirho: &'a str,
        requested_by_chirho: &'a str,
        include_private_chirho: bool,
        private_blob_key_ids_chirho: &'a [String],
        erasure_record_seqs_chirho: &'a [u64],
        backup_propagation_record_seqs_chirho: &'a [u64],
        legal_hold_record_seqs_chirho: &'a [u64],
        source_counts_chirho: &'a [SubjectExportSourceCountChirho],
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(&MessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        subject_chirho: &record_chirho.subject_chirho,
        requested_by_chirho: &record_chirho.requested_by_chirho,
        include_private_chirho: record_chirho.include_private_chirho,
        private_blob_key_ids_chirho: &record_chirho.private_blob_key_ids_chirho,
        erasure_record_seqs_chirho: &record_chirho.erasure_record_seqs_chirho,
        backup_propagation_record_seqs_chirho: &record_chirho.backup_propagation_record_seqs_chirho,
        legal_hold_record_seqs_chirho: &record_chirho.legal_hold_record_seqs_chirho,
        source_counts_chirho: &record_chirho.source_counts_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    })?)
}

fn subject_export_evidence_backup_only_message_chirho(
    record_chirho: &SubjectExportEvidenceRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct MessageChirho<'a> {
        seq_chirho: u64,
        subject_chirho: &'a str,
        requested_by_chirho: &'a str,
        include_private_chirho: bool,
        private_blob_key_ids_chirho: &'a [String],
        erasure_record_seqs_chirho: &'a [u64],
        backup_propagation_record_seqs_chirho: &'a [u64],
        source_counts_chirho: &'a [SubjectExportSourceCountChirho],
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(&MessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        subject_chirho: &record_chirho.subject_chirho,
        requested_by_chirho: &record_chirho.requested_by_chirho,
        include_private_chirho: record_chirho.include_private_chirho,
        private_blob_key_ids_chirho: &record_chirho.private_blob_key_ids_chirho,
        erasure_record_seqs_chirho: &record_chirho.erasure_record_seqs_chirho,
        backup_propagation_record_seqs_chirho: &record_chirho.backup_propagation_record_seqs_chirho,
        source_counts_chirho: &record_chirho.source_counts_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    })?)
}

fn subject_export_evidence_legacy_message_chirho(
    record_chirho: &SubjectExportEvidenceRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct MessageChirho<'a> {
        seq_chirho: u64,
        subject_chirho: &'a str,
        requested_by_chirho: &'a str,
        include_private_chirho: bool,
        private_blob_key_ids_chirho: &'a [String],
        erasure_record_seqs_chirho: &'a [u64],
        source_counts_chirho: &'a [SubjectExportSourceCountChirho],
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(&MessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        subject_chirho: &record_chirho.subject_chirho,
        requested_by_chirho: &record_chirho.requested_by_chirho,
        include_private_chirho: record_chirho.include_private_chirho,
        private_blob_key_ids_chirho: &record_chirho.private_blob_key_ids_chirho,
        erasure_record_seqs_chirho: &record_chirho.erasure_record_seqs_chirho,
        source_counts_chirho: &record_chirho.source_counts_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    })?)
}

fn subject_export_evidence_signature_valid_chirho(
    pubkey_chirho: &str,
    record_chirho: &SubjectExportEvidenceRecordChirho,
) -> Result<bool> {
    if !record_chirho.schema_chirho.is_empty() {
        let message_chirho = subject_export_evidence_message_chirho(record_chirho)?;
        return signer_chirho::verify_with_pubkey_chirho(
            pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        );
    }
    let message_chirho = subject_export_evidence_no_schema_message_chirho(record_chirho)?;
    if signer_chirho::verify_with_pubkey_chirho(
        pubkey_chirho,
        &message_chirho,
        &record_chirho.sig_chirho,
    )? {
        return Ok(true);
    }
    if record_chirho.legal_hold_record_seqs_chirho.is_empty() {
        let backup_only_message_chirho =
            subject_export_evidence_backup_only_message_chirho(record_chirho)?;
        if signer_chirho::verify_with_pubkey_chirho(
            pubkey_chirho,
            &backup_only_message_chirho,
            &record_chirho.sig_chirho,
        )? {
            return Ok(true);
        }
    }
    if record_chirho
        .backup_propagation_record_seqs_chirho
        .is_empty()
        && record_chirho.legal_hold_record_seqs_chirho.is_empty()
    {
        let legacy_message_chirho = subject_export_evidence_legacy_message_chirho(record_chirho)?;
        return signer_chirho::verify_with_pubkey_chirho(
            pubkey_chirho,
            &legacy_message_chirho,
            &record_chirho.sig_chirho,
        );
    }
    Ok(false)
}

fn load_jsonl_chirho<T: for<'de> Deserialize<'de>>(path_chirho: &Path) -> Result<Vec<T>> {
    let Some(text_chirho) = read_log_text_chirho(path_chirho)? else {
        return Ok(Vec::new());
    };
    let mut records_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        records_chirho.push(serde_json::from_str(line_chirho)?);
    }
    Ok(records_chirho)
}

fn validate_export_token_chirho(name_chirho: &str, value_chirho: &str) -> Result<()> {
    if value_chirho.trim().is_empty()
        || value_chirho.len() > 256
        || !value_chirho.chars().all(|ch_chirho| {
            ch_chirho.is_ascii_alphanumeric() || matches!(ch_chirho, '-' | '_' | '/' | ':' | '.')
        })
    {
        bail!("{name_chirho} must be a short opaque token");
    }
    Ok(())
}

#[cfg(test)]
#[path = "data_rights_chirho/tests_chirho.rs"]
mod tests_chirho;
