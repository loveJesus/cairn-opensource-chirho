// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Support and realtime source collectors for portable subject exports.

use super::{
    exact_matches_chirho, match_account_chirho, match_exact_chirho, match_private_blob_chirho,
    push_if_matched_chirho, push_matching_records_chirho, SubjectRecordExportChirho,
    REALTIME_TRANSCRIPT_ARTIFACT_EXPORT_SOURCE_CHIRHO,
};
use crate::{realtime_legacy_evidence_chirho, store_chirho};
use anyhow::Result;
use std::collections::BTreeSet;
use std::path::Path;

pub(super) fn export_realtime_records_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    key_ids_chirho: &BTreeSet<String>,
    out_chirho: &mut Vec<SubjectRecordExportChirho>,
) -> Result<()> {
    let mut subject_sessions_chirho = BTreeSet::new();
    let mut transcript_artifacts_chirho = Vec::new();
    for record_chirho in
        realtime_legacy_evidence_chirho::load_realtime_sessions_chirho(root_chirho)?
    {
        let mut matches_chirho = Vec::new();
        match_exact_chirho(
            "caller_chirho",
            &record_chirho.caller_chirho,
            subject_chirho,
            &mut matches_chirho,
        );
        match_account_chirho(
            "payer_chirho",
            &record_chirho.payer_chirho,
            subject_chirho,
            &mut matches_chirho,
        );
        if !matches_chirho.is_empty() {
            subject_sessions_chirho.insert(record_chirho.session_id_chirho.clone());
        }
        if let Some(artifact_hash_chirho) = record_chirho.transcript_chirho.clone() {
            let artifact_chirho: realtime_legacy_evidence_chirho::RealtimeTranscriptArtifactChirho =
                store_chirho::get_object_chirho(root_chirho, &artifact_hash_chirho)?;
            transcript_artifacts_chirho.push((
                artifact_hash_chirho,
                artifact_chirho,
                !matches_chirho.is_empty(),
            ));
        }
        push_if_matched_chirho(
            "realtime.sessions-chirho",
            matches_chirho,
            record_chirho,
            out_chirho,
        )?;
    }
    push_matching_records_chirho(
        "realtime.events-chirho",
        realtime_legacy_evidence_chirho::load_realtime_events_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, _subject_chirho, key_ids_chirho| {
            let mut matches_chirho = Vec::new();
            if subject_sessions_chirho.contains(&record_chirho.session_id_chirho) {
                matches_chirho.push("session_id_chirho via realtime.sessions-chirho".to_string());
            }
            match_private_blob_chirho(
                "payload_chirho",
                &record_chirho.payload_chirho,
                key_ids_chirho,
                &mut matches_chirho,
            );
            matches_chirho
        },
        key_ids_chirho,
    )?;
    for (artifact_hash_chirho, artifact_chirho, matched_session_chirho) in
        transcript_artifacts_chirho
    {
        let mut matches_chirho = Vec::new();
        if matched_session_chirho {
            matches_chirho.push("transcript_chirho via realtime.sessions-chirho".to_string());
        }
        match_exact_chirho(
            "artifact.caller_chirho",
            &artifact_chirho.caller_chirho,
            subject_chirho,
            &mut matches_chirho,
        );
        match_private_blob_chirho(
            "artifact.transcript_blob_chirho",
            &artifact_chirho.transcript_blob_chirho,
            key_ids_chirho,
            &mut matches_chirho,
        );
        for blob_chirho in &artifact_chirho.event_payloads_chirho {
            match_private_blob_chirho(
                "artifact.event_payloads_chirho",
                blob_chirho,
                key_ids_chirho,
                &mut matches_chirho,
            );
        }
        push_if_matched_chirho(
            REALTIME_TRANSCRIPT_ARTIFACT_EXPORT_SOURCE_CHIRHO,
            matches_chirho,
            serde_json::json!({
                "artifact_chirho": artifact_hash_chirho,
                "artifact_record_chirho": artifact_chirho,
            }),
            out_chirho,
        )?;
    }
    push_matching_records_chirho(
        "realtime.epilogues-chirho",
        realtime_legacy_evidence_chirho::load_realtime_epilogues_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "caller_chirho",
                &record_chirho.caller_chirho,
                subject_chirho,
            )
        },
        key_ids_chirho,
    )?;
    Ok(())
}
