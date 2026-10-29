// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Subject-bound private storage for DAG edge/intermediate values.

use crate::model_chirho::HashChirho;
use crate::{cas_chirho, privacy_chirho, seqlog_chirho};
use anyhow::{anyhow, bail, Context, Result};
use cairn_signer_chirho::signer_chirho;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "dag_private_value_chirho/attribution_source_chirho.rs"]
mod attribution_source_chirho;
#[path = "dag_private_value_chirho/value_view_chirho.rs"]
mod value_view_chirho;
pub use attribution_source_chirho::{PrivateValueOwnerChirho, RunAttributionSourceChirho};
#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
pub use value_view_chirho::private_value_view_metrics_chirho;
pub use value_view_chirho::{
    spawn_private_value_view_warm_up_chirho, warm_private_value_view_chirho,
};

pub const PRIVATE_DAG_VALUE_SCHEMA_CHIRHO: &str = "private-dag-value-v1-chirho";
const PRIVATE_DAG_VALUE_LOCK_CHIRHO: &str = "private-dag-values-chirho";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDagValueContextChirho {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dag_chirho: Option<HashChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_chirho: Option<HashChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_chirho: Option<HashChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_chirho: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDagValueRecordChirho {
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub subject_chirho: String,
    pub value_hash_chirho: HashChirho,
    pub blob_chirho: privacy_chirho::PrivateBlobRefChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dag_chirho: Option<HashChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_chirho: Option<HashChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_chirho: Option<HashChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_chirho: Option<String>,
    pub bytes_chirho: usize,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

/// A run's private values by content hash: each hash's subject and owner source, and its bytes once read.
/// The same bytes can arrive under two domains (two branches computing equal values); the first domain is
/// kept for reading, and the hash is marked AMBIGUOUS, so nothing may inherit a domain from it rather than
/// silently taking whichever arrived last (gpt #28935).
#[derive(Clone, Debug, Default)]
pub struct PrivateDagValueResolverChirho {
    subjects_chirho: BTreeMap<HashChirho, (String, PrivateValueOwnerChirho)>,
    ambiguous_chirho: BTreeSet<HashChirho>,
    bytes_chirho: BTreeMap<HashChirho, Vec<u8>>,
}

impl PrivateDagValueResolverChirho {
    pub fn insert_private_bytes_chirho(
        &mut self,
        subject_chirho: &str,
        owner_chirho: PrivateValueOwnerChirho,
        bytes_chirho: &[u8],
    ) -> HashChirho {
        let hash_chirho = cas_chirho::hash_chirho(bytes_chirho);
        self.note_domain_chirho(&hash_chirho, subject_chirho, owner_chirho);
        self.bytes_chirho
            .insert(hash_chirho.clone(), bytes_chirho.to_vec());
        hash_chirho
    }

    pub fn insert_private_hash_chirho(
        &mut self,
        subject_chirho: &str,
        owner_chirho: PrivateValueOwnerChirho,
        hash_chirho: &HashChirho,
    ) {
        self.note_domain_chirho(hash_chirho, subject_chirho, owner_chirho);
    }

    fn note_domain_chirho(
        &mut self,
        hash_chirho: &HashChirho,
        subject_chirho: &str,
        owner_chirho: PrivateValueOwnerChirho,
    ) {
        match self.subjects_chirho.get(hash_chirho) {
            Some((existing_subject_chirho, existing_owner_chirho))
                if existing_subject_chirho != subject_chirho
                    || *existing_owner_chirho != owner_chirho =>
            {
                self.ambiguous_chirho.insert(hash_chirho.clone());
            }
            Some(_) => {}
            None => {
                self.subjects_chirho.insert(
                    hash_chirho.clone(),
                    (subject_chirho.to_string(), owner_chirho),
                );
            }
        }
    }

    /// The private domain a value of this hash carries, if it is private. An ambiguous hash refuses.
    pub fn domain_for_hash_chirho(
        &self,
        hash_chirho: &HashChirho,
    ) -> Result<Option<(String, PrivateValueOwnerChirho)>> {
        if self.ambiguous_chirho.contains(hash_chirho) {
            bail!(
                "PrivateValueDomainAmbiguousChirho: one private value arrived under two subjects or owners \
                 in this run, so no output may inherit a domain from it"
            );
        }
        Ok(self.subjects_chirho.get(hash_chirho).cloned())
    }

    pub fn read_value_bytes_chirho(
        &mut self,
        root_chirho: &Path,
        hash_chirho: &HashChirho,
    ) -> Result<Vec<u8>> {
        if let Some(bytes_chirho) = self.bytes_chirho.get(hash_chirho) {
            return Ok(bytes_chirho.clone());
        }
        if let Some((subject_chirho, _owner_chirho)) =
            self.subjects_chirho.get(hash_chirho).cloned()
        {
            let bytes_chirho =
                load_private_dag_value_bytes_chirho(root_chirho, &subject_chirho, hash_chirho)?;
            self.bytes_chirho
                .insert(hash_chirho.clone(), bytes_chirho.clone());
            return Ok(bytes_chirho);
        }
        cas_chirho::get_chirho(root_chirho, hash_chirho)
            .with_context(|| format!("value object {} not in store", hash_chirho.0))
    }
}

/// Where a value is stored: public CAS, or a private blob under a subject whose owner source travels with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValueStoragePolicyChirho {
    PublicCasChirho,
    PrivateBlobRefChirho {
        subject_chirho: String,
        owner_chirho: PrivateValueOwnerChirho,
    },
}

impl ValueStoragePolicyChirho {
    pub fn private_subject_chirho(&self) -> Option<&str> {
        match self {
            Self::PublicCasChirho => None,
            Self::PrivateBlobRefChirho { subject_chirho, .. } => Some(subject_chirho.as_str()),
        }
    }

    /// The subject and its owner source, for a private policy.
    pub fn private_domain_chirho(&self) -> Option<(&str, PrivateValueOwnerChirho)> {
        match self {
            Self::PublicCasChirho => None,
            Self::PrivateBlobRefChirho {
                subject_chirho,
                owner_chirho,
            } => Some((subject_chirho.as_str(), *owner_chirho)),
        }
    }
}

/// Store one DAG value by its policy. A private value's key is attributed from the run's source by the
/// policy's owner source, so a run without one refuses before anything is written.
pub fn store_dag_value_with_policy_chirho(
    root_chirho: &Path,
    bytes_chirho: &[u8],
    policy_chirho: &ValueStoragePolicyChirho,
    context_chirho: PrivateDagValueContextChirho,
    resolver_chirho: Option<&mut PrivateDagValueResolverChirho>,
    source_chirho: &RunAttributionSourceChirho<'_>,
) -> Result<HashChirho> {
    match policy_chirho {
        ValueStoragePolicyChirho::PublicCasChirho => {
            Ok(cas_chirho::add_chirho(root_chirho, bytes_chirho)?)
        }
        ValueStoragePolicyChirho::PrivateBlobRefChirho {
            subject_chirho,
            owner_chirho,
        } => {
            let attribution_chirho = source_chirho.resolve_chirho(*owner_chirho)?;
            let hash_chirho = store_private_dag_value_chirho(
                root_chirho,
                &attribution_chirho,
                subject_chirho,
                bytes_chirho,
                context_chirho,
            )?;
            if let Some(resolver_chirho) = resolver_chirho {
                resolver_chirho.insert_private_bytes_chirho(
                    subject_chirho,
                    *owner_chirho,
                    bytes_chirho,
                );
            }
            Ok(hash_chirho)
        }
    }
}

/// An ADMITTED run's private request (checkpoint brick S5a, agy #25958 option 1). The admission stored it before the
/// run's pending record (`persist_request_before_admission_chirho`), so the run REUSES that verified record: the bytes
/// go only to the run's resolver, and nothing is stored a second time. Records are keyed by (subject, value hash), so
/// the record reused is one of these exact bytes for this subject, never another subject's.
/// - The bytes must hash to the admitted coordinate, or the run refuses.
/// - A record that is claimed but does not verify refuses, as every resolution does.
/// - A MISSING record refuses too. On the admitted road it cannot be missing: a fresh admission stores the request
///   before appending, and a resumed run's latest record verified only because its request resolved
///   (`record_verify_chirho`). So its absence is a broken invariant, and storing the bytes here would hide it.
///
/// Workflow: `spec-chirho/workflows-chirho/perf-chirho/execution-checkpoint-brick-design-chirho.md` (S5a).
pub(crate) fn reuse_admitted_private_request_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    bytes_chirho: &[u8],
    request_chirho: &HashChirho,
    resolver_chirho: &mut PrivateDagValueResolverChirho,
) -> Result<HashChirho> {
    if cas_chirho::hash_chirho(bytes_chirho) != *request_chirho {
        bail!("an admitted run's private input does not hash to its admitted request");
    }
    if verified_private_dag_value_record_for_subject_chirho(
        root_chirho,
        subject_chirho,
        request_chirho,
    )?
    .is_none()
    {
        bail!(
            "AdmittedPrivateRequestMissingChirho: an admitted run's private request has no stored record, though its \
             admission stores or verifies one"
        );
    }
    // An admitted private request is the request user's own input (app_session's request-user plane).
    resolver_chirho.insert_private_bytes_chirho(
        subject_chirho,
        PrivateValueOwnerChirho::RequestActorChirho,
        bytes_chirho,
    );
    Ok(request_chirho.clone())
}

fn private_dag_values_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("private-dag-values-chirho.jsonl")
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_millis() as u64)
        .unwrap_or(0)
}

pub fn store_private_dag_value_chirho(
    root_chirho: &Path,
    attribution_chirho: &privacy_chirho::PrivateBlobAttributionChirho,
    subject_chirho: &str,
    value_chirho: &[u8],
    context_chirho: PrivateDagValueContextChirho,
) -> Result<HashChirho> {
    privacy_chirho::validate_privacy_subject_chirho(subject_chirho)?;
    let value_hash_chirho = cas_chirho::hash_chirho(value_chirho);
    // Checkpoint brick S2: refuse BEFORE the blob is written when the value log would refuse the append, so a broken
    // value log does not leave an orphan blob and key behind every refused store. The append re-checks under its
    // lock; this early check only spares the side effects.
    value_view_chirho::current_value_record_count_chirho(root_chirho)?;
    let blob_chirho = privacy_chirho::store_private_blob_chirho(
        root_chirho,
        attribution_chirho,
        subject_chirho,
        value_chirho,
    )?;
    append_private_dag_value_record_chirho(
        root_chirho,
        subject_chirho,
        value_hash_chirho.clone(),
        blob_chirho,
        value_chirho.len(),
        context_chirho,
    )?;
    Ok(value_hash_chirho)
}

/// Reads back a private DAG value's plaintext for ONE subject.
///
/// The record that answers must VERIFY, not merely match. Selecting on `subject == requested` over
/// the raw JSONL is a check against an unverified signal: appending one unsigned line that names an
/// existing hash and blob ref under a DIFFERENT subject rebinds that blob, and this function then
/// hands the first subject's plaintext to a caller asking as the second. The blob's own MAC, the
/// AEAD and the plaintext hash check all still pass — every one of them is a property of the
/// substituted blob rather than of who may read it — so the binding has to be proven at the record.
pub fn load_private_dag_value_bytes_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    value_hash_chirho: &HashChirho,
) -> Result<Vec<u8>> {
    let record_chirho = verified_private_dag_value_record_for_subject_chirho(
        root_chirho,
        subject_chirho,
        value_hash_chirho,
    )?
    .ok_or_else(|| {
        anyhow!(
            "private DAG value {} for subject '{}' is not recorded",
            value_hash_chirho.0,
            subject_chirho
        )
    })?;
    let bytes_chirho =
        privacy_chirho::load_private_blob_chirho(root_chirho, &record_chirho.blob_chirho)
            .with_context(|| format!("load private DAG value {}", value_hash_chirho.0))?;
    let actual_chirho = cas_chirho::hash_chirho(&bytes_chirho);
    if actual_chirho != *value_hash_chirho {
        bail!(
            "private DAG value hash mismatch: record says {}, plaintext hashes to {}",
            value_hash_chirho.0,
            actual_chirho.0
        );
    }
    Ok(bytes_chirho)
}

pub fn private_dag_value_recorded_chirho(
    root_chirho: &Path,
    value_hash_chirho: &HashChirho,
) -> Result<bool> {
    Ok(value_view_chirho::claim_count_chirho(
        root_chirho,
        value_view_chirho::ClaimKeyChirho::HashChirho(value_hash_chirho.clone()),
    )? > 0)
}

pub fn private_dag_value_recorded_for_subject_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    value_hash_chirho: &HashChirho,
) -> Result<bool> {
    privacy_chirho::validate_privacy_subject_chirho(subject_chirho)?;
    Ok(value_view_chirho::claim_count_chirho(
        root_chirho,
        value_view_chirho::ClaimKeyChirho::PairChirho((
            subject_chirho.to_string(),
            value_hash_chirho.clone(),
        )),
    )? > 0)
}

#[cfg(test)]
thread_local! {
    /// Private-value log reads on this thread: the one-pass scaling arms' counter.
    pub(crate) static PRIVATE_DAG_VALUE_LOG_LOADS_CHIRHO: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Private-value records verified on this thread: proves a pass verifies each needed one once.
    pub(crate) static PRIVATE_DAG_VALUE_RECORD_VERIFICATIONS_CHIRHO: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

pub fn load_private_dag_value_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<PrivateDagValueRecordChirho>> {
    #[cfg(test)]
    PRIVATE_DAG_VALUE_LOG_LOADS_CHIRHO
        .with(|count_chirho| count_chirho.set(count_chirho.get() + 1));
    let path_chirho = private_dag_values_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let mut records_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        records_chirho
            .push(serde_json::from_str(line_chirho).context("decode PrivateDagValueRecordChirho")?);
    }
    Ok(records_chirho)
}

/// Everything one record must satisfy on its own: the log-position check is the caller's, because
/// sequence is a property of the whole log rather than of the record.
///
/// Shared by the whole-log verifier and the single-hash resolution below so the bar a private value
/// must clear cannot drift depending on which door asked.
///
/// Blob ownership resolves through the privacy blob log's verified view (checkpoint brick S1): O(1)
/// per record, plus whatever was appended since the last call.
fn verify_private_dag_value_record_chirho(
    root_chirho: &Path,
    pubkey_chirho: &str,
    record_chirho: &PrivateDagValueRecordChirho,
) -> Result<()> {
    #[cfg(test)]
    PRIVATE_DAG_VALUE_RECORD_VERIFICATIONS_CHIRHO
        .with(|count_chirho| count_chirho.set(count_chirho.get() + 1));
    if record_chirho.schema_chirho != PRIVATE_DAG_VALUE_SCHEMA_CHIRHO {
        bail!(
            "private DAG value record {} has unsupported schema '{}'",
            record_chirho.seq_chirho,
            record_chirho.schema_chirho
        );
    }
    privacy_chirho::validate_privacy_subject_chirho(&record_chirho.subject_chirho)?;
    privacy_chirho::verify_private_blob_ref_subject_chirho(
        root_chirho,
        "private DAG value",
        &record_chirho.blob_chirho,
        &record_chirho.subject_chirho,
    )?;
    let message_chirho = private_dag_value_record_message_chirho(record_chirho)?;
    if !signer_chirho::verify_with_pubkey_chirho(
        pubkey_chirho,
        &message_chirho,
        &record_chirho.sig_chirho,
    )? {
        bail!(
            "private DAG value record {} signature invalid",
            record_chirho.seq_chirho
        );
    }
    Ok(())
}

/// Resolves a value hash to a private DAG value record that actually VERIFIES.
///
/// `private_dag_value_recorded_chirho` answers only "does some line claim this hash", and
/// `load_private_dag_value_records_chirho` parses the JSONL WITHOUT checking signatures — so a single
/// appended line naming any hash satisfies it, with no ciphertext, no key, no signature and no
/// subject binding behind it. A verifier that accepts that reports green over missing evidence.
/// Every caller that resolves a hash it could not find in public CAS must come through here instead.
///
/// Deliberately no decrypt: requiring one would turn a legitimate crypto-shred (keys deleted,
/// ciphertext retained) into a red verify, which is the erasure behaviour working as designed.
///
/// `Ok(None)` means nothing claims the hash — the caller keeps its own not-found error, which is the
/// more accurate one. An `Err` means a record DOES claim it and does not verify: the loud case.
pub fn verified_private_dag_value_record_chirho(
    root_chirho: &Path,
    value_hash_chirho: &HashChirho,
) -> Result<Option<PrivateDagValueRecordChirho>> {
    // Checkpoint brick S2: the claiming records come from the private-value index, earliest first and one at a time,
    // instead of a whole-log load. Their verification below is unchanged.
    let claiming_chirho = value_view_chirho::claims_chirho(
        root_chirho,
        value_view_chirho::ClaimKeyChirho::HashChirho(value_hash_chirho.clone()),
        value_view_chirho::ClaimOrderChirho::EarliestFirstChirho,
    )?;
    if claiming_chirho.is_empty() {
        return Ok(None);
    }
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let mut last_failure_chirho = None;
    for claim_chirho in claiming_chirho {
        let record_chirho = claim_chirho?;
        match verify_private_dag_value_record_chirho(root_chirho, &pubkey_chirho, &record_chirho) {
            // The same bytes may legitimately rest under more than one subject; one verifying
            // record is the evidence, so a later unverifiable duplicate cannot mask it.
            Ok(()) => return Ok(Some(record_chirho)),
            Err(failure_chirho) => last_failure_chirho = Some(failure_chirho),
        }
    }
    Err(last_failure_chirho
        .unwrap_or_else(|| anyhow!("private DAG value record verification produced no verdict"))
        .context(format!(
            "private DAG value {} is claimed only by records that do not verify",
            value_hash_chirho.0
        )))
}

/// The subject-bound sibling: resolves (subject, value hash) to a record that VERIFIES.
///
/// Every read-side caller that is asking *on behalf of a subject* belongs here rather than at
/// `private_dag_value_recorded_for_subject_chirho`, which matches the subject field of an
/// unverified line — and a line is exactly what an attacker can append. Subject binding is only
/// worth anything once the record carrying it has been proven: schema, privacy-log-backed blob
/// ownership, and signature.
///
/// Latest-first, matching the read order this replaced, and one verifying record is the evidence —
/// a later unverifiable duplicate cannot mask an earlier good one. `Ok(None)` means no record
/// claims the pair; an `Err` means one does and does not verify.
///
/// This is `PrivateDagValueSubjectResolverChirho` asked once. A caller resolving many pairs in one
/// pass — a verifier walking a log — holds one resolver instead, so the logs are read once.
pub fn verified_private_dag_value_record_for_subject_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    value_hash_chirho: &HashChirho,
) -> Result<Option<PrivateDagValueRecordChirho>> {
    Ok(
        PrivateDagValueSubjectResolverChirho::new_chirho(root_chirho)
            .verified_record_chirho(subject_chirho, value_hash_chirho)?
            .cloned(),
    )
}

/// Resolves many (subject, value hash) pairs to private DAG value records that VERIFY.
///
/// The claiming records come from the private-value index (checkpoint brick S2), which is current and costs O(1)
/// plus the records appended since the last call, so a resolver is no longer a snapshot of one moment: each question
/// sees the log as it stands. Each pair's claiming records are verified with the single call's own check, in the
/// single call's order: the subject validated first; `Ok(None)` when no record claims the pair; the latest-first
/// first VERIFYING record when one does; and when only records that do not verify claim it, the earliest claiming
/// record's failure under the same context. Only a pair that VERIFIED is remembered for the rest of the pass, so a
/// refusal is always produced by freshly run code.
///
/// Hold one for one pass, never across passes: a pair that verified stays answered for the resolver's life, without
/// its record being checked again.
pub(crate) struct PrivateDagValueSubjectResolverChirho {
    root_chirho: PathBuf,
    verified_chirho: BTreeMap<(String, HashChirho), PrivateDagValueRecordChirho>,
    pubkey_chirho: Option<String>,
}

impl PrivateDagValueSubjectResolverChirho {
    /// The root is owned, so a resolver can live in a log view's background job, which must be `'static` (checkpoint
    /// brick S3).
    pub(crate) fn new_chirho(root_chirho: &Path) -> Self {
        Self {
            root_chirho: root_chirho.to_path_buf(),
            verified_chirho: BTreeMap::new(),
            pubkey_chirho: None,
        }
    }

    /// `Ok(None)`: nothing claims the pair. `Ok(Some(_))`: the latest-first first record claiming
    /// it that verifies. `Err(_)`: records claim it and none of them verifies.
    pub(crate) fn verified_record_chirho(
        &mut self,
        subject_chirho: &str,
        value_hash_chirho: &HashChirho,
    ) -> Result<Option<&PrivateDagValueRecordChirho>> {
        privacy_chirho::validate_privacy_subject_chirho(subject_chirho)?;
        let key_chirho = (subject_chirho.to_string(), value_hash_chirho.clone());
        if self.verified_chirho.contains_key(&key_chirho) {
            return Ok(self.verified_chirho.get(&key_chirho));
        }
        let claiming_chirho = value_view_chirho::claims_chirho(
            &self.root_chirho,
            value_view_chirho::ClaimKeyChirho::PairChirho(key_chirho.clone()),
            value_view_chirho::ClaimOrderChirho::LatestFirstChirho,
        )?;
        if claiming_chirho.is_empty() {
            return Ok(None);
        }
        let pubkey_chirho = match &mut self.pubkey_chirho {
            Some(pubkey_chirho) => pubkey_chirho,
            slot_chirho @ None => {
                slot_chirho.insert(signer_chirho::pubkey_hex_chirho(&self.root_chirho)?)
            }
        };
        let mut last_failure_chirho = None;
        for claim_chirho in claiming_chirho {
            let record_chirho = claim_chirho?;
            match verify_private_dag_value_record_chirho(
                &self.root_chirho,
                pubkey_chirho,
                &record_chirho,
            ) {
                Ok(()) => {
                    self.verified_chirho
                        .insert(key_chirho.clone(), record_chirho);
                    return Ok(self.verified_chirho.get(&key_chirho));
                }
                Err(failure_chirho) => last_failure_chirho = Some(failure_chirho),
            }
        }
        Err(last_failure_chirho
            .unwrap_or_else(|| anyhow!("private DAG value record verification produced no verdict"))
            .context(format!(
                "private DAG value {} for subject '{}' is claimed only by records that do not verify",
                value_hash_chirho.0, subject_chirho
            )))
    }
}

/// Every value hash backed by a private DAG value record that VERIFIES, collected in one pass.
///
/// The display path needs the same bar as the verifier but must not pay for it per row: resolving
/// each record individually would make a listing O(rows x records). One pass, then membership.
/// Unlike `verified_private_dag_value_record_chirho` this reports no error for a claimed-but-broken
/// record — it simply is not in the set, so the listing LABELS that row unresolvable instead of
/// failing the whole listing. Authoritative verification keeps the loud path (M144 posture:
/// listings label, verifiers fail closed).
pub fn verified_private_dag_value_hashes_chirho(
    root_chirho: &Path,
) -> Result<std::collections::BTreeSet<HashChirho>> {
    let records_chirho = value_view_chirho::all_records_chirho(root_chirho)?;
    if records_chirho.is_empty() {
        return Ok(std::collections::BTreeSet::new());
    }
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let mut verified_chirho = std::collections::BTreeSet::new();
    for record_chirho in &records_chirho {
        if verify_private_dag_value_record_chirho(root_chirho, &pubkey_chirho, record_chirho)
            .is_ok()
        {
            verified_chirho.insert(record_chirho.value_hash_chirho.clone());
        }
    }
    Ok(verified_chirho)
}

pub fn verify_private_dag_values_chirho(root_chirho: &Path) -> Result<usize> {
    let records_chirho = load_private_dag_value_records_chirho(root_chirho)?;
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    for (index_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != index_chirho as u64 {
            bail!(
                "private DAG value record seq {} did not match line {}",
                record_chirho.seq_chirho,
                index_chirho
            );
        }
        verify_private_dag_value_record_chirho(root_chirho, &pubkey_chirho, record_chirho)?;
    }
    Ok(records_chirho.len())
}

fn append_private_dag_value_record_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    value_hash_chirho: HashChirho,
    blob_chirho: privacy_chirho::PrivateBlobRefChirho,
    bytes_chirho: usize,
    context_chirho: PrivateDagValueContextChirho,
) -> Result<PrivateDagValueRecordChirho> {
    seqlog_chirho::with_named_lock_chirho(root_chirho, PRIVATE_DAG_VALUE_LOCK_CHIRHO, || {
        let path_chirho = private_dag_values_path_chirho(root_chirho);
        // Checkpoint brick S2, the S1 store rule: the index is brought current FIRST and refuses on a complete bad
        // line while it is still in the log; only then may recovery repair an unterminated tail. The seq comes from
        // the seqlog's recovered length, O(1), where it was a full typed load (census execution-effects row A3,
        // value half).
        let indexed_records_chirho =
            value_view_chirho::current_value_record_count_chirho(root_chirho)?;
        let seq_chirho = seqlog_chirho::recover_jsonl_len_unlocked_chirho(&path_chirho)?;
        if seq_chirho != indexed_records_chirho {
            bail!(
                "private-value log holds {seq_chirho} records by recovery but {indexed_records_chirho} indexed \
                 records; refusing to append"
            );
        }
        let mut record_chirho = PrivateDagValueRecordChirho {
            schema_chirho: PRIVATE_DAG_VALUE_SCHEMA_CHIRHO.to_string(),
            seq_chirho,
            subject_chirho: subject_chirho.to_string(),
            value_hash_chirho,
            blob_chirho,
            dag_chirho: context_chirho.dag_chirho,
            run_chirho: context_chirho.run_chirho,
            node_chirho: context_chirho.node_chirho,
            port_chirho: context_chirho.port_chirho,
            edge_chirho: context_chirho.edge_chirho,
            bytes_chirho,
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho = private_dag_value_record_message_chirho(&record_chirho)?;
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

fn private_dag_value_record_message_chirho(
    record_chirho: &PrivateDagValueRecordChirho,
) -> Result<Vec<u8>> {
    let mut message_chirho = record_chirho.clone();
    message_chirho.sig_chirho.clear();
    serde_json::to_vec(&message_chirho).context("encode PrivateDagValueRecordChirho message")
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    const SECRET_CHIRHO: &[u8] = b"diagnosis: Hepzibah Subject-Needle chirho";

    fn subject_root_chirho(label_chirho: &str) -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        std::env::temp_dir().join(format!(
            "cairn-private-subject-{label_chirho}-{nanos_chirho}-{n_chirho}"
        ))
    }

    fn records_path_for_tests_chirho(root_chirho: &Path) -> PathBuf {
        private_dag_values_path_chirho(root_chirho)
    }

    /// Appends one record straight to the log, bypassing the signing door the way an attacker with
    /// append access does. `sign_chirho` decides whether it carries a VALID signature, which is what
    /// separates "an unsigned line was refused" from "the subject binding was refused".
    fn append_rebinding_record_chirho(
        root_chirho: &Path,
        original_chirho: &PrivateDagValueRecordChirho,
        new_subject_chirho: &str,
        sign_chirho: bool,
    ) {
        let path_chirho = records_path_for_tests_chirho(root_chirho);
        let before_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let mut forged_chirho = original_chirho.clone();
        forged_chirho.seq_chirho = before_chirho.lines().count() as u64;
        forged_chirho.subject_chirho = new_subject_chirho.to_string();
        forged_chirho.sig_chirho = String::new();
        if sign_chirho {
            let message_chirho = private_dag_value_record_message_chirho(&forged_chirho).unwrap();
            forged_chirho.sig_chirho =
                signer_chirho::sign_message_chirho(root_chirho, &message_chirho).unwrap();
        }
        std::fs::write(
            &path_chirho,
            format!(
                "{before_chirho}{}\n",
                serde_json::to_string(&forged_chirho).unwrap()
            ),
        )
        .unwrap();
        // Proof the append landed before anything depends on it: a mutation that silently no-ops
        // reports the strongest possible result while having tested nothing.
        let after_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        assert_eq!(
            after_chirho.lines().count(),
            before_chirho.lines().count() + 1,
            "the rebinding record was not appended, so the assertions below prove nothing"
        );
        assert!(
            after_chirho.contains(new_subject_chirho),
            "the appended record does not name the rebinding subject"
        );
    }

    /// F4-S3 review finding 2: reading a private DAG value must bind the REQUESTED SUBJECT through
    /// a record that verifies.
    ///
    /// The loader used to select on `subject == requested` over the raw JSONL, which is a check
    /// against an unverified signal. Appending one line that names an existing hash and an existing
    /// blob ref under a DIFFERENT subject rebound that blob, and the loader then handed the first
    /// subject's plaintext to a caller asking as the second. Every downstream check still passed —
    /// the blob's MAC, the AEAD, and the plaintext hash are all properties of the substituted blob
    /// rather than of who may read it.
    ///
    /// The forged record here is correctly SIGNED, which is not something an attacker can do. That
    /// is deliberate: it removes the signature as a possible refusal so the only thing left that can
    /// refuse is the subject binding itself, and the arm cannot pass for the neighbouring reason.
    ///
    /// MIGRATION PATH — if this goes red because the read SUCCEEDED, the loader is back on the bare
    /// record match and a cross-subject read is live. If it refuses by a different identity, read
    /// the refusal before editing the assertion.
    #[test]
    fn a_signed_record_cannot_rebind_another_subjects_blob_to_itself_chirho() {
        let root_chirho = subject_root_chirho("signed-rebind");
        let owner_chirho = "user/private-owner-chirho";
        let stranger_chirho = "user/private-stranger-chirho";

        let value_hash_chirho = store_private_dag_value_chirho(
            &root_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                owner_chirho,
            ),
            owner_chirho,
            SECRET_CHIRHO,
            PrivateDagValueContextChirho::default(),
        )
        .unwrap();
        let original_chirho = load_private_dag_value_records_chirho(&root_chirho)
            .unwrap()
            .pop()
            .expect("the write door recorded nothing to rebind");

        // POSITIVE CONTROL: the legitimate reader gets the plaintext. Without it a later refusal
        // could simply mean the fixture never stored anything readable.
        assert_eq!(
            load_private_dag_value_bytes_chirho(&root_chirho, owner_chirho, &value_hash_chirho)
                .unwrap(),
            SECRET_CHIRHO,
            "control: the owner cannot read its own value, so this arm is measuring a broken fixture"
        );

        append_rebinding_record_chirho(&root_chirho, &original_chirho, stranger_chirho, true);

        let refusal_chirho = format!(
            "{:#}",
            load_private_dag_value_bytes_chirho(&root_chirho, stranger_chirho, &value_hash_chirho)
                .expect_err(
                    "a stranger read another subject's plaintext through a rebinding record"
                )
        );
        assert!(
            refusal_chirho.contains("belongs to subject"),
            "the refusal must be the SUBJECT BINDING, not a neighbouring check: {refusal_chirho}"
        );
        assert!(
            !refusal_chirho.contains(std::str::from_utf8(SECRET_CHIRHO).unwrap()),
            "the refusal leaked the plaintext it refused to hand over: {refusal_chirho}"
        );

        // The owner is untouched: the fix refuses the rebinding, not the legitimate read.
        assert_eq!(
            load_private_dag_value_bytes_chirho(&root_chirho, owner_chirho, &value_hash_chirho)
                .unwrap(),
            SECRET_CHIRHO,
            "the fix broke the legitimate owner's read as well as the stranger's"
        );

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    /// The realistic shape of the same attack: an UNSIGNED appended line. Kept separate from the
    /// signed arm because the two fail at different gates, and collapsing them would let one gate
    /// cover for the other.
    #[test]
    fn an_unsigned_record_cannot_rebind_another_subjects_blob_to_itself_chirho() {
        let root_chirho = subject_root_chirho("unsigned-rebind");
        let owner_chirho = "user/private-owner-chirho";
        let stranger_chirho = "user/private-stranger-chirho";

        let value_hash_chirho = store_private_dag_value_chirho(
            &root_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                owner_chirho,
            ),
            owner_chirho,
            SECRET_CHIRHO,
            PrivateDagValueContextChirho::default(),
        )
        .unwrap();
        let original_chirho = load_private_dag_value_records_chirho(&root_chirho)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            load_private_dag_value_bytes_chirho(&root_chirho, owner_chirho, &value_hash_chirho)
                .unwrap(),
            SECRET_CHIRHO,
            "control: the owner cannot read its own value"
        );

        append_rebinding_record_chirho(&root_chirho, &original_chirho, stranger_chirho, false);

        let refusal_chirho = format!(
            "{:#}",
            load_private_dag_value_bytes_chirho(&root_chirho, stranger_chirho, &value_hash_chirho)
                .expect_err("a stranger read another subject's plaintext through an unsigned line")
        );
        assert!(
            !refusal_chirho.contains("is not recorded"),
            "the refusal claims nothing claims the pair, when a line does: {refusal_chirho}"
        );
        assert!(
            !refusal_chirho.contains(std::str::from_utf8(SECRET_CHIRHO).unwrap()),
            "the refusal leaked the plaintext: {refusal_chirho}"
        );

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    /// A subject that nothing claims keeps the accurate "is not recorded", so the two failure modes
    /// stay distinguishable to whoever reads the error.
    #[test]
    fn an_unclaimed_subject_keeps_the_not_recorded_refusal_chirho() {
        let root_chirho = subject_root_chirho("unclaimed");
        let owner_chirho = "user/private-owner-chirho";
        let value_hash_chirho = store_private_dag_value_chirho(
            &root_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                owner_chirho,
            ),
            owner_chirho,
            SECRET_CHIRHO,
            PrivateDagValueContextChirho::default(),
        )
        .unwrap();

        let refusal_chirho = format!(
            "{:#}",
            load_private_dag_value_bytes_chirho(
                &root_chirho,
                "user/private-nobody-chirho",
                &value_hash_chirho
            )
            .expect_err("an unclaimed subject read a value")
        );
        assert!(
            refusal_chirho.contains("is not recorded"),
            "an unclaimed pair should keep the not-recorded refusal: {refusal_chirho}"
        );

        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
