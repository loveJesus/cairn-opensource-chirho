// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! P3 fold plane: verify a replica's copied Gate 1 authority state against the SOURCE's signed head,
//! then independently reproduce the four Ring-A CLSD digests. This is the authority-bearing core of
//! P3 — it must verify against the PINNED SOURCE key (never the replica's own), because the replica
//! holds no source signing key. The chain is: the source-signed head pins the anchor prefix digest;
//! the prefix digest hash-chains every anchor line (including the per-group state digests they carry),
//! so a tampered or truncated anchor prefix fails the head signature; and folding the replica's copied
//! family logs by the anchor-pinned counts and asserting equality with those source-signed state
//! digests binds the family logs too. Every byte a replica trusts traces to the source's key.
//!
//! Reuses `cairn-model-gate1`'s canonical message fns and `cairn-projection`'s fold verbatim (one
//! source of truth), and replicates the small pure prefix-digest chain from the root anchor module
//! byte-for-byte (proven by a root-level integration test that verifies a REAL root export here).

use anyhow::{anyhow, bail, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_model_gate1_chirho::{
    unsigned_gate1_anchor_head_replication_message_chirho,
    validate_gate1_anchor_head_replication_record_chirho, Gate1AnchorHeadReplicationRecordChirho,
    Gate1LogAnchorRecordChirho, GATE1_LOG_ANCHORS_FILE_CHIRHO, GATE1_RING_A_ANCHOR_TARGETS_CHIRHO,
};
use cairn_projection_chirho::gate1_state_digest_chirho::{
    gate1_ring_a_semantic_state_digests_for_prefix_chirho, gate1_semantic_group_for_family_chirho,
};
use cairn_signer_chirho::signer_chirho::verify_with_pubkey_chirho;
use std::collections::BTreeMap;
use std::path::Path;

const PREFIX_ZERO_BYTES_CHIRHO: [u8; 32] = [0u8; 32];

/// Evidence a verified fold produces: schema-tagged counts, no paths or bytes, safe to persist.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VerifiedFoldReportChirho {
    pub schema_chirho: String,
    /// Anchor records the source-signed head retained (the length witness).
    pub anchor_record_count_chirho: u64,
    /// Ring-A groups whose independently-folded digest matched the source-signed state digest.
    pub verified_group_count_chirho: u64,
    /// Anchor records present on the replica beyond the signed head count (the replica is ahead —
    /// it must never be BEHIND, which fails closed above).
    pub unverified_tail_count_chirho: u64,
}

pub const VERIFIED_FOLD_REPORT_SCHEMA_CHIRHO: &str = "replica-verified-fold-v1-chirho";

/// Read the non-empty JSONL lines of a file exactly as the root anchor module does (split on `\n`,
/// drop whitespace-only lines), so the prefix digest is byte-identical.
fn read_nonempty_jsonl_lines_chirho(path_chirho: &Path) -> Result<Vec<Vec<u8>>> {
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let bytes_chirho = std::fs::read(path_chirho)?;
    Ok(bytes_chirho
        .split(|byte_chirho| *byte_chirho == b'\n')
        .filter(|line_chirho| {
            !line_chirho
                .iter()
                .all(|byte_chirho| byte_chirho.is_ascii_whitespace())
        })
        .map(|line_chirho| line_chirho.to_vec())
        .collect())
}

/// The running blake3 hash-chain over a prefix of raw JSONL lines — byte-identical to the root anchor
/// module's `prefix_digest_for_lines_chirho`, so a replica computes the same prefix digest the source
/// signed.
fn prefix_digest_for_lines_chirho<'a_chirho>(
    lines_chirho: impl Iterator<Item = &'a_chirho Vec<u8>>,
) -> HashChirho {
    let mut previous_chirho = PREFIX_ZERO_BYTES_CHIRHO;
    for line_chirho in lines_chirho {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(&previous_chirho);
        hasher_chirho.update(line_chirho);
        previous_chirho = *hasher_chirho.finalize().as_bytes();
    }
    HashChirho(
        previous_chirho
            .iter()
            .map(|b_chirho| format!("{b_chirho:02x}"))
            .collect(),
    )
}

/// Verify a replica root's copied Gate 1 authority state against the source-signed head, and
/// independently reproduce the four Ring-A CLSD digests, trusting only the pinned source key.
///
/// `replica_root_chirho` holds the copied anchor log + Ring-A family logs. `head_bytes_chirho` is the
/// source's signed `Gate1AnchorHeadReplicationRecordChirho` (canonical JSON). `source_pubkey_hex_chirho`
/// is the source node's public key, resolved from the D3 signed membership roster.
/// `min_anchor_record_count_chirho` is the caller's anti-rollback floor: a caller that persists the
/// count it last verified passes `Some(that)` so a stale-but-validly-signed earlier head (which folds
/// against the append-only log's prefix) is rejected instead of silently rolling the authority view
/// back; `None` on a first sync accepts any count (the report still surfaces the tail honestly).
/// This function reads only; it never moves a head.
pub fn verify_replicated_authority_fold_chirho(
    replica_root_chirho: &Path,
    head_bytes_chirho: &[u8],
    source_pubkey_hex_chirho: &str,
    min_anchor_record_count_chirho: Option<u64>,
) -> Result<VerifiedFoldReportChirho> {
    // 1. The source-signed head, verified against the PINNED SOURCE key (never the replica's own).
    let head_chirho: Gate1AnchorHeadReplicationRecordChirho =
        serde_json::from_slice(head_bytes_chirho)?;
    validate_gate1_anchor_head_replication_record_chirho(&head_chirho)?;
    if head_chirho.key_id_chirho != source_pubkey_hex_chirho {
        bail!("replicated anchor head key id does not match the pinned source key");
    }
    let message_chirho = unsigned_gate1_anchor_head_replication_message_chirho(&head_chirho)?;
    if !verify_with_pubkey_chirho(
        source_pubkey_hex_chirho,
        &message_chirho,
        &head_chirho.sig_chirho,
    )? {
        bail!("replicated anchor head signature is invalid for the pinned source key");
    }

    // 1a. Anti-rollback floor: an earlier head is still validly signed and its prefix digest still
    // matches the append-only log, so signature + prefix checks alone cannot catch a rollback. A
    // caller that threads its last-verified count rejects any head below it.
    if let Some(floor_chirho) = min_anchor_record_count_chirho {
        if head_chirho.anchor_record_count_chirho < floor_chirho {
            bail!(
                "replicated anchor head count {} is below the caller's anti-rollback floor {} \
                 (stale-head replay)",
                head_chirho.anchor_record_count_chirho,
                floor_chirho
            );
        }
    }

    // 2. Length witness + prefix digest: the copied anchor prefix must reproduce the source-signed
    // digest. Because the digest hash-chains every anchor line, this makes the whole prefix authentic
    // — a truncated (short) or tampered anchor log fails closed here.
    let anchor_path_chirho = replica_root_chirho.join(GATE1_LOG_ANCHORS_FILE_CHIRHO);
    let anchor_lines_chirho = read_nonempty_jsonl_lines_chirho(&anchor_path_chirho)?;
    let count_chirho = head_chirho.anchor_record_count_chirho as usize;
    if anchor_lines_chirho.len() < count_chirho {
        bail!(
            "replica anchor log has {} records, below the source-signed head count {}",
            anchor_lines_chirho.len(),
            count_chirho
        );
    }
    let replica_prefix_digest_chirho =
        prefix_digest_for_lines_chirho(anchor_lines_chirho.iter().take(count_chirho));
    if replica_prefix_digest_chirho != head_chirho.anchor_prefix_digest_chirho {
        bail!("replica anchor prefix digest does not match the source-signed head (tamper/truncation)");
    }

    // 3. The anchor prefix is now authentic. Per family, keep its LAST anchor record — which pins that
    // family's retained line count AND its raw prefix digest together, so pairing them is desync-free
    // across any anchor history. Per group, keep the last source-signed semantic state digest.
    let mut last_anchor_by_family_chirho: BTreeMap<String, Gate1LogAnchorRecordChirho> =
        BTreeMap::new();
    let mut expected_group_digests_chirho: BTreeMap<String, HashChirho> = BTreeMap::new();
    for line_chirho in anchor_lines_chirho.iter().take(count_chirho) {
        let record_chirho: Gate1LogAnchorRecordChirho = serde_json::from_slice(line_chirho)?;
        let group_spec_chirho = gate1_semantic_group_for_family_chirho(
            &record_chirho.family_chirho,
        )
        .ok_or_else(|| {
            anyhow!(
                "anchor record names non-Ring-A family {}",
                record_chirho.family_chirho
            )
        })?;
        if let Some(state_digest_chirho) = record_chirho.state_digest_chirho.clone() {
            expected_group_digests_chirho.insert(
                group_spec_chirho.group_chirho.to_string(),
                state_digest_chirho,
            );
        }
        last_anchor_by_family_chirho.insert(record_chirho.family_chirho.clone(), record_chirho);
    }

    // 3a. Coverage bound to the source-signed head: every declared Ring-A family must be anchored and
    // every declared semantic group must carry a signed digest. Without this a legacy anchor history
    // (all `state_digest=None`) would bind ZERO family logs yet still return Ok — a false accept.
    if last_anchor_by_family_chirho.len() as u64 != head_chirho.physical_target_count_chirho {
        bail!(
            "replica anchor prefix covers {} families, not the source-signed {} Ring-A targets",
            last_anchor_by_family_chirho.len(),
            head_chirho.physical_target_count_chirho
        );
    }
    for family_chirho in GATE1_RING_A_ANCHOR_TARGETS_CHIRHO {
        if !last_anchor_by_family_chirho.contains_key(family_chirho) {
            bail!("replica anchor prefix is missing Ring-A family {family_chirho}");
        }
    }
    if expected_group_digests_chirho.len() as u64 != head_chirho.semantic_group_count_chirho {
        bail!(
            "replica anchor prefix binds {} semantic groups, not the source-signed {}",
            expected_group_digests_chirho.len(),
            head_chirho.semantic_group_count_chirho
        );
    }

    // 3b. RAW per-family binding: each copied family log's raw prefix (at the anchor-pinned count) must
    // reproduce the anchor's signed `prefix_digest`. This binds the family-log BYTES — a raw tamper
    // that reduces to the same SEMANTIC state (which the fold in step 4 would miss) still fails here.
    let mut counts_chirho: BTreeMap<String, u64> = BTreeMap::new();
    for (family_chirho, record_chirho) in &last_anchor_by_family_chirho {
        let family_path_chirho = replica_root_chirho.join(family_chirho);
        let family_lines_chirho = read_nonempty_jsonl_lines_chirho(&family_path_chirho)?;
        let family_count_chirho = record_chirho.line_count_chirho as usize;
        if family_lines_chirho.len() < family_count_chirho {
            bail!(
                "replica family log {family_chirho} has {} rows, below the source-signed count {}",
                family_lines_chirho.len(),
                family_count_chirho
            );
        }
        let raw_digest_chirho =
            prefix_digest_for_lines_chirho(family_lines_chirho.iter().take(family_count_chirho));
        if raw_digest_chirho != record_chirho.prefix_digest_chirho {
            bail!(
                "replica family log {family_chirho} raw prefix digest diverges from the \
                 source-signed anchor (byte tamper/truncation)"
            );
        }
        counts_chirho.insert(family_chirho.clone(), record_chirho.line_count_chirho);
    }

    // 4. SEMANTIC binding: independently fold the now raw-verified family logs by the pinned counts
    // and assert each group's digest equals the source-signed state digest.
    let folded_chirho =
        gate1_ring_a_semantic_state_digests_for_prefix_chirho(replica_root_chirho, &counts_chirho)?;
    for (group_chirho, expected_chirho) in &expected_group_digests_chirho {
        let actual_chirho = folded_chirho.get(group_chirho).ok_or_else(|| {
            anyhow!("independent fold produced no digest for Ring-A group {group_chirho}")
        })?;
        if actual_chirho != expected_chirho {
            bail!(
                "replica independent fold for Ring-A group {group_chirho} diverges from the \
                 source-signed state digest"
            );
        }
    }

    Ok(VerifiedFoldReportChirho {
        schema_chirho: VERIFIED_FOLD_REPORT_SCHEMA_CHIRHO.to_string(),
        anchor_record_count_chirho: head_chirho.anchor_record_count_chirho,
        verified_group_count_chirho: expected_group_digests_chirho.len() as u64,
        unverified_tail_count_chirho: (anchor_lines_chirho.len() - count_chirho) as u64,
    })
}
