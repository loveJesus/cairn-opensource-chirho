// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! B2.1 ref-snapshot plane: carry a source's app/app-route refs to a read-only replica as a
//! signed, rollback-proof, equivocation-detecting snapshot — the ONLY ref family that crosses the
//! replication boundary, and it transfers no authority (a replica can serve from the snapshot but
//! can never advance anything upstream). Design + pre-commitments (a)-(e):
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/b2-replica-serve-design-chirho.md`.
//!
//! Pattern lineage: head rows are signed by the SAME node sign-root that signs the Gate 1 anchor
//! head and verified against the PINNED roster-resolved source key (`fold_plane_chirho`); the
//! durable floor persists `{seq, stone hash}` so a restarted replica idempotently re-mounts the
//! snapshot it already trusted, refuses stale-head rollback, and fails LOUDLY on equivocation
//! (one source key signing two different snapshots at one seq).

use anyhow::{anyhow, bail, Context, Result};
use cairn_core_chirho::cas_chirho::hash_chirho;
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_core_chirho::ports_chirho::ContentStoreChirho;
use cairn_core_chirho::refs_chirho::load_refs_chirho;
use cairn_durable_chirho::{append_durable_line_chirho, write_file_durable_chirho};
use cairn_signer_chirho::signer_chirho::{
    pubkey_hex_chirho, sign_message_chirho, verify_with_pubkey_chirho,
};
use cairn_store_fs_chirho::FsContentStoreChirho;
use std::collections::BTreeMap;
use std::path::Path;

/// The ONE replicable log name the snapshot plane adds (the structured allowlist exception).
pub const REF_SNAPSHOT_LOG_FILE_CHIRHO: &str = "ref-snapshot-log-chirho.jsonl";
pub const REF_SNAPSHOT_SCHEMA_CHIRHO: &str = "ref-snapshot-v1-chirho";
pub const REF_SNAPSHOT_HEAD_SCHEMA_CHIRHO: &str = "ref-snapshot-head-v1-chirho";
/// Durable floor file on the REPLICA — deliberately separate from `replica-sync-floor-chirho.json`
/// so the fold plane and the snapshot plane cannot mask each other's rollback checks.
pub const REF_SNAPSHOT_FLOOR_FILE_CHIRHO: &str = "ref-snapshot-floor-chirho.json";
pub const REF_SNAPSHOT_FLOOR_SCHEMA_CHIRHO: &str = "ref-snapshot-floor-v1-chirho";
pub const REF_SNAPSHOT_MOUNT_REPORT_SCHEMA_CHIRHO: &str = "ref-snapshot-mount-report-v1-chirho";

fn is_ref_segment_chirho(segment_chirho: &str) -> bool {
    !segment_chirho.is_empty()
        && segment_chirho != "."
        && segment_chirho != ".."
        && !segment_chirho.chars().any(|ch_chirho| {
            ch_chirho == '/' || ch_chirho.is_whitespace() || ch_chirho.is_control()
        })
}

/// Pre-commitment (c), enforced at export AND mount: exactly the `app/<name>` and
/// `app-route/<app>/<route>` branch families may cross — `HEAD`, Gate 1 mode refs, and every
/// money/identity family structurally cannot.
pub fn is_snapshot_ref_name_chirho(name_chirho: &str) -> bool {
    if let Some(app_chirho) = name_chirho.strip_prefix("app/") {
        return is_ref_segment_chirho(app_chirho);
    }
    if let Some(rest_chirho) = name_chirho.strip_prefix("app-route/") {
        if let Some((app_chirho, route_chirho)) = rest_chirho.split_once('/') {
            return is_ref_segment_chirho(app_chirho) && is_ref_segment_chirho(route_chirho);
        }
    }
    false
}

fn is_lower_hex64_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_hexdigit() && !byte_chirho.is_ascii_uppercase())
}

/// The snapshot stone: a content-addressed, canonical-JSON map of exactly the servable ref
/// families at one source moment. Stored in CAS, so it rides the existing verified object plane.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RefSnapshotChirho {
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub source_time_unix_chirho: u64,
    pub refs_chirho: BTreeMap<String, HashChirho>,
}

impl RefSnapshotChirho {
    pub fn new_chirho(
        refs_chirho: BTreeMap<String, HashChirho>,
        seq_chirho: u64,
        source_time_unix_chirho: u64,
    ) -> Result<Self> {
        for (name_chirho, value_chirho) in &refs_chirho {
            if !is_snapshot_ref_name_chirho(name_chirho) {
                bail!("ref snapshot refuses non-app/app-route ref name {name_chirho:?}");
            }
            if !is_lower_hex64_chirho(&value_chirho.0) {
                bail!("ref snapshot refuses malformed target hash for {name_chirho:?}");
            }
        }
        Ok(Self {
            schema_chirho: REF_SNAPSHOT_SCHEMA_CHIRHO.to_string(),
            seq_chirho,
            source_time_unix_chirho,
            refs_chirho,
        })
    }

    pub fn canonical_bytes_chirho(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("serialize ref snapshot")
    }

    /// The content-independent identity of the refs map alone (seq/time excluded), used for
    /// idempotent re-export: unchanged refs never mint a new seq.
    pub fn refs_digest_chirho(&self) -> Result<HashChirho> {
        let bytes_chirho =
            serde_json::to_vec(&self.refs_chirho).context("serialize ref snapshot refs")?;
        Ok(hash_chirho(&bytes_chirho))
    }
}

fn validate_snapshot_chirho(snapshot_chirho: &RefSnapshotChirho) -> Result<()> {
    if snapshot_chirho.schema_chirho != REF_SNAPSHOT_SCHEMA_CHIRHO {
        bail!(
            "ref snapshot schema {} is not {REF_SNAPSHOT_SCHEMA_CHIRHO}",
            snapshot_chirho.schema_chirho
        );
    }
    for (name_chirho, value_chirho) in &snapshot_chirho.refs_chirho {
        if !is_snapshot_ref_name_chirho(name_chirho) {
            bail!("ref snapshot carries non-app/app-route ref name {name_chirho:?}");
        }
        if !is_lower_hex64_chirho(&value_chirho.0) {
            bail!("ref snapshot carries malformed target hash for {name_chirho:?}");
        }
    }
    Ok(())
}

/// One signed export head row in `ref-snapshot-log-chirho.jsonl`. Signed by the source node's
/// sign-root (the SAME key that signs the Gate 1 anchor head — one roster entry covers both
/// planes) and verified on the replica against the pinned roster-resolved pubkey.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RefSnapshotHeadRecordChirho {
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub source_time_unix_chirho: u64,
    pub snapshot_hash_chirho: HashChirho,
    pub refs_digest_chirho: HashChirho,
    pub ref_count_chirho: u64,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

pub fn validate_ref_snapshot_head_chirho(
    record_chirho: &RefSnapshotHeadRecordChirho,
) -> Result<()> {
    if record_chirho.schema_chirho != REF_SNAPSHOT_HEAD_SCHEMA_CHIRHO {
        bail!(
            "ref snapshot head schema {} is not {REF_SNAPSHOT_HEAD_SCHEMA_CHIRHO}",
            record_chirho.schema_chirho
        );
    }
    if !is_lower_hex64_chirho(&record_chirho.snapshot_hash_chirho.0) {
        bail!("ref snapshot head carries a malformed snapshot hash");
    }
    if !is_lower_hex64_chirho(&record_chirho.refs_digest_chirho.0) {
        bail!("ref snapshot head carries a malformed refs digest");
    }
    if !is_lower_hex64_chirho(&record_chirho.key_id_chirho) {
        bail!("ref snapshot head carries a malformed key id");
    }
    if record_chirho.sig_chirho.is_empty() {
        bail!("ref snapshot head carries an empty signature");
    }
    Ok(())
}

/// The canonical bytes a head signature covers: the record with `sig_chirho` cleared.
pub fn unsigned_ref_snapshot_head_message_chirho(
    record_chirho: &RefSnapshotHeadRecordChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.sig_chirho = String::new();
    serde_json::to_vec(&unsigned_chirho).context("serialize unsigned ref snapshot head")
}

fn read_nonempty_lines_chirho(bytes_chirho: &[u8]) -> Vec<Vec<u8>> {
    bytes_chirho
        .split(|byte_chirho| *byte_chirho == b'\n')
        .filter(|line_chirho| {
            !line_chirho
                .iter()
                .all(|byte_chirho| byte_chirho.is_ascii_whitespace())
        })
        .map(|line_chirho| line_chirho.to_vec())
        .collect()
}

/// Parse and verify EVERY row of a snapshot log against the pinned source key, failing closed on
/// a malformed row, a wrong/foreign key id, an invalid signature, a non-increasing seq, or an
/// in-log equivocation (two rows at one seq — loud, naming both stone hashes). Returns the rows
/// oldest-first; the newest row is the mount candidate.
pub fn read_verified_snapshot_heads_chirho(
    log_bytes_chirho: &[u8],
    source_pubkey_hex_chirho: &str,
) -> Result<Vec<RefSnapshotHeadRecordChirho>> {
    let mut heads_chirho: Vec<RefSnapshotHeadRecordChirho> = Vec::new();
    for (index_chirho, line_chirho) in read_nonempty_lines_chirho(log_bytes_chirho)
        .iter()
        .enumerate()
    {
        let record_chirho: RefSnapshotHeadRecordChirho = serde_json::from_slice(line_chirho)
            .with_context(|| format!("ref snapshot log row {index_chirho} is malformed"))?;
        validate_ref_snapshot_head_chirho(&record_chirho)?;
        if record_chirho.key_id_chirho != source_pubkey_hex_chirho {
            bail!(
                "ref snapshot log row {index_chirho} key id does not match the pinned source key"
            );
        }
        let message_chirho = unsigned_ref_snapshot_head_message_chirho(&record_chirho)?;
        if !verify_with_pubkey_chirho(
            source_pubkey_hex_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!("ref snapshot log row {index_chirho} signature is invalid for the pinned source key");
        }
        if let Some(previous_chirho) = heads_chirho.last() {
            if record_chirho.seq_chirho == previous_chirho.seq_chirho {
                if record_chirho.snapshot_hash_chirho != previous_chirho.snapshot_hash_chirho {
                    bail!(
                        "ref snapshot EQUIVOCATION in log: seq {} signed for two different stones \
                         ({} vs {})",
                        record_chirho.seq_chirho,
                        previous_chirho.snapshot_hash_chirho.0,
                        record_chirho.snapshot_hash_chirho.0
                    );
                }
                bail!(
                    "ref snapshot log repeats seq {} (duplicate export row)",
                    record_chirho.seq_chirho
                );
            }
            if record_chirho.seq_chirho < previous_chirho.seq_chirho {
                bail!(
                    "ref snapshot log seq went backwards ({} after {})",
                    record_chirho.seq_chirho,
                    previous_chirho.seq_chirho
                );
            }
        }
        heads_chirho.push(record_chirho);
    }
    Ok(heads_chirho)
}

/// The durable replica floor: the seq AND stone hash last fully mounted (A2 semantics).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RefSnapshotFloorChirho {
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub snapshot_hash_chirho: HashChirho,
}

pub fn read_ref_snapshot_floor_chirho(
    replica_root_chirho: &Path,
) -> Result<Option<RefSnapshotFloorChirho>> {
    let path_chirho = replica_root_chirho.join(REF_SNAPSHOT_FLOOR_FILE_CHIRHO);
    if !path_chirho.exists() {
        return Ok(None);
    }
    let bytes_chirho =
        std::fs::read(&path_chirho).with_context(|| format!("read {}", path_chirho.display()))?;
    let floor_chirho: RefSnapshotFloorChirho =
        serde_json::from_slice(&bytes_chirho).context("parse ref snapshot floor")?;
    if floor_chirho.schema_chirho != REF_SNAPSHOT_FLOOR_SCHEMA_CHIRHO {
        bail!(
            "ref snapshot floor schema {} is not {REF_SNAPSHOT_FLOOR_SCHEMA_CHIRHO}",
            floor_chirho.schema_chirho
        );
    }
    Ok(Some(floor_chirho))
}

pub fn write_ref_snapshot_floor_chirho(
    replica_root_chirho: &Path,
    floor_chirho: &RefSnapshotFloorChirho,
) -> Result<()> {
    let bytes_chirho = serde_json::to_vec(floor_chirho).context("serialize ref snapshot floor")?;
    write_file_durable_chirho(
        &replica_root_chirho.join(REF_SNAPSHOT_FLOOR_FILE_CHIRHO),
        &bytes_chirho,
    )
    .context("write ref snapshot floor")
}

/// How a head cleared the floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FloorDecisionChirho {
    /// `seq > floor` (or no floor yet): a new snapshot mounts and raises the floor.
    FreshMountChirho,
    /// `seq == floor` with a byte-identical stone hash: the restart-safe re-mount.
    IdempotentRemountChirho,
}

/// A2 floor semantics: below the floor is rollback; at the floor with the SAME stone is an
/// idempotent re-mount (a restarted replica must keep serving); at the floor with a DIFFERENT
/// stone is equivocation and fails LOUDLY naming both hashes; above the floor is a fresh mount.
pub fn check_head_against_floor_chirho(
    head_chirho: &RefSnapshotHeadRecordChirho,
    floor_chirho: Option<&RefSnapshotFloorChirho>,
) -> Result<FloorDecisionChirho> {
    let Some(floor_chirho) = floor_chirho else {
        return Ok(FloorDecisionChirho::FreshMountChirho);
    };
    if head_chirho.seq_chirho < floor_chirho.seq_chirho {
        bail!(
            "ref snapshot head seq {} is below the replica's durable floor {} (stale-head rollback)",
            head_chirho.seq_chirho,
            floor_chirho.seq_chirho
        );
    }
    if head_chirho.seq_chirho == floor_chirho.seq_chirho {
        if head_chirho.snapshot_hash_chirho == floor_chirho.snapshot_hash_chirho {
            return Ok(FloorDecisionChirho::IdempotentRemountChirho);
        }
        bail!(
            "ref snapshot EQUIVOCATION: the source key signed two different snapshots at seq {} \
             (mounted floor stone {} vs offered stone {})",
            head_chirho.seq_chirho,
            floor_chirho.snapshot_hash_chirho.0,
            head_chirho.snapshot_hash_chirho.0
        );
    }
    Ok(FloorDecisionChirho::FreshMountChirho)
}

/// The read-only mounted view (pre-commitment a): lookups and evidence accessors ONLY — no save,
/// no branch move, no CAS write, no path back to `RefsChirho`. The serve layer receives this type
/// and therefore cannot express a head mutation.
#[derive(Clone, Debug)]
pub struct ReplicaRefsViewChirho {
    refs_chirho: BTreeMap<String, HashChirho>,
    seq_chirho: u64,
    source_time_unix_chirho: u64,
    source_key_id_chirho: String,
    snapshot_hash_chirho: HashChirho,
}

impl ReplicaRefsViewChirho {
    pub fn ref_hash_chirho(&self, name_chirho: &str) -> Option<&HashChirho> {
        self.refs_chirho.get(name_chirho)
    }

    pub fn ref_names_chirho(&self) -> impl Iterator<Item = &str> {
        self.refs_chirho
            .keys()
            .map(|name_chirho| name_chirho.as_str())
    }

    pub fn ref_count_chirho(&self) -> u64 {
        self.refs_chirho.len() as u64
    }

    pub fn seq_chirho(&self) -> u64 {
        self.seq_chirho
    }

    pub fn source_time_unix_chirho(&self) -> u64 {
        self.source_time_unix_chirho
    }

    pub fn source_key_id_chirho(&self) -> &str {
        &self.source_key_id_chirho
    }

    pub fn snapshot_hash_chirho(&self) -> &HashChirho {
        &self.snapshot_hash_chirho
    }
}

/// Load a head's stone from the VERIFIED store and bind it: schema, head↔stone seq equality,
/// refs-digest equality, the name allowlist again, and direct-target presence (every ref's target
/// object must already be in the replica store — the serve layer deep-checks the artifact chain
/// it actually serves on top of this).
pub fn mount_ref_snapshot_chirho<C>(
    store_chirho: &C,
    head_chirho: &RefSnapshotHeadRecordChirho,
) -> Result<ReplicaRefsViewChirho>
where
    C: ContentStoreChirho + ?Sized,
{
    let bytes_chirho = store_chirho
        .get_chirho(&head_chirho.snapshot_hash_chirho)
        .map_err(|error_chirho| anyhow!("load ref snapshot stone: {error_chirho}"))?
        .ok_or_else(|| {
            anyhow!(
                "ref snapshot stone {} is not in the replica store (pull it first)",
                head_chirho.snapshot_hash_chirho.0
            )
        })?;
    let snapshot_chirho: RefSnapshotChirho =
        serde_json::from_slice(&bytes_chirho).context("parse ref snapshot stone")?;
    validate_snapshot_chirho(&snapshot_chirho)?;
    if snapshot_chirho.seq_chirho != head_chirho.seq_chirho {
        bail!(
            "ref snapshot stone seq {} does not match the signed head seq {}",
            snapshot_chirho.seq_chirho,
            head_chirho.seq_chirho
        );
    }
    if snapshot_chirho.refs_digest_chirho()? != head_chirho.refs_digest_chirho {
        bail!("ref snapshot stone refs digest does not match the signed head");
    }
    if snapshot_chirho.refs_chirho.len() as u64 != head_chirho.ref_count_chirho {
        bail!("ref snapshot stone ref count does not match the signed head");
    }
    for (name_chirho, target_chirho) in &snapshot_chirho.refs_chirho {
        let present_chirho = store_chirho
            .get_chirho(target_chirho)
            .map_err(|error_chirho| anyhow!("read snapshot ref target: {error_chirho}"))?
            .is_some();
        if !present_chirho {
            bail!(
                "ref snapshot closure object missing: {name_chirho:?} -> {} is not in the replica \
                 store",
                target_chirho.0
            );
        }
    }
    Ok(ReplicaRefsViewChirho {
        refs_chirho: snapshot_chirho.refs_chirho,
        seq_chirho: snapshot_chirho.seq_chirho,
        source_time_unix_chirho: snapshot_chirho.source_time_unix_chirho,
        source_key_id_chirho: head_chirho.key_id_chirho.clone(),
        snapshot_hash_chirho: head_chirho.snapshot_hash_chirho.clone(),
    })
}

/// The staleness evidence row a mount emits (pre-commitment d): counts, times, and the labeled
/// replica clock — no paths, safe to persist or print.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RefSnapshotMountReportChirho {
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub source_time_unix_chirho: u64,
    /// The REPLICA's clock at verification — labeled as such; never compared to the source time
    /// for correctness decisions.
    pub verified_at_unix_chirho: u64,
    pub source_key_id_chirho: String,
    pub ref_count_chirho: u64,
    pub decision_chirho: FloorDecisionChirho,
}

/// The one-call replica flow: verify every log row against the pinned key, apply the A2 floor
/// semantics, mount the newest snapshot from the verified store, THEN raise the durable floor.
/// `verified_at_unix_chirho` is passed in so the module stays clock-free and vector-testable.
pub fn mount_latest_verified_snapshot_chirho<C>(
    store_chirho: &C,
    replica_root_chirho: &Path,
    log_bytes_chirho: &[u8],
    source_pubkey_hex_chirho: &str,
    verified_at_unix_chirho: u64,
) -> Result<(ReplicaRefsViewChirho, RefSnapshotMountReportChirho)>
where
    C: ContentStoreChirho + ?Sized,
{
    let heads_chirho =
        read_verified_snapshot_heads_chirho(log_bytes_chirho, source_pubkey_hex_chirho)?;
    let Some(newest_chirho) = heads_chirho.last() else {
        bail!("ref snapshot log has no rows; nothing to mount");
    };
    let floor_chirho = read_ref_snapshot_floor_chirho(replica_root_chirho)?;
    let decision_chirho = check_head_against_floor_chirho(newest_chirho, floor_chirho.as_ref())?;
    let view_chirho = mount_ref_snapshot_chirho(store_chirho, newest_chirho)?;
    // Raise the floor only after the full mount verified (pre-commitment b).
    write_ref_snapshot_floor_chirho(
        replica_root_chirho,
        &RefSnapshotFloorChirho {
            schema_chirho: REF_SNAPSHOT_FLOOR_SCHEMA_CHIRHO.to_string(),
            seq_chirho: newest_chirho.seq_chirho,
            snapshot_hash_chirho: newest_chirho.snapshot_hash_chirho.clone(),
        },
    )?;
    let report_chirho = RefSnapshotMountReportChirho {
        schema_chirho: REF_SNAPSHOT_MOUNT_REPORT_SCHEMA_CHIRHO.to_string(),
        seq_chirho: newest_chirho.seq_chirho,
        source_time_unix_chirho: newest_chirho.source_time_unix_chirho,
        verified_at_unix_chirho,
        source_key_id_chirho: newest_chirho.key_id_chirho.clone(),
        ref_count_chirho: newest_chirho.ref_count_chirho,
        decision_chirho,
    };
    Ok((view_chirho, report_chirho))
}

/// What a source-side export produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefSnapshotExportChirho {
    pub head_chirho: RefSnapshotHeadRecordChirho,
    /// `false` ⇒ the refs were unchanged since the last export; no new seq was minted and no row
    /// was appended (idempotent re-export).
    pub appended_chirho: bool,
}

/// SOURCE-side export (writer region only — this is the sole place the snapshot plane signs):
/// select the app/app-route refs from the source root, store the stone in the source's own CAS,
/// and append one signed head row — signed via the SAME sign-root as the Gate 1 anchor head. An
/// export with unchanged refs returns the existing head and appends nothing, so retried export
/// tooling never mints seq churn or duplicate rows.
pub fn export_ref_snapshot_chirho(
    source_root_chirho: &Path,
    source_time_unix_chirho: u64,
) -> Result<RefSnapshotExportChirho> {
    let refs_chirho = load_refs_chirho(source_root_chirho)?;
    let selected_chirho: BTreeMap<String, HashChirho> = refs_chirho
        .branches_chirho
        .iter()
        .filter(|(name_chirho, _)| is_snapshot_ref_name_chirho(name_chirho))
        .map(|(name_chirho, hash_chirho)| (name_chirho.clone(), hash_chirho.clone()))
        .collect();
    let source_pubkey_chirho = pubkey_hex_chirho(source_root_chirho)?;
    let log_path_chirho = source_root_chirho.join(REF_SNAPSHOT_LOG_FILE_CHIRHO);
    let existing_bytes_chirho = if log_path_chirho.exists() {
        std::fs::read(&log_path_chirho)
            .with_context(|| format!("read {}", log_path_chirho.display()))?
    } else {
        Vec::new()
    };
    // The source verifies its own log before extending it — a corrupt or foreign row surfaces at
    // export, not at the replica.
    let existing_heads_chirho =
        read_verified_snapshot_heads_chirho(&existing_bytes_chirho, &source_pubkey_chirho)?;
    let next_seq_chirho = existing_heads_chirho
        .last()
        .map(|head_chirho| head_chirho.seq_chirho + 1)
        .unwrap_or(1);
    let snapshot_chirho =
        RefSnapshotChirho::new_chirho(selected_chirho, next_seq_chirho, source_time_unix_chirho)?;
    let refs_digest_chirho = snapshot_chirho.refs_digest_chirho()?;
    if let Some(last_chirho) = existing_heads_chirho.last() {
        if last_chirho.refs_digest_chirho == refs_digest_chirho {
            return Ok(RefSnapshotExportChirho {
                head_chirho: last_chirho.clone(),
                appended_chirho: false,
            });
        }
    }
    let store_chirho = FsContentStoreChirho::new_chirho(source_root_chirho);
    let stone_bytes_chirho = snapshot_chirho.canonical_bytes_chirho()?;
    let snapshot_hash_chirho = store_chirho
        .put_chirho(&stone_bytes_chirho)
        .map_err(|error_chirho| anyhow!("store ref snapshot stone: {error_chirho}"))?;
    let mut head_chirho = RefSnapshotHeadRecordChirho {
        schema_chirho: REF_SNAPSHOT_HEAD_SCHEMA_CHIRHO.to_string(),
        seq_chirho: next_seq_chirho,
        source_time_unix_chirho,
        snapshot_hash_chirho,
        refs_digest_chirho,
        ref_count_chirho: snapshot_chirho.refs_chirho.len() as u64,
        key_id_chirho: source_pubkey_chirho,
        sig_chirho: String::new(),
    };
    let message_chirho = unsigned_ref_snapshot_head_message_chirho(&head_chirho)?;
    head_chirho.sig_chirho = sign_message_chirho(source_root_chirho, &message_chirho)?;
    validate_ref_snapshot_head_chirho(&head_chirho)?;
    let mut line_chirho =
        serde_json::to_vec(&head_chirho).context("serialize ref snapshot head")?;
    line_chirho.push(b'\n');
    append_durable_line_chirho(&log_path_chirho, &line_chirho)
        .context("append ref snapshot head row")?;
    Ok(RefSnapshotExportChirho {
        head_chirho,
        appended_chirho: true,
    })
}
