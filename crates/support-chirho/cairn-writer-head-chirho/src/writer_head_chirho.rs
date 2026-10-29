// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Local consistency-group writer fence tokens.

use anyhow::{bail, Context, Result};
use cairn_core_chirho::model_chirho::consistency_group_storage_hash_chirho;
pub use cairn_core_chirho::model_chirho::{
    consistency_group_digest_chirho, tagged_writer_fence_group_digest_chirho,
    ConsistencyGroupIdChirho, TaggedWriterFenceGroupDigestChirho,
};
use cairn_durable_chirho::log_path_chirho::open_log_no_follow_chirho;
use cairn_durable_chirho::write_file_durable_chirho;
use cairn_seqlog_chirho::seqlog_chirho;
use cairn_tenant_chirho::tenant_chirho::{self, TenantIdChirho};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{Error as IoErrorChirho, ErrorKind, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const WRITER_FENCES_DIR_CHIRHO: &str = "writer-fences-chirho";
pub const WRITER_FENCE_SCHEMA_CHIRHO: &str = "writer-fence-v1-chirho";
pub const WRITER_FENCE_LOCK_CHIRHO: &str = "writer-fence-chirho";
pub const WRITER_EPOCH_COMPONENT_BITS_CHIRHO: u32 = 32;
pub const WRITER_EPOCH_COMPONENT_MAX_CHIRHO: u64 = u32::MAX as u64;
pub const MAX_WRITER_FENCE_FILE_BYTES_CHIRHO: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompositeWriterEpochChirho {
    pub geo_term_chirho: u32,
    pub local_grant_seq_chirho: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompositeWriterEpochRefusalChirho {
    ComponentOutOfRangeChirho,
    ZeroElectedTermChirho,
    DeposedGeoTermChirho,
    LocalGrantSequenceExhaustedChirho,
    GeoAuthorityAlreadyActiveChirho,
}

impl fmt::Display for CompositeWriterEpochRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(match self {
            Self::ComponentOutOfRangeChirho => "CompositeWriterEpochComponentOutOfRangeChirho",
            Self::ZeroElectedTermChirho => "ZeroElectedWriterTermChirho",
            Self::DeposedGeoTermChirho => "DeposedWriterGeoTermChirho",
            Self::LocalGrantSequenceExhaustedChirho => "LocalWriterGrantSequenceExhaustedChirho",
            Self::GeoAuthorityAlreadyActiveChirho => "GeoWriterAuthorityAlreadyActiveChirho",
        })
    }
}

impl std::error::Error for CompositeWriterEpochRefusalChirho {}

pub fn compose_writer_epoch_chirho(
    geo_term_chirho: u64,
    local_grant_seq_chirho: u64,
) -> std::result::Result<u64, CompositeWriterEpochRefusalChirho> {
    if geo_term_chirho > WRITER_EPOCH_COMPONENT_MAX_CHIRHO
        || local_grant_seq_chirho > WRITER_EPOCH_COMPONENT_MAX_CHIRHO
    {
        return Err(CompositeWriterEpochRefusalChirho::ComponentOutOfRangeChirho);
    }
    Ok((geo_term_chirho << WRITER_EPOCH_COMPONENT_BITS_CHIRHO) | local_grant_seq_chirho)
}

pub fn split_writer_epoch_chirho(epoch_chirho: u64) -> CompositeWriterEpochChirho {
    CompositeWriterEpochChirho {
        geo_term_chirho: (epoch_chirho >> WRITER_EPOCH_COMPONENT_BITS_CHIRHO) as u32,
        local_grant_seq_chirho: epoch_chirho as u32,
    }
}

fn is_geo_term_latched_chirho(geo_term_chirho: u64) -> bool {
    geo_term_chirho != 0
}

pub fn with_head_commit_chirho<T, F>(root_chirho: &Path, action_chirho: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    seqlog_chirho::with_append_log_lock_chirho(root_chirho, action_chirho)
}

/// Issue a writer fence, then hold the append lock while running a Gate 1 authority writer.
///
/// The nesting is writer-fence OUTER -> append-log INNER. It is the same lock order used by
/// `ledger_chirho::with_ledger_authority_lock_chirho`; that wrapper should delegate here in a small
/// cleanup once the remaining Ring-A families have migrated.
pub fn with_gate1_authority_scope_chirho<T, F>(root_chirho: &Path, action_chirho: F) -> Result<T>
where
    F: FnOnce(&WriterFenceTokenChirho) -> Result<T>,
{
    with_head_transition_scope_chirho(root_chirho, action_chirho)
}

/// Issue a current writer fence and hold the append lock for one local head transition.
pub fn with_head_transition_scope_chirho<T, F>(root_chirho: &Path, action_chirho: F) -> Result<T>
where
    F: FnOnce(&WriterFenceTokenChirho) -> Result<T>,
{
    with_issued_writer_fence_for_root_chirho(root_chirho, |token_chirho| {
        seqlog_chirho::with_append_log_lock_chirho(root_chirho, || action_chirho(token_chirho))
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriterFenceTokenChirho {
    pub group_chirho: ConsistencyGroupIdChirho,
    pub epoch_chirho: u64,
    pub issued_at_ms_chirho: u64,
}

/// Non-authoritative PREPARE evidence that one persisted elected fence epoch existed for one root.
///
/// This value is a monotonic lower bound, not held authority. Its fields and sole mint stay in this
/// module so a caller cannot manufacture a cross-root or cross-group observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedFenceLowerBoundChirho {
    group_chirho: ConsistencyGroupIdChirho,
    epoch_chirho: u64,
    canonical_root_chirho: PathBuf,
    root_device_chirho: u64,
    root_inode_chirho: u64,
}

impl PreparedFenceLowerBoundChirho {
    pub fn group_chirho(&self) -> &ConsistencyGroupIdChirho {
        &self.group_chirho
    }

    pub fn epoch_chirho(&self) -> u64 {
        self.epoch_chirho
    }

    pub fn canonical_root_chirho(&self) -> &Path {
        &self.canonical_root_chirho
    }

    pub fn root_identity_matches_chirho(&self, root_chirho: &Path) -> Result<bool> {
        let canonical_root_chirho = root_chirho.canonicalize().with_context(|| {
            format!("canonicalize prepared-fence root {}", root_chirho.display())
        })?;
        let metadata_chirho = std::fs::metadata(&canonical_root_chirho).with_context(|| {
            format!(
                "read prepared-fence root identity {}",
                canonical_root_chirho.display()
            )
        })?;
        Ok(canonical_root_chirho == self.canonical_root_chirho
            && metadata_chirho.dev() == self.root_device_chirho
            && metadata_chirho.ino() == self.root_inode_chirho)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriterAuthorityEraChirho {
    LocalChirho,
    ElectedChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparedFenceObservationRefusalChirho {
    WrongGroupChirho,
    UnavailableChirho,
    NotElectedChirho,
    RootReboundChirho,
}

impl fmt::Display for PreparedFenceObservationRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(match self {
            Self::WrongGroupChirho => "PreparedFenceWrongGroupChirho",
            Self::UnavailableChirho => "PreparedFenceUnavailableChirho",
            Self::NotElectedChirho => "PreparedFenceNotElectedChirho",
            Self::RootReboundChirho => "PreparedFenceRootReboundChirho",
        })
    }
}

impl std::error::Error for PreparedFenceObservationRefusalChirho {}

/// Pure preparation result for a descriptor-owned elected fence scope.
///
/// The caller must hold the exact writer-fence lock while reading the input bytes, installing any
/// returned replacement bytes, and performing its final local mutation. This type carries no I/O,
/// callback, journal, or election authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedElectedWriterFenceChirho {
    token_chirho: WriterFenceTokenChirho,
    durable_state_epoch_before_chirho: Option<u64>,
    replacement_state_bytes_chirho: Option<Vec<u8>>,
}

impl PreparedElectedWriterFenceChirho {
    pub fn token_chirho(&self) -> &WriterFenceTokenChirho {
        &self.token_chirho
    }

    pub fn replacement_state_bytes_chirho(&self) -> Option<&[u8]> {
        self.replacement_state_bytes_chirho.as_deref()
    }

    pub fn durable_state_epoch_before_chirho(&self) -> Option<u64> {
        self.durable_state_epoch_before_chirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct WriterFenceStateChirho {
    schema_chirho: String,
    group_chirho: ConsistencyGroupIdChirho,
    epoch_chirho: u64,
    issued_at_ms_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriterFenceVerifyErrorChirho {
    NoFenceIssuedChirho,
    GroupMismatchChirho,
    StaleWriterFenceChirho,
    ForgedEpochChirho,
    CorruptFenceFileChirho,
}

impl fmt::Display for WriterFenceVerifyErrorChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label_chirho = match self {
            Self::NoFenceIssuedChirho => "NoFenceIssuedChirho",
            Self::GroupMismatchChirho => "GroupMismatchChirho",
            Self::StaleWriterFenceChirho => "StaleWriterFenceChirho",
            Self::ForgedEpochChirho => "ForgedEpochChirho",
            Self::CorruptFenceFileChirho => "CorruptFenceFileChirho",
        };
        formatter_chirho.write_str(label_chirho)
    }
}

impl std::error::Error for WriterFenceVerifyErrorChirho {}

pub fn consistency_group_for_root_chirho(root_chirho: &Path) -> Result<ConsistencyGroupIdChirho> {
    match tenant_chirho::tenant_id_for_root_chirho(root_chirho)? {
        TenantIdChirho::TenantChirho(tenant_id_chirho) => {
            Ok(ConsistencyGroupIdChirho::TenantChirho { tenant_id_chirho })
        }
        TenantIdChirho::PlatformRootChirho => Ok(ConsistencyGroupIdChirho::RootPathChirho {
            canonical_root_chirho: canonical_root_path_chirho(root_chirho)?,
        }),
    }
}

/// Classify the persisted one-way writer-authority era without minting authority.
pub fn writer_authority_era_chirho(root_chirho: &Path) -> Result<WriterAuthorityEraChirho> {
    let group_chirho = consistency_group_for_root_chirho(root_chirho)?;
    let Some(state_chirho) = read_writer_fence_state_chirho(root_chirho, &group_chirho)? else {
        return Ok(WriterAuthorityEraChirho::LocalChirho);
    };
    if !is_geo_term_latched_chirho(u64::from(
        split_writer_epoch_chirho(state_chirho.epoch_chirho).geo_term_chirho,
    )) {
        Ok(WriterAuthorityEraChirho::LocalChirho)
    } else {
        Ok(WriterAuthorityEraChirho::ElectedChirho)
    }
}

/// Observe the persisted elected epoch as PREPARE-only lower-bound evidence.
///
/// This bounded read takes no writer-fence lock and grants no mutation authority. A root identity
/// change across the read refuses rather than binding evidence to a pathname that moved.
pub fn observe_prepared_fence_lower_bound_chirho(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
) -> Result<PreparedFenceLowerBoundChirho> {
    let actual_group_chirho = consistency_group_for_root_chirho(root_chirho)?;
    if actual_group_chirho != *group_chirho {
        return Err(PreparedFenceObservationRefusalChirho::WrongGroupChirho.into());
    }
    let canonical_root_chirho = root_chirho
        .canonicalize()
        .with_context(|| format!("canonicalize prepared-fence root {}", root_chirho.display()))?;
    let before_chirho = std::fs::metadata(&canonical_root_chirho).with_context(|| {
        format!(
            "read prepared-fence root identity {}",
            canonical_root_chirho.display()
        )
    })?;
    let state_chirho = read_writer_fence_state_chirho(root_chirho, group_chirho)?
        .ok_or(PreparedFenceObservationRefusalChirho::UnavailableChirho)?;
    if !is_geo_term_latched_chirho(u64::from(
        split_writer_epoch_chirho(state_chirho.epoch_chirho).geo_term_chirho,
    )) {
        return Err(PreparedFenceObservationRefusalChirho::NotElectedChirho.into());
    }
    let canonical_after_chirho = root_chirho.canonicalize().with_context(|| {
        format!(
            "re-canonicalize prepared-fence root {}",
            root_chirho.display()
        )
    })?;
    let after_chirho = std::fs::metadata(&canonical_after_chirho).with_context(|| {
        format!(
            "re-read prepared-fence root identity {}",
            canonical_after_chirho.display()
        )
    })?;
    if canonical_after_chirho != canonical_root_chirho
        || before_chirho.dev() != after_chirho.dev()
        || before_chirho.ino() != after_chirho.ino()
    {
        return Err(PreparedFenceObservationRefusalChirho::RootReboundChirho.into());
    }
    Ok(PreparedFenceLowerBoundChirho {
        group_chirho: group_chirho.clone(),
        epoch_chirho: state_chirho.epoch_chirho,
        canonical_root_chirho,
        root_device_chirho: before_chirho.dev(),
        root_inode_chirho: before_chirho.ino(),
    })
}

pub fn issue_writer_fence_for_root_chirho(root_chirho: &Path) -> Result<WriterFenceTokenChirho> {
    std::fs::create_dir_all(root_chirho)
        .with_context(|| format!("create writer fence root {}", root_chirho.display()))?;
    let group_chirho = consistency_group_for_root_chirho(root_chirho)?;
    issue_writer_fence_chirho(root_chirho, &group_chirho)
}

/// Issue a fresh writer fence and run `action_chirho` while the fence lock is still held.
///
/// G1.3 ledger dual-write uses this as the local single-writer serializer: the fence named lock is
/// acquired first, a monotonic fence token is persisted, and the caller may then take the append
/// lock inside `action_chirho`. This intentionally serializes ledger writers until the authority
/// envelope has been appended and its head advanced.
pub fn with_issued_writer_fence_for_root_chirho<T, F>(
    root_chirho: &Path,
    action_chirho: F,
) -> Result<T>
where
    F: FnOnce(&WriterFenceTokenChirho) -> Result<T>,
{
    std::fs::create_dir_all(root_chirho)
        .with_context(|| format!("create writer fence root {}", root_chirho.display()))?;
    let group_chirho = consistency_group_for_root_chirho(root_chirho)?;
    with_issued_writer_fence_chirho(root_chirho, &group_chirho, action_chirho)
}

pub fn issue_writer_fence_chirho(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
) -> Result<WriterFenceTokenChirho> {
    seqlog_chirho::with_named_lock_chirho(root_chirho, WRITER_FENCE_LOCK_CHIRHO, || {
        issue_writer_fence_unlocked_chirho(root_chirho, group_chirho)
    })
}

/// Issue the next composite `(geo_term, local_grant_seq)` fence for one elected consistency
/// group. The caller supplies only the term it currently holds; the low component is derived from
/// the durable per-group state while the existing writer-fence lock is held. A lower term, a zero
/// elected term, or low-half exhaustion refuses without changing the durable state.
/// See `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-a6-money-election-design-chirho.md`
/// sections 1 and 5. This primitive does not decide who holds the term; the A6 bridge must supply an
/// authenticated, lease-valid election result and the final sink still verifies the exact epoch.
pub fn issue_elected_writer_fence_for_root_chirho(
    root_chirho: &Path,
    geo_term_chirho: u64,
) -> Result<WriterFenceTokenChirho> {
    std::fs::create_dir_all(root_chirho)
        .with_context(|| format!("create writer fence root {}", root_chirho.display()))?;
    let group_chirho = consistency_group_for_root_chirho(root_chirho)?;
    issue_elected_writer_fence_chirho(root_chirho, &group_chirho, geo_term_chirho)
}

pub fn issue_elected_writer_fence_chirho(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
    geo_term_chirho: u64,
) -> Result<WriterFenceTokenChirho> {
    seqlog_chirho::with_named_lock_chirho(root_chirho, WRITER_FENCE_LOCK_CHIRHO, || {
        issue_elected_writer_fence_unlocked_chirho(root_chirho, group_chirho, geo_term_chirho)
    })
}

/// Reuse a still-current elected grant, or durably issue its replacement, while holding the
/// per-group writer-fence lock around one final local mutation.
///
/// A resident journal actor passes its cached grant on every append. The steady-state path verifies
/// one bounded per-group fence file and performs no fence write; a term change or process restart
/// issues exactly one replacement. A stale cached grant refuses so overlapping residents cannot
/// silently fence each other in the same term. `action_chirho` must contain only the local final-sink
/// mutation. In particular, callers release this lock before any outbound provider effect.
///
/// See `spec-chirho/workflows-chirho/distributed-ha-chirho/p5-cutover-and-lease-design-chirho.md`
/// section 4.
pub fn with_reused_or_issued_elected_writer_fence_chirho<T, F>(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
    geo_term_chirho: u64,
    current_token_chirho: Option<&WriterFenceTokenChirho>,
    action_chirho: F,
) -> Result<(WriterFenceTokenChirho, T)>
where
    F: FnOnce(&WriterFenceTokenChirho) -> Result<T>,
{
    if !is_geo_term_latched_chirho(geo_term_chirho) {
        return Err(CompositeWriterEpochRefusalChirho::ZeroElectedTermChirho.into());
    }
    compose_writer_epoch_chirho(geo_term_chirho, 0)?;
    seqlog_chirho::with_named_lock_chirho(root_chirho, WRITER_FENCE_LOCK_CHIRHO, || {
        let reusable_chirho = match current_token_chirho {
            Some(token_chirho) if token_chirho.group_chirho != *group_chirho => {
                return Err(WriterFenceVerifyErrorChirho::GroupMismatchChirho.into())
            }
            Some(token_chirho) if token_chirho.epoch_chirho == 0 => {
                return Err(WriterFenceVerifyErrorChirho::ForgedEpochChirho.into())
            }
            Some(token_chirho)
                if u64::from(
                    split_writer_epoch_chirho(token_chirho.epoch_chirho).geo_term_chirho,
                ) == geo_term_chirho =>
            {
                match verify_writer_fence_chirho(root_chirho, group_chirho, token_chirho) {
                    Ok(()) => Some(token_chirho.clone()),
                    Err(WriterFenceVerifyErrorChirho::StaleWriterFenceChirho) => {
                        return Err(WriterFenceVerifyErrorChirho::StaleWriterFenceChirho.into())
                    }
                    Err(error_chirho) => return Err(error_chirho.into()),
                }
            }
            Some(_) | None => None,
        };
        let token_chirho = match reusable_chirho {
            Some(token_chirho) => token_chirho,
            None => issue_elected_writer_fence_unlocked_chirho(
                root_chirho,
                group_chirho,
                geo_term_chirho,
            )?,
        };
        let result_chirho = action_chirho(&token_chirho)?;
        Ok((token_chirho, result_chirho))
    })
}

pub fn with_issued_writer_fence_chirho<T, F>(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
    action_chirho: F,
) -> Result<T>
where
    F: FnOnce(&WriterFenceTokenChirho) -> Result<T>,
{
    seqlog_chirho::with_named_lock_chirho(root_chirho, WRITER_FENCE_LOCK_CHIRHO, || {
        let token_chirho = issue_writer_fence_unlocked_chirho(root_chirho, group_chirho)?;
        action_chirho(&token_chirho)
    })
}

pub fn verify_writer_fence_for_root_chirho(
    root_chirho: &Path,
    token_chirho: &WriterFenceTokenChirho,
) -> std::result::Result<(), WriterFenceVerifyErrorChirho> {
    if !root_chirho.exists() {
        return Err(WriterFenceVerifyErrorChirho::NoFenceIssuedChirho);
    }
    let group_chirho = consistency_group_for_root_chirho(root_chirho)
        .map_err(|_| WriterFenceVerifyErrorChirho::CorruptFenceFileChirho)?;
    verify_writer_fence_chirho(root_chirho, &group_chirho, token_chirho)
}

pub fn verify_writer_fence_chirho(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
    token_chirho: &WriterFenceTokenChirho,
) -> std::result::Result<(), WriterFenceVerifyErrorChirho> {
    if token_chirho.epoch_chirho == 0 {
        return Err(WriterFenceVerifyErrorChirho::ForgedEpochChirho);
    }
    if &token_chirho.group_chirho != group_chirho {
        return Err(WriterFenceVerifyErrorChirho::GroupMismatchChirho);
    }
    let Some(state_chirho) = read_writer_fence_state_for_verify_chirho(root_chirho, group_chirho)?
    else {
        return Err(WriterFenceVerifyErrorChirho::NoFenceIssuedChirho);
    };
    if state_chirho.schema_chirho != WRITER_FENCE_SCHEMA_CHIRHO
        || state_chirho.group_chirho != *group_chirho
        || state_chirho.epoch_chirho == 0
    {
        return Err(WriterFenceVerifyErrorChirho::CorruptFenceFileChirho);
    }
    if token_chirho.epoch_chirho > state_chirho.epoch_chirho {
        return Err(WriterFenceVerifyErrorChirho::ForgedEpochChirho);
    }
    if token_chirho.epoch_chirho < state_chirho.epoch_chirho {
        return Err(WriterFenceVerifyErrorChirho::StaleWriterFenceChirho);
    }
    Ok(())
}

pub fn writer_fence_path_chirho(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
) -> Result<PathBuf> {
    Ok(root_chirho.join(writer_fence_storage_key_chirho(group_chirho)?))
}

/// The fixed logical storage key shared by pathname and descriptor-owned fence implementations.
pub fn writer_fence_storage_key_chirho(group_chirho: &ConsistencyGroupIdChirho) -> Result<String> {
    Ok(format!(
        "{WRITER_FENCES_DIR_CHIRHO}/{}.json",
        consistency_group_storage_hash_chirho(group_chirho)?
    ))
}

/// Resolve one elected fence decision without performing I/O or running caller work.
///
/// `durable_state_bytes_chirho` must be the bounded state read while the exact fence lock is held.
/// A cached exact-current token is reused without replacement bytes. A clean restart or newer term
/// returns one complete replacement state. A stale/forged/deposed token fails closed.
pub fn prepare_reused_or_issued_elected_writer_fence_chirho(
    group_chirho: &ConsistencyGroupIdChirho,
    geo_term_chirho: u64,
    current_token_chirho: Option<&WriterFenceTokenChirho>,
    durable_state_bytes_chirho: Option<&[u8]>,
    issued_at_ms_chirho: u64,
) -> Result<PreparedElectedWriterFenceChirho> {
    if !is_geo_term_latched_chirho(geo_term_chirho) {
        return Err(CompositeWriterEpochRefusalChirho::ZeroElectedTermChirho.into());
    }
    compose_writer_epoch_chirho(geo_term_chirho, 0)?;
    let durable_state_chirho = durable_state_bytes_chirho
        .map(|bytes_chirho| decode_writer_fence_state_bytes_chirho(bytes_chirho, group_chirho))
        .transpose()?;

    let reusable_chirho = match current_token_chirho {
        Some(token_chirho) if token_chirho.group_chirho != *group_chirho => {
            return Err(WriterFenceVerifyErrorChirho::GroupMismatchChirho.into())
        }
        Some(token_chirho) if token_chirho.epoch_chirho == 0 => {
            return Err(WriterFenceVerifyErrorChirho::ForgedEpochChirho.into())
        }
        Some(token_chirho)
            if u64::from(split_writer_epoch_chirho(token_chirho.epoch_chirho).geo_term_chirho)
                == geo_term_chirho =>
        {
            verify_writer_fence_state_chirho(
                durable_state_chirho.as_ref(),
                group_chirho,
                token_chirho,
            )?;
            Some(token_chirho.clone())
        }
        Some(_) | None => None,
    };

    if let Some(token_chirho) = reusable_chirho {
        return Ok(PreparedElectedWriterFenceChirho {
            token_chirho,
            durable_state_epoch_before_chirho: durable_state_chirho
                .as_ref()
                .map(|state_chirho| state_chirho.epoch_chirho),
            replacement_state_bytes_chirho: None,
        });
    }

    let (state_chirho, token_chirho) = next_elected_writer_fence_state_chirho(
        durable_state_chirho.as_ref(),
        group_chirho,
        geo_term_chirho,
        issued_at_ms_chirho,
    )?;
    let replacement_state_bytes_chirho = serde_json::to_vec_pretty(&state_chirho)?;
    if replacement_state_bytes_chirho.len() > MAX_WRITER_FENCE_FILE_BYTES_CHIRHO {
        bail!("CorruptFenceFileChirho: encoded writer fence exceeds the bounded file size");
    }
    Ok(PreparedElectedWriterFenceChirho {
        token_chirho,
        durable_state_epoch_before_chirho: durable_state_chirho
            .as_ref()
            .map(|state_chirho| state_chirho.epoch_chirho),
        replacement_state_bytes_chirho: Some(replacement_state_bytes_chirho),
    })
}

fn writer_fences_dir_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(WRITER_FENCES_DIR_CHIRHO)
}

/// Read the group's fence state. Only a genuine absence, of the fence or of a directory above it, is no
/// fence; a link at the fence path or at the fence directory, a non-regular entry, a denied or non-directory
/// parent, and every other error refuse, so an unexaminable fence never reads as the Local era (C2.1 brick
/// 1b-0; agy #29613, gpt #29614, gpt #29681).
fn read_writer_fence_state_chirho(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
) -> Result<Option<WriterFenceStateChirho>> {
    let path_chirho = writer_fence_path_chirho(root_chirho, group_chirho)?;
    let Some(bytes_chirho) = read_bounded_fence_file_chirho(&path_chirho)
        .with_context(|| format!("read bounded fence {}", path_chirho.display()))?
    else {
        return Ok(None);
    };
    let state_chirho: WriterFenceStateChirho = serde_json::from_slice(&bytes_chirho)
        .with_context(|| format!("CorruptFenceFileChirho: decode {}", path_chirho.display()))?;
    if state_chirho.schema_chirho != WRITER_FENCE_SCHEMA_CHIRHO
        || state_chirho.group_chirho != *group_chirho
        || state_chirho.epoch_chirho == 0
    {
        bail!("CorruptFenceFileChirho: invalid writer fence state");
    }
    Ok(Some(state_chirho))
}

fn read_writer_fence_state_for_verify_chirho(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
) -> std::result::Result<Option<WriterFenceStateChirho>, WriterFenceVerifyErrorChirho> {
    let path_chirho = writer_fence_path_chirho(root_chirho, group_chirho)
        .map_err(|_| WriterFenceVerifyErrorChirho::CorruptFenceFileChirho)?;
    // Only a genuine absence is "no fence issued"; anything unexaminable is a corrupt fence (agy #29619).
    let Some(bytes_chirho) = read_bounded_fence_file_chirho(&path_chirho)
        .map_err(|_| WriterFenceVerifyErrorChirho::CorruptFenceFileChirho)?
    else {
        return Ok(None);
    };
    let state_chirho: WriterFenceStateChirho = serde_json::from_slice(&bytes_chirho)
        .map_err(|_| WriterFenceVerifyErrorChirho::CorruptFenceFileChirho)?;
    Ok(Some(state_chirho))
}

fn decode_writer_fence_state_bytes_chirho(
    bytes_chirho: &[u8],
    group_chirho: &ConsistencyGroupIdChirho,
) -> std::result::Result<WriterFenceStateChirho, WriterFenceVerifyErrorChirho> {
    if bytes_chirho.len() > MAX_WRITER_FENCE_FILE_BYTES_CHIRHO {
        return Err(WriterFenceVerifyErrorChirho::CorruptFenceFileChirho);
    }
    let state_chirho: WriterFenceStateChirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_| WriterFenceVerifyErrorChirho::CorruptFenceFileChirho)?;
    if state_chirho.schema_chirho != WRITER_FENCE_SCHEMA_CHIRHO
        || state_chirho.group_chirho != *group_chirho
        || state_chirho.epoch_chirho == 0
    {
        return Err(WriterFenceVerifyErrorChirho::CorruptFenceFileChirho);
    }
    Ok(state_chirho)
}

fn verify_writer_fence_state_chirho(
    state_chirho: Option<&WriterFenceStateChirho>,
    group_chirho: &ConsistencyGroupIdChirho,
    token_chirho: &WriterFenceTokenChirho,
) -> std::result::Result<(), WriterFenceVerifyErrorChirho> {
    if token_chirho.epoch_chirho == 0 {
        return Err(WriterFenceVerifyErrorChirho::ForgedEpochChirho);
    }
    if &token_chirho.group_chirho != group_chirho {
        return Err(WriterFenceVerifyErrorChirho::GroupMismatchChirho);
    }
    let Some(state_chirho) = state_chirho else {
        return Err(WriterFenceVerifyErrorChirho::NoFenceIssuedChirho);
    };
    if state_chirho.schema_chirho != WRITER_FENCE_SCHEMA_CHIRHO
        || state_chirho.group_chirho != *group_chirho
        || state_chirho.epoch_chirho == 0
    {
        return Err(WriterFenceVerifyErrorChirho::CorruptFenceFileChirho);
    }
    if token_chirho.epoch_chirho > state_chirho.epoch_chirho {
        return Err(WriterFenceVerifyErrorChirho::ForgedEpochChirho);
    }
    if token_chirho.epoch_chirho < state_chirho.epoch_chirho {
        return Err(WriterFenceVerifyErrorChirho::StaleWriterFenceChirho);
    }
    Ok(())
}

fn write_writer_fence_state_chirho(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
    state_chirho: &WriterFenceStateChirho,
) -> Result<()> {
    std::fs::create_dir_all(writer_fences_dir_chirho(root_chirho))
        .with_context(|| format!("create {}", writer_fences_dir_chirho(root_chirho).display()))?;
    let bytes_chirho = serde_json::to_vec_pretty(state_chirho)?;
    if bytes_chirho.len() > MAX_WRITER_FENCE_FILE_BYTES_CHIRHO {
        bail!("CorruptFenceFileChirho: encoded writer fence exceeds the bounded file size");
    }
    write_file_durable_chirho(
        &writer_fence_path_chirho(root_chirho, group_chirho)?,
        &bytes_chirho,
    )
    .context("write writer fence state")
}

/// Open the fence without following a link, never waiting on a pipe, and read it bounded. `None` only for a
/// genuine absence of the fence or of its directory; the opened handle itself must be a regular file
/// (`open_log_no_follow_chirho`). The fence directory must be a real directory: a link there, live or
/// dangling, is redirected, never absent (gpt #29681). The probe and the open are two steps, so a directory
/// swapped between them is followed; swapping it needs write authority over the root, which can already
/// delete the fence.
fn read_bounded_fence_file_chirho(path_chirho: &Path) -> std::io::Result<Option<Vec<u8>>> {
    if let Some(dir_chirho) = path_chirho.parent() {
        match std::fs::symlink_metadata(dir_chirho) {
            Ok(metadata_chirho) if metadata_chirho.file_type().is_dir() => {}
            Ok(metadata_chirho) => {
                return Err(IoErrorChirho::new(
                    ErrorKind::InvalidData,
                    if metadata_chirho.file_type().is_symlink() {
                        "writer fence directory is a link"
                    } else {
                        "writer fence directory is not a directory"
                    },
                ));
            }
            Err(error_chirho) if error_chirho.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error_chirho) => return Err(error_chirho),
        }
    }
    let Some(mut file_chirho) = open_log_no_follow_chirho(path_chirho)? else {
        return Ok(None);
    };
    let mut bytes_chirho = Vec::with_capacity(MAX_WRITER_FENCE_FILE_BYTES_CHIRHO.min(4096));
    file_chirho
        .by_ref()
        .take((MAX_WRITER_FENCE_FILE_BYTES_CHIRHO + 1) as u64)
        .read_to_end(&mut bytes_chirho)?;
    if bytes_chirho.len() > MAX_WRITER_FENCE_FILE_BYTES_CHIRHO {
        return Err(IoErrorChirho::new(
            ErrorKind::InvalidData,
            "writer fence exceeds bounded file size",
        ));
    }
    Ok(Some(bytes_chirho))
}

fn issue_writer_fence_unlocked_chirho(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
) -> Result<WriterFenceTokenChirho> {
    let state_chirho = read_writer_fence_state_chirho(root_chirho, group_chirho)?;
    let current_epoch_chirho = state_chirho
        .as_ref()
        .map(|state_chirho| state_chirho.epoch_chirho)
        .unwrap_or(0);
    let current_parts_chirho = split_writer_epoch_chirho(current_epoch_chirho);
    if is_geo_term_latched_chirho(u64::from(current_parts_chirho.geo_term_chirho)) {
        return Err(CompositeWriterEpochRefusalChirho::GeoAuthorityAlreadyActiveChirho.into());
    }
    let next_local_grant_seq_chirho = current_parts_chirho
        .local_grant_seq_chirho
        .checked_add(1)
        .ok_or(CompositeWriterEpochRefusalChirho::LocalGrantSequenceExhaustedChirho)?;
    let next_epoch_chirho = compose_writer_epoch_chirho(0, u64::from(next_local_grant_seq_chirho))?;
    let issued_at_ms_chirho = now_ms_chirho();
    let state_chirho = WriterFenceStateChirho {
        schema_chirho: WRITER_FENCE_SCHEMA_CHIRHO.to_string(),
        group_chirho: group_chirho.clone(),
        epoch_chirho: next_epoch_chirho,
        issued_at_ms_chirho,
    };
    write_writer_fence_state_chirho(root_chirho, group_chirho, &state_chirho)?;
    Ok(WriterFenceTokenChirho {
        group_chirho: group_chirho.clone(),
        epoch_chirho: next_epoch_chirho,
        issued_at_ms_chirho,
    })
}

fn issue_elected_writer_fence_unlocked_chirho(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
    geo_term_chirho: u64,
) -> Result<WriterFenceTokenChirho> {
    let current_state_chirho = read_writer_fence_state_chirho(root_chirho, group_chirho)?;
    let (state_chirho, token_chirho) = next_elected_writer_fence_state_chirho(
        current_state_chirho.as_ref(),
        group_chirho,
        geo_term_chirho,
        now_ms_chirho(),
    )?;
    write_writer_fence_state_chirho(root_chirho, group_chirho, &state_chirho)?;
    Ok(token_chirho)
}

fn next_elected_writer_fence_state_chirho(
    current_state_chirho: Option<&WriterFenceStateChirho>,
    group_chirho: &ConsistencyGroupIdChirho,
    geo_term_chirho: u64,
    issued_at_ms_chirho: u64,
) -> Result<(WriterFenceStateChirho, WriterFenceTokenChirho)> {
    if !is_geo_term_latched_chirho(geo_term_chirho) {
        return Err(CompositeWriterEpochRefusalChirho::ZeroElectedTermChirho.into());
    }
    compose_writer_epoch_chirho(geo_term_chirho, 0)?;

    let current_epoch_chirho = current_state_chirho
        .map(|state_chirho| state_chirho.epoch_chirho)
        .unwrap_or(0);
    let current_parts_chirho = split_writer_epoch_chirho(current_epoch_chirho);
    let requested_term_chirho = geo_term_chirho as u32;
    if current_parts_chirho.geo_term_chirho > requested_term_chirho {
        return Err(CompositeWriterEpochRefusalChirho::DeposedGeoTermChirho.into());
    }
    let next_local_grant_seq_chirho =
        if current_parts_chirho.geo_term_chirho < requested_term_chirho {
            0
        } else {
            current_parts_chirho
                .local_grant_seq_chirho
                .checked_add(1)
                .ok_or(CompositeWriterEpochRefusalChirho::LocalGrantSequenceExhaustedChirho)?
        };
    let next_epoch_chirho =
        compose_writer_epoch_chirho(geo_term_chirho, u64::from(next_local_grant_seq_chirho))?;
    if next_epoch_chirho <= current_epoch_chirho {
        return Err(CompositeWriterEpochRefusalChirho::DeposedGeoTermChirho.into());
    }

    let state_chirho = WriterFenceStateChirho {
        schema_chirho: WRITER_FENCE_SCHEMA_CHIRHO.to_string(),
        group_chirho: group_chirho.clone(),
        epoch_chirho: next_epoch_chirho,
        issued_at_ms_chirho,
    };
    let token_chirho = WriterFenceTokenChirho {
        group_chirho: group_chirho.clone(),
        epoch_chirho: next_epoch_chirho,
        issued_at_ms_chirho,
    };
    Ok((state_chirho, token_chirho))
}

fn canonical_root_path_chirho(root_chirho: &Path) -> Result<String> {
    Ok(root_chirho
        .canonicalize()
        .with_context(|| format!("canonicalize {}", root_chirho.display()))?
        .display()
        .to_string())
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "writer_head_chirho/elected_scope_tests_chirho.rs"]
mod elected_scope_tests_chirho;

#[cfg(test)]
#[path = "writer_head_chirho/fence_read_tests_chirho.rs"]
mod fence_read_tests_chirho;

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::sync::{Arc, Barrier};

    fn temp_root_chirho(label_chirho: &str) -> PathBuf {
        let root_chirho = std::env::temp_dir().join(format!(
            "cairn-writer-head-{label_chirho}-{}-{}",
            std::process::id(),
            now_ms_chirho()
        ));
        let _ = std::fs::remove_dir_all(&root_chirho);
        root_chirho
    }

    #[test]
    fn first_issue_uses_epoch_one_and_root_path_group_chirho() {
        let root_chirho = temp_root_chirho("first");
        let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
        assert_eq!(token_chirho.epoch_chirho, 1);
        match token_chirho.group_chirho {
            ConsistencyGroupIdChirho::RootPathChirho {
                ref canonical_root_chirho,
            } => assert!(canonical_root_chirho.contains("cairn-writer-head-first")),
            other_chirho => panic!("unexpected group {other_chirho:?}"),
        }
        verify_writer_fence_for_root_chirho(&root_chirho, &token_chirho).unwrap();
        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn tenant_root_uses_tenant_consistency_group_chirho() {
        let platform_root_chirho = temp_root_chirho("tenant");
        let tenant_root_chirho = tenant_chirho::root_for_tenant_chirho(
            &platform_root_chirho,
            &TenantIdChirho::TenantChirho("tenant-a-chirho".to_string()),
        )
        .unwrap();
        let token_chirho = issue_writer_fence_for_root_chirho(&tenant_root_chirho).unwrap();
        assert_eq!(
            token_chirho.group_chirho,
            ConsistencyGroupIdChirho::TenantChirho {
                tenant_id_chirho: "tenant-a-chirho".to_string()
            }
        );
        verify_writer_fence_for_root_chirho(&tenant_root_chirho, &token_chirho).unwrap();
        let _ = std::fs::remove_dir_all(platform_root_chirho);
    }

    #[test]
    fn stale_token_is_rejected_chirho() {
        let root_chirho = temp_root_chirho("stale");
        let old_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
        let current_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
        assert_eq!(current_chirho.epoch_chirho, old_chirho.epoch_chirho + 1);
        assert_eq!(
            verify_writer_fence_for_root_chirho(&root_chirho, &old_chirho).unwrap_err(),
            WriterFenceVerifyErrorChirho::StaleWriterFenceChirho
        );
        verify_writer_fence_for_root_chirho(&root_chirho, &current_chirho).unwrap();
        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn composite_writer_epoch_round_trips_and_bounds_components_chirho() {
        let packed_chirho = compose_writer_epoch_chirho(7, 11).unwrap();
        assert_eq!(
            split_writer_epoch_chirho(packed_chirho),
            CompositeWriterEpochChirho {
                geo_term_chirho: 7,
                local_grant_seq_chirho: 11,
            }
        );
        assert_eq!(
            compose_writer_epoch_chirho(WRITER_EPOCH_COMPONENT_MAX_CHIRHO + 1, 0).unwrap_err(),
            CompositeWriterEpochRefusalChirho::ComponentOutOfRangeChirho
        );
        assert_eq!(
            compose_writer_epoch_chirho(1, WRITER_EPOCH_COMPONENT_MAX_CHIRHO + 1).unwrap_err(),
            CompositeWriterEpochRefusalChirho::ComponentOutOfRangeChirho
        );
    }

    #[test]
    fn elected_writer_fence_jumps_term_then_bumps_only_local_half_chirho() {
        let root_chirho = temp_root_chirho("elected-packing");
        let pre_geo_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
        assert_eq!(pre_geo_chirho.epoch_chirho, 1);

        let first_term_chirho =
            issue_elected_writer_fence_for_root_chirho(&root_chirho, 4).unwrap();
        assert_eq!(
            split_writer_epoch_chirho(first_term_chirho.epoch_chirho),
            CompositeWriterEpochChirho {
                geo_term_chirho: 4,
                local_grant_seq_chirho: 0,
            }
        );
        let local_regrant_chirho =
            issue_elected_writer_fence_for_root_chirho(&root_chirho, 4).unwrap();
        assert_eq!(
            split_writer_epoch_chirho(local_regrant_chirho.epoch_chirho),
            CompositeWriterEpochChirho {
                geo_term_chirho: 4,
                local_grant_seq_chirho: 1,
            }
        );
        let handoff_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 5).unwrap();
        assert_eq!(
            split_writer_epoch_chirho(handoff_chirho.epoch_chirho),
            CompositeWriterEpochChirho {
                geo_term_chirho: 5,
                local_grant_seq_chirho: 0,
            }
        );
        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn deposed_term_and_local_issuer_refuse_after_geo_activation_chirho() {
        let root_chirho = temp_root_chirho("elected-deposed");
        let current_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 9).unwrap();

        let deposed_chirho =
            issue_elected_writer_fence_for_root_chirho(&root_chirho, 8).unwrap_err();
        assert_eq!(
            deposed_chirho.downcast_ref::<CompositeWriterEpochRefusalChirho>(),
            Some(&CompositeWriterEpochRefusalChirho::DeposedGeoTermChirho)
        );
        let local_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap_err();
        assert_eq!(
            local_chirho.downcast_ref::<CompositeWriterEpochRefusalChirho>(),
            Some(&CompositeWriterEpochRefusalChirho::GeoAuthorityAlreadyActiveChirho)
        );
        verify_writer_fence_for_root_chirho(&root_chirho, &current_chirho).unwrap();
        let _ = std::fs::remove_dir_all(root_chirho);
    }

    /// **The dispatcher's era predicate and the local fence's refusal predicate must AGREE.**
    ///
    /// Reviewer-chosen arm (claude_chirho, S1 adversarial review — independent of the mover's pins).
    /// `dispatch_head_transition_chirho` routes to the LOCAL body when `writer_authority_era_chirho`
    /// reports `LocalChirho`, and the local issuer refuses a latched root. Both paths now normalize
    /// their raw or composite geo term through `is_geo_term_latched_chirho`; this arm proves that
    /// the two callers still interpret one persisted root consistently.
    ///
    /// S1's own arms exercise each path ALONE — never-latched runs the local body; elected refuses
    /// by name. **Neither asks both questions about one root.** So if the fence predicate were ever
    /// loosened relative to the era predicate, `dispatch` would send a write down the local path and
    /// the fence would issue for it: a LOCAL write landing on an ELECTED root. That is a
    /// money-authority violation, which is why the end-to-end agreement remains pinned even after
    /// the predicate is centralized.
    ///
    /// MIGRATION PATH, because the two failure directions are not equally serious:
    /// - era reports `ElectedChirho` and the local issuer ISSUES → **stop; authority defect.** The
    ///   local path is reachable on a latched root. Do not "fix" this test.
    /// - era reports `LocalChirho` and the local issuer REFUSES → the era predicate drifted
    ///   permissive. Safe (writes refuse) but wrong; retarget at the drifted predicate.
    #[test]
    fn authority_era_and_local_fence_issuance_agree_on_one_root_chirho() {
        let root_chirho = temp_root_chirho("era-fence-agreement");
        std::fs::create_dir_all(&root_chirho).unwrap();

        // NEVER-LATCHED: era says Local, so the local issuer MUST issue.
        assert_eq!(
            writer_authority_era_chirho(&root_chirho).unwrap(),
            WriterAuthorityEraChirho::LocalChirho,
            "fixture precondition: a fresh root is never-latched"
        );
        issue_writer_fence_for_root_chirho(&root_chirho).expect(
            "era reports LocalChirho, so the local issuer must issue; disagreement here means \
             dispatch would route to a body whose fence then refuses",
        );

        // LATCHED: era says Elected, so the local issuer MUST refuse, and BY NAME.
        issue_elected_writer_fence_for_root_chirho(&root_chirho, 7).unwrap();
        assert_eq!(
            writer_authority_era_chirho(&root_chirho).unwrap(),
            WriterAuthorityEraChirho::ElectedChirho,
            "fixture precondition: the root is now geo-latched"
        );
        let refusal_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap_err();
        assert_eq!(
            refusal_chirho.downcast_ref::<CompositeWriterEpochRefusalChirho>(),
            Some(&CompositeWriterEpochRefusalChirho::GeoAuthorityAlreadyActiveChirho),
            "era reports ElectedChirho but the local issuer did not refuse by name: a local write \
             could land on an elected root"
        );
        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn elected_writer_fence_refuses_zero_term_and_low_half_wrap_chirho() {
        let root_chirho = temp_root_chirho("elected-wrap");
        std::fs::create_dir_all(&root_chirho).unwrap();
        let group_chirho = consistency_group_for_root_chirho(&root_chirho).unwrap();
        let zero_chirho =
            issue_elected_writer_fence_chirho(&root_chirho, &group_chirho, 0).unwrap_err();
        assert_eq!(
            zero_chirho.downcast_ref::<CompositeWriterEpochRefusalChirho>(),
            Some(&CompositeWriterEpochRefusalChirho::ZeroElectedTermChirho)
        );

        write_writer_fence_state_chirho(
            &root_chirho,
            &group_chirho,
            &WriterFenceStateChirho {
                schema_chirho: WRITER_FENCE_SCHEMA_CHIRHO.to_string(),
                group_chirho: group_chirho.clone(),
                epoch_chirho: WRITER_EPOCH_COMPONENT_MAX_CHIRHO,
                issued_at_ms_chirho: 1,
            },
        )
        .unwrap();
        let legacy_wrap_chirho =
            issue_writer_fence_chirho(&root_chirho, &group_chirho).unwrap_err();
        assert_eq!(
            legacy_wrap_chirho.downcast_ref::<CompositeWriterEpochRefusalChirho>(),
            Some(&CompositeWriterEpochRefusalChirho::LocalGrantSequenceExhaustedChirho)
        );
        assert_eq!(
            read_writer_fence_state_chirho(&root_chirho, &group_chirho)
                .unwrap()
                .unwrap()
                .epoch_chirho,
            WRITER_EPOCH_COMPONENT_MAX_CHIRHO,
            "legacy low-half refusal must not mutate the durable fence"
        );
        let elected_recovery_chirho =
            issue_elected_writer_fence_chirho(&root_chirho, &group_chirho, 1).unwrap();
        assert_eq!(
            split_writer_epoch_chirho(elected_recovery_chirho.epoch_chirho),
            CompositeWriterEpochChirho {
                geo_term_chirho: 1,
                local_grant_seq_chirho: 0,
            },
            "a strictly newer elected term is the only recovery from legacy low-half exhaustion"
        );

        let max_epoch_chirho =
            compose_writer_epoch_chirho(3, WRITER_EPOCH_COMPONENT_MAX_CHIRHO).unwrap();
        write_writer_fence_state_chirho(
            &root_chirho,
            &group_chirho,
            &WriterFenceStateChirho {
                schema_chirho: WRITER_FENCE_SCHEMA_CHIRHO.to_string(),
                group_chirho: group_chirho.clone(),
                epoch_chirho: max_epoch_chirho,
                issued_at_ms_chirho: 1,
            },
        )
        .unwrap();
        let wrap_chirho =
            issue_elected_writer_fence_chirho(&root_chirho, &group_chirho, 3).unwrap_err();
        assert_eq!(
            wrap_chirho.downcast_ref::<CompositeWriterEpochRefusalChirho>(),
            Some(&CompositeWriterEpochRefusalChirho::LocalGrantSequenceExhaustedChirho)
        );
        assert_eq!(
            read_writer_fence_state_chirho(&root_chirho, &group_chirho)
                .unwrap()
                .unwrap()
                .epoch_chirho,
            max_epoch_chirho,
            "elected low-half refusal must not mutate the durable fence"
        );
        let next_term_chirho =
            issue_elected_writer_fence_chirho(&root_chirho, &group_chirho, 4).unwrap();
        assert_eq!(
            split_writer_epoch_chirho(next_term_chirho.epoch_chirho),
            CompositeWriterEpochChirho {
                geo_term_chirho: 4,
                local_grant_seq_chirho: 0,
            }
        );
        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn missing_fence_file_is_not_implicit_epoch_zero_chirho() {
        let root_chirho = temp_root_chirho("missing");
        let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
        let group_chirho = token_chirho.group_chirho.clone();
        std::fs::remove_file(writer_fence_path_chirho(&root_chirho, &group_chirho).unwrap())
            .unwrap();
        assert_eq!(
            verify_writer_fence_for_root_chirho(&root_chirho, &token_chirho).unwrap_err(),
            WriterFenceVerifyErrorChirho::NoFenceIssuedChirho
        );
        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn verify_missing_root_does_not_create_root_chirho() {
        let root_chirho = temp_root_chirho("missing-root");
        let token_chirho = WriterFenceTokenChirho {
            group_chirho: ConsistencyGroupIdChirho::RootPathChirho {
                canonical_root_chirho: root_chirho.display().to_string(),
            },
            epoch_chirho: 1,
            issued_at_ms_chirho: 0,
        };
        assert_eq!(
            verify_writer_fence_for_root_chirho(&root_chirho, &token_chirho).unwrap_err(),
            WriterFenceVerifyErrorChirho::NoFenceIssuedChirho
        );
        assert!(!root_chirho.exists());
    }

    #[test]
    fn group_mismatch_is_rejected_before_state_trust_chirho() {
        let left_chirho = temp_root_chirho("left");
        let right_chirho = temp_root_chirho("right");
        let token_chirho = issue_writer_fence_for_root_chirho(&left_chirho).unwrap();
        issue_writer_fence_for_root_chirho(&right_chirho).unwrap();
        assert_eq!(
            verify_writer_fence_for_root_chirho(&right_chirho, &token_chirho).unwrap_err(),
            WriterFenceVerifyErrorChirho::GroupMismatchChirho
        );
        let _ = std::fs::remove_dir_all(left_chirho);
        let _ = std::fs::remove_dir_all(right_chirho);
    }

    #[test]
    fn forged_zero_and_future_epochs_are_rejected_chirho() {
        let root_chirho = temp_root_chirho("forged");
        let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
        let mut zero_chirho = token_chirho.clone();
        zero_chirho.epoch_chirho = 0;
        assert_eq!(
            verify_writer_fence_for_root_chirho(&root_chirho, &zero_chirho).unwrap_err(),
            WriterFenceVerifyErrorChirho::ForgedEpochChirho
        );
        let mut future_chirho = token_chirho.clone();
        future_chirho.epoch_chirho += 1;
        assert_eq!(
            verify_writer_fence_for_root_chirho(&root_chirho, &future_chirho).unwrap_err(),
            WriterFenceVerifyErrorChirho::ForgedEpochChirho
        );
        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn corrupt_fence_file_fails_closed_chirho() {
        let root_chirho = temp_root_chirho("corrupt");
        let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
        std::fs::write(
            writer_fence_path_chirho(&root_chirho, &token_chirho.group_chirho).unwrap(),
            b"not json",
        )
        .unwrap();
        assert_eq!(
            verify_writer_fence_for_root_chirho(&root_chirho, &token_chirho).unwrap_err(),
            WriterFenceVerifyErrorChirho::CorruptFenceFileChirho
        );
        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn two_groups_keep_independent_epoch_spaces_chirho() {
        let left_chirho = temp_root_chirho("group-a");
        let right_chirho = temp_root_chirho("group-b");
        let left_token_chirho = issue_writer_fence_for_root_chirho(&left_chirho).unwrap();
        let right_token_chirho = issue_writer_fence_for_root_chirho(&right_chirho).unwrap();
        assert_eq!(left_token_chirho.epoch_chirho, 1);
        assert_eq!(right_token_chirho.epoch_chirho, 1);
        verify_writer_fence_for_root_chirho(&left_chirho, &left_token_chirho).unwrap();
        verify_writer_fence_for_root_chirho(&right_chirho, &right_token_chirho).unwrap();
        let _ = std::fs::remove_dir_all(left_chirho);
        let _ = std::fs::remove_dir_all(right_chirho);
    }

    #[test]
    fn concurrent_issue_gets_distinct_monotonic_epochs_chirho() {
        let root_chirho = Arc::new(temp_root_chirho("concurrent"));
        std::fs::create_dir_all(root_chirho.as_ref()).unwrap();
        let barrier_chirho = Arc::new(Barrier::new(8));
        let mut handles_chirho = Vec::new();
        for _ in 0..8 {
            let root_chirho = Arc::clone(&root_chirho);
            let barrier_chirho = Arc::clone(&barrier_chirho);
            handles_chirho.push(std::thread::spawn(move || {
                barrier_chirho.wait();
                issue_writer_fence_for_root_chirho(root_chirho.as_ref()).unwrap()
            }));
        }
        let mut epochs_chirho = handles_chirho
            .into_iter()
            .map(|handle_chirho| handle_chirho.join().unwrap().epoch_chirho)
            .collect::<Vec<_>>();
        epochs_chirho.sort_unstable();
        assert_eq!(epochs_chirho, (1..=8).collect::<Vec<_>>());
        let _ = std::fs::remove_dir_all(root_chirho.as_ref());
    }

    #[test]
    fn issued_at_ms_is_advisory_and_not_compared_chirho() {
        let root_chirho = temp_root_chirho("time");
        let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
        let path_chirho =
            writer_fence_path_chirho(&root_chirho, &token_chirho.group_chirho).unwrap();
        let mut state_chirho: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path_chirho).unwrap()).unwrap();
        state_chirho["issued_at_ms_chirho"] = serde_json::json!(0);
        std::fs::write(
            &path_chirho,
            serde_json::to_vec_pretty(&state_chirho).unwrap(),
        )
        .unwrap();
        let mut changed_time_token_chirho = token_chirho;
        changed_time_token_chirho.issued_at_ms_chirho = u64::MAX;
        verify_writer_fence_for_root_chirho(&root_chirho, &changed_time_token_chirho).unwrap();
        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn canonical_group_id_is_injective_across_variants_chirho() {
        // The two variants never collide (variant-prefixed), so an A1.4 preferred-leader lookup can't
        // match the wrong group; the form is stable for equal ids.
        let tenant_chirho = ConsistencyGroupIdChirho::TenantChirho {
            tenant_id_chirho: "x".to_string(),
        };
        let root_chirho = ConsistencyGroupIdChirho::RootPathChirho {
            canonical_root_chirho: "x".to_string(),
        };
        assert_ne!(
            tenant_chirho.canonical_id_chirho(),
            root_chirho.canonical_id_chirho(),
            "the same inner string under different variants must not collide"
        );
        assert_eq!(
            tenant_chirho.canonical_id_chirho(),
            ConsistencyGroupIdChirho::TenantChirho {
                tenant_id_chirho: "x".to_string(),
            }
            .canonical_id_chirho(),
            "equal group ids produce the same canonical string"
        );
    }
}
