// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The per-member cluster-config cross-bind (design section 5.5): it parses each member's SAFE cluster-
//! config projection under file custody, digests that safe projection (never raw config bytes), and
//! matches it to the verified plan build's bound `config_projection_chirho`, proving configs parse and
//! cross-bind WITHOUT starting electors or creating roots. The safe projection carries only group/root
//! identity digests, public member keys, raft ids, closed roles, numeric endpoints, and cadence — no
//! path, token, or secret is representable, so digesting it commits no private path/token value.

use crate::codec_chirho::{canonical_record_bytes_chirho, parse_canonical_chirho};
use crate::digest_chirho::{GeoConsistencyGroupDigestChirho, GeoNodeConfigProjectionDigestChirho};
use crate::error_chirho::{GeoGenesisRefusalChirho, GeoGenesisResultChirho};
use crate::metadata_chirho::GeoMemberRoleChirho;
use crate::scalar_chirho::{GeoEd25519PublicKeyChirho, GeoRaftIdChirho};
use crate::topology_chirho::GeoEndpointAddressV1Chirho;
use crate::verify_chirho::VerifiedGeoGenesisPlanChirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

/// Operator-sized bound; a member config projection is startup config, never a growing data surface.
pub const MAX_CLUSTER_CONFIG_PROJECTION_BYTES_CHIRHO: u64 = 64 * 1024;
/// Representable member band inside one node's cluster view.
pub const MIN_CLUSTER_CONFIG_MEMBERS_CHIRHO: usize = 3;
pub const MAX_CLUSTER_CONFIG_MEMBERS_CHIRHO: usize = 64;
/// The election tick cadence band (milliseconds), mirroring the deployed cluster-file bound.
pub const MIN_CLUSTER_TICK_MS_CHIRHO: u32 = 10;
pub const MAX_CLUSTER_TICK_MS_CHIRHO: u32 = 1_000;

/// Domain-separated digest tag: keeps a cluster-config projection digest distinct from every other
/// blake3 usage, so one class of bytes can never masquerade as this projection digest.
const CLUSTER_CONFIG_PROJECTION_DIGEST_DOMAIN_CHIRHO: &str =
    "cairn-geo-genesis/cluster-config-projection-v1-chirho";

/// Closed schema token; unknown versions refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoClusterConfigProjectionSchemaChirho {
    V1Chirho,
}

/// One member entry inside a node's safe cluster-config projection: a raft id, the member's public
/// node key, a closed role, and one numeric transport endpoint. No URL, hostname, path, or free text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoClusterConfigMemberProjectionV1Chirho {
    pub raft_id_chirho: GeoRaftIdChirho,
    pub node_key_chirho: GeoEd25519PublicKeyChirho,
    pub role_chirho: GeoMemberRoleChirho,
    pub endpoint_chirho: GeoEndpointAddressV1Chirho,
}

/// The SAFE projection of one member's cluster config: the consistency-group identity DIGEST (never the
/// raw path/tenant string), the node's own public key and raft id, the tick cadence, and the sorted
/// member set. This is the exact private config projected to safe fields BEFORE it is digested — a raw
/// path, token, or secret is unrepresentable by type (design section 11).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoClusterConfigProjectionSourceV1Chirho {
    pub schema_chirho: GeoClusterConfigProjectionSchemaChirho,
    pub consistency_group_chirho: GeoConsistencyGroupDigestChirho,
    pub local_raft_id_chirho: GeoRaftIdChirho,
    pub node_key_chirho: GeoEd25519PublicKeyChirho,
    pub tick_ms_chirho: u32,
    pub members_chirho: Vec<GeoClusterConfigMemberProjectionV1Chirho>,
}

impl GeoClusterConfigProjectionSourceV1Chirho {
    /// Structural validation: cadence in band, member count in band, members ascending-strict by raft
    /// id (single canonical order, no duplicate), unique node keys, and the local node/raft id present
    /// among the members. There is no single canonical projection otherwise, so the digest is refused.
    pub(crate) fn validate_chirho(&self) -> GeoGenesisResultChirho<()> {
        if self.tick_ms_chirho < MIN_CLUSTER_TICK_MS_CHIRHO
            || self.tick_ms_chirho > MAX_CLUSTER_TICK_MS_CHIRHO
        {
            return Err(GeoGenesisRefusalChirho::ConfigProjectionSourceRefusedChirho);
        }
        if self.members_chirho.len() < MIN_CLUSTER_CONFIG_MEMBERS_CHIRHO
            || self.members_chirho.len() > MAX_CLUSTER_CONFIG_MEMBERS_CHIRHO
        {
            return Err(GeoGenesisRefusalChirho::ConfigProjectionSourceRefusedChirho);
        }
        if !self
            .members_chirho
            .windows(2)
            .all(|pair_chirho| pair_chirho[0].raft_id_chirho < pair_chirho[1].raft_id_chirho)
        {
            return Err(GeoGenesisRefusalChirho::ConfigProjectionSourceRefusedChirho);
        }
        let mut node_keys_chirho = BTreeSet::new();
        for member_chirho in &self.members_chirho {
            if !node_keys_chirho.insert(member_chirho.node_key_chirho) {
                return Err(GeoGenesisRefusalChirho::ConfigProjectionSourceRefusedChirho);
            }
        }
        let local_present_chirho = self.members_chirho.iter().any(|member_chirho| {
            member_chirho.raft_id_chirho == self.local_raft_id_chirho
                && member_chirho.node_key_chirho == self.node_key_chirho
        });
        if !local_present_chirho {
            return Err(GeoGenesisRefusalChirho::ConfigProjectionSourceRefusedChirho);
        }
        Ok(())
    }
}

/// Parse candidate bytes into a structurally valid safe cluster-config projection: size bound, unknown/
/// duplicate-field refusal, exact canonical round-trip, then structural validation. No file is touched.
pub fn parse_cluster_config_projection_source_chirho(
    bytes_chirho: &[u8],
) -> GeoGenesisResultChirho<GeoClusterConfigProjectionSourceV1Chirho> {
    let source_chirho: GeoClusterConfigProjectionSourceV1Chirho =
        parse_canonical_chirho(bytes_chirho)?;
    source_chirho.validate_chirho()?;
    Ok(source_chirho)
}

/// The domain-separated blake3 digest of a member's SAFE cluster-config projection. This is the value
/// the plan binds as `config_projection_chirho`; it is a digest of safe projected fields, never of raw
/// config bytes, so it commits no private path/token value.
pub fn cluster_config_projection_digest_chirho(
    source_chirho: &GeoClusterConfigProjectionSourceV1Chirho,
) -> GeoGenesisResultChirho<GeoNodeConfigProjectionDigestChirho> {
    let canonical_chirho = canonical_record_bytes_chirho(source_chirho)?;
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(CLUSTER_CONFIG_PROJECTION_DIGEST_DOMAIN_CHIRHO.as_bytes());
    hasher_chirho.update(&[0u8]);
    hasher_chirho.update(&canonical_chirho);
    GeoNodeConfigProjectionDigestChirho::from_hex_chirho(&hasher_chirho.finalize().to_hex())
}

/// Verify file custody before an authority-bearing read of a member config projection: non-symlink,
/// regular file, and privately permissioned. This owns only the file boundary; parsing owns the schema.
/// The same-owner check against the operator config file is deferred to 8.7 (no in-memory anchor here).
pub fn verify_cluster_config_projection_custody_chirho(
    config_path_chirho: &Path,
) -> GeoGenesisResultChirho<()> {
    let metadata_chirho =
        std::fs::symlink_metadata(config_path_chirho).map_err(|_error_chirho| {
            GeoGenesisRefusalChirho::ConfigProjectionSourceCustodyRefusedChirho
        })?;
    if metadata_chirho.file_type().is_symlink() || !metadata_chirho.is_file() {
        return Err(GeoGenesisRefusalChirho::ConfigProjectionSourceCustodyRefusedChirho);
    }
    if !private_config_mode_chirho(&metadata_chirho) {
        return Err(GeoGenesisRefusalChirho::ConfigProjectionSourceCustodyRefusedChirho);
    }
    Ok(())
}

/// Custody-check, bounded-read, and parse a member config projection from a file. Refuses before
/// unbounded allocation if the file exceeds the config-sized limit. Never starts an elector, creates a
/// root, or writes anything.
pub fn load_cluster_config_projection_source_chirho(
    config_path_chirho: &Path,
) -> GeoGenesisResultChirho<GeoClusterConfigProjectionSourceV1Chirho> {
    verify_cluster_config_projection_custody_chirho(config_path_chirho)?;
    let file_chirho = std::fs::File::open(config_path_chirho).map_err(|_error_chirho| {
        GeoGenesisRefusalChirho::ConfigProjectionSourceCustodyRefusedChirho
    })?;
    let mut bytes_chirho = Vec::new();
    file_chirho
        .take(MAX_CLUSTER_CONFIG_PROJECTION_BYTES_CHIRHO + 1)
        .read_to_end(&mut bytes_chirho)
        .map_err(|_error_chirho| {
            GeoGenesisRefusalChirho::ConfigProjectionSourceCustodyRefusedChirho
        })?;
    if bytes_chirho.len() as u64 > MAX_CLUSTER_CONFIG_PROJECTION_BYTES_CHIRHO {
        return Err(GeoGenesisRefusalChirho::ConfigProjectionSourceCustodyRefusedChirho);
    }
    parse_cluster_config_projection_source_chirho(&bytes_chirho)
}

/// The bound config cross-bind: proof that every plan member's safe config projection digests to the
/// exact `config_projection_chirho` the plan build bound. Its fields are private and there is no public
/// constructor, so a caller cannot fabricate a "cross-bound" posture — the only way to obtain one is
/// through `cross_bind_member_configs_chirho`. It carries ONLY the plan digest, a member count, and the
/// matched safe-projection digests (which equal the plan's), never a config byte, endpoint, or path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGenesisConfigCrossBindChirho {
    plan_digest_chirho: crate::digest_chirho::GeoGenesisPlanDigestChirho,
    member_count_chirho: usize,
    projection_digests_chirho: Vec<GeoNodeConfigProjectionDigestChirho>,
}

impl VerifiedGenesisConfigCrossBindChirho {
    /// The verified plan digest this cross-bind is bound to.
    pub fn plan_digest_chirho(&self) -> crate::digest_chirho::GeoGenesisPlanDigestChirho {
        self.plan_digest_chirho
    }

    /// The number of members whose config projections were cross-bound one-to-one.
    pub fn member_count_chirho(&self) -> usize {
        self.member_count_chirho
    }

    /// The cross-bound safe-projection digests (sorted; each equals a plan build's bound digest).
    pub fn projection_digests_chirho(&self) -> &[GeoNodeConfigProjectionDigestChirho] {
        &self.projection_digests_chirho
    }
}

/// Cross-bind every member's supplied safe config projection to the verified plan build set. The
/// sources must cover the plan population one-to-one by node key; each source's recomputed safe-
/// projection digest must equal its plan build's bound `config_projection_chirho`. A missing/foreign
/// source refuses coverage; a digest that does not match refuses by its own reason. NO side effects:
/// this computes digests over in-memory bytes and creates/starts nothing.
pub fn cross_bind_member_configs_chirho(
    verified_plan_chirho: &VerifiedGeoGenesisPlanChirho,
    sources_chirho: &[GeoClusterConfigProjectionSourceV1Chirho],
) -> GeoGenesisResultChirho<VerifiedGenesisConfigCrossBindChirho> {
    let builds_chirho = &verified_plan_chirho
        .plan_chirho()
        .builds_chirho
        .members_chirho;
    if sources_chirho.len() != builds_chirho.len() {
        return Err(GeoGenesisRefusalChirho::ConfigCrossBindCoverageRefusedChirho);
    }
    // Unique node keys among the sources: a duplicate would let one config stand for two plan members.
    let mut source_keys_chirho = BTreeSet::new();
    for source_chirho in sources_chirho {
        if !source_keys_chirho.insert(source_chirho.node_key_chirho) {
            return Err(GeoGenesisRefusalChirho::ConfigCrossBindCoverageRefusedChirho);
        }
    }

    let mut projection_digests_chirho = Vec::with_capacity(builds_chirho.len());
    for build_chirho in builds_chirho {
        let source_chirho = sources_chirho
            .iter()
            .find(|source_chirho| source_chirho.node_key_chirho == build_chirho.node_key_chirho)
            .ok_or(GeoGenesisRefusalChirho::ConfigCrossBindCoverageRefusedChirho)?;
        let derived_chirho = cluster_config_projection_digest_chirho(source_chirho)?;
        if derived_chirho != build_chirho.config_projection_chirho {
            return Err(GeoGenesisRefusalChirho::ConfigProjectionDigestMismatchChirho);
        }
        projection_digests_chirho.push(derived_chirho);
    }
    projection_digests_chirho.sort_by_key(|digest_chirho| *digest_chirho.as_bytes_chirho());

    Ok(VerifiedGenesisConfigCrossBindChirho {
        plan_digest_chirho: verified_plan_chirho.plan_digest_chirho(),
        member_count_chirho: builds_chirho.len(),
        projection_digests_chirho,
    })
}

#[cfg(unix)]
fn private_config_mode_chirho(metadata_chirho: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata_chirho.permissions().mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn private_config_mode_chirho(_metadata_chirho: &std::fs::Metadata) -> bool {
    true
}
