// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The section-3 scalar vocabulary: opaque, validated coordinate newtypes for identities, public
//! crypto material, consensus/freshness numbers, transport endpoints, and coarse time. No field is a
//! bare `String`, `Path`, or `Value`; private keys are unrepresentable and only public bytes exist.

use crate::codec_chirho::{geo_hex_newtype_chirho, geo_uint_newtype_chirho};
use crate::error_chirho::{GeoGenesisRefusalChirho, GeoGenesisResultChirho};
use serde::{Deserialize, Serialize};

geo_hex_newtype_chirho!(
    /// `[u8; 32]` CSPRNG operation identity. Not derived from host, tenant, account, path, or
    /// payload; names one immutable intent across retry and every member marker. All-zero refuses.
    GeoGenesisInstanceIdChirho,
    32,
    reject_zero
);

geo_hex_newtype_chirho!(
    /// `[u8; 20]` git object coordinate (lowercase 40-hex), never source text or a path.
    GeoGitCommitIdChirho,
    20
);

geo_hex_newtype_chirho!(
    /// `[u8; 32]` Ed25519 public verification material. Format only at 8.2a; curve-point and custody
    /// checks land in 8.2b. Private keys are unrepresentable.
    GeoEd25519PublicKeyChirho,
    32
);

geo_hex_newtype_chirho!(
    /// `[u8; 64]` Ed25519 public signature bytes only. Verification over an unsigned canonical object
    /// is 8.2b; 8.2a fixes the wire slot and length.
    GeoEd25519SignatureChirho,
    64
);

geo_hex_newtype_chirho!(
    /// `[u8; 32]` WireGuard public transport identity, never the WireGuard private key.
    GeoWireGuardPublicKeyChirho,
    32
);

geo_hex_newtype_chirho!(
    /// `[u8; 32]` random identity of the empty authoritative root; never a path or tenant/account
    /// digest. All-zero refuses.
    GeoFreshRootIdentityChirho,
    32,
    reject_zero
);

geo_hex_newtype_chirho!(
    /// `[u8; 32]` random placement identity for this genesis; not derived from customer text.
    /// All-zero refuses.
    GeoTenantRootIdentityChirho,
    32,
    reject_zero
);

geo_uint_newtype_chirho!(
    /// Nonzero Raft consensus coordinate; unique across the exact member set.
    GeoRaftIdChirho,
    u64,
    nonzero ZeroRaftIdChirho
);

geo_uint_newtype_chirho!(
    /// Nonzero election-freshness coordinate; must equal the authenticated exact-term view (8.2b).
    GeoElectionTermChirho,
    u64,
    nonzero ZeroElectionTermChirho
);

geo_uint_newtype_chirho!(
    /// Nonzero monotone signed-roster revision, no prose.
    GeoAppliedRosterRevisionChirho,
    u64,
    nonzero ZeroRosterRevisionChirho
);

geo_uint_newtype_chirho!(
    /// Durable Raft membership-application coordinate; zero is admitted only for the explicitly
    /// verified initial configuration.
    GeoAppliedConfIndexChirho,
    u64
);

geo_uint_newtype_chirho!(
    /// Nonzero transport port (`1..=65535`); role-specific ports must be distinct on one address.
    GeoPortChirho,
    u16,
    nonzero ZeroPortChirho
);

geo_uint_newtype_chirho!(
    /// Cardinality only; member/evidence-specific bounds are enforced where the count is used.
    GeoSmallCountChirho,
    u16
);

/// Coarse-time ceiling: minutes from 2020-01-01T00:00Z to 2100-01-01T00:00Z (29,220 days).
pub const GEO_UTC_MINUTE_MAX_CHIRHO: u32 = 42_076_800;

/// Coarse evidence time in whole minutes since 2020-01-01; no timezone, path, or hostname detail.
/// Monotone across plan, marker, publication, and acceptance events (checked at the record level).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GeoUtcMinuteChirho(u32);

impl GeoUtcMinuteChirho {
    /// Construct, refusing any minute beyond the 2100 ceiling.
    pub fn new_chirho(value_chirho: u32) -> GeoGenesisResultChirho<Self> {
        if value_chirho > GEO_UTC_MINUTE_MAX_CHIRHO {
            return Err(GeoGenesisRefusalChirho::TimeOutOfRangeChirho);
        }
        Ok(Self(value_chirho))
    }

    /// The coarse minute coordinate.
    pub fn get_chirho(&self) -> u32 {
        self.0
    }
}

crate::codec_chirho::geo_uint_serde_chirho!(GeoUtcMinuteChirho, u32);

/// Numeric transport address only: four or sixteen octets, never a hostname, URL, path, userinfo, or
/// free text. Externally tagged so each variant carries exactly its fixed-length octet array.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoIpAddressChirho {
    /// Four IPv4 octets.
    Ipv4Chirho([u8; 4]),
    /// Sixteen IPv6 octets.
    Ipv6Chirho([u8; 16]),
}
