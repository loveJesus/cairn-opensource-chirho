// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Fixed, value-redacted refusals at the geo-genesis vocabulary boundary. Each validation failure
//! names its own distinct reason so a caller never has to collapse a topology mistake, an
//! unresolved ruling, and a malformed byte into one opaque error.

use crate::trust_chirho::{GeoGenesisMessageClassChirho, GeoSignerRoleChirho};
use std::error::Error;
use std::fmt;

/// The single result alias for every geo-genesis construction, codec, and validation call.
pub type GeoGenesisResultChirho<ValueChirho> = Result<ValueChirho, GeoGenesisRefusalChirho>;

/// Which ruling field refused; keyed by decision, not by human-readable prose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeoRulingFieldChirho {
    CellAdvanceChirho,
    Item7ReplicaCountChirho,
    Item7MembershipFreshnessChirho,
    Item7DurabilityChirho,
    Item7ClosureChirho,
    Item7FailureSemanticsChirho,
    Item7ReadServingChirho,
    Gg6OrderingChirho,
    TrustProfileChirho,
}

/// Which member coordinate collided; the offending value is never echoed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeoMemberCoordinateChirho {
    RaftIdChirho,
    NodeKeyChirho,
    WireGuardKeyChirho,
    EndpointChirho,
}

/// Which durable guard-marker holder refused; names the ROLE only, never a path or the offending
/// bytes. The operator guard root is the single authoritative one-time gate (ruling 2); member roots
/// are defense-in-depth (design section 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeoGuardHolderRoleChirho {
    OperatorGuardChirho,
    MemberChirho,
}

/// Why a redaction-safe dry-run packet (8.3) was refused. Every field of the packet is typed/bounded
/// (safety by typing is the PRIMARY privacy control), so these markers are defense-in-depth that is
/// unfirable-by-construction while the packet stays typed; each names its own leak class so a planted
/// positive control proves the corresponding scanner rule is live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeoDryRunLeakReasonChirho {
    /// The packet is not the one canonical encoding of its typed value.
    NonCanonicalChirho,
    /// The packet schema token is not the one this loader accepts.
    SchemaChirho,
    /// The packet carries an empty or malformed integrity/content digest.
    EmptyDigestChirho,
    /// The packet's recomputed integrity digest does not equal its bound digest.
    IntegrityDigestChirho,
    /// The packet bytes contain a host-path marker.
    ForbiddenHostPathChirho,
    /// The packet bytes contain a bearer/authorization marker.
    ForbiddenBearerMarkerChirho,
    /// The packet bytes contain free-text principal/account/email data.
    ForbiddenPrincipalMarkerChirho,
    /// The packet bytes contain raw provider payload/secret data.
    ForbiddenProviderBytesChirho,
    /// The packet bytes contain a numeric endpoint / address / port marker (the 8.3-added class).
    ForbiddenEndpointChirho,
}

impl fmt::Display for GeoDryRunLeakReasonChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(match self {
            Self::NonCanonicalChirho => "packet is not canonical",
            Self::SchemaChirho => "packet schema is unsupported",
            Self::EmptyDigestChirho => "packet contains an empty digest",
            Self::IntegrityDigestChirho => "packet integrity digest is invalid",
            Self::ForbiddenHostPathChirho => "packet contains a host path marker",
            Self::ForbiddenBearerMarkerChirho => "packet contains a bearer marker",
            Self::ForbiddenPrincipalMarkerChirho => "packet contains free-text principal data",
            Self::ForbiddenProviderBytesChirho => "packet contains raw provider data",
            Self::ForbiddenEndpointChirho => "packet contains a numeric endpoint marker",
        })
    }
}

/// Every distinct way a geo-genesis value, record, or set is refused. Serde/format failures collapse
/// into the malformed family (the bytes could not even be parsed into typed values); every semantic
/// check that runs on already-parsed values carries its own reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeoGenesisRefusalChirho {
    // --- wire / format layer ------------------------------------------------------------------
    /// Unknown field, duplicate key, unknown enum token, wrong-length array, float, null, or any
    /// other serde parse failure; the bytes are not a typed geo-genesis value.
    MalformedChirho,
    /// The bytes parsed but are not the one canonical encoding of the value they decode to.
    NotCanonicalChirho,
    /// The candidate bytes exceed the fixed record size bound before any parse is attempted.
    TooLargeChirho,
    /// A fixed byte array was not exactly `2*len` lowercase hex characters.
    HexEncodingChirho,
    /// The declared schema token is not the one this loader accepts.
    SchemaRefusedChirho,

    // --- scalar construction ------------------------------------------------------------------
    /// A CSPRNG operation/placement identity (instance, fresh root, tenant root) was all-zero.
    AllZeroIdentityChirho,
    /// A Raft consensus coordinate was zero.
    ZeroRaftIdChirho,
    /// An election-freshness term was zero.
    ZeroElectionTermChirho,
    /// A signed-roster revision was zero.
    ZeroRosterRevisionChirho,
    /// A transport port was zero.
    ZeroPortChirho,
    /// A coarse evidence time is beyond the representable 2020-01-01..2100-01-01 window.
    TimeOutOfRangeChirho,
    /// An initial ledger epoch that must be nonzero was zero.
    ZeroInitialEpochChirho,

    // --- rulings ------------------------------------------------------------------------------
    /// A ruling field is still `UnresolvedChirho`; authoring/signing/derivation must refuse.
    UnresolvedRulingChirho { field_chirho: GeoRulingFieldChirho },

    // --- topology / plan semantics ------------------------------------------------------------
    /// The member population is outside the representable `3..=64` band.
    MemberCountOutOfRangeChirho,
    /// Members are not sorted ascending by Raft id, so there is no single canonical order.
    MembersNotSortedChirho,
    /// Two members share a Raft id, node key, WireGuard key, or numeric endpoint.
    DuplicateMemberCoordinateChirho {
        coordinate_chirho: GeoMemberCoordinateChirho,
    },
    /// The declared voter/learner role counts do not satisfy the plan's own minimum.
    MemberRoleCountRefusedChirho,
    /// Fewer distinct providers than the declared minimum failure-domain spread.
    ProviderSpreadRefusedChirho,
    /// Fewer distinct regions than the declared minimum failure-domain spread.
    RegionSpreadRefusedChirho,
    /// A member's endpoint set does not carry exactly one address/port per required role, or two
    /// roles collide on one address/port.
    EndpointRoleRefusedChirho,
    /// A member custody binding has an empty, over-bounded, unsorted, or duplicated verifier-ref set.
    CustodyBindingRefusedChirho,
    /// The build-evidence set does not map one-to-one onto the topology members by node key.
    BuildMemberMismatchChirho,
    /// A member's build target/architecture disagrees between topology and build evidence.
    BuildTargetMismatchChirho,
    /// The plan authority window is not in `1..=1440` minutes after authoring.
    LifetimeRefusedChirho,
    /// Two coarse times are not monotone (authored before expiry, before deadlines).
    TimeOrderRefusedChirho,
    /// A GG disposition carries a verdict that is not allowed for its key under any ruling.
    GgVerdictRefusedChirho { gg_index_chirho: u8 },
    /// The canary plan does not declare a zero real-subject population or a nonzero window.
    CanaryRefusedChirho,
    /// A bounded set (evidence refs, admissions, markers) is out of its declared count band.
    SetCountOutOfRangeChirho,
    /// A record's cross-field identity coordinates disagree (e.g. an unsigned/signed pair).
    CrossFieldMismatchChirho,
    /// A record's phase field is not the one fixed phase its record type may carry.
    PhaseRefusedChirho,
    /// A marker-set holder slot carries the wrong holder kind (operator-guard vs member).
    MarkerHolderKindRefusedChirho,

    // --- signer boundary (8.2b) ---------------------------------------------------------------
    /// An Ed25519 public key (pin or embedded key) does not decode to a valid curve point.
    NonCurvePointKeyChirho,
    /// A signature does not verify against the custody-pinned key over the domain-separated class
    /// message. Distinct from a pin mismatch: the embedded key matched but the signature is wrong.
    SignatureRefusedChirho,
    /// The embedded signer public key does not equal the custody-supplied expected pin for its role;
    /// a plan/packet may never self-select its verifier.
    CustodyPinMismatchChirho,
    /// A role-bound signer was asked to sign, or a verifier to admit, a message class that role does
    /// not own. This is the split-trust cross-role refusal (plan key cannot sign an acceptance class).
    CrossRoleMessageClassRefusedChirho {
        signer_role_chirho: GeoSignerRoleChirho,
        message_class_chirho: GeoGenesisMessageClassChirho,
    },
    /// The custody trust pins are themselves invalid: not the ruled split profile, non-distinct keys,
    /// or a non-curve pin.
    TrustPinsRefusedChirho,
    /// The plan's trust profile is not the ruled `SplitDedicatedPlanAndAcceptanceAuthoritiesChirho`.
    RuledTrustProfileRefusedChirho,
    /// The plan's GG6 ordering is not the ruled `WiringReadyThenHostedAcceptedChirho` (phase split).
    RuledGg6OrderingRefusedChirho,
    /// The GG6 disposition verdict is inconsistent with the GG6 ordering ruling (phase split requires
    /// a wiring-ready verdict; strict requires satisfied).
    Gg6VerdictOrderingMismatchChirho,
    /// The independently reloaded ledger regenesis plan digest does not equal the plan's bound digest.
    LedgerPlanDigestMismatchChirho,
    /// An existing dedicated signing key could not be loaded (absent, non-regular, wrong length, or
    /// all-zero). This loader NEVER generates a key.
    ExistingSigningKeyRefusedChirho,

    // --- custody non-equivalence (8.2b, ruling 1) ---------------------------------------------
    /// A required custody-evidence attestation is absent.
    CustodyEvidenceMissingChirho,
    /// A custody attestation does not verify against the pinned custody authority (bad signature or
    /// a non-curve custody-authority key).
    CustodyAttestationUnverifiableChirho,
    /// A custody attestation names its own verifier — its embedded attestation-signer key is not the
    /// externally pinned custody authority. The artifact may never choose its own trust anchor.
    CustodySelfSelectedChirho,
    /// A custody attestation does not protect the expected pinned authority key it claims custody of.
    CustodySubjectMismatchChirho,
    /// The two custody-evidence refs authenticate the SAME custody domain, so they cannot contain
    /// device compromise; two distinct domains are required.
    CustodySameDomainChirho,

    // --- acceptance pure verifier (8.2b, ruling 6) --------------------------------------------
    /// One of the section-6.3 acceptance equations failed, named by its number (1..=10). An omitted,
    /// duplicate, stale, or inconsistent value refuses by its own equation rather than collapsing.
    AcceptanceEquationRefusedChirho { equation_chirho: u8 },
    /// The acceptance packet does not bind the verified plan (plan ref, instance, trust profile, or
    /// hard gates disagree with the plan it claims to accept).
    AcceptancePlanBindingRefusedChirho,

    // --- durable one-time intent guard (8.2c) -------------------------------------------------
    /// The supplied guard roots do not bind the verified plan population one-to-one: a member root is
    /// missing, foreign, duplicated, or names the wrong role/raft/node coordinate for its plan member.
    GuardRootBindingRefusedChirho,
    /// The supplied member signers do not cover the plan population one-to-one by node key (a plan
    /// member has no matching signer, or the signer's key is not a planned member).
    GuardMemberSignerRefusedChirho,
    /// A valid, DIFFERENT authoritative intent marker is already durably present at a guard root, so a
    /// prior genesis reserved this instance. A second genesis refuses BEFORE any output. Named by role.
    GenesisAlreadyReservedChirho {
        holder_role_chirho: GeoGuardHolderRoleChirho,
    },
    /// Existing marker bytes at a guard root are malformed, unreadable, non-canonical, or fail
    /// signature verification. This FAILS CLOSED and is NEVER counted as marker absence. Named by role.
    GuardMarkerUnverifiableChirho {
        holder_role_chirho: GeoGuardHolderRoleChirho,
    },
    /// An I/O failure while creating, syncing, or re-reading a durable marker; the guard fails closed
    /// rather than treating an unreadable write as success or absence.
    GuardMarkerIoRefusedChirho,
    /// The produced intent marker set does not bind the verified plan population (operator-guard
    /// identity, or a member marker's role/raft/node/instance/plan/marker coordinate, disagrees).
    MarkerSetPlanBindingRefusedChirho,

    // --- pre-genesis custody checkpoint (8.3, ruling 3) ---------------------------------------
    /// The operator custody config's dedicated plan-authority key pin does not equal the verified
    /// plan's plan-signer key: the operator did not supply the key this plan is authored under.
    CustodyPresencePlanKeyPinMismatchChirho,
    /// The operator custody config's held signed-roster projection does not equal the verified plan's
    /// roster projection: the per-member key pins are anchored to a different roster.
    CustodyPresenceRosterProjectionMismatchChirho,
    /// The operator's per-member key custody pins do not cover the verified plan population one-to-one,
    /// or a pin's node/WireGuard public key disagrees with its plan member. Names the coordinate only.
    CustodyPresenceMemberPinRefusedChirho {
        coordinate_chirho: GeoMemberCoordinateChirho,
    },
    /// The custody-supplied operator guard root location is absent or fails metadata custody (missing,
    /// symlink, not a directory, or world/group-accessible). Fails closed; never plan-selected.
    CustodyPresenceGuardRootUnverifiableChirho,

    // --- config cross-bind (8.3) --------------------------------------------------------------
    /// A member's supplied safe cluster-config projection source fails custody (symlink, non-regular,
    /// broad mode, oversize, or unreadable) before any digest is derived.
    ConfigProjectionSourceCustodyRefusedChirho,
    /// A member's safe cluster-config projection source is structurally invalid (unsorted, duplicate,
    /// or out-of-band members) so no single canonical projection digest exists.
    ConfigProjectionSourceRefusedChirho,
    /// The supplied config projection sources do not cover the verified plan population one-to-one by
    /// node key (a plan member has no matching config source, or a source names no plan member).
    ConfigCrossBindCoverageRefusedChirho,
    /// A member's recomputed safe-projection digest does not equal the verified plan build's bound
    /// `config_projection_chirho`: the parsed config does not project to the planned digest.
    ConfigProjectionDigestMismatchChirho,

    // --- redaction-safe dry-run packet (8.3) --------------------------------------------------
    /// A checked count sum overflowed while building the dry-run packet from the verified plan.
    DryRunCountOverflowChirho,
    /// The custody-presence and config-cross-bind tokens do not bind the SAME verified plan as the plan
    /// the dry-run packet is built for; a packet may only summarize one consistent genesis.
    DryRunTokenBindingRefusedChirho,
    /// The dry-run packet was refused; typed field is safe by construction, so this names the
    /// defense-in-depth leak/validation class that fired.
    DryRunPacketRefusedChirho {
        reason_chirho: GeoDryRunLeakReasonChirho,
    },
}

impl fmt::Display for GeoGenesisRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message_chirho = match self {
            Self::MalformedChirho => "geo-genesis bytes are not a typed value",
            Self::NotCanonicalChirho => "geo-genesis bytes are not the canonical encoding",
            Self::TooLargeChirho => "geo-genesis candidate bytes exceed the size bound",
            Self::HexEncodingChirho => "geo-genesis fixed array is not exact lowercase hex",
            Self::SchemaRefusedChirho => "geo-genesis schema token is unsupported",
            Self::AllZeroIdentityChirho => "geo-genesis identity must not be all zero",
            Self::ZeroRaftIdChirho => "geo-genesis raft id must be nonzero",
            Self::ZeroElectionTermChirho => "geo-genesis election term must be nonzero",
            Self::ZeroRosterRevisionChirho => "geo-genesis applied roster revision must be nonzero",
            Self::ZeroPortChirho => "geo-genesis port must be nonzero",
            Self::TimeOutOfRangeChirho => {
                "geo-genesis coarse time is outside the 2020..2100 window"
            }
            Self::ZeroInitialEpochChirho => "geo-genesis initial ledger epoch must be nonzero",
            Self::UnresolvedRulingChirho { .. } => "geo-genesis ruling field is unresolved",
            Self::MemberCountOutOfRangeChirho => {
                "geo-genesis member population is out of the 3..=64 band"
            }
            Self::MembersNotSortedChirho => "geo-genesis members are not sorted by raft id",
            Self::DuplicateMemberCoordinateChirho { .. } => {
                "geo-genesis members share a coordinate"
            }
            Self::MemberRoleCountRefusedChirho => "geo-genesis voter/learner counts are refused",
            Self::ProviderSpreadRefusedChirho => "geo-genesis provider spread is insufficient",
            Self::RegionSpreadRefusedChirho => "geo-genesis region spread is insufficient",
            Self::EndpointRoleRefusedChirho => "geo-genesis endpoint roles are refused",
            Self::CustodyBindingRefusedChirho => "geo-genesis member custody binding is refused",
            Self::BuildMemberMismatchChirho => {
                "geo-genesis build evidence does not match the members"
            }
            Self::BuildTargetMismatchChirho => "geo-genesis build target disagrees with the member",
            Self::LifetimeRefusedChirho => {
                "geo-genesis authority window is out of the 1..=1440 band"
            }
            Self::TimeOrderRefusedChirho => "geo-genesis coarse times are not monotone",
            Self::GgVerdictRefusedChirho { .. } => {
                "geo-genesis GG verdict is not allowed for its key"
            }
            Self::CanaryRefusedChirho => "geo-genesis canary plan is refused",
            Self::SetCountOutOfRangeChirho => "geo-genesis bounded set count is out of range",
            Self::CrossFieldMismatchChirho => {
                "geo-genesis cross-field identity coordinates disagree"
            }
            Self::PhaseRefusedChirho => {
                "geo-genesis record phase is not the fixed phase for its type"
            }
            Self::MarkerHolderKindRefusedChirho => "geo-genesis marker holder kind is refused",
            Self::NonCurvePointKeyChirho => {
                "geo-genesis public key is not a valid ed25519 curve point"
            }
            Self::SignatureRefusedChirho => {
                "geo-genesis signature does not verify against the pinned key"
            }
            Self::CustodyPinMismatchChirho => {
                "geo-genesis embedded signer key does not match the custody pin"
            }
            Self::CrossRoleMessageClassRefusedChirho { .. } => {
                "geo-genesis signer role does not own this message class"
            }
            Self::TrustPinsRefusedChirho => "geo-genesis custody trust pins are refused",
            Self::RuledTrustProfileRefusedChirho => {
                "geo-genesis trust profile is not the ruled split profile"
            }
            Self::RuledGg6OrderingRefusedChirho => {
                "geo-genesis GG6 ordering is not the ruled phase split"
            }
            Self::Gg6VerdictOrderingMismatchChirho => {
                "geo-genesis GG6 verdict is inconsistent with the GG6 ordering ruling"
            }
            Self::LedgerPlanDigestMismatchChirho => {
                "geo-genesis reloaded ledger regenesis plan digest does not match"
            }
            Self::ExistingSigningKeyRefusedChirho => {
                "geo-genesis existing signing key could not be loaded (never generated)"
            }
            Self::CustodyEvidenceMissingChirho => "geo-genesis custody evidence is missing",
            Self::CustodyAttestationUnverifiableChirho => {
                "geo-genesis custody attestation does not verify against the pinned custody authority"
            }
            Self::CustodySelfSelectedChirho => {
                "geo-genesis custody attestation names its own verifier"
            }
            Self::CustodySubjectMismatchChirho => {
                "geo-genesis custody attestation does not protect the expected authority key"
            }
            Self::CustodySameDomainChirho => {
                "geo-genesis custody evidence authenticates the same custody domain"
            }
            Self::AcceptanceEquationRefusedChirho { .. } => {
                "geo-genesis acceptance equation failed"
            }
            Self::AcceptancePlanBindingRefusedChirho => {
                "geo-genesis acceptance packet does not bind the verified plan"
            }
            Self::GuardRootBindingRefusedChirho => {
                "geo-genesis guard roots do not bind the verified plan population"
            }
            Self::GuardMemberSignerRefusedChirho => {
                "geo-genesis member signers do not cover the plan population"
            }
            Self::GenesisAlreadyReservedChirho { .. } => {
                "geo-genesis intent is already durably reserved at a guard root"
            }
            Self::GuardMarkerUnverifiableChirho { .. } => {
                "geo-genesis existing guard marker is unverifiable (fail closed, not absence)"
            }
            Self::GuardMarkerIoRefusedChirho => {
                "geo-genesis durable marker i/o failed (fail closed)"
            }
            Self::MarkerSetPlanBindingRefusedChirho => {
                "geo-genesis intent marker set does not bind the verified plan population"
            }
            Self::CustodyPresencePlanKeyPinMismatchChirho => {
                "geo-genesis custody config plan-authority key pin does not match the plan"
            }
            Self::CustodyPresenceRosterProjectionMismatchChirho => {
                "geo-genesis custody config roster projection does not match the plan"
            }
            Self::CustodyPresenceMemberPinRefusedChirho { .. } => {
                "geo-genesis member custody key pin does not cover the plan population"
            }
            Self::CustodyPresenceGuardRootUnverifiableChirho => {
                "geo-genesis operator guard root location is absent or fails custody"
            }
            Self::ConfigProjectionSourceCustodyRefusedChirho => {
                "geo-genesis member config projection source fails custody"
            }
            Self::ConfigProjectionSourceRefusedChirho => {
                "geo-genesis member config projection source is structurally invalid"
            }
            Self::ConfigCrossBindCoverageRefusedChirho => {
                "geo-genesis config sources do not cover the plan population"
            }
            Self::ConfigProjectionDigestMismatchChirho => {
                "geo-genesis config projection digest does not match the plan build"
            }
            Self::DryRunCountOverflowChirho => "geo-genesis dry-run packet count overflowed",
            Self::DryRunTokenBindingRefusedChirho => {
                "geo-genesis dry-run packet tokens do not bind the same plan"
            }
            Self::DryRunPacketRefusedChirho { .. } => "geo-genesis dry-run packet is refused",
        };
        formatter_chirho.write_str(message_chirho)?;
        match self {
            Self::UnresolvedRulingChirho { field_chirho } => {
                write!(formatter_chirho, ": {field_chirho:?}")
            }
            Self::DuplicateMemberCoordinateChirho { coordinate_chirho } => {
                write!(formatter_chirho, ": {coordinate_chirho:?}")
            }
            Self::GgVerdictRefusedChirho { gg_index_chirho } => {
                write!(formatter_chirho, ": gg{gg_index_chirho}")
            }
            Self::AcceptanceEquationRefusedChirho { equation_chirho } => {
                write!(formatter_chirho, ": equation {equation_chirho}")
            }
            Self::CrossRoleMessageClassRefusedChirho {
                signer_role_chirho,
                message_class_chirho,
            } => {
                write!(
                    formatter_chirho,
                    ": {signer_role_chirho:?} cannot sign {message_class_chirho:?}"
                )
            }
            Self::GenesisAlreadyReservedChirho { holder_role_chirho }
            | Self::GuardMarkerUnverifiableChirho { holder_role_chirho } => {
                write!(formatter_chirho, ": {holder_role_chirho:?}")
            }
            Self::CustodyPresenceMemberPinRefusedChirho { coordinate_chirho } => {
                write!(formatter_chirho, ": {coordinate_chirho:?}")
            }
            Self::DryRunPacketRefusedChirho { reason_chirho } => {
                write!(formatter_chirho, ": {reason_chirho}")
            }
            _ => Ok(()),
        }
    }
}

impl Error for GeoGenesisRefusalChirho {}
