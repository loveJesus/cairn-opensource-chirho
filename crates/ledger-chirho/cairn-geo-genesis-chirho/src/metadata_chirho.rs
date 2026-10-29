// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Closed infrastructure vocabularies (section 3.1). Adding a provider, region, target, role, or
//! test kind is a reviewed V2 schema event, never an `OtherChirho(String)` escape hatch — every enum
//! is field-less with an explicit snake-case wire token, so an unreviewed label refuses at parse.

use serde::{Deserialize, Serialize};

/// Infrastructure provider class; covers the mapped topology and recorded later options only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoProviderChirho {
    HetznerChirho,
    OvhChirho,
    AwsChirho,
    DigitalOceanChirho,
}

/// Failure-domain region class; no hostname or free-form location text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoRegionChirho {
    GermanyChirho,
    FranceChirho,
    UnitedStatesChirho,
}

/// Build target; each variant fixes both the triple and the architecture, so the historical
/// architecture/triple mismatch is unrepresentable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoBuildTargetChirho {
    Aarch64UnknownLinuxGnuChirho,
    X8664UnknownLinuxGnuChirho,
}

/// Raft membership role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoMemberRoleChirho {
    VoterChirho,
    LearnerChirho,
}

/// Required endpoint role on a member; each carries exactly one numeric address/port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoEndpointRoleChirho {
    ElectionChirho,
    MirrorChirho,
    CapabilityReadChirho,
}

/// Synthetic canary kind; only the reviewed synthetic-credits canary exists in V1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoCanaryKindChirho {
    SyntheticCreditsCanaryV1Chirho,
}

/// The eight product goal-gate keys, GG1 through GG8.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoGgKeyChirho {
    Gg1Chirho,
    Gg2Chirho,
    Gg3Chirho,
    Gg4Chirho,
    Gg5Chirho,
    Gg6Chirho,
    Gg7Chirho,
    Gg8Chirho,
}

/// A GG disposition verdict; the allowed key/verdict pairs are checked at the disposition level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoGgVerdictChirho {
    VerifiedSatisfiedChirho,
    VerifiedWiringReadyChirho,
    StandingAdditiveChirho,
}

/// The four ordered genesis phases; a record's phase token is fixed at its type, never caller-open.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoGenesisPhaseChirho {
    PlanVerifiedChirho,
    IntentReservedChirho,
    RootPublishedChirho,
    HostedAcceptedChirho,
}

/// The single member-admission phase; an unadmitted record cannot parse as an admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoMemberAdmissionPhaseChirho {
    AdmittedChirho,
}
