// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Verify one signed conservation snapshot, then MEASURE conservation with the single CF4 checker.
//!
//! This port exists so the converger stops accepting a caller's `conservation_zero_sum` boolean. The
//! contract carries the snapshot ROWS, never a verdict: a signed verdict is a forgeable aggregate,
//! because re-signing a tampered verdict leaves the consumer nothing but the signature to refuse. By
//! carrying rows, a tamper that breaks conservation and is honestly re-signed still refuses — at the
//! conservation law, not at the signature.
//!
//! The equations are NOT restated here. [`cairn_ledger_conservation_monitor_chirho`] is a pure leaf
//! (its only dependency is the shared ledger model) and owns seven laws: two drift laws plus five
//! STRUCTURAL laws that are precisely how a tampered snapshot would otherwise hide drift — by
//! duplicating, omitting, or orphaning a row. A partial host-side mirror would be silently weaker
//! than the checker it claims to mirror, and two money-conservation checkers that must agree forever
//! is the worse hazard. So this module verifies authenticity and delegates arithmetic.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.

use cairn_ledger_conservation_monitor_chirho::model_chirho::{
    DomainKindConservationRollupChirho, GlobalKindSupplyChirho,
    HeadConsistentConservationSnapshotChirho,
};
use cairn_ledger_conservation_monitor_chirho::ports_chirho::VerifiedConservationSnapshotPortChirho;
use cairn_ledger_conservation_monitor_chirho::{
    run_conservation_monitor_once_chirho, ConservationMonitorFailureChirho,
};

use super::contract_chirho::Gd7PlanRefusalChirho;
use std::sync::Arc;

pub const GD7_CONSERVATION_SNAPSHOT_SCHEMA_V1_CHIRHO: &str = "gd7-conservation-snapshot-v1-chirho";

/// One conservation snapshot with the signature over its canonical content line.
///
/// The signature covers [`gd7_conservation_snapshot_signed_content_line_chirho`], so every quantity
/// the checker will read is inside the signed bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedGd7ConservationSnapshotChirho {
    pub snapshot_chirho: HeadConsistentConservationSnapshotChirho,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

/// Supplies the signed conservation snapshot for the cut being certified.
///
/// The adapter owes the monitor port's own contract: verify sources, bind coverage to signed
/// registries, and acquire every view at ONE signed head. This port adds the signature so the
/// converger can check authenticity itself rather than trusting the adapter's word for it.
pub trait Gd7ConservationSnapshotSourcePortChirho {
    fn load_signed_conservation_snapshot_chirho(
        &self,
    ) -> Result<SignedGd7ConservationSnapshotChirho, Gd7PlanRefusalChirho>;
}

/// Injected verification root for the conservation snapshot signer.
///
/// Deliberately separate from the source: a port that both supplies and vouches for its own bytes
/// could verify its own tampering.
pub trait Gd7ConservationSnapshotVerifierPortChirho {
    fn key_id_chirho(&self) -> String;
    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool;
}

pub struct Gd7ConservationProofPortsChirho<'ports_chirho> {
    source_chirho: &'ports_chirho dyn Gd7ConservationSnapshotSourcePortChirho,
    verifier_chirho: &'ports_chirho dyn Gd7ConservationSnapshotVerifierPortChirho,
}

/// Spawn-owned, read-only conservation source for per-reconciliation certification.
///
/// Implementations reopen and verify their source on every call. This is deliberately not a
/// cached snapshot and is not an append-path dependency: certification is a cold reconciliation
/// operation. The actor owns the provider; mailbox callers can provide no conservation evidence.
pub trait Gd7ConservationSnapshotProviderChirho: Send + Sync {
    fn load_signed_conservation_snapshot_chirho(
        &self,
    ) -> Result<SignedGd7ConservationSnapshotChirho, Gd7PlanRefusalChirho>;
}

pub type Gd7ConservationSnapshotProviderRefChirho = Arc<dyn Gd7ConservationSnapshotProviderChirho>;

impl<'ports_chirho> Gd7ConservationProofPortsChirho<'ports_chirho> {
    pub fn new_chirho(
        source_chirho: &'ports_chirho dyn Gd7ConservationSnapshotSourcePortChirho,
        verifier_chirho: &'ports_chirho dyn Gd7ConservationSnapshotVerifierPortChirho,
    ) -> Self {
        Self {
            source_chirho,
            verifier_chirho,
        }
    }
}

/// Conservation evidence MEASURED by the CF4 checker over a signature-verified snapshot.
///
/// Fields are private with no public constructor, so a caller cannot hand the converger an
/// assertion about conservation it did not measure — the same discipline as the terminal evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gd7ConservationEvidenceChirho {
    snapshot_digest_chirho: String,
    head_checkpoint_digest_chirho: String,
    domain_kind_rollups_checked_chirho: u64,
    global_supplies_checked_chirho: u64,
}

impl Gd7ConservationEvidenceChirho {
    pub fn snapshot_digest_chirho(&self) -> &str {
        &self.snapshot_digest_chirho
    }

    pub fn head_checkpoint_digest_chirho(&self) -> &str {
        &self.head_checkpoint_digest_chirho
    }

    pub fn domain_kind_rollups_checked_chirho(&self) -> u64 {
        self.domain_kind_rollups_checked_chirho
    }

    pub fn global_supplies_checked_chirho(&self) -> u64 {
        self.global_supplies_checked_chirho
    }
}

/// Host-owned canonical wire mirror of the snapshot.
///
/// The monitor's DTOs deliberately derive no `Serialize`, and that is kept: the signed bytes must
/// not depend on a foreign crate's field order or derive. These key names are OURS, so a field
/// reordering upstream cannot silently move what a signature covers. Amounts are decimal STRINGS
/// because `u128` exceeds what a JSON number is portably specified to carry.
#[derive(serde::Serialize)]
struct ConservationSnapshotWireChirho<'wire_chirho> {
    schema_chirho: &'static str,
    head_epoch_chirho: u64,
    head_checkpoint_digest_chirho: &'wire_chirho str,
    head_covered_record_count_chirho: u64,
    rollups_chirho: Vec<ConservationRollupWireChirho<'wire_chirho>>,
    global_supplies_chirho: Vec<ConservationGlobalSupplyWireChirho<'wire_chirho>>,
}

#[derive(serde::Serialize)]
struct ConservationRollupWireChirho<'wire_chirho> {
    money_group_chirho: &'wire_chirho str,
    cluster_chirho: &'wire_chirho str,
    kind_id_chirho: &'wire_chirho str,
    account_net_chirho: String,
    local_supply_chirho: String,
}

#[derive(serde::Serialize)]
struct ConservationGlobalSupplyWireChirho<'wire_chirho> {
    money_group_chirho: &'wire_chirho str,
    kind_id_chirho: &'wire_chirho str,
    supply_chirho: String,
}

/// Canonical signed content line for one conservation snapshot.
///
/// JSON is chosen for the same reason the convergence outcome rows use it: its escaping keeps the
/// encoding injective over the free-form money-group, cluster, and kind identifiers, so two
/// different snapshots cannot canonicalize to the same bytes and hide a tamper.
///
/// ROW ORDER IS CANONICALIZED HERE, and that is load-bearing rather than tidiness. A snapshot's
/// rollups and supplies are SETS; their vector order is an artifact of whichever adapter built
/// them. The CF4 checker already reads them order-independently (it keys them into maps), so
/// without this sort two byte-different lines would check identically while producing two different
/// certificate digests for the same money state. Sorting makes the digest a function of the money,
/// not of the adapter's insertion order.
///
/// The sort key includes the AMOUNTS, so rows sharing a key still order deterministically — and it
/// deliberately does not deduplicate: a duplicated rollup must survive into the encoding so the
/// checker's structural law still fires on it.
pub fn gd7_conservation_snapshot_signed_content_line_chirho(
    snapshot_chirho: &HeadConsistentConservationSnapshotChirho,
) -> Result<String, Gd7PlanRefusalChirho> {
    let mut rollups_chirho: Vec<&DomainKindConservationRollupChirho> =
        snapshot_chirho.rollups_chirho.iter().collect();
    rollups_chirho.sort_by(|left_chirho, right_chirho| {
        (
            &left_chirho.domain_chirho.money_group_chirho,
            &left_chirho.domain_chirho.cluster_chirho,
            &left_chirho.kind_id_chirho,
            left_chirho.account_net_chirho,
            left_chirho.local_supply_chirho,
        )
            .cmp(&(
                &right_chirho.domain_chirho.money_group_chirho,
                &right_chirho.domain_chirho.cluster_chirho,
                &right_chirho.kind_id_chirho,
                right_chirho.account_net_chirho,
                right_chirho.local_supply_chirho,
            ))
    });
    let mut supplies_chirho: Vec<&GlobalKindSupplyChirho> =
        snapshot_chirho.global_supplies_chirho.iter().collect();
    supplies_chirho.sort_by(|left_chirho, right_chirho| {
        (
            &left_chirho.money_group_chirho,
            &left_chirho.kind_id_chirho,
            left_chirho.supply_chirho,
        )
            .cmp(&(
                &right_chirho.money_group_chirho,
                &right_chirho.kind_id_chirho,
                right_chirho.supply_chirho,
            ))
    });
    let wire_chirho = ConservationSnapshotWireChirho {
        schema_chirho: GD7_CONSERVATION_SNAPSHOT_SCHEMA_V1_CHIRHO,
        head_epoch_chirho: snapshot_chirho.head_chirho.epoch_chirho,
        head_checkpoint_digest_chirho: &snapshot_chirho.head_chirho.checkpoint_digest_chirho.0,
        head_covered_record_count_chirho: snapshot_chirho.head_chirho.covered_record_count_chirho,
        rollups_chirho: rollups_chirho
            .into_iter()
            .map(|rollup_chirho| ConservationRollupWireChirho {
                money_group_chirho: &rollup_chirho.domain_chirho.money_group_chirho.0,
                cluster_chirho: &rollup_chirho.domain_chirho.cluster_chirho.0,
                kind_id_chirho: &rollup_chirho.kind_id_chirho.0,
                account_net_chirho: rollup_chirho.account_net_chirho.to_string(),
                local_supply_chirho: rollup_chirho.local_supply_chirho.to_string(),
            })
            .collect(),
        global_supplies_chirho: supplies_chirho
            .into_iter()
            .map(|supply_chirho| ConservationGlobalSupplyWireChirho {
                money_group_chirho: &supply_chirho.money_group_chirho.0,
                kind_id_chirho: &supply_chirho.kind_id_chirho.0,
                supply_chirho: supply_chirho.supply_chirho.to_string(),
            })
            .collect(),
    };
    serde_json::to_string(&wire_chirho).map_err(|_| Gd7PlanRefusalChirho::SerializationChirho)
}

/// Adapt an ALREADY signature-verified snapshot to the checker's own read-only port.
///
/// The monitor port's contract binds adapters to verify before returning. That obligation is
/// discharged by [`verify_gd7_conservation_snapshot_chirho`], which is the only constructor of this
/// wrapper and does the signature check first — the wrapper is never reachable with unverified bytes.
struct VerifiedLoadedSnapshotPortChirho(HeadConsistentConservationSnapshotChirho);

impl VerifiedConservationSnapshotPortChirho for VerifiedLoadedSnapshotPortChirho {
    type ErrorChirho = std::convert::Infallible;

    fn load_verified_head_consistent_snapshot_chirho(
        &self,
    ) -> Result<HeadConsistentConservationSnapshotChirho, Self::ErrorChirho> {
        Ok(self.0.clone())
    }
}

/// Verify the snapshot's signature, then MEASURE conservation through the CF4 checker.
///
/// Order is load-time critical: authenticity first, arithmetic second. The two refusals are
/// deliberately distinct types so a caller — and a tamper arm — can tell "these bytes were not
/// signed by the expected root" apart from "these authentic bytes do not conserve money".
pub(super) fn verify_gd7_conservation_snapshot_chirho(
    ports_chirho: &Gd7ConservationProofPortsChirho<'_>,
) -> Result<Gd7ConservationEvidenceChirho, Gd7PlanRefusalChirho> {
    let signed_chirho = ports_chirho
        .source_chirho
        .load_signed_conservation_snapshot_chirho()?;
    let content_line_chirho =
        gd7_conservation_snapshot_signed_content_line_chirho(&signed_chirho.snapshot_chirho)?;
    if signed_chirho.key_id_chirho != ports_chirho.verifier_chirho.key_id_chirho()
        || !ports_chirho
            .verifier_chirho
            .verify_chirho(&content_line_chirho, &signed_chirho.sig_chirho)
    {
        return Err(Gd7PlanRefusalChirho::InvalidConservationSnapshotSignatureChirho);
    }

    let green_chirho = run_conservation_monitor_once_chirho(&VerifiedLoadedSnapshotPortChirho(
        signed_chirho.snapshot_chirho.clone(),
    ))
    .map_err(|failure_chirho| match failure_chirho {
        ConservationMonitorFailureChirho::IncidentChirho(incident_chirho) => {
            Gd7PlanRefusalChirho::ConservationIncidentChirho(incident_chirho.kind_chirho)
        }
        // The wrapper's error type is uninhabited: the snapshot is already in hand here.
        ConservationMonitorFailureChirho::VerifiedSnapshotUnavailableChirho(never_chirho) => {
            match never_chirho {}
        }
    })?;

    Ok(Gd7ConservationEvidenceChirho {
        snapshot_digest_chirho: blake3::hash(content_line_chirho.as_bytes())
            .to_hex()
            .to_string(),
        head_checkpoint_digest_chirho: green_chirho.head_chirho.checkpoint_digest_chirho.0.clone(),
        domain_kind_rollups_checked_chirho: u64::try_from(
            green_chirho.domain_kind_rollups_checked_chirho,
        )
        .map_err(|_| Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?,
        global_supplies_checked_chirho: u64::try_from(green_chirho.global_supplies_checked_chirho)
            .map_err(|_| Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?,
    })
}
