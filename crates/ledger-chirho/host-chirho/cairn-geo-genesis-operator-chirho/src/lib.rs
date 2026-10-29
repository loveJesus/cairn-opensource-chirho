// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Read-only geo-genesis operator checks: verify a candidate plan against the two pinned authority keys
//! and the reviewed ledger plan, and verify a dry-run packet's bytes. Each answers with one report of
//! safe digests and counts, and the crate names no door that mutates a root or makes a key.
//!
//! BUILDING a dry-run packet is not here. `build_dry_run_packet_chirho` needs a custody-presence token,
//! which comes only from `GeoOperatorCustodyConfigV1Chirho`. By design that config has no file form, and
//! its loader is brick 8.7.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/item8-geo-genesis-plan-design-chirho.md` §9-§10.

use cairn_geo_genesis_chirho::{
    verify_dry_run_packet_chirho, verify_plan_chirho, GeoEd25519PublicKeyChirho,
    GeoGenesisDryRunPacketV1Chirho, GeoGenesisRefusalChirho, GeoGenesisTrustPinsChirho,
};
use cairn_ledger_regenesis_chirho::{canonical_plan_bytes_chirho, LedgerRegenesisPlanV1Chirho};
use serde::Serialize;

/// The largest plan, ledger plan or packet file the operator reads.
pub const OPERATOR_INPUT_MAX_BYTES_CHIRHO: u64 = 1024 * 1024;
pub const PLAN_REPORT_SCHEMA_CHIRHO: &str = "geo-genesis-plan-verify-report-v1-chirho";
pub const DRY_RUN_REPORT_SCHEMA_CHIRHO: &str = "geo-genesis-dry-run-verify-report-v1-chirho";
pub const REFUSAL_SCHEMA_CHIRHO: &str = "geo-genesis-operator-refusal-v1-chirho";

/// Why a check refused. Every variant is a fixed identity: none carries a path, a key or a file byte.
#[derive(Debug)]
pub enum OperatorRefusalChirho {
    /// An input file could not be read within the bound, as a single-link regular file.
    InputUnreadableChirho { input_chirho: &'static str },
    /// A pin is not the hex form of a 32-byte Ed25519 public key.
    PinKeyInvalidChirho { pin_chirho: &'static str },
    /// The reviewed ledger plan does not parse as `LedgerRegenesisPlanV1Chirho`.
    LedgerPlanInvalidChirho,
    /// The reviewed ledger plan parses, but its bytes are not its canonical bytes.
    LedgerPlanNotCanonicalChirho,
    /// The genesis crate's own typed refusal.
    GenesisChirho(GeoGenesisRefusalChirho),
}

impl OperatorRefusalChirho {
    /// The refusal's fixed identity, for the one refusal line.
    pub fn identity_chirho(&self) -> String {
        match self {
            Self::InputUnreadableChirho { input_chirho } => {
                format!("InputUnreadableChirho:{input_chirho}")
            }
            Self::PinKeyInvalidChirho { pin_chirho } => format!("PinKeyInvalidChirho:{pin_chirho}"),
            Self::LedgerPlanInvalidChirho => "LedgerPlanInvalidChirho".to_string(),
            Self::LedgerPlanNotCanonicalChirho => "LedgerPlanNotCanonicalChirho".to_string(),
            Self::GenesisChirho(refusal_chirho) => format!("{refusal_chirho:?}"),
        }
    }
}

/// What a verified plan safely reports.
#[derive(Debug, Serialize)]
pub struct PlanVerifyReportChirho {
    pub schema_chirho: &'static str,
    pub plan_digest_chirho: serde_json::Value,
}

/// What a verified dry-run packet reports: the packet itself, which carries only counts, closed enums
/// and digests by construction.
#[derive(Debug, Serialize)]
pub struct DryRunVerifyReportChirho {
    pub schema_chirho: &'static str,
    pub packet_chirho: GeoGenesisDryRunPacketV1Chirho,
}

/// Verify candidate plan bytes against the two pinned authority keys and the reviewed ledger plan.
pub fn verify_plan_report_chirho(
    plan_bytes_chirho: &[u8],
    ledger_plan_bytes_chirho: &[u8],
    plan_authority_key_hex_chirho: &str,
    acceptance_authority_key_hex_chirho: &str,
) -> Result<PlanVerifyReportChirho, OperatorRefusalChirho> {
    let plan_authority_key_chirho =
        pin_key_chirho(plan_authority_key_hex_chirho, "plan-authority")?;
    let acceptance_authority_key_chirho =
        pin_key_chirho(acceptance_authority_key_hex_chirho, "acceptance-authority")?;
    let pins_chirho = GeoGenesisTrustPinsChirho::new_split_chirho(
        plan_authority_key_chirho,
        acceptance_authority_key_chirho,
    )
    .map_err(OperatorRefusalChirho::GenesisChirho)?;
    let ledger_plan_chirho = reviewed_ledger_plan_chirho(ledger_plan_bytes_chirho)?;
    let verified_chirho = verify_plan_chirho(plan_bytes_chirho, &pins_chirho, &ledger_plan_chirho)
        .map_err(OperatorRefusalChirho::GenesisChirho)?;
    Ok(PlanVerifyReportChirho {
        schema_chirho: PLAN_REPORT_SCHEMA_CHIRHO,
        plan_digest_chirho: serde_json::to_value(verified_chirho.plan_digest_chirho())
            .expect("a plan digest serializes"),
    })
}

/// Verify dry-run packet bytes: canonical round-trip, integrity digest and the no-leak scan.
pub fn verify_dry_run_report_chirho(
    packet_bytes_chirho: &[u8],
) -> Result<DryRunVerifyReportChirho, OperatorRefusalChirho> {
    let packet_chirho = verify_dry_run_packet_chirho(packet_bytes_chirho)
        .map_err(OperatorRefusalChirho::GenesisChirho)?;
    Ok(DryRunVerifyReportChirho {
        schema_chirho: DRY_RUN_REPORT_SCHEMA_CHIRHO,
        packet_chirho,
    })
}

fn pin_key_chirho(
    hex_chirho: &str,
    pin_chirho: &'static str,
) -> Result<GeoEd25519PublicKeyChirho, OperatorRefusalChirho> {
    GeoEd25519PublicKeyChirho::from_hex_chirho(hex_chirho)
        .map_err(|_error_chirho| OperatorRefusalChirho::PinKeyInvalidChirho { pin_chirho })
}

/// The reviewed ledger plan, only in its canonical bytes, so the plan is checked against exactly the
/// bytes that were reviewed.
fn reviewed_ledger_plan_chirho(
    bytes_chirho: &[u8],
) -> Result<LedgerRegenesisPlanV1Chirho, OperatorRefusalChirho> {
    let plan_chirho: LedgerRegenesisPlanV1Chirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_error_chirho| OperatorRefusalChirho::LedgerPlanInvalidChirho)?;
    let canonical_chirho = canonical_plan_bytes_chirho(&plan_chirho)
        .map_err(|_error_chirho| OperatorRefusalChirho::LedgerPlanInvalidChirho)?;
    if canonical_chirho != bytes_chirho {
        return Err(OperatorRefusalChirho::LedgerPlanNotCanonicalChirho);
    }
    Ok(plan_chirho)
}
