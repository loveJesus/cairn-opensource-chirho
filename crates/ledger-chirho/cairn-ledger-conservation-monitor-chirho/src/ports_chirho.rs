// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Read-only verified-view port for one standing conservation check.

use crate::model_chirho::HeadConsistentConservationSnapshotChirho;

/// Supplies a complete conservation snapshot from verified views at one signed checkpoint.
///
/// Contract, binding on every adapter:
///
/// - verify content addresses, signatures, source completeness, and projection/supply derivation
///   before returning; raw projection, local-supply, or issuer-supply rows are forbidden;
/// - bind coverage and cardinality to the verified domain and stable-kind registries; unregistered
///   or incomplete input fails closed, every observed `(money-group, kind)` aggregate has exactly
///   one issuer-supply row, no issuer row lacks domain coverage, and allocation remains bounded by
///   those signed inventories;
/// - acquire account rollups, local-supply allocations, and independent R2 issuer supplies at one
///   atomic signed head/epoch cut, never as independently sampled views;
/// - fail closed on unavailable, unverified, mixed-head, or incomplete input;
/// - remain read-only. This port has no correction, rebalance, admission, or persistence method.
///
/// Projection and supply owners implement this trait above the pure checker. The checker therefore
/// depends downward only on ledger DTOs and can survive Gate-1 deletion and serve as a CF6 regenesis
/// acceptance gate.
pub trait VerifiedConservationSnapshotPortChirho {
    type ErrorChirho;

    fn load_verified_head_consistent_snapshot_chirho(
        &self,
    ) -> Result<HeadConsistentConservationSnapshotChirho, Self::ErrorChirho>;
}
