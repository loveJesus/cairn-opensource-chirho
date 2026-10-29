// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Measured usage, NODE-signed — the third capacity source, bound to the node that produced it.
//!
//! CF8 acceptance, verbatim: *"measured usage is **node-signed** with HLC and monotone sequence."*
//! [`super::measurement_freshness_chirho`] already reasons carefully about stale and replayed stamps and
//! freezes scaling in both directions — but until now it classified an UNSIGNED number:
//! `MeasurementStampChirho` carried the HLC and the sequence and nothing binding either to the node that
//! reported them. Freshness without attribution answers "is this recent" and never "whose is it".
//!
//! **Node-signed, and that asymmetry against capacity grants is deliberate.** A capacity grant is a
//! statement about what a node may OFFER — an operator act, so a registrar signs it, and a node signing
//! its own allocatable would be self-attestation. Measured usage is the opposite kind of fact: a report
//! about the node's own observed state, which only the node can produce. So the authority here is the
//! NODE's key, and the caller supplies a per-node port rather than one registrar port for the fleet.
//!
//! **This does not make the number true.** A node reports its own usage and could report it wrongly;
//! nothing in a signature fixes that. What signing buys is that a usage figure is attributable and
//! unforgeable BY OTHER NODES, so one node cannot report usage on another's behalf to have it drained or
//! filled. Corroborating the figure against the world is a different problem and is not claimed here.
//!
//! Follows the shared envelope contract:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/signed-authority-chirho/signed-intent-envelope-contract-chirho.md`.
//!
//! Pure: no I/O, no clock. Freshness classification stays in `measurement_freshness_chirho`; this module
//! establishes only that the stamp is authentic and whose it is.

use super::capacity_dominance_chirho::AllocatableCapacityChirho;
use super::measurement_freshness_chirho::MeasurementStampChirho;
use cairn_core_chirho::store_chirho::hash_object_chirho;
use serde::{Deserialize, Serialize};

pub const USAGE_MEASUREMENT_INTENT_SCHEMA_V1_CHIRHO: &str =
    "cairn.node-usage-measurement-intent.v1.chirho";
pub const USAGE_MEASUREMENT_ATTESTATION_SCHEMA_V1_CHIRHO: &str =
    "cairn.node-usage-measurement-attestation.v1.chirho";
pub const USAGE_MEASUREMENT_ATTESTATION_DOMAIN_V1_CHIRHO: &str =
    "cairn.node-usage-measurement-attestation.domain.v1.chirho";
pub const MAX_USAGE_TOKEN_BYTES_CHIRHO: usize = 128;
/// A signature is not an identifier: a bare ed25519 signature in hex is exactly 128 chars.
pub const MAX_USAGE_SIGNATURE_BYTES_CHIRHO: usize = 512;

/// Verification-only measurement authority, keyed to ONE node. There is deliberately no `sign_chirho`.
///
/// Per-node rather than per-fleet on purpose: the whole point is that a usage report is bound to the
/// node that made it, and a single fleet-wide key would let any holder report for any node.
pub trait NodeMeasurementAuthorityPortChirho {
    /// The signing key expected for THIS node.
    fn node_key_id_chirho(&self) -> String;
    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool;
}

/// What the node reports about itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageMeasurementIntentChirho {
    pub schema_chirho: String,
    pub node_id_chirho: String,
    /// HLC reading and per-node monotone sequence — the freshness coordinates the clause names.
    pub stamp_chirho: MeasurementStampChirho,
    /// Observed usage, in the SAME units as allocatable capacity and placement demand, because the
    /// clause requires demand and capacity to share units and a third unit here would silently break
    /// every headroom comparison.
    pub observed_usage_chirho: AllocatableCapacityChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageMeasurementAttestationChirho {
    pub schema_chirho: String,
    pub signature_domain_chirho: String,
    pub intent_chirho: UsageMeasurementIntentChirho,
    pub intent_digest_chirho: String,
    pub node_key_id_chirho: String,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UsageMeasurementRefusalChirho {
    RecordSchemaMismatchChirho {
        found_chirho: String,
    },
    IntentSchemaMismatchChirho {
        found_chirho: String,
    },
    SignatureDomainMismatchChirho {
        found_chirho: String,
    },
    FieldTooLongChirho {
        field_chirho: String,
        bytes_chirho: usize,
    },
    /// Signed by a key that is not this node's. Distinct from a bad signature: an operator who wired the
    /// wrong node's key deserves to be told which mistake they made.
    UnknownNodeKeyChirho {
        found_chirho: String,
        expected_chirho: String,
    },
    IntentDigestMismatchChirho {
        found_chirho: String,
        recomputed_chirho: String,
    },
    SignatureInvalidChirho,
    /// A measurement for a different node than the caller is reading. The report is authentic and
    /// belongs to somebody else.
    NodeIdMismatchChirho {
        found_chirho: String,
        expected_chirho: String,
    },
    EncodeChirho,
}

/// A usage report that verified against the node's own key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedUsageMeasurementChirho {
    intent_chirho: UsageMeasurementIntentChirho,
}

impl VerifiedUsageMeasurementChirho {
    pub fn node_id_chirho(&self) -> &str {
        &self.intent_chirho.node_id_chirho
    }
    pub fn stamp_chirho(&self) -> MeasurementStampChirho {
        self.intent_chirho.stamp_chirho
    }
    /// Build a verified measurement WITHOUT a signature, for arms in other modules that are about
    /// what a registry does with verified evidence rather than about how it got verified. Test-only:
    /// production reaches this type solely through `verify_usage_measurement_chirho`.
    #[cfg(test)]
    pub(crate) fn unverified_for_test_chirho(
        node_id_chirho: &str,
        stamp_chirho: MeasurementStampChirho,
        observed_usage_chirho: AllocatableCapacityChirho,
    ) -> Self {
        Self {
            intent_chirho: UsageMeasurementIntentChirho {
                schema_chirho: USAGE_MEASUREMENT_INTENT_SCHEMA_V1_CHIRHO.to_string(),
                node_id_chirho: node_id_chirho.to_string(),
                stamp_chirho,
                observed_usage_chirho,
            },
        }
    }

    pub fn observed_usage_chirho(&self) -> &AllocatableCapacityChirho {
        &self.intent_chirho.observed_usage_chirho
    }
}

pub fn usage_intent_digest_chirho(
    intent_chirho: &UsageMeasurementIntentChirho,
) -> Result<String, UsageMeasurementRefusalChirho> {
    hash_object_chirho(intent_chirho)
        .map(|hash_chirho| hash_chirho.0)
        .map_err(|_error_chirho| UsageMeasurementRefusalChirho::EncodeChirho)
}

/// The exact bytes a node signs. Binds both schemas and the node key as well as the domain.
pub fn unsigned_usage_message_chirho(record_chirho: &UsageMeasurementAttestationChirho) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        record_chirho.signature_domain_chirho,
        record_chirho.schema_chirho,
        record_chirho.intent_chirho.schema_chirho,
        record_chirho.node_key_id_chirho,
        record_chirho.intent_digest_chirho,
    )
}

/// Verify one usage report for `expected_node_id_chirho` against that node's key.
///
/// Order per the envelope contract: shape, bounds, KEY, recomputed digest, signature, then node binding.
pub fn verify_usage_measurement_chirho(
    record_chirho: &UsageMeasurementAttestationChirho,
    authority_chirho: &dyn NodeMeasurementAuthorityPortChirho,
    expected_node_id_chirho: &str,
) -> Result<VerifiedUsageMeasurementChirho, UsageMeasurementRefusalChirho> {
    if record_chirho.schema_chirho != USAGE_MEASUREMENT_ATTESTATION_SCHEMA_V1_CHIRHO {
        return Err(UsageMeasurementRefusalChirho::RecordSchemaMismatchChirho {
            found_chirho: record_chirho.schema_chirho.clone(),
        });
    }
    if record_chirho.intent_chirho.schema_chirho != USAGE_MEASUREMENT_INTENT_SCHEMA_V1_CHIRHO {
        return Err(UsageMeasurementRefusalChirho::IntentSchemaMismatchChirho {
            found_chirho: record_chirho.intent_chirho.schema_chirho.clone(),
        });
    }
    if record_chirho.signature_domain_chirho != USAGE_MEASUREMENT_ATTESTATION_DOMAIN_V1_CHIRHO {
        return Err(
            UsageMeasurementRefusalChirho::SignatureDomainMismatchChirho {
                found_chirho: record_chirho.signature_domain_chirho.clone(),
            },
        );
    }
    for (field_chirho, value_chirho, bound_chirho) in [
        (
            "node_id_chirho",
            &record_chirho.intent_chirho.node_id_chirho,
            MAX_USAGE_TOKEN_BYTES_CHIRHO,
        ),
        (
            "node_key_id_chirho",
            &record_chirho.node_key_id_chirho,
            MAX_USAGE_TOKEN_BYTES_CHIRHO,
        ),
        (
            "intent_digest_chirho",
            &record_chirho.intent_digest_chirho,
            MAX_USAGE_TOKEN_BYTES_CHIRHO,
        ),
        (
            "sig_chirho",
            &record_chirho.sig_chirho,
            MAX_USAGE_SIGNATURE_BYTES_CHIRHO,
        ),
    ] {
        if value_chirho.len() > bound_chirho {
            return Err(UsageMeasurementRefusalChirho::FieldTooLongChirho {
                field_chirho: field_chirho.to_string(),
                bytes_chirho: value_chirho.len(),
            });
        }
    }
    // Key BEFORE signature, per the envelope contract.
    let expected_key_chirho = authority_chirho.node_key_id_chirho();
    if record_chirho.node_key_id_chirho != expected_key_chirho {
        return Err(UsageMeasurementRefusalChirho::UnknownNodeKeyChirho {
            found_chirho: record_chirho.node_key_id_chirho.clone(),
            expected_chirho: expected_key_chirho,
        });
    }
    let recomputed_chirho = usage_intent_digest_chirho(&record_chirho.intent_chirho)?;
    if recomputed_chirho != record_chirho.intent_digest_chirho {
        return Err(UsageMeasurementRefusalChirho::IntentDigestMismatchChirho {
            found_chirho: record_chirho.intent_digest_chirho.clone(),
            recomputed_chirho,
        });
    }
    if !authority_chirho.verify_chirho(
        &unsigned_usage_message_chirho(record_chirho),
        &record_chirho.sig_chirho,
    ) {
        return Err(UsageMeasurementRefusalChirho::SignatureInvalidChirho);
    }
    if record_chirho.intent_chirho.node_id_chirho != expected_node_id_chirho {
        return Err(UsageMeasurementRefusalChirho::NodeIdMismatchChirho {
            found_chirho: record_chirho.intent_chirho.node_id_chirho.clone(),
            expected_chirho: expected_node_id_chirho.to_string(),
        });
    }
    Ok(VerifiedUsageMeasurementChirho {
        intent_chirho: record_chirho.intent_chirho.clone(),
    })
}

#[cfg(test)]
#[path = "usage_measurement_attestation_tests_chirho.rs"]
mod usage_measurement_attestation_tests_chirho;
