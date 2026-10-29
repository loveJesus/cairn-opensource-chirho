// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! A node's allocatable capacity is a GRANT it is given, never a number it declares about itself.
//!
//! CF8 clause 7, verbatim: *"allocatable CPU millicores/memory bytes/durable bytes are **signed at
//! node registration**"*. The clause does not say by whom, and that omission decides the whole
//! design, so it is ruled here rather than left to a caller.
//!
//! **Registrar-signed, verified at the node — never node-signed.** A node signing its own allocatable
//! capacity is self-attestation: a compromised or merely misconfigured node declares whatever
//! capacity it likes and then satisfies its own admission check. Inflated allocatable is not a
//! cosmetic error — it is exactly what lets a placement land somewhere that cannot hold it. So this
//! port exposes verification ONLY. A node can refuse a capacity grant it was not given; it cannot
//! mint one. That is the same shape, for the same reason, as the tenant-migration destination
//! authority port, whose header says a destination signed by the moving node "would be
//! self-authorization".
//!
//! **The asymmetry against measured usage is deliberate, not an inconsistency.** Clause 7 requires
//! measured usage to be NODE-signed, and that is right: usage is a report about the node's own
//! observed state, which only the node can produce, and which
//! [`super::measurement_freshness_chirho`] already treats as untrusted — replayed and clock-rewound
//! both freeze the node. Allocatable is the opposite kind of fact: a statement of what the node is
//! permitted to offer, which is an operator act.
//!
//! **Check order is part of the contract.** The authority key is checked BEFORE the signature, so an
//! attestation from an unknown signer refuses as `UnknownAuthorityKeyChirho` rather than as a bare
//! signature failure — an operator who pasted the wrong key is told which mistake they made. The
//! intent digest is RECOMPUTED rather than trusted, because a self-reported digest verifies only that
//! the record is internally consistent with itself.
//!
//! Pure: no I/O, no clock. Verification is a trait call the caller supplies.

use super::capacity_dominance_chirho::AllocatableCapacityChirho;
use crate::failure_domain_chirho::FailureDomainChirho;
use cairn_core_chirho::store_chirho::hash_object_chirho;
use serde::{Deserialize, Serialize};

pub const NODE_CAPACITY_INTENT_SCHEMA_V1_CHIRHO: &str = "cairn.node-capacity-intent.v1.chirho";
pub const NODE_CAPACITY_ATTESTATION_SCHEMA_V1_CHIRHO: &str =
    "cairn.node-capacity-attestation.v1.chirho";
/// Domain-separated from the record domain so a signature over one can never be replayed as the
/// other.
pub const NODE_CAPACITY_INTENT_DOMAIN_V1_CHIRHO: &str =
    "cairn.node-capacity-intent.domain.v1.chirho";
pub const NODE_CAPACITY_ATTESTATION_DOMAIN_V1_CHIRHO: &str =
    "cairn.node-capacity-attestation.domain.v1.chirho";
/// Identifier-shaped fields — node id, provider, region, key id — are short opaque tokens.
///
/// Bounding each field beats bounding the encoded total: it names WHICH field ran long, and it does
/// not require this pure crate to take a JSON dependency just to measure a length.
pub const MAX_NODE_CAPACITY_TOKEN_BYTES_CHIRHO: usize = 128;

/// A signature is NOT an identifier, and giving it the token bound was wrong: a bare ed25519
/// signature in hex is 128 chars, so the identifier bound left it exactly zero headroom and any
/// scheme carrying a prefix or a different encoding refused as malformed. Found by the positive
/// control arm — the verifier was refusing every grant, including a correct one.
pub const MAX_NODE_CAPACITY_SIGNATURE_BYTES_CHIRHO: usize = 512;

/// Verification-only registrar authority. There is deliberately no `sign_chirho`.
pub trait NodeRegistrationAuthorityPortChirho {
    /// Which registrar key this authority will accept. Compared before any signature work.
    fn authority_key_id_chirho(&self) -> String;
    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool;
}

/// What the registrar is asserting: this node, in this failure domain, may offer this much.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeCapacityIntentChirho {
    pub schema_chirho: String,
    pub node_id_chirho: String,
    pub domain_chirho: FailureDomainChirho,
    pub allocatable_chirho: AllocatableCapacityChirho,
    /// Monotone per node, intended so an older grant cannot be replayed over a newer one.
    ///
    /// **THIS MODULE DOES NOT ENFORCE THAT, and the field must not be read as if it did.**
    /// Verification is stateless: it holds one record and has nothing to compare a sequence against.
    /// A correctly signed OLD grant therefore verifies exactly like a new one. Replay protection is
    /// the caller's, and it needs durable state — keep the highest sequence seen per node and reject
    /// anything at or below it. Recorded here rather than left implied, because a sequence number
    /// sitting in a signed record looks like protection whether or not anyone is checking it.
    pub registration_seq_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeCapacityAttestationChirho {
    pub schema_chirho: String,
    pub signature_domain_chirho: String,
    pub intent_chirho: NodeCapacityIntentChirho,
    pub intent_digest_chirho: String,
    pub authority_key_id_chirho: String,
    pub sig_chirho: String,
}

/// Why a capacity grant was refused. Each variant names the specific mistake, because "attestation
/// invalid" tells an operator nothing they can act on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapacityAttestationRefusalChirho {
    RecordSchemaMismatchChirho {
        found_chirho: String,
    },
    IntentSchemaMismatchChirho {
        found_chirho: String,
    },
    SignatureDomainMismatchChirho {
        found_chirho: String,
    },
    /// A free-form field ran past the token bound. Names the field, so the caller can fix it.
    FieldTooLongChirho {
        field_chirho: String,
        bytes_chirho: usize,
    },
    /// The grant was signed by a key this authority does not accept. Distinct from a bad signature.
    UnknownAuthorityKeyChirho {
        found_chirho: String,
        expected_chirho: String,
    },
    /// The record's self-reported digest does not match a recomputation over its own intent.
    IntentDigestMismatchChirho {
        found_chirho: String,
        recomputed_chirho: String,
    },
    SignatureInvalidChirho,
    /// A grant for a different node than the caller is registering.
    NodeIdMismatchChirho {
        found_chirho: String,
        expected_chirho: String,
    },
    /// Zero in a hard dimension is the value that arrives by default-initialisation, and a node that
    /// can hold nothing is not a registration — it is an unfilled form.
    ZeroCapacityDimensionChirho {
        dimension_chirho: String,
    },
    EncodeChirho,
}

/// A capacity grant that has been verified. The ONLY way to obtain one is
/// [`verify_node_capacity_attestation_chirho`], so holding one is itself the evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedNodeCapacityChirho {
    intent_chirho: NodeCapacityIntentChirho,
}

impl VerifiedNodeCapacityChirho {
    pub fn node_id_chirho(&self) -> &str {
        &self.intent_chirho.node_id_chirho
    }
    pub fn domain_chirho(&self) -> &FailureDomainChirho {
        &self.intent_chirho.domain_chirho
    }
    pub fn allocatable_chirho(&self) -> &AllocatableCapacityChirho {
        &self.intent_chirho.allocatable_chirho
    }
    pub fn registration_seq_chirho(&self) -> u64 {
        self.intent_chirho.registration_seq_chirho
    }

    /// Wrap a grant that was never attested — TEST ONLY.
    ///
    /// Mirrors `VerifiedTopologyGrantChirho::unverified_for_test_chirho`: arms about registry
    /// arithmetic and lifecycle advancement should not each need a signing fixture. It is `cfg(test)`,
    /// so no production path can reach it, which keeps verification the only shipping way to obtain a
    /// `VerifiedNodeCapacityChirho`.
    #[cfg(test)]
    pub(crate) fn unverified_for_test_chirho(
        node_id_chirho: &str,
        domain_chirho: FailureDomainChirho,
        allocatable_chirho: AllocatableCapacityChirho,
    ) -> Self {
        Self {
            intent_chirho: NodeCapacityIntentChirho {
                schema_chirho: NODE_CAPACITY_INTENT_SCHEMA_V1_CHIRHO.to_string(),
                node_id_chirho: node_id_chirho.to_string(),
                domain_chirho,
                allocatable_chirho,
                registration_seq_chirho: 0,
            },
        }
    }
}

/// Recompute an intent's digest. Never trust the one in the record.
pub fn node_capacity_intent_digest_chirho(
    intent_chirho: &NodeCapacityIntentChirho,
) -> Result<String, CapacityAttestationRefusalChirho> {
    hash_object_chirho(intent_chirho)
        .map(|hash_chirho| hash_chirho.0)
        .map_err(|_error_chirho| CapacityAttestationRefusalChirho::EncodeChirho)
}

/// The exact bytes a registrar signs. Carries the record's own domain, so an intent-domain signature
/// cannot be replayed as a record-domain one.
pub fn unsigned_node_capacity_message_chirho(
    record_chirho: &NodeCapacityAttestationChirho,
) -> String {
    format!(
        "{}|{}|{}|{}",
        record_chirho.signature_domain_chirho,
        record_chirho.schema_chirho,
        record_chirho.authority_key_id_chirho,
        record_chirho.intent_digest_chirho,
    )
}

/// Verify a registrar's capacity grant for `expected_node_id_chirho`.
///
/// Refuses in a fixed order so the refusal identifies the FIRST thing wrong rather than an arbitrary
/// one: shape, then size, then key, then digest, then signature, then binding, then the values.
pub fn verify_node_capacity_attestation_chirho(
    record_chirho: &NodeCapacityAttestationChirho,
    authority_chirho: &dyn NodeRegistrationAuthorityPortChirho,
    expected_node_id_chirho: &str,
) -> Result<VerifiedNodeCapacityChirho, CapacityAttestationRefusalChirho> {
    if record_chirho.schema_chirho != NODE_CAPACITY_ATTESTATION_SCHEMA_V1_CHIRHO {
        return Err(
            CapacityAttestationRefusalChirho::RecordSchemaMismatchChirho {
                found_chirho: record_chirho.schema_chirho.clone(),
            },
        );
    }
    if record_chirho.intent_chirho.schema_chirho != NODE_CAPACITY_INTENT_SCHEMA_V1_CHIRHO {
        return Err(
            CapacityAttestationRefusalChirho::IntentSchemaMismatchChirho {
                found_chirho: record_chirho.intent_chirho.schema_chirho.clone(),
            },
        );
    }
    if record_chirho.signature_domain_chirho != NODE_CAPACITY_ATTESTATION_DOMAIN_V1_CHIRHO {
        return Err(
            CapacityAttestationRefusalChirho::SignatureDomainMismatchChirho {
                found_chirho: record_chirho.signature_domain_chirho.clone(),
            },
        );
    }
    for (field_chirho, value_chirho, bound_chirho) in [
        (
            "node_id_chirho",
            &record_chirho.intent_chirho.node_id_chirho,
            MAX_NODE_CAPACITY_TOKEN_BYTES_CHIRHO,
        ),
        (
            "provider_chirho",
            &record_chirho.intent_chirho.domain_chirho.provider_chirho,
            MAX_NODE_CAPACITY_TOKEN_BYTES_CHIRHO,
        ),
        (
            "region_chirho",
            &record_chirho.intent_chirho.domain_chirho.region_chirho,
            MAX_NODE_CAPACITY_TOKEN_BYTES_CHIRHO,
        ),
        (
            "authority_key_id_chirho",
            &record_chirho.authority_key_id_chirho,
            MAX_NODE_CAPACITY_TOKEN_BYTES_CHIRHO,
        ),
        (
            "intent_digest_chirho",
            &record_chirho.intent_digest_chirho,
            MAX_NODE_CAPACITY_TOKEN_BYTES_CHIRHO,
        ),
        (
            "sig_chirho",
            &record_chirho.sig_chirho,
            MAX_NODE_CAPACITY_SIGNATURE_BYTES_CHIRHO,
        ),
    ] {
        if value_chirho.len() > bound_chirho {
            return Err(CapacityAttestationRefusalChirho::FieldTooLongChirho {
                field_chirho: field_chirho.to_string(),
                bytes_chirho: value_chirho.len(),
            });
        }
    }
    // Key BEFORE signature: an unknown signer is a different mistake from a bad signature, and an
    // operator who pasted the wrong key deserves to be told which one they made.
    let expected_key_chirho = authority_chirho.authority_key_id_chirho();
    if record_chirho.authority_key_id_chirho != expected_key_chirho {
        return Err(
            CapacityAttestationRefusalChirho::UnknownAuthorityKeyChirho {
                found_chirho: record_chirho.authority_key_id_chirho.clone(),
                expected_chirho: expected_key_chirho,
            },
        );
    }
    let recomputed_chirho = node_capacity_intent_digest_chirho(&record_chirho.intent_chirho)?;
    if recomputed_chirho != record_chirho.intent_digest_chirho {
        return Err(
            CapacityAttestationRefusalChirho::IntentDigestMismatchChirho {
                found_chirho: record_chirho.intent_digest_chirho.clone(),
                recomputed_chirho,
            },
        );
    }
    if !authority_chirho.verify_chirho(
        &unsigned_node_capacity_message_chirho(record_chirho),
        &record_chirho.sig_chirho,
    ) {
        return Err(CapacityAttestationRefusalChirho::SignatureInvalidChirho);
    }
    if record_chirho.intent_chirho.node_id_chirho != expected_node_id_chirho {
        return Err(CapacityAttestationRefusalChirho::NodeIdMismatchChirho {
            found_chirho: record_chirho.intent_chirho.node_id_chirho.clone(),
            expected_chirho: expected_node_id_chirho.to_string(),
        });
    }
    let allocatable_chirho = &record_chirho.intent_chirho.allocatable_chirho;
    for dimension_chirho in super::capacity_dominance_chirho::CAPACITY_DIMENSIONS_CHIRHO {
        if allocatable_chirho.in_dimension_chirho(dimension_chirho) == 0 {
            return Err(
                CapacityAttestationRefusalChirho::ZeroCapacityDimensionChirho {
                    dimension_chirho: format!("{dimension_chirho:?}"),
                },
            );
        }
    }
    Ok(VerifiedNodeCapacityChirho {
        intent_chirho: record_chirho.intent_chirho.clone(),
    })
}

#[cfg(test)]
#[path = "capacity_attestation_tests_chirho.rs"]
mod capacity_attestation_tests_chirho;
