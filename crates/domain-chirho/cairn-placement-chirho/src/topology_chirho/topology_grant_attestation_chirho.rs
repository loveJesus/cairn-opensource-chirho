// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! A grant is only a ceiling if somebody else signed it. This is the signature the grant checker assumed.
//!
//! CF8 clause 10 requires *"the topology-plan principal carries a **signed** grant with explicit
//! node-count, spend-rate, provider-allowlist, and minimum-control/storage-floor bounds"*.
//! [`super::topology_grant_chirho`] implements every bound and says so plainly in its own header:
//! *"Signature verification of the grant is the caller's."* **This module is that caller**, and until
//! it existed the bounds were checked against a grant anybody could construct — a ceiling with no
//! authority behind it.
//!
//! Follows the shared envelope contract:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/signed-authority-chirho/signed-intent-envelope-contract-chirho.md`.
//! Read it before changing the check ORDER — key before signature, and the intent digest recomputed
//! rather than trusted, are both load-bearing and both easy to invert without noticing.
//!
//! **The port verifies and cannot sign.** A planner signing its own grant is the self-modification
//! this family already refuses one level up: `topology_grant_chirho` rejects a plan carrying a
//! `proposed_grant_chirho` unconditionally, *"because no ceiling constrains a planner that can raise
//! its own ceiling"*. A planner that could SIGN a grant would walk through the same door from the
//! other side, so there is no `sign_chirho` here.
//!
//! **This message format is new and deliberately the most complete of the three.** Having no existing
//! signatures to preserve, it binds the signature domain, BOTH schemas, the key id, and the intent
//! digest. The other two envelopes bind less because their formats predate this contract and cannot be
//! changed without a signature migration — see the contract doc's "DO NOT UNIFY" section.
//!
//! Pure: no I/O, no clock. Verification is a trait call the caller supplies.

use super::topology_grant_chirho::TopologyGrantChirho;
use cairn_core_chirho::store_chirho::hash_object_chirho;
use serde::{Deserialize, Serialize};

pub const TOPOLOGY_GRANT_INTENT_SCHEMA_V1_CHIRHO: &str = "cairn.topology-grant-intent.v1.chirho";
pub const TOPOLOGY_GRANT_ATTESTATION_SCHEMA_V1_CHIRHO: &str =
    "cairn.topology-grant-attestation.v1.chirho";
pub const TOPOLOGY_GRANT_ATTESTATION_DOMAIN_V1_CHIRHO: &str =
    "cairn.topology-grant-attestation.domain.v1.chirho";
/// Identifier-shaped fields are short opaque tokens.
pub const MAX_TOPOLOGY_GRANT_TOKEN_BYTES_CHIRHO: usize = 128;
/// A signature is NOT an identifier: a bare ed25519 signature in hex is exactly 128 chars, so the
/// identifier bound would leave it zero headroom. Learned the hard way on the capacity envelope.
pub const MAX_TOPOLOGY_GRANT_SIGNATURE_BYTES_CHIRHO: usize = 512;

/// Verification-only grant authority. There is deliberately no `sign_chirho`.
pub trait TopologyGrantAuthorityPortChirho {
    fn authority_key_id_chirho(&self) -> String;
    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool;
}

/// What the grant authority asserts: this principal may plan within these bounds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyGrantIntentChirho {
    pub schema_chirho: String,
    /// The topology-plan principal the grant is issued TO. Clause 10's "the topology-plan principal
    /// carries a signed grant" — a grant not bound to a principal is a ceiling anyone may cite.
    pub principal_chirho: String,
    pub grant_chirho: TopologyGrantChirho,
    /// Monotone per principal. See the refusal note: this module does NOT enforce it.
    pub issued_seq_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyGrantAttestationChirho {
    pub schema_chirho: String,
    pub signature_domain_chirho: String,
    pub intent_chirho: TopologyGrantIntentChirho,
    pub intent_digest_chirho: String,
    pub authority_key_id_chirho: String,
    pub sig_chirho: String,
}

/// Why a grant attestation was refused. Distinct identities, in check order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TopologyGrantAttestationRefusalChirho {
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
    UnknownAuthorityKeyChirho {
        found_chirho: String,
        expected_chirho: String,
    },
    IntentDigestMismatchChirho {
        found_chirho: String,
        recomputed_chirho: String,
    },
    SignatureInvalidChirho,
    /// A validly signed grant issued to somebody else.
    PrincipalMismatchChirho {
        found_chirho: String,
        expected_chirho: String,
    },
    /// The bounds contradict each other: the role floors cannot fit inside the node ceiling, so no
    /// plan could ever satisfy this grant. Refused rather than accepted-and-useless, because a grant
    /// nobody can satisfy is far more likely a mistake than an intention.
    UnsatisfiableGrantChirho {
        minimum_total_chirho: u32,
        max_nodes_chirho: u32,
    },
    /// Zero is what arrives by default-initialisation, and a grant permitting no nodes is an unfilled
    /// form rather than a deliberate ceiling.
    ZeroNodeCeilingChirho,
    EncodeChirho,
}

/// A grant that has been verified against its authority AND bound to the principal citing it. The
/// only way to obtain one is [`verify_topology_grant_attestation_chirho`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedTopologyGrantChirho {
    intent_chirho: TopologyGrantIntentChirho,
}

impl VerifiedTopologyGrantChirho {
    pub fn principal_chirho(&self) -> &str {
        &self.intent_chirho.principal_chirho
    }
    pub fn grant_chirho(&self) -> &TopologyGrantChirho {
        &self.intent_chirho.grant_chirho
    }
    pub fn issued_seq_chirho(&self) -> u64 {
        self.intent_chirho.issued_seq_chirho
    }

    /// Wrap a grant that was never attested — TEST ONLY.
    ///
    /// It exists so arms about plan arithmetic and spread do not each need a signing fixture. It is
    /// `cfg(test)`, so no production path can reach it, which is what keeps verification the only
    /// shipping way to obtain a `VerifiedTopologyGrantChirho`.
    #[cfg(test)]
    pub(crate) fn unverified_for_test_chirho(
        grant_chirho: TopologyGrantChirho,
        principal_chirho: &str,
    ) -> Self {
        Self {
            intent_chirho: TopologyGrantIntentChirho {
                schema_chirho: TOPOLOGY_GRANT_INTENT_SCHEMA_V1_CHIRHO.to_string(),
                principal_chirho: principal_chirho.to_string(),
                grant_chirho,
                issued_seq_chirho: 0,
            },
        }
    }
}

/// Recompute the intent digest. Never trust the one in the record.
pub fn topology_grant_intent_digest_chirho(
    intent_chirho: &TopologyGrantIntentChirho,
) -> Result<String, TopologyGrantAttestationRefusalChirho> {
    hash_object_chirho(intent_chirho)
        .map(|hash_chirho| hash_chirho.0)
        .map_err(|_error_chirho| TopologyGrantAttestationRefusalChirho::EncodeChirho)
}

/// The exact bytes a grant authority signs. Binds both schemas as well as the domain, so a signature
/// cannot be replayed across record kinds.
pub fn unsigned_topology_grant_message_chirho(
    record_chirho: &TopologyGrantAttestationChirho,
) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        record_chirho.signature_domain_chirho,
        record_chirho.schema_chirho,
        record_chirho.intent_chirho.schema_chirho,
        record_chirho.authority_key_id_chirho,
        record_chirho.intent_digest_chirho,
    )
}

/// Verify a grant attestation for `expected_principal_chirho`.
///
/// Order per the envelope contract: schemas, domain, field bounds, KEY, recomputed digest, signature,
/// then the intent-specific bindings — principal, then the grant's own internal consistency.
pub fn verify_topology_grant_attestation_chirho(
    record_chirho: &TopologyGrantAttestationChirho,
    authority_chirho: &dyn TopologyGrantAuthorityPortChirho,
    expected_principal_chirho: &str,
) -> Result<VerifiedTopologyGrantChirho, TopologyGrantAttestationRefusalChirho> {
    if record_chirho.schema_chirho != TOPOLOGY_GRANT_ATTESTATION_SCHEMA_V1_CHIRHO {
        return Err(
            TopologyGrantAttestationRefusalChirho::RecordSchemaMismatchChirho {
                found_chirho: record_chirho.schema_chirho.clone(),
            },
        );
    }
    if record_chirho.intent_chirho.schema_chirho != TOPOLOGY_GRANT_INTENT_SCHEMA_V1_CHIRHO {
        return Err(
            TopologyGrantAttestationRefusalChirho::IntentSchemaMismatchChirho {
                found_chirho: record_chirho.intent_chirho.schema_chirho.clone(),
            },
        );
    }
    if record_chirho.signature_domain_chirho != TOPOLOGY_GRANT_ATTESTATION_DOMAIN_V1_CHIRHO {
        return Err(
            TopologyGrantAttestationRefusalChirho::SignatureDomainMismatchChirho {
                found_chirho: record_chirho.signature_domain_chirho.clone(),
            },
        );
    }
    for (field_chirho, value_chirho, bound_chirho) in [
        (
            "principal_chirho",
            &record_chirho.intent_chirho.principal_chirho,
            MAX_TOPOLOGY_GRANT_TOKEN_BYTES_CHIRHO,
        ),
        (
            "grant_id_chirho",
            &record_chirho.intent_chirho.grant_chirho.grant_id_chirho,
            MAX_TOPOLOGY_GRANT_TOKEN_BYTES_CHIRHO,
        ),
        (
            "authority_key_id_chirho",
            &record_chirho.authority_key_id_chirho,
            MAX_TOPOLOGY_GRANT_TOKEN_BYTES_CHIRHO,
        ),
        (
            "intent_digest_chirho",
            &record_chirho.intent_digest_chirho,
            MAX_TOPOLOGY_GRANT_TOKEN_BYTES_CHIRHO,
        ),
        (
            "sig_chirho",
            &record_chirho.sig_chirho,
            MAX_TOPOLOGY_GRANT_SIGNATURE_BYTES_CHIRHO,
        ),
    ] {
        if value_chirho.len() > bound_chirho {
            return Err(TopologyGrantAttestationRefusalChirho::FieldTooLongChirho {
                field_chirho: field_chirho.to_string(),
                bytes_chirho: value_chirho.len(),
            });
        }
    }
    // Key BEFORE signature: an unknown signer is a different mistake from a bad signature.
    let expected_key_chirho = authority_chirho.authority_key_id_chirho();
    if record_chirho.authority_key_id_chirho != expected_key_chirho {
        return Err(
            TopologyGrantAttestationRefusalChirho::UnknownAuthorityKeyChirho {
                found_chirho: record_chirho.authority_key_id_chirho.clone(),
                expected_chirho: expected_key_chirho,
            },
        );
    }
    let recomputed_chirho = topology_grant_intent_digest_chirho(&record_chirho.intent_chirho)?;
    if recomputed_chirho != record_chirho.intent_digest_chirho {
        return Err(
            TopologyGrantAttestationRefusalChirho::IntentDigestMismatchChirho {
                found_chirho: record_chirho.intent_digest_chirho.clone(),
                recomputed_chirho,
            },
        );
    }
    if !authority_chirho.verify_chirho(
        &unsigned_topology_grant_message_chirho(record_chirho),
        &record_chirho.sig_chirho,
    ) {
        return Err(TopologyGrantAttestationRefusalChirho::SignatureInvalidChirho);
    }
    if record_chirho.intent_chirho.principal_chirho != expected_principal_chirho {
        return Err(
            TopologyGrantAttestationRefusalChirho::PrincipalMismatchChirho {
                found_chirho: record_chirho.intent_chirho.principal_chirho.clone(),
                expected_chirho: expected_principal_chirho.to_string(),
            },
        );
    }
    let grant_chirho = &record_chirho.intent_chirho.grant_chirho;
    if grant_chirho.max_nodes_chirho == 0 {
        return Err(TopologyGrantAttestationRefusalChirho::ZeroNodeCeilingChirho);
    }
    let minimum_total_chirho = grant_chirho
        .minimum_control_nodes_chirho
        .saturating_add(grant_chirho.minimum_storage_nodes_chirho);
    if minimum_total_chirho > grant_chirho.max_nodes_chirho {
        return Err(
            TopologyGrantAttestationRefusalChirho::UnsatisfiableGrantChirho {
                minimum_total_chirho,
                max_nodes_chirho: grant_chirho.max_nodes_chirho,
            },
        );
    }
    Ok(VerifiedTopologyGrantChirho {
        intent_chirho: record_chirho.intent_chirho.clone(),
    })
}

#[cfg(test)]
#[path = "topology_grant_attestation_tests_chirho.rs"]
mod topology_grant_attestation_tests_chirho;
