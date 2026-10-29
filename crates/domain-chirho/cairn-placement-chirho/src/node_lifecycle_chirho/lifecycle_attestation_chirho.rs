// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! A lifecycle transition is an operator ACT, so it is signed — and it is only accepted if the rules
//! would have allowed it.
//!
//! A capacity grant enters a node at `ProvisionedChirho` and nothing else moves it. Everything that
//! matters downstream keys off the state: `admits_new_placement_chirho` is true ONLY for
//! `JoinedChirho`, so whatever can write "joined" can open a node to placements. That makes a
//! transition an authority act, not bookkeeping, and it is signed by the same registrar authority that
//! grants capacity.
//!
//! Follows the shared envelope contract:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/signed-authority-chirho/signed-intent-envelope-contract-chirho.md`.
//!
//! **The record carries the FACTS the signer asserted, and verification re-checks the rule against
//! them.** `transition_refusals_chirho` needs runtime facts — does the node still hold leadership, is
//! ownership proven, how many placements are still resident — which a later reader cannot recover. So
//! the signer states them and signs them, and this module replays
//! [`super::apply_transition_chirho`] against exactly those asserted facts. **An operator therefore
//! cannot record an illegal transition at all**: a retire signed while claiming leadership is still
//! held is refused here, not merely frowned at later, and the assertion is on the record for anyone
//! auditing what the signer believed.
//!
//! What this does NOT do is check the asserted facts against the world. Nothing in a signed record can:
//! the facts were true, or were claimed, at signing time on another machine. The value is that the
//! claim is bound, attributable, and rule-checked — not that it is independently corroborated.
//!
//! Pure: no I/O, no clock. Verification is a trait call the caller supplies.

use super::{
    apply_transition_chirho, LifecycleTransitionChirho, NodeLifecycleFactsChirho,
    NodeLifecycleStateChirho,
};
use cairn_core_chirho::store_chirho::hash_object_chirho;
use serde::{Deserialize, Serialize};

pub const LIFECYCLE_TRANSITION_INTENT_SCHEMA_V1_CHIRHO: &str =
    "cairn.node-lifecycle-transition-intent.v1.chirho";
pub const LIFECYCLE_TRANSITION_ATTESTATION_SCHEMA_V1_CHIRHO: &str =
    "cairn.node-lifecycle-transition-attestation.v1.chirho";
pub const LIFECYCLE_TRANSITION_ATTESTATION_DOMAIN_V1_CHIRHO: &str =
    "cairn.node-lifecycle-transition-attestation.domain.v1.chirho";
pub const MAX_LIFECYCLE_TOKEN_BYTES_CHIRHO: usize = 128;
/// A signature is not an identifier: a bare ed25519 signature in hex is exactly 128 chars.
pub const MAX_LIFECYCLE_SIGNATURE_BYTES_CHIRHO: usize = 512;

/// Verification-only lifecycle authority. There is deliberately no `sign_chirho`.
pub trait LifecycleAuthorityPortChirho {
    fn authority_key_id_chirho(&self) -> String;
    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool;
}

/// What the signer asserts: this node, in this state, with these facts, makes this transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleTransitionIntentChirho {
    pub schema_chirho: String,
    pub node_id_chirho: String,
    /// The state the signer believed the node was in. Checked against the replayed state by the store,
    /// so a transition signed against a stale view cannot be applied out of order.
    pub from_state_chirho: NodeLifecycleStateChirho,
    pub transition_chirho: LifecycleTransitionChirho,
    /// The runtime facts asserted at signing time. Bound by the signature and re-checked against the
    /// rule here; NOT independently corroborated, and the module header says so.
    pub asserted_facts_chirho: AssertedLifecycleFactsChirho,
    /// Monotone per node. The store keeps the high-water mark; verification is stateless.
    pub transition_seq_chirho: u64,
}

/// The facts the rule needs, as asserted. Deliberately a separate type from
/// [`NodeLifecycleFactsChirho`], which carries the state as well: the state here comes from
/// `from_state_chirho`, and having one field able to disagree with itself would be a defect waiting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssertedLifecycleFactsChirho {
    pub holds_leadership_chirho: bool,
    pub ownership_proven_chirho: bool,
    pub resident_placements_chirho: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleTransitionAttestationChirho {
    pub schema_chirho: String,
    pub signature_domain_chirho: String,
    pub intent_chirho: LifecycleTransitionIntentChirho,
    pub intent_digest_chirho: String,
    pub authority_key_id_chirho: String,
    pub sig_chirho: String,
}

/// Why a lifecycle attestation was refused. Distinct identities, in check order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleAttestationRefusalChirho {
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
    NodeIdMismatchChirho {
        found_chirho: String,
        expected_chirho: String,
    },
    /// The transition the record asks for is not legal from the state it names, given the facts it
    /// asserts. Carries every reason, because an operator should see all the fixes at once.
    IllegalTransitionChirho {
        reasons_chirho: Vec<String>,
    },
    EncodeChirho,
}

/// A transition that verified AND is legal under the rule given its asserted facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedLifecycleTransitionChirho {
    intent_chirho: LifecycleTransitionIntentChirho,
    resulting_state_chirho: NodeLifecycleStateChirho,
}

impl VerifiedLifecycleTransitionChirho {
    pub fn node_id_chirho(&self) -> &str {
        &self.intent_chirho.node_id_chirho
    }
    pub fn from_state_chirho(&self) -> NodeLifecycleStateChirho {
        self.intent_chirho.from_state_chirho
    }
    pub fn resulting_state_chirho(&self) -> NodeLifecycleStateChirho {
        self.resulting_state_chirho
    }
    pub fn transition_seq_chirho(&self) -> u64 {
        self.intent_chirho.transition_seq_chirho
    }
}

pub fn lifecycle_intent_digest_chirho(
    intent_chirho: &LifecycleTransitionIntentChirho,
) -> Result<String, LifecycleAttestationRefusalChirho> {
    hash_object_chirho(intent_chirho)
        .map(|hash_chirho| hash_chirho.0)
        .map_err(|_error_chirho| LifecycleAttestationRefusalChirho::EncodeChirho)
}

/// The exact bytes a lifecycle authority signs. Binds both schemas as well as the domain.
pub fn unsigned_lifecycle_message_chirho(
    record_chirho: &LifecycleTransitionAttestationChirho,
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

/// Verify one lifecycle transition for `expected_node_id_chirho`.
///
/// Order per the envelope contract, with the RULE check last: shape, bounds, key, recomputed digest,
/// signature, node binding, then legality. Legality is last because a record that is not authentic
/// should report that rather than a rule complaint about bytes nobody signed.
pub fn verify_lifecycle_attestation_chirho(
    record_chirho: &LifecycleTransitionAttestationChirho,
    authority_chirho: &dyn LifecycleAuthorityPortChirho,
    expected_node_id_chirho: &str,
) -> Result<VerifiedLifecycleTransitionChirho, LifecycleAttestationRefusalChirho> {
    if record_chirho.schema_chirho != LIFECYCLE_TRANSITION_ATTESTATION_SCHEMA_V1_CHIRHO {
        return Err(
            LifecycleAttestationRefusalChirho::RecordSchemaMismatchChirho {
                found_chirho: record_chirho.schema_chirho.clone(),
            },
        );
    }
    if record_chirho.intent_chirho.schema_chirho != LIFECYCLE_TRANSITION_INTENT_SCHEMA_V1_CHIRHO {
        return Err(
            LifecycleAttestationRefusalChirho::IntentSchemaMismatchChirho {
                found_chirho: record_chirho.intent_chirho.schema_chirho.clone(),
            },
        );
    }
    if record_chirho.signature_domain_chirho != LIFECYCLE_TRANSITION_ATTESTATION_DOMAIN_V1_CHIRHO {
        return Err(
            LifecycleAttestationRefusalChirho::SignatureDomainMismatchChirho {
                found_chirho: record_chirho.signature_domain_chirho.clone(),
            },
        );
    }
    for (field_chirho, value_chirho, bound_chirho) in [
        (
            "node_id_chirho",
            &record_chirho.intent_chirho.node_id_chirho,
            MAX_LIFECYCLE_TOKEN_BYTES_CHIRHO,
        ),
        (
            "authority_key_id_chirho",
            &record_chirho.authority_key_id_chirho,
            MAX_LIFECYCLE_TOKEN_BYTES_CHIRHO,
        ),
        (
            "intent_digest_chirho",
            &record_chirho.intent_digest_chirho,
            MAX_LIFECYCLE_TOKEN_BYTES_CHIRHO,
        ),
        (
            "sig_chirho",
            &record_chirho.sig_chirho,
            MAX_LIFECYCLE_SIGNATURE_BYTES_CHIRHO,
        ),
    ] {
        if value_chirho.len() > bound_chirho {
            return Err(LifecycleAttestationRefusalChirho::FieldTooLongChirho {
                field_chirho: field_chirho.to_string(),
                bytes_chirho: value_chirho.len(),
            });
        }
    }
    // Key BEFORE signature: an unknown signer is a different mistake from a bad signature.
    let expected_key_chirho = authority_chirho.authority_key_id_chirho();
    if record_chirho.authority_key_id_chirho != expected_key_chirho {
        return Err(
            LifecycleAttestationRefusalChirho::UnknownAuthorityKeyChirho {
                found_chirho: record_chirho.authority_key_id_chirho.clone(),
                expected_chirho: expected_key_chirho,
            },
        );
    }
    let recomputed_chirho = lifecycle_intent_digest_chirho(&record_chirho.intent_chirho)?;
    if recomputed_chirho != record_chirho.intent_digest_chirho {
        return Err(
            LifecycleAttestationRefusalChirho::IntentDigestMismatchChirho {
                found_chirho: record_chirho.intent_digest_chirho.clone(),
                recomputed_chirho,
            },
        );
    }
    if !authority_chirho.verify_chirho(
        &unsigned_lifecycle_message_chirho(record_chirho),
        &record_chirho.sig_chirho,
    ) {
        return Err(LifecycleAttestationRefusalChirho::SignatureInvalidChirho);
    }
    if record_chirho.intent_chirho.node_id_chirho != expected_node_id_chirho {
        return Err(LifecycleAttestationRefusalChirho::NodeIdMismatchChirho {
            found_chirho: record_chirho.intent_chirho.node_id_chirho.clone(),
            expected_chirho: expected_node_id_chirho.to_string(),
        });
    }
    // THE rule check. An authentic record still cannot record an illegal transition.
    let facts_chirho = NodeLifecycleFactsChirho {
        state_chirho: record_chirho.intent_chirho.from_state_chirho,
        holds_leadership_chirho: record_chirho
            .intent_chirho
            .asserted_facts_chirho
            .holds_leadership_chirho,
        ownership_proven_chirho: record_chirho
            .intent_chirho
            .asserted_facts_chirho
            .ownership_proven_chirho,
        resident_placements_chirho: record_chirho
            .intent_chirho
            .asserted_facts_chirho
            .resident_placements_chirho,
    };
    let resulting_state_chirho =
        apply_transition_chirho(facts_chirho, record_chirho.intent_chirho.transition_chirho)
            .map_err(|refusals_chirho| {
                LifecycleAttestationRefusalChirho::IllegalTransitionChirho {
                    reasons_chirho: refusals_chirho
                        .iter()
                        .map(|refusal_chirho| format!("{refusal_chirho:?}"))
                        .collect(),
                }
            })?;
    Ok(VerifiedLifecycleTransitionChirho {
        intent_chirho: record_chirho.intent_chirho.clone(),
        resulting_state_chirho,
    })
}

#[cfg(test)]
#[path = "lifecycle_attestation_tests_chirho.rs"]
mod lifecycle_attestation_tests_chirho;
