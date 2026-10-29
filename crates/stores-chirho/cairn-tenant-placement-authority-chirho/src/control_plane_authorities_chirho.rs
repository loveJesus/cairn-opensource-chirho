// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Real ed25519 verifiers for the placement control plane, and the key separation they must satisfy.
//!
//! The four verify-only ports converged on one shape without being designed together — each wants a
//! key id and a `verify_chirho(canonical_unsigned, sig)`. So one adapter serves all four, over the
//! same `verify_with_pubkey_chirho` the shipping tenant-placement record verifier already uses, and
//! fail-closed the same way: a malformed key or signature verifies to `false` rather than erroring
//! into a caller that might treat the error as "not applicable".
//!
//! **The separation check is the reason this module exists rather than four inline closures.** Cairn
//! ruled capacity grants REGISTRAR-signed with verify-only at the node, because a node signing its own
//! allocatable is self-attestation and an inflated allocatable is exactly what lets a placement land
//! where it cannot fit. Today that ruling lives only in the TYPE SYSTEM: two different ports. But the
//! ports are structurally identical, so a caller that passed the SAME key id as both the capacity
//! registrar and a node's measurement authority would defeat the ruling while every type checked out.
//!
//! All three collisions are real authority, not hygiene:
//!
//! ```text
//! node key == capacity registrar   the node signs its own allocatable       (self-attestation)
//! node key == lifecycle authority  the node declares itself JoinedChirho    (admits its own placements)
//! node key == topology grant       the node raises the ceilings binding it  (self-modification)
//! node key == budget authority     the node authorizes its own spend        (self-funding)
//! ```
//!
//! Refusals name ROLES and node ids, never key material, so a refusal is safe to print.

use cairn_placement_chirho::capacity_chirho::capacity_attestation_chirho::NodeRegistrationAuthorityPortChirho;
use cairn_placement_chirho::capacity_chirho::usage_measurement_attestation_chirho::NodeMeasurementAuthorityPortChirho;
use cairn_placement_chirho::node_lifecycle_chirho::lifecycle_attestation_chirho::LifecycleAuthorityPortChirho;
use cairn_placement_chirho::topology_chirho::topology_grant_attestation_chirho::TopologyGrantAuthorityPortChirho;
use cairn_signer_chirho::signer_chirho::verify_with_pubkey_chirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Which authority a key stands for. Used in refusals so no key material has to be printed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityRoleChirho {
    CapacityRegistrarChirho,
    LifecycleChirho,
    TopologyGrantChirho,
    /// Authorizes budget movements. A node holding THIS key could sign its own spend, which is the
    /// same self-attestation the capacity ruling forbids, one authority over.
    BudgetChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlPlaneAuthorityRefusalChirho {
    MalformedKeyChirho {
        role_chirho: AuthorityRoleChirho,
    },
    MalformedNodeMeasurementKeyChirho {
        node_id_chirho: String,
    },
    /// Two of the four fleet authorities share a key, so one holder speaks for both.
    FleetAuthorityKeysNotDistinctChirho,
    /// A node's own signing key is also a fleet authority key — the node would be attesting evidence
    /// about itself that cairn ruled must come from somewhere else.
    NodeWouldSignItsOwnEvidenceChirho {
        node_id_chirho: String,
        role_chirho: AuthorityRoleChirho,
    },
}

/// One key id, verifying with real ed25519, satisfying every control-plane port.
#[derive(Clone, Debug)]
pub struct PubkeyAuthorityChirho {
    key_id_chirho: String,
}

impl PubkeyAuthorityChirho {
    fn new_unchecked_chirho(key_id_chirho: &str) -> Self {
        Self {
            key_id_chirho: key_id_chirho.to_string(),
        }
    }

    /// Fail closed: a malformed key, malformed signature, or failed verification are all `false`.
    /// `verify_with_pubkey_chirho` returns `Result<bool>`, and collapsing its error to `false` is the
    /// safe direction — the alternative is a caller distinguishing "bad key" from "bad signature" and
    /// treating one of them as not-applicable.
    fn verify_bytes_chirho(&self, message_chirho: &str, sig_chirho: &str) -> bool {
        verify_with_pubkey_chirho(&self.key_id_chirho, message_chirho.as_bytes(), sig_chirho)
            .unwrap_or(false)
    }
}

impl NodeRegistrationAuthorityPortChirho for PubkeyAuthorityChirho {
    fn authority_key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }
    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        self.verify_bytes_chirho(canonical_unsigned_chirho, sig_chirho)
    }
}

impl LifecycleAuthorityPortChirho for PubkeyAuthorityChirho {
    fn authority_key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }
    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        self.verify_bytes_chirho(canonical_unsigned_chirho, sig_chirho)
    }
}

impl TopologyGrantAuthorityPortChirho for PubkeyAuthorityChirho {
    fn authority_key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }
    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        self.verify_bytes_chirho(canonical_unsigned_chirho, sig_chirho)
    }
}

impl cairn_placement_chirho::budget_chirho::budget_event_attestation_chirho::BudgetAuthorityPortChirho
    for PubkeyAuthorityChirho
{
    fn authority_key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }
    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        self.verify_bytes_chirho(canonical_unsigned_chirho, sig_chirho)
    }
}

impl NodeMeasurementAuthorityPortChirho for PubkeyAuthorityChirho {
    fn node_key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }
    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        self.verify_bytes_chirho(canonical_unsigned_chirho, sig_chirho)
    }
}

impl crate::placement_registry_load_chirho::NodeMeasurementAuthorityResolverChirho
    for ControlPlaneAuthoritiesChirho
{
    fn authority_for_node_chirho(
        &self,
        node_id_chirho: &str,
    ) -> Option<&dyn NodeMeasurementAuthorityPortChirho> {
        self.node_measurement_chirho
            .get(node_id_chirho)
            .map(|authority_chirho| authority_chirho as &dyn NodeMeasurementAuthorityPortChirho)
    }
}

/// A verifier for ONE role, for callers that genuinely involve one authority.
///
/// Deliberately narrow, and the narrowness is the point. The separation check exists because a NODE
/// key doubling as a fleet key defeats the registrar-signs-not-the-node ruling. A caller that verifies
/// only topology grants has no node key in the picture at all, so there is no separation to check and
/// requiring three unrelated keys would be ceremony that teaches operators to pass whatever satisfies
/// it. **Anything that verifies a node's own evidence must go through
/// [`resolve_control_plane_authorities_chirho`] instead** — this constructor makes no separation claim
/// and must not be read as one.
pub fn single_role_verifier_chirho(
    key_id_chirho: &str,
) -> Result<PubkeyAuthorityChirho, ControlPlaneAuthorityRefusalChirho> {
    if !well_formed_key_chirho(key_id_chirho) {
        return Err(ControlPlaneAuthorityRefusalChirho::MalformedKeyChirho {
            role_chirho: AuthorityRoleChirho::TopologyGrantChirho,
        });
    }
    Ok(PubkeyAuthorityChirho::new_unchecked_chirho(key_id_chirho))
}

/// An ed25519 public key id: 64 lower-hex characters.
fn well_formed_key_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .chars()
            .all(|c_chirho| c_chirho.is_ascii_digit() || ('a'..='f').contains(&c_chirho))
}

/// The verifiers a placement control plane runs on, with separation already proven.
///
/// Constructed only through [`resolve_control_plane_authorities_chirho`], so a caller cannot assemble
/// a set that skipped the separation check.
#[derive(Clone, Debug)]
pub struct ControlPlaneAuthoritiesChirho {
    capacity_registrar_chirho: PubkeyAuthorityChirho,
    lifecycle_chirho: PubkeyAuthorityChirho,
    topology_grant_chirho: PubkeyAuthorityChirho,
    budget_chirho: PubkeyAuthorityChirho,
    node_measurement_chirho: BTreeMap<String, PubkeyAuthorityChirho>,
}

impl ControlPlaneAuthoritiesChirho {
    pub fn capacity_registrar_chirho(&self) -> &PubkeyAuthorityChirho {
        &self.capacity_registrar_chirho
    }
    pub fn lifecycle_chirho(&self) -> &PubkeyAuthorityChirho {
        &self.lifecycle_chirho
    }
    pub fn topology_grant_chirho(&self) -> &PubkeyAuthorityChirho {
        &self.topology_grant_chirho
    }
    pub fn budget_chirho(&self) -> &PubkeyAuthorityChirho {
        &self.budget_chirho
    }
    /// The verifier for one node's own usage reports; `None` for a node with no declared key, which
    /// callers must treat as "cannot verify this node's measurements" rather than as permission.
    pub fn node_measurement_chirho(&self, node_id_chirho: &str) -> Option<&PubkeyAuthorityChirho> {
        self.node_measurement_chirho.get(node_id_chirho)
    }
}

/// Resolve the control plane's verifiers, refusing any arrangement where one key speaks for two
/// authorities.
pub fn resolve_control_plane_authorities_chirho(
    capacity_registrar_key_chirho: &str,
    lifecycle_key_chirho: &str,
    topology_grant_key_chirho: &str,
    budget_key_chirho: &str,
    node_measurement_keys_chirho: &BTreeMap<String, String>,
) -> Result<ControlPlaneAuthoritiesChirho, ControlPlaneAuthorityRefusalChirho> {
    for (role_chirho, key_chirho) in [
        (
            AuthorityRoleChirho::CapacityRegistrarChirho,
            capacity_registrar_key_chirho,
        ),
        (AuthorityRoleChirho::LifecycleChirho, lifecycle_key_chirho),
        (
            AuthorityRoleChirho::TopologyGrantChirho,
            topology_grant_key_chirho,
        ),
        (AuthorityRoleChirho::BudgetChirho, budget_key_chirho),
    ] {
        if !well_formed_key_chirho(key_chirho) {
            return Err(ControlPlaneAuthorityRefusalChirho::MalformedKeyChirho { role_chirho });
        }
    }

    // The four fleet authorities must be four different holders.
    let distinct_chirho = [
        capacity_registrar_key_chirho,
        lifecycle_key_chirho,
        topology_grant_key_chirho,
        budget_key_chirho,
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    if distinct_chirho.len() != 4 {
        return Err(ControlPlaneAuthorityRefusalChirho::FleetAuthorityKeysNotDistinctChirho);
    }

    let mut node_measurement_chirho = BTreeMap::new();
    for (node_id_chirho, node_key_chirho) in node_measurement_keys_chirho {
        if !well_formed_key_chirho(node_key_chirho) {
            return Err(
                ControlPlaneAuthorityRefusalChirho::MalformedNodeMeasurementKeyChirho {
                    node_id_chirho: node_id_chirho.clone(),
                },
            );
        }
        // A node holding a fleet authority key is the ruling being defeated in place.
        for (role_chirho, fleet_key_chirho) in [
            (
                AuthorityRoleChirho::CapacityRegistrarChirho,
                capacity_registrar_key_chirho,
            ),
            (AuthorityRoleChirho::LifecycleChirho, lifecycle_key_chirho),
            (
                AuthorityRoleChirho::TopologyGrantChirho,
                topology_grant_key_chirho,
            ),
            (AuthorityRoleChirho::BudgetChirho, budget_key_chirho),
        ] {
            if node_key_chirho == fleet_key_chirho {
                return Err(
                    ControlPlaneAuthorityRefusalChirho::NodeWouldSignItsOwnEvidenceChirho {
                        node_id_chirho: node_id_chirho.clone(),
                        role_chirho,
                    },
                );
            }
        }
        node_measurement_chirho.insert(
            node_id_chirho.clone(),
            PubkeyAuthorityChirho::new_unchecked_chirho(node_key_chirho),
        );
    }

    Ok(ControlPlaneAuthoritiesChirho {
        capacity_registrar_chirho: PubkeyAuthorityChirho::new_unchecked_chirho(
            capacity_registrar_key_chirho,
        ),
        lifecycle_chirho: PubkeyAuthorityChirho::new_unchecked_chirho(lifecycle_key_chirho),
        topology_grant_chirho: PubkeyAuthorityChirho::new_unchecked_chirho(
            topology_grant_key_chirho,
        ),
        budget_chirho: PubkeyAuthorityChirho::new_unchecked_chirho(budget_key_chirho),
        node_measurement_chirho,
    })
}

#[cfg(test)]
#[path = "control_plane_authorities_tests_chirho.rs"]
mod control_plane_authorities_tests_chirho;
