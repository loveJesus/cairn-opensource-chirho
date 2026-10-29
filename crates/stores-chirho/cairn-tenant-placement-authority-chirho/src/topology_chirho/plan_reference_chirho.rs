// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! A signed pointer to a plan nobody resolved is weaker than it looks. This resolves it.
//!
//! `tenant-placement-authority-chirho.md` states the gap plainly:
//!
//! > *"`topology_plan_digest_chirho` is a placement-authority-signed cross-reference. This brick uses
//! > the configured Geo PlanAuthority pin to enforce key separation; it does not load or independently
//! > verify the referenced plan artifact, and the field does not prove the referent exists."*
//!
//! So today the field is checked for lower-hex SHAPE and nothing else. A well-formed digest naming
//! nothing at all passes, which matters because CF8 clause 9 wants *plan hashes in evidence* — and a
//! hash that resolves to nothing is evidence of nothing. Shape is not resolution.
//!
//! **FOUR resolution outcomes, and the three non-`Found` ones are the whole point.** The obvious
//! design gives the resolver `Found` and `NotFound`, then treats every non-`Found` as "absent" — which
//! re-creates the exact defect this repo has already paid for: an `Err` meaning *absent OR unreadable*
//! read as *absent*, so a fallback written for absence quietly rescues a corrupt object.
//!
//! The count is not arbitrary — **it mirrors what the layer below can already say.**
//! `cas_chirho::read_verified_chirho` returns Verified / Absent / Unreadable / Tampered, and
//! `get_chirho` is the LOSSY wrapper that collapses absent and unreadable into one `io::Error`. A port
//! offering fewer outcomes than its own source forces every adapter to collapse one, and whichever it
//! collapses is the next conflation. So: [`AbsentChirho`](TopologyPlanResolutionChirho::AbsentChirho)
//! (no such object), [`UnreadableChirho`](TopologyPlanResolutionChirho::UnreadableChirho) (present,
//! could not be read), and [`TamperedChirho`](TopologyPlanResolutionChirho::TamperedChirho) (read
//! fine, filed under an address its bytes do not produce) refuse under **three different identities**.
//! Present-but-wrong must never take the absent path.
//!
//! **The port resolves and cannot mint.** It returns what a root already holds; there is no
//! constructor here that writes a plan, so a node cannot satisfy its own reference.
//!
//! Pure: no I/O of its own. The filesystem or store reach belongs to whoever implements the port.

use cairn_placement_chirho::topology_chirho::plan_hash_chirho::plan_hash_chirho;
use cairn_placement_chirho::topology_chirho::topology_grant_chirho::DesiredTopologyPlanChirho;
use serde::{Deserialize, Serialize};

/// What a root can say about a plan digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TopologyPlanResolutionChirho {
    /// This root holds the named plan.
    FoundChirho(Box<DesiredTopologyPlanChirho>),
    /// This root holds no object at that digest. The ONLY outcome a caller may treat as "nothing
    /// here"; it must never be widened to cover a read failure.
    AbsentChirho,
    /// Something is at that digest and could not be read or parsed — truncated, permission denied, a
    /// directory where a file was expected. Deliberately NOT `AbsentChirho`, because a
    /// present-but-unreadable object is a fail-closed condition and an absent one is merely a miss.
    UnreadableChirho,
    /// Present and READABLE, but the stored bytes do not hash to the address they were filed under.
    ///
    /// **This case exists because the layer below can already express it.** `cas_chirho`'s
    /// `read_verified_chirho` returns Verified / Absent / Unreadable / Tampered, and `get_chirho` is
    /// the LOSSY wrapper that collapses absent and unreadable into one `io::Error` — the precise
    /// conflation this repo has paid for. A port that offered fewer outcomes than its own source would
    /// force every adapter to collapse one, so this mirrors the source's distinctions instead of
    /// discarding them. Tampered is not "unreadable": the bytes read fine and are wrong.
    TamperedChirho,
}

/// Resolves a topology-plan digest against whatever a root actually holds. Verification only.
pub trait TopologyPlanResolverPortChirho {
    fn resolve_plan_chirho(&self, digest_chirho: &str) -> TopologyPlanResolutionChirho;
}

/// Why a plan reference was refused. Each arm is a DIFFERENT identity so a caller cannot collapse
/// them, which is the failure mode this module exists to prevent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TopologyPlanReferenceRefusalChirho {
    /// Not a lower-hex digest at all. Shape, checked before anything is resolved.
    MalformedDigestChirho { found_chirho: String },
    /// Well-formed, and this root holds nothing at it. The dangling-reference case.
    PlanAbsentChirho { digest_chirho: String },
    /// Present and unreadable. Distinct from absent ON PURPOSE.
    PlanUnreadableChirho { digest_chirho: String },
    /// Present, readable, and filed under an address its own bytes do not produce.
    PlanTamperedChirho { digest_chirho: String },
    /// Resolved to a plan that re-hashes to something else — the reference names a different plan
    /// than the one returned, so somebody substituted one.
    PlanDigestMismatchChirho {
        declared_chirho: String,
        recomputed_chirho: String,
    },
}

/// A plan reference that resolved AND re-hashed. Obtainable only through
/// [`verify_topology_plan_reference_chirho`], so holding one is the evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedTopologyPlanReferenceChirho {
    digest_chirho: String,
    plan_chirho: DesiredTopologyPlanChirho,
}

impl VerifiedTopologyPlanReferenceChirho {
    pub fn digest_chirho(&self) -> &str {
        &self.digest_chirho
    }
    pub fn plan_chirho(&self) -> &DesiredTopologyPlanChirho {
        &self.plan_chirho
    }
}

/// Resolve a declared plan digest and prove the resolved plan re-hashes to it.
///
/// Order: shape, then resolution, then re-hash. The re-hash is last and is not optional — a resolver
/// that returned the wrong plan would otherwise be believed, and the digest is the only thing binding
/// the reference to its referent.
pub fn verify_topology_plan_reference_chirho(
    declared_digest_chirho: &str,
    resolver_chirho: &dyn TopologyPlanResolverPortChirho,
) -> Result<VerifiedTopologyPlanReferenceChirho, TopologyPlanReferenceRefusalChirho> {
    if !crate::is_lower_hex_digest_chirho(declared_digest_chirho) {
        return Err(TopologyPlanReferenceRefusalChirho::MalformedDigestChirho {
            found_chirho: declared_digest_chirho.to_string(),
        });
    }
    let plan_chirho = match resolver_chirho.resolve_plan_chirho(declared_digest_chirho) {
        TopologyPlanResolutionChirho::FoundChirho(plan_chirho) => *plan_chirho,
        TopologyPlanResolutionChirho::AbsentChirho => {
            return Err(TopologyPlanReferenceRefusalChirho::PlanAbsentChirho {
                digest_chirho: declared_digest_chirho.to_string(),
            })
        }
        TopologyPlanResolutionChirho::UnreadableChirho => {
            return Err(TopologyPlanReferenceRefusalChirho::PlanUnreadableChirho {
                digest_chirho: declared_digest_chirho.to_string(),
            })
        }
        TopologyPlanResolutionChirho::TamperedChirho => {
            return Err(TopologyPlanReferenceRefusalChirho::PlanTamperedChirho {
                digest_chirho: declared_digest_chirho.to_string(),
            })
        }
    };
    let recomputed_chirho = plan_hash_chirho(&plan_chirho).0;
    if recomputed_chirho != declared_digest_chirho {
        return Err(
            TopologyPlanReferenceRefusalChirho::PlanDigestMismatchChirho {
                declared_chirho: declared_digest_chirho.to_string(),
                recomputed_chirho,
            },
        );
    }
    Ok(VerifiedTopologyPlanReferenceChirho {
        digest_chirho: declared_digest_chirho.to_string(),
        plan_chirho,
    })
}

#[cfg(test)]
#[path = "plan_reference_tests_chirho.rs"]
mod topology_plan_reference_tests_chirho;
