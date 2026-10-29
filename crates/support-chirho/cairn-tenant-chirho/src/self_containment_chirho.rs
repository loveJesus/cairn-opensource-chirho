// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! A tenant root is movable only if every hash its logs reference resolves INSIDE that root.
//!
//! CF8 acceptance, verbatim: *"a self-containment verifier proves every tenant-log content hash
//! resolves in that tenant root."*
//!
//! **Why this is the precondition for migration.** A tenant root is the migration unit (G1: one
//! customer app per tenant root). Moving it to another machine moves its objects; a reference to a
//! hash that lives *outside* it therefore survives the move as a **dangling** reference — the log
//! still names an object that is now unreachable. The verifier's whole job is to make that
//! discoverable **before** the move rather than after.
//!
//! **Resolving somewhere is not resolving here.** The resolver is tenant-scoped by construction: it
//! answers "is this object in THIS root", never "does this object exist". A hash that resolves in a
//! sibling tenant's root, or in a shared CAS, is **still dangling for this tenant** — that is the
//! whole distinction, and a resolver that answered the global question would make this verifier pass
//! on exactly the roots it exists to catch.
//!
//! **THE HONEST BOUND, and it is the important sentence in this file.** This verifies the references
//! it is **given**. It cannot know whether that list is complete — enumerating every referencing
//! surface is the *migration completeness manifest*'s job, a separate criterion. **A green result here
//! over a short list means "nothing I was shown dangles", not "this root is self-contained."**
//! Composing the two is what makes the claim real; either alone is a half-proof, and the half that
//! looks most convincing is this one.
//!
//! Pure: no I/O, no store. The resolver is injected, so the verifier is testable without a root and
//! cannot accidentally consult a global index.

use serde::{Deserialize, Serialize};

/// Answers whether a hash-named content or runtime artifact resolves **inside one tenant root**.
pub trait TenantObjectResolverChirho {
    /// `true` only if the artifact is present and verifies in THIS tenant root.
    fn resolves_in_tenant_chirho(&self, hash_chirho: &str) -> bool;
}

/// One place a tenant log names a content hash. Carries the coordinates an operator needs to find it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantLogReferenceChirho {
    pub log_name_chirho: String,
    pub seq_chirho: u64,
    pub hash_chirho: String,
}

/// A reference that does not resolve inside the tenant root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelfContainmentRefusalChirho {
    DanglingReferenceChirho {
        log_name_chirho: String,
        seq_chirho: u64,
        hash_chirho: String,
    },
    /// Resolves in the SOURCE root and not here — an object this move would lose.
    ///
    /// A separate identity from [`Self::DanglingReferenceChirho`] on purpose, because the two carry
    /// different certainty and demand different operator action. Without a source oracle, "does not
    /// resolve here" also catches every 64-hex token that was never a CAS reference at all — a
    /// public key, a token hash, an idempotency digest — so it is an UPPER BOUND. With one, the
    /// artifact demonstrably exists at the source and demonstrably does not exist here, which is
    /// not an upper bound on anything: it is a copy that lost bytes.
    LostAgainstSourceChirho {
        log_name_chirho: String,
        seq_chirho: u64,
        hash_chirho: String,
    },
}

/// Every reference that fails to resolve inside this tenant root, in the order given.
///
/// Every occurrence is reported, not every distinct hash: an operator repairing a root needs each
/// SITE, and collapsing duplicates would hide that a single missing object is named from four logs.
pub fn self_containment_refusals_chirho<ResolverChirho>(
    references_chirho: &[TenantLogReferenceChirho],
    resolver_chirho: &ResolverChirho,
) -> Vec<SelfContainmentRefusalChirho>
where
    ResolverChirho: TenantObjectResolverChirho + ?Sized,
{
    references_chirho
        .iter()
        .filter(|reference_chirho| {
            !resolver_chirho.resolves_in_tenant_chirho(&reference_chirho.hash_chirho)
        })
        .map(
            |reference_chirho| SelfContainmentRefusalChirho::DanglingReferenceChirho {
                log_name_chirho: reference_chirho.log_name_chirho.clone(),
                seq_chirho: reference_chirho.seq_chirho,
                hash_chirho: reference_chirho.hash_chirho.clone(),
            },
        )
        .collect()
}

/// The verdict a caller should act on, carrying the count it was computed over.
///
/// The count is part of the verdict on purpose: **"self-contained over 0 references" is not a
/// successful migration precheck**, and a caller that only reads a boolean cannot tell those apart.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfContainmentVerdictChirho {
    pub references_checked_chirho: usize,
    pub refusals_chirho: Vec<SelfContainmentRefusalChirho>,
}

impl SelfContainmentVerdictChirho {
    /// Self-contained AND checked over at least one reference. A caller wanting the vacuous case must
    /// ask for it explicitly by reading `references_checked_chirho`.
    pub fn is_self_contained_over_evidence_chirho(&self) -> bool {
        self.refusals_chirho.is_empty() && self.references_checked_chirho > 0
    }
}

/// Verify a target root against the SOURCE root that is being moved, which is a different — and on
/// a real root, a decidable — question.
///
/// **Why this exists, measured on a live drill root on 2026-08-19.** The one-root form asks "does
/// every 64-hex token in my logs resolve here". The scanner that produces those tokens is
/// deliberately shape-based and shared with GC marking, where over-approximating REACHABILITY is the
/// safe direction. For a migration precheck the safe direction is the opposite, and reusing it made
/// the half unachievable: on a healthy serving root, 79 of 95 tokens did not resolve — and every one
/// of them was a `pubkey_chirho`, a `token_hash_chirho`, a `key_id_chirho`, a principal hash or an
/// unrelated coordinate digest. The production resolver now also verifies the shipped non-CAS
/// runtime records that logs genuinely name: `runkeys-chirho` and signed `effects-chirho`. A bar no
/// production root can clear is not a bar, but neither may a real carried artifact be hidden in the
/// unresolved bucket merely because it is not stored in CAS.
///
/// With the source root in hand the three cases separate cleanly, and only one of them is a fault:
///
/// - resolves HERE — carried, nothing to say;
/// - resolves at the SOURCE and not here — [`SelfContainmentRefusalChirho::LostAgainstSourceChirho`],
///   the move lost an artifact, which is exactly what this half exists to catch;
/// - resolves NOWHERE — not demonstrably a supported root reference. Counted and returned so a caller can
///   report it, never a refusal, because refusing here is refusing every public key in the root.
///
/// The vacuity guard survives and gets STRONGER: `references_checked_chirho` counts only tokens the
/// source actually resolved, so a target compared against an empty source cannot pass by having
/// nothing to lose.
pub fn verify_tenant_self_containment_against_source_chirho<TargetChirho, SourceChirho>(
    references_chirho: &[TenantLogReferenceChirho],
    target_resolver_chirho: &TargetChirho,
    source_resolver_chirho: &SourceChirho,
) -> SourceComparedContainmentVerdictChirho
where
    TargetChirho: TenantObjectResolverChirho + ?Sized,
    SourceChirho: TenantObjectResolverChirho + ?Sized,
{
    let mut refusals_chirho = Vec::new();
    let mut resolved_at_source_chirho = 0usize;
    let mut unresolved_anywhere_chirho = 0usize;
    for reference_chirho in references_chirho {
        if target_resolver_chirho.resolves_in_tenant_chirho(&reference_chirho.hash_chirho) {
            resolved_at_source_chirho += 1;
            continue;
        }
        if source_resolver_chirho.resolves_in_tenant_chirho(&reference_chirho.hash_chirho) {
            resolved_at_source_chirho += 1;
            refusals_chirho.push(SelfContainmentRefusalChirho::LostAgainstSourceChirho {
                log_name_chirho: reference_chirho.log_name_chirho.clone(),
                seq_chirho: reference_chirho.seq_chirho,
                hash_chirho: reference_chirho.hash_chirho.clone(),
            });
            continue;
        }
        unresolved_anywhere_chirho += 1;
    }
    SourceComparedContainmentVerdictChirho {
        verdict_chirho: SelfContainmentVerdictChirho {
            references_checked_chirho: resolved_at_source_chirho,
            refusals_chirho,
        },
        unresolved_anywhere_chirho,
    }
}

/// A source-compared verdict, plus the count this comparison can newly distinguish.
///
/// The extra number is not decoration: it is the difference between "your copy lost objects" and
/// "your logs contain public keys", and an operator handed one number cannot tell those apart.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceComparedContainmentVerdictChirho {
    pub verdict_chirho: SelfContainmentVerdictChirho,
    /// Tokens that resolved in NEITHER root — an upper bound on nothing, and a fault in nothing.
    pub unresolved_anywhere_chirho: usize,
}

/// Verify a tenant root's self-containment over the references supplied.
pub fn verify_tenant_self_containment_chirho<ResolverChirho>(
    references_chirho: &[TenantLogReferenceChirho],
    resolver_chirho: &ResolverChirho,
) -> SelfContainmentVerdictChirho
where
    ResolverChirho: TenantObjectResolverChirho + ?Sized,
{
    SelfContainmentVerdictChirho {
        references_checked_chirho: references_chirho.len(),
        refusals_chirho: self_containment_refusals_chirho(references_chirho, resolver_chirho),
    }
}

#[cfg(test)]
#[path = "self_containment_tests_chirho.rs"]
mod self_containment_tests_chirho;
