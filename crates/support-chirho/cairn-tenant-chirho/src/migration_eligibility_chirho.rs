// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Compute a root's three migration verdicts and issue its preliminary check from them.
//!
//! One place, deliberately. The precheck is issued only when completeness, self-containment AND
//! disposition all pass over real evidence, and two callers computing that independently could
//! drift into disagreeing about what "eligible" means — the operator path would then activate on a
//! bar the verifier never applied.
//!
//! HONEST SCOPE, corrected 2026-08-19: the resident activation path asks THIS function.
//! `tenant-migration-verify` does NOT — it computes the same three verdicts inline because it must
//! PRINT each finding, and this function returns a verdict rather than a report. What the two do
//! share is the composition rule itself (`preliminary_migration_check_chirho`), so neither can
//! clear a root on a subset of halves. The remaining difference is one input: this function is
//! given the configured ledger namespace and the report is not.

use crate::capacity_admission_chirho::TenantCapacityAdmissionVerdictChirho;
use crate::migration_completeness_chirho::{
    declared_root_surfaces_chirho, preliminary_migration_check_chirho,
    verify_migration_completeness_chirho, PreliminaryMigrationCheckChirho,
    PreliminaryMigrationHalfFailureChirho, RootSurfaceEnumeratorChirho,
};
use crate::root_surfaces_chirho::{
    tenant_log_references_chirho, RootSurfaceSnapshotChirho, TenantScopedArtifactResolverChirho,
};
use crate::self_containment_chirho::TenantObjectResolverChirho;
use crate::self_containment_chirho::{
    verify_tenant_self_containment_against_source_chirho, verify_tenant_self_containment_chirho,
};
use crate::surface_disposition_chirho::{
    verify_required_surfaces_chirho, verify_surface_dispositions_chirho,
};
use std::path::Path;

/// Why a root is not presently eligible for migration preparation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MigrationEligibilityRefusalChirho {
    /// The root could not be read at all. Distinct from a failed half on purpose: "I could not
    /// look" and "I looked and it failed" are different answers, and collapsing them would let an
    /// unreadable root read as a clean refusal.
    RootUnreadableChirho,
    /// One or more halves failed over real evidence. Each entry carries a bounded, sanitized
    /// surface summary so operator output cannot echo an attacker-controlled filesystem name.
    HalvesFailedChirho {
        failed_chirho: Vec<PreliminaryMigrationHalfFailureChirho>,
    },
}

/// Issue the preliminary check for `root_chirho`, or say which half refused.
/// `configured_namespace_root_surface_chirho` is the root-level directory holding this root's
/// CONFIGURED ledger storage namespace, from its ledger config. It must be supplied rather than
/// guessed: the name is the operator's choice, and without it a root refuses on its own journal's
/// parent directory — measured against a real drill root on 2026-08-19.
/// `capacity_admission_chirho` is the target's capacity verdict when one has been decided. It is
/// supplied rather than computed because the evidence and the admission conjunction live in the
/// placement crates, which depend on THIS one — see `capacity_admission_chirho` for why that makes
/// a port the only direction that works. **Passing `None` SKIPS the half**, which is scaffolding
/// until the production migration road makes absence fail closed.
/// `source_resolver_chirho` resolves objects in the root being MOVED FROM, when there is one. It is
/// a RESOLVER rather than a path because the caller that holds a source root holds it by verified
/// descriptor custody, and taking a path here would re-admit the caller-supplied path string that
/// type exists to refuse. Supplying it changes what
/// the self-containment half can decide: without it, a token that resolves nowhere is indistinguishable
/// from a lost object and must be refused; with it, "lost against the source" is a fact rather than an
/// upper bound. See `verify_tenant_self_containment_against_source_chirho` for the measurement that
/// forced this distinction.
pub fn preliminary_check_for_root_chirho(
    root_chirho: &Path,
    configured_namespace_root_surface_chirho: Option<&str>,
    source_resolver_chirho: Option<&dyn TenantObjectResolverChirho>,
    source_surfaces_chirho: Option<&[String]>,
    capacity_admission_chirho: Option<&TenantCapacityAdmissionVerdictChirho>,
) -> Result<PreliminaryMigrationCheckChirho, MigrationEligibilityRefusalChirho> {
    let snapshot_chirho = RootSurfaceSnapshotChirho::open_chirho(root_chirho)
        .map_err(|_error_chirho| MigrationEligibilityRefusalChirho::RootUnreadableChirho)?;
    // The configured namespace is declared for BOTH halves, from the one place that knows it.
    // Supplying it to disposition alone was a real drift: a target passed disposition and refused
    // completeness on the same directory, and the operator saw two half-names with one cause.
    let mut declared_chirho = declared_root_surfaces_chirho();
    if let Some(configured_chirho) = configured_namespace_root_surface_chirho {
        declared_chirho.insert(configured_chirho.to_string());
    }
    let completeness_chirho =
        verify_migration_completeness_chirho(&declared_chirho, &snapshot_chirho);
    let references_chirho = tenant_log_references_chirho(root_chirho)
        .map_err(|_error_chirho| MigrationEligibilityRefusalChirho::RootUnreadableChirho)?;
    let target_resolver_chirho = TenantScopedArtifactResolverChirho::for_root_chirho(root_chirho);
    let containment_chirho = match source_resolver_chirho {
        Some(source_chirho) => {
            verify_tenant_self_containment_against_source_chirho(
                &references_chirho,
                &target_resolver_chirho,
                source_chirho,
            )
            .verdict_chirho
        }
        // No oracle, no weakening: the one-root form is exactly as strict as it has always been.
        None => verify_tenant_self_containment_chirho(&references_chirho, &target_resolver_chirho),
    };
    let disposition_chirho = verify_surface_dispositions_chirho(
        &snapshot_chirho.observed_surfaces_chirho(),
        configured_namespace_root_surface_chirho,
    );
    // Only computable with a source in hand, and mandatory when there is one: it is the only half
    // that can see what the target is MISSING.
    let required_surfaces_chirho = source_surfaces_chirho.map(|source_chirho| {
        verify_required_surfaces_chirho(source_chirho, &snapshot_chirho.observed_surfaces_chirho())
    });
    preliminary_migration_check_chirho(
        &completeness_chirho,
        &containment_chirho,
        &disposition_chirho,
        required_surfaces_chirho.as_ref(),
        capacity_admission_chirho,
    )
    .map_err(
        |failed_chirho| MigrationEligibilityRefusalChirho::HalvesFailedChirho { failed_chirho },
    )
}
