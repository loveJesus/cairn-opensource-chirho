// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! An unknown root surface REFUSES a migration; it is never quietly skipped.
//!
//! CF8 acceptance, verbatim: *"the migration completeness manifest enumerates every actual root
//! surface and **refuses unknowns**."*
//!
//! **This is one of THREE parts, and no part is a successful precheck alone.** Self-containment
//! ([`super::self_containment_chirho`]) proves *the references you were shown* all resolve locally.
//! Completeness proves *you were shown everything*. Disposition
//! ([`super::surface_disposition_chirho`]) proves *something has decided what happens to each one*.
//! A root can pass any subset while failing the migration: a short reference list makes
//! self-containment trivially green, a manifest that covers every surface says nothing about whether
//! those surfaces' contents resolve, and both together say nothing about a private signing key
//! nobody has decided how to move. The three together are the preflight claim, which is why
//! [`preliminary_migration_check_chirho`] takes all of them and will not be constructed from a
//! subset. It is deliberately not activation authority: the ledger-host migration contract must
//! rebind the target after a real source-append fence to the exact verified source tail.
//!
//! **The asymmetry is deliberate and is the criterion's actual content.**
//! - **Observed but NOT declared → REFUSE.** Something exists in this root that the manifest does not
//!   cover, so a migration would silently leave it behind. This is the fail-closed direction: an
//!   unknown surface is exactly the thing you cannot reason about, and "skip what you do not
//!   recognise" is how data is lost quietly.
//! - **Declared but NOT observed → REPORT, do not refuse.** The manifest names a surface this root
//!   does not have. That is ordinary — a root need not use every surface the platform defines — but it
//!   is worth surfacing, because the other reading is that you are pointed at the wrong root.
//!
//! Collapsing those two into one "mismatch" would force the caller to treat a routine absence as
//! severely as a data-loss hazard, and callers respond to that by ignoring both.
//!
//! Pure: no I/O. The observed set is supplied by an injected enumerator, so this is testable without
//! a root and cannot accidentally consult a live filesystem.

use super::self_containment_chirho::{SelfContainmentRefusalChirho, SelfContainmentVerdictChirho};
use super::surface_disposition_chirho::{
    disposition_population_digest_chirho, DispositionPopulationDigestChirho,
    DispositionRefusalChirho, DispositionVerdictChirho, RequiredSurfaceRefusalChirho,
    RequiredSurfaceVerdictChirho, CARRIED_UNPROJECTED_LOG_SURFACES_CHIRHO,
    PLATFORM_ONLY_LOG_SURFACES_CHIRHO,
};
use crate::capacity_admission_chirho::TenantCapacityAdmissionVerdictChirho;
use cairn_projection_chirho::projection_chirho::static_surface_manifest_chirho;
use cairn_seqlog_chirho::SEQLOG_HEAD_SUFFIX_CHIRHO;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Enumerates the surfaces actually present in one root.
pub trait RootSurfaceEnumeratorChirho {
    /// Every surface observed in this root, by stable name.
    fn observed_surfaces_chirho(&self) -> Vec<String>;
}

/// The platform's declared LOG surfaces: the projection manifest, plus the logs a migration carries
/// that the projection must not read.
///
/// **The manifest is not restated here.** A hand-maintained copy would drift from the real one
/// the first time somebody added a surface, and it would drift SILENTLY in the permissive direction:
/// a surface missing from a duplicated declaration reads as "undeclared", which this module refuses
/// — but a surface missing from the ORIGINAL while present in the copy reads as fine. Sourcing the
/// set from [`static_surface_manifest_chirho`] means a new platform surface is declared in exactly
/// one place, and that place is already load-bearing for projection.
///
/// **The one other list is its complement, not a copy.**
/// [`CARRIED_UNPROJECTED_LOG_SURFACES_CHIRHO`] names the tenant logs the projection must NOT read
/// (CF8 Step B, 2026-10-26). The projection reads every log in its manifest, so declaring a credential
/// log there to make a migration carry it would widen what the projection reads. No log is in both
/// lists, and a test refuses one that is. Everything that consumes this set follows it: the
/// completeness manifest and its head sidecars, the carried disposition, and the tenant-log reference
/// scan that self-containment checks.
///
/// **NAMING THE POPULATION, because the clause says "every actual root surface" and this is not
/// that.** These are JSONL LOG surfaces: the ones the Gate 1 projection ingests, plus the carried
/// logs it must not. A tenant root also holds
/// content-addressed objects, refs, run seals, and private blobs, and NONE of those are declared
/// here. That gap is not papered over: an enumerator that walks a real root will observe them, and
/// they will come back as [`CompletenessRefusalChirho::UnknownSurfaceChirho`] until somebody
/// declares them with a disposition. **That refusal is the correct state, not a defect** — it is
/// CF8 clause 5's "every remaining surface is explicitly exported, custody-transferred, rebuilt, or
/// proven disposable" showing up as a red rather than as an absence nobody noticed.
pub fn declared_log_surfaces_chirho() -> BTreeSet<String> {
    static_surface_manifest_chirho()
        .iter()
        .chain(CARRIED_UNPROJECTED_LOG_SURFACES_CHIRHO)
        .map(|surface_chirho| (*surface_chirho).to_string())
        .collect()
}

/// EVERY declared root surface: the declared logs and the platform-only logs, each with its head
/// sidecar, plus the non-log surfaces that carry a disposition.
///
/// This is the set the clause actually means by "the migration completeness manifest". The log
/// manifest alone is not it — a root holds objects, refs, and the runtime-record chain too, and
/// calling those "undeclared" when the disposition table names them by hand would report a decision
/// that HAS been made as one that has not.
///
/// **The two halves stay independent on purpose, and will both fire for a genuinely unknown
/// surface.** That is two verifiers agreeing, not redundancy: completeness asks whether the platform
/// knows the surface at all, disposition asks what a move does with it, and
/// [`super::surface_disposition_chirho::verify_surface_dispositions_chirho`] is usable on its own by
/// a caller that never ran completeness — so its own fail-closed rule has to hold without help.
pub fn declared_root_surfaces_chirho() -> BTreeSet<String> {
    let logs_chirho = declared_log_surfaces_chirho();
    let mut declared_chirho = logs_chirho.clone();
    // Each declared log's O(1) head sidecar is part of the manifest, DERIVED from the log rather
    // than listed. The disposition half already derives it; a manifest that did not would refuse the
    // companion of a surface it carries — measured on a real target on 2026-08-19, where fourteen
    // sidecars read as UNDECLARED while every one of their logs was carried.
    declared_chirho.extend(
        logs_chirho
            .iter()
            .map(|log_chirho| format!("{log_chirho}{SEQLOG_HEAD_SUFFIX_CHIRHO}")),
    );
    // A platform-only log is KNOWN, so completeness names it, and its policy refuses it as not a
    // migration unit. Its sidecar is known for the same reason the declared logs' sidecars are.
    for log_chirho in PLATFORM_ONLY_LOG_SURFACES_CHIRHO {
        declared_chirho.insert((*log_chirho).to_string());
        declared_chirho.insert(format!("{log_chirho}{SEQLOG_HEAD_SUFFIX_CHIRHO}"));
    }
    declared_chirho.extend(
        crate::surface_disposition_chirho::NON_LOG_SURFACE_POLICIES_CHIRHO
            .iter()
            .map(|(surface_chirho, _)| (*surface_chirho).to_string()),
    );
    declared_chirho
}

/// Why a migration is refused on completeness grounds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompletenessRefusalChirho {
    /// Present in the root, absent from the manifest — a migration would leave it behind.
    UnknownSurfaceChirho { surface_chirho: String },
}

/// The completeness result: hard refusals, plus the soft observation that is not a refusal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletenessVerdictChirho {
    pub observed_count_chirho: usize,
    pub refusals_chirho: Vec<CompletenessRefusalChirho>,
    /// Declared by the manifest but not present here. Informational — a root need not use every
    /// surface — though it can also mean the manifest is pointed at the wrong root.
    pub declared_but_absent_chirho: Vec<String>,
}

impl CompletenessVerdictChirho {
    /// Complete AND computed over at least one observed surface — the same vacuity guard the
    /// self-containment verdict carries, for the same reason: a root that enumerated nothing has not
    /// been checked.
    pub fn is_complete_over_evidence_chirho(&self) -> bool {
        self.refusals_chirho.is_empty() && self.observed_count_chirho > 0
    }
}

/// Compare what the root actually has against what the manifest declares.
pub fn verify_migration_completeness_chirho<EnumeratorChirho>(
    declared_surfaces_chirho: &BTreeSet<String>,
    enumerator_chirho: &EnumeratorChirho,
) -> CompletenessVerdictChirho
where
    EnumeratorChirho: RootSurfaceEnumeratorChirho + ?Sized,
{
    let observed_chirho = enumerator_chirho.observed_surfaces_chirho();
    let observed_set_chirho: BTreeSet<&str> = observed_chirho.iter().map(String::as_str).collect();
    let refusals_chirho = observed_chirho
        .iter()
        .filter(|surface_chirho| !declared_surfaces_chirho.contains(*surface_chirho))
        .map(
            |surface_chirho| CompletenessRefusalChirho::UnknownSurfaceChirho {
                surface_chirho: surface_chirho.clone(),
            },
        )
        .collect::<Vec<_>>();
    let declared_but_absent_chirho = declared_surfaces_chirho
        .iter()
        .filter(|surface_chirho| !observed_set_chirho.contains(surface_chirho.as_str()))
        .cloned()
        .collect();
    CompletenessVerdictChirho {
        observed_count_chirho: observed_chirho.len(),
        refusals_chirho,
        declared_but_absent_chirho,
    }
}

/// A preliminary migration check: every applicable half passed over real evidence.
///
/// There is deliberately no way to build this from a subset. The type is the composition rule — a
/// caller cannot hold a successful precheck while having checked only what it found convenient.
/// It carries no root, tenant, journal cut, or writer authority and therefore cannot authorize a
/// handoff by itself.
///
/// **It became three when the disposition half arrived, and the reason is worth keeping.** Two
/// halves prove you were shown everything and that what you were shown resolves locally. Neither
/// says what a migration DOES with a surface — so a root could pass both while holding a private
/// signing key nobody had decided how to move. "Present and accounted for" is not "carried".
///
/// **It became four when a real migration ran (2026-08-19), and that reason is sharper.** All three
/// ask about what a root HAS. None could ask what it LACKS — so a target passed every one of them
/// and activated into a state where it could not start, because the surfaces carrying its signing
/// identity were absent, and absence was invisible to every question being asked. The fourth half
/// needs a source to compare against, so it is optional in the type and mandatory whenever a source
/// exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreliminaryMigrationCheckChirho {
    references_checked_chirho: usize,
    surfaces_observed_chirho: usize,
    disposition_population_digest_chirho: DispositionPopulationDigestChirho,
}

impl PreliminaryMigrationCheckChirho {
    pub fn references_checked_chirho(&self) -> usize {
        self.references_checked_chirho
    }
    pub fn surfaces_observed_chirho(&self) -> usize {
        self.surfaces_observed_chirho
    }
    pub fn disposition_population_digest_chirho(&self) -> &DispositionPopulationDigestChirho {
        &self.disposition_population_digest_chirho
    }
}

/// Maximum distinct surface names retained for one failed half.
pub const PRELIMINARY_MIGRATION_SURFACE_DETAIL_LIMIT_CHIRHO: usize = 8;
/// Maximum length of one retained surface name. Names use an ASCII-only alphabet, so bytes and
/// characters have the same bound.
pub const PRELIMINARY_MIGRATION_SURFACE_NAME_LIMIT_CHIRHO: usize = 64;
/// Fixed replacement for an empty, overlong, non-ASCII, or punctuation-bearing surface name.
pub const UNREPORTABLE_MIGRATION_SURFACE_CHIRHO: &str = "unreportable-surface-chirho";

/// The closed set of independently evaluated preliminary migration halves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreliminaryMigrationHalfChirho {
    CompletenessChirho,
    SelfContainmentChirho,
    DispositionChirho,
    RequiredSurfacesChirho,
    ClassifierIdentityChirho,
    CapacityAdmissionChirho,
}

impl PreliminaryMigrationHalfChirho {
    pub fn name_chirho(self) -> &'static str {
        match self {
            Self::CompletenessChirho => "completeness-chirho",
            Self::SelfContainmentChirho => "self-containment-chirho",
            Self::DispositionChirho => "disposition-chirho",
            Self::RequiredSurfacesChirho => "required-surfaces-chirho",
            Self::ClassifierIdentityChirho => "classifier-identity-chirho",
            Self::CapacityAdmissionChirho => "capacity-admission-chirho",
        }
    }
}

/// One failed half with a bounded, operator-safe surface summary.
///
/// Construction is private so downstream callers cannot bypass the sanitizer and place a raw
/// filesystem name into an operator response. Self-containment refusals retain only their log
/// surface; sequence numbers and content hashes remain inside the verifier verdict and do not cross
/// this boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct PreliminaryMigrationHalfFailureChirho {
    half_chirho: PreliminaryMigrationHalfChirho,
    surfaces_chirho: Vec<String>,
    dropped_surface_count_chirho: usize,
}

impl PreliminaryMigrationHalfFailureChirho {
    fn from_surfaces_chirho<'surface_chirho>(
        half_chirho: PreliminaryMigrationHalfChirho,
        surfaces_chirho: impl IntoIterator<Item = &'surface_chirho str>,
    ) -> Self {
        let raw_surfaces_chirho: BTreeSet<&str> = surfaces_chirho.into_iter().collect();
        let raw_surface_count_chirho = raw_surfaces_chirho.len();
        let safe_surfaces_chirho: BTreeSet<String> = raw_surfaces_chirho
            .into_iter()
            .map(sanitized_migration_surface_chirho)
            .collect();
        let had_unreportable_surface_chirho =
            safe_surfaces_chirho.contains(UNREPORTABLE_MIGRATION_SURFACE_CHIRHO);
        let mut surfaces_chirho: Vec<String> = safe_surfaces_chirho
            .into_iter()
            .take(PRELIMINARY_MIGRATION_SURFACE_DETAIL_LIMIT_CHIRHO)
            .collect();
        if had_unreportable_surface_chirho
            && !surfaces_chirho
                .iter()
                .any(|surface_chirho| surface_chirho == UNREPORTABLE_MIGRATION_SURFACE_CHIRHO)
        {
            surfaces_chirho.pop();
            surfaces_chirho.push(UNREPORTABLE_MIGRATION_SURFACE_CHIRHO.to_owned());
            surfaces_chirho.sort();
        }
        let dropped_surface_count_chirho =
            raw_surface_count_chirho.saturating_sub(surfaces_chirho.len());
        Self {
            half_chirho,
            surfaces_chirho,
            dropped_surface_count_chirho,
        }
    }

    pub fn half_chirho(&self) -> PreliminaryMigrationHalfChirho {
        self.half_chirho
    }

    pub fn surfaces_chirho(&self) -> &[String] {
        &self.surfaces_chirho
    }

    pub fn dropped_surface_count_chirho(&self) -> usize {
        self.dropped_surface_count_chirho
    }
}

impl fmt::Debug for PreliminaryMigrationHalfFailureChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("PreliminaryMigrationHalfFailureChirho")
            .field("half_chirho", &self.half_chirho.name_chirho())
            .field("surfaces_chirho", &self.surfaces_chirho)
            .field(
                "dropped_surface_count_chirho",
                &self.dropped_surface_count_chirho,
            )
            .finish()
    }
}

impl fmt::Display for PreliminaryMigrationHalfFailureChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter_chirho,
            "{}[surfaces_chirho={};dropped_surface_count_chirho={}]",
            self.half_chirho.name_chirho(),
            if self.surfaces_chirho.is_empty() {
                "none-chirho".to_owned()
            } else {
                self.surfaces_chirho.join("|")
            },
            self.dropped_surface_count_chirho
        )
    }
}

fn sanitized_migration_surface_chirho(surface_chirho: &str) -> String {
    let accepted_chirho = !surface_chirho.is_empty()
        && surface_chirho.len() <= PRELIMINARY_MIGRATION_SURFACE_NAME_LIMIT_CHIRHO
        && surface_chirho.bytes().all(|byte_chirho| {
            byte_chirho.is_ascii_alphanumeric() || matches!(byte_chirho, b'-' | b'_' | b'.')
        });
    if accepted_chirho {
        surface_chirho.to_owned()
    } else {
        UNREPORTABLE_MIGRATION_SURFACE_CHIRHO.to_owned()
    }
}

/// Issue a non-authoritative precheck only if every applicable half passes over real evidence.
pub fn preliminary_migration_check_chirho(
    completeness_chirho: &CompletenessVerdictChirho,
    self_containment_chirho: &SelfContainmentVerdictChirho,
    disposition_chirho: &DispositionVerdictChirho,
    required_surfaces_chirho: Option<&RequiredSurfaceVerdictChirho>,
    capacity_admission_chirho: Option<&TenantCapacityAdmissionVerdictChirho>,
) -> Result<PreliminaryMigrationCheckChirho, Vec<PreliminaryMigrationHalfFailureChirho>> {
    let mut failures_chirho = Vec::new();
    let expected_classifier_digest_chirho = disposition_population_digest_chirho();
    let disposition_classifier_matches_chirho = disposition_chirho
        .disposition_population_digest_chirho
        == expected_classifier_digest_chirho;
    let required_classifier_matches_chirho =
        required_surfaces_chirho.is_none_or(|required_chirho| {
            required_chirho.disposition_population_digest_chirho
                == expected_classifier_digest_chirho
        });
    if !disposition_classifier_matches_chirho || !required_classifier_matches_chirho {
        failures_chirho.push(PreliminaryMigrationHalfFailureChirho::from_surfaces_chirho(
            PreliminaryMigrationHalfChirho::ClassifierIdentityChirho,
            std::iter::empty(),
        ));
    }
    if !completeness_chirho.is_complete_over_evidence_chirho() {
        failures_chirho.push(PreliminaryMigrationHalfFailureChirho::from_surfaces_chirho(
            PreliminaryMigrationHalfChirho::CompletenessChirho,
            completeness_chirho
                .refusals_chirho
                .iter()
                .map(|refusal_chirho| match refusal_chirho {
                    CompletenessRefusalChirho::UnknownSurfaceChirho { surface_chirho } => {
                        surface_chirho.as_str()
                    }
                }),
        ));
    }
    if !self_containment_chirho.is_self_contained_over_evidence_chirho() {
        failures_chirho.push(PreliminaryMigrationHalfFailureChirho::from_surfaces_chirho(
            PreliminaryMigrationHalfChirho::SelfContainmentChirho,
            self_containment_chirho.refusals_chirho.iter().map(
                |refusal_chirho| match refusal_chirho {
                    SelfContainmentRefusalChirho::DanglingReferenceChirho {
                        log_name_chirho,
                        ..
                    }
                    | SelfContainmentRefusalChirho::LostAgainstSourceChirho {
                        log_name_chirho,
                        ..
                    } => log_name_chirho.as_str(),
                },
            ),
        ));
    }
    if !disposition_chirho.is_disposed_over_evidence_chirho() {
        failures_chirho.push(PreliminaryMigrationHalfFailureChirho::from_surfaces_chirho(
            PreliminaryMigrationHalfChirho::DispositionChirho,
            disposition_chirho
                .refusals_chirho
                .iter()
                .map(|refusal_chirho| match refusal_chirho {
                    DispositionRefusalChirho::UndisposedSurfaceChirho { surface_chirho }
                    | DispositionRefusalChirho::CustodyTransferNotMechanisedChirho {
                        surface_chirho,
                    }
                    | DispositionRefusalChirho::NotAMigrationUnitChirho { surface_chirho } => {
                        surface_chirho.as_str()
                    }
                }),
        ));
    }
    // The FOURTH half, and the only one that can see an ABSENCE. Optional because it needs a source
    // to compare against: a one-root report has nothing to be missing FROM. When a source is in
    // hand it is not optional at all — see `verify_required_surfaces_chirho` for the migration that
    // activated into a root which could not start, because what was missing was missing from the
    // check too.
    if let Some(required_surfaces_chirho) = required_surfaces_chirho {
        if !required_surfaces_chirho.is_complete_over_evidence_chirho() {
            failures_chirho.push(PreliminaryMigrationHalfFailureChirho::from_surfaces_chirho(
                PreliminaryMigrationHalfChirho::RequiredSurfacesChirho,
                required_surfaces_chirho
                    .refusals_chirho
                    .iter()
                    .map(|refusal_chirho| match refusal_chirho {
                        RequiredSurfaceRefusalChirho::MissingAtTargetChirho { surface_chirho } => {
                            surface_chirho.as_str()
                        }
                    }),
            ));
        }
    }
    // The SIXTH half, and the only one whose evidence lives outside this crate entirely. Optional
    // for the same reason the fourth is: a report with no capacity evidence in hand has nothing to
    // decide. When a verdict IS supplied it is not optional at all, and its own anti-vacuity guard
    // is what stops "no evidence" reading as "nothing was insufficient".
    //
    // The refusal strings go through the same sanitizer as every other half. That is deliberate: a
    // capacity refusal names node ids and evidence coordinates, which is exactly the payload the
    // half-failure boundary exists to keep out of an operator response.
    if let Some(capacity_admission_chirho) = capacity_admission_chirho {
        if !capacity_admission_chirho.is_admitted_over_evidence_chirho() {
            failures_chirho.push(PreliminaryMigrationHalfFailureChirho::from_surfaces_chirho(
                PreliminaryMigrationHalfChirho::CapacityAdmissionChirho,
                capacity_admission_chirho
                    .refusals_chirho
                    .iter()
                    .map(String::as_str),
            ));
        }
    }
    if failures_chirho.is_empty() {
        Ok(PreliminaryMigrationCheckChirho {
            references_checked_chirho: self_containment_chirho.references_checked_chirho,
            surfaces_observed_chirho: completeness_chirho.observed_count_chirho,
            disposition_population_digest_chirho: expected_classifier_digest_chirho,
        })
    } else {
        Err(failures_chirho)
    }
}

#[cfg(test)]
#[path = "migration_completeness_tests_chirho.rs"]
mod migration_completeness_tests_chirho;
