// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Re-enter a CONSUMED credits-demo root at app promotion and drive it to one app head, one route
//! head, and one price head — skipping whatever already exists, and adding nothing on a second run.
//!
//! This is the continuation half of `setup_chirho`. That module refuses a non-fresh root; this one
//! refuses a FRESH root, and the two predicates are deliberately the same observations read in
//! opposite directions rather than two independent detectors that could drift apart.
//!
//! **There is no regenesis path here, by construction.** H3, identity, OAuth, candidate and review
//! coordinates are INVENTORIED from the root at runtime; none is recomputed, and none is hardcoded.
//! A continuation that could regenesis could destroy the state it was invoked to finish.

use anyhow::{bail, Context, Result};
use cairn_chirho::app_model_chirho::app_policy_chirho;
use cairn_chirho::model_chirho::HashChirho;
use cairn_chirho::{app_source_manifest_chirho, refs_chirho, review_chirho, store_chirho};
use cairn_writer_head_chirho::head_transition_authority_chirho::HeadTransitionAuthorityPortChirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::constants_chirho;

const REVIEWED_CANDIDATE_POINTER_SCHEMA_CHIRHO: &str =
    "credits-demo-reviewed-candidate-pointer-v1-chirho";
const MAX_REVIEWED_CANDIDATE_POINTER_BYTES_CHIRHO: u64 = 4096;

pub const REVIEWED_CANDIDATE_POINTER_MISSING_REFUSAL_CHIRHO: &str =
    "CreditsDemoReviewedCandidatePointerMissingChirho";
pub const REVIEWED_CANDIDATE_POINTER_UNSAFE_REFUSAL_CHIRHO: &str =
    "CreditsDemoReviewedCandidatePointerUnsafeChirho";
pub const REVIEWED_CANDIDATE_POINTER_INVALID_REFUSAL_CHIRHO: &str =
    "CreditsDemoReviewedCandidatePointerInvalidChirho";
pub const REVIEWED_CANDIDATE_REPORT_INVALID_REFUSAL_CHIRHO: &str =
    "CreditsDemoReviewedCandidateReportInvalidChirho";
pub const REVIEWED_CANDIDATE_APP_MISMATCH_REFUSAL_CHIRHO: &str =
    "CreditsDemoReviewedCandidateAppMismatchChirho";
pub const REVIEWED_CANDIDATE_ROUTE_MISSING_REFUSAL_CHIRHO: &str =
    "CreditsDemoReviewedSpendRouteMissingChirho";
pub const REVIEWED_CANDIDATE_ROUTE_DUPLICATE_REFUSAL_CHIRHO: &str =
    "CreditsDemoReviewedSpendRouteDuplicateChirho";
pub const REVIEWED_INPUTS_NOT_EXTERNAL_REFUSAL_CHIRHO: &str =
    "CreditsDemoReviewedInputsNotExternalChirho";
pub const CONTINUATION_PHASE_STALLED_REFUSAL_CHIRHO: &str =
    "CreditsDemoContinuationPhaseStalledChirho";

/// A bounded locator for one already-stored review report. It grants no authority: every read
/// revalidates the report, candidate, manifest, executable closure, app name, and selected route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreditsDemoReviewedCandidatePointerChirho {
    pub schema_chirho: String,
    pub app_chirho: String,
    pub owner_chirho: String,
    pub source_review_report_chirho: HashChirho,
    pub candidate_root_dag_chirho: HashChirho,
}

struct ValidatedCreditsDemoCandidateChirho {
    pointer_chirho: CreditsDemoReviewedCandidatePointerChirho,
    report_chirho: app_source_manifest_chirho::AppSourceReviewReportChirho,
    spend_route_chirho: app_source_manifest_chirho::AppSourceCandidateRouteReportChirho,
}

pub fn reviewed_candidate_pointer_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho
        .join(constants_chirho::REVIEWED_INPUTS_DIR_CHIRHO)
        .join(constants_chirho::REVIEWED_CANDIDATE_POINTER_FILE_CHIRHO)
}

fn validate_hash_text_chirho(value_chirho: &str, refusal_chirho: &str) -> Result<HashChirho> {
    if value_chirho.len() != 64
        || !value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
    {
        bail!("{refusal_chirho}: expected one canonical lowercase 64-hex hash");
    }
    Ok(HashChirho(value_chirho.to_owned()))
}

fn require_safe_reviewed_inputs_dir_chirho(root_chirho: &Path) -> Result<PathBuf> {
    let dir_chirho = root_chirho.join(constants_chirho::REVIEWED_INPUTS_DIR_CHIRHO);
    require_safe_reviewed_inputs_dir_at_chirho(&dir_chirho)
}

fn require_safe_reviewed_inputs_dir_at_chirho(dir_chirho: &Path) -> Result<PathBuf> {
    let metadata_chirho = std::fs::symlink_metadata(dir_chirho).with_context(|| {
        format!(
            "{REVIEWED_CANDIDATE_POINTER_UNSAFE_REFUSAL_CHIRHO}: inspect {}",
            dir_chirho.display()
        )
    })?;
    if metadata_chirho.file_type().is_symlink() || !metadata_chirho.is_dir() {
        bail!(
            "{REVIEWED_CANDIDATE_POINTER_UNSAFE_REFUSAL_CHIRHO}: reviewed-inputs is not a real directory"
        );
    }
    Ok(dir_chirho.to_path_buf())
}

fn require_safe_external_reviewed_inputs_dir_chirho(
    root_chirho: &Path,
    reviewed_inputs_dir_chirho: &Path,
) -> Result<PathBuf> {
    let dir_chirho = require_safe_reviewed_inputs_dir_at_chirho(reviewed_inputs_dir_chirho)?;
    let canonical_root_chirho = std::fs::canonicalize(root_chirho).with_context(|| {
        format!(
            "{REVIEWED_INPUTS_NOT_EXTERNAL_REFUSAL_CHIRHO}: canonicalize selected root {}",
            root_chirho.display()
        )
    })?;
    let canonical_dir_chirho = std::fs::canonicalize(&dir_chirho).with_context(|| {
        format!(
            "{REVIEWED_INPUTS_NOT_EXTERNAL_REFUSAL_CHIRHO}: canonicalize reviewed inputs {}",
            dir_chirho.display()
        )
    })?;
    if canonical_dir_chirho.starts_with(&canonical_root_chirho) {
        bail!(
            "{REVIEWED_INPUTS_NOT_EXTERNAL_REFUSAL_CHIRHO}: reviewed inputs must live outside the tenant root"
        );
    }
    let root_metadata_chirho = std::fs::metadata(&canonical_root_chirho)?;
    let dir_metadata_chirho = std::fs::metadata(&canonical_dir_chirho)?;
    if root_metadata_chirho.uid() != dir_metadata_chirho.uid()
        || dir_metadata_chirho.mode() & 0o077 != 0
    {
        bail!(
            "{REVIEWED_CANDIDATE_POINTER_UNSAFE_REFUSAL_CHIRHO}: external reviewed-inputs custody differs from the selected root"
        );
    }
    Ok(canonical_dir_chirho)
}

fn read_bounded_pointer_bytes_chirho(path_chirho: &Path) -> Result<Vec<u8>> {
    let path_metadata_chirho = std::fs::symlink_metadata(path_chirho).with_context(|| {
        format!(
            "{REVIEWED_CANDIDATE_POINTER_MISSING_REFUSAL_CHIRHO}: {}",
            path_chirho.display()
        )
    })?;
    if path_metadata_chirho.file_type().is_symlink() || !path_metadata_chirho.is_file() {
        bail!("{REVIEWED_CANDIDATE_POINTER_UNSAFE_REFUSAL_CHIRHO}: pointer is not a real file");
    }
    let file_chirho = File::open(path_chirho).with_context(|| {
        format!(
            "{REVIEWED_CANDIDATE_POINTER_UNSAFE_REFUSAL_CHIRHO}: open {}",
            path_chirho.display()
        )
    })?;
    let opened_metadata_chirho = file_chirho.metadata().with_context(|| {
        format!("{REVIEWED_CANDIDATE_POINTER_UNSAFE_REFUSAL_CHIRHO}: inspect opened pointer")
    })?;
    if path_metadata_chirho.dev() != opened_metadata_chirho.dev()
        || path_metadata_chirho.ino() != opened_metadata_chirho.ino()
        || opened_metadata_chirho.len() > MAX_REVIEWED_CANDIDATE_POINTER_BYTES_CHIRHO
    {
        bail!(
            "{REVIEWED_CANDIDATE_POINTER_UNSAFE_REFUSAL_CHIRHO}: pointer identity or size changed"
        );
    }
    let mut bytes_chirho = Vec::with_capacity(opened_metadata_chirho.len() as usize);
    file_chirho
        .take(MAX_REVIEWED_CANDIDATE_POINTER_BYTES_CHIRHO + 1)
        .read_to_end(&mut bytes_chirho)?;
    if bytes_chirho.len() as u64 > MAX_REVIEWED_CANDIDATE_POINTER_BYTES_CHIRHO {
        bail!("{REVIEWED_CANDIDATE_POINTER_UNSAFE_REFUSAL_CHIRHO}: pointer is oversized");
    }
    Ok(bytes_chirho)
}

fn unique_spend_route_chirho(
    report_chirho: &app_source_manifest_chirho::AppSourceReviewReportChirho,
) -> Result<app_source_manifest_chirho::AppSourceCandidateRouteReportChirho> {
    let mut routes_chirho = report_chirho
        .candidate_chirho
        .routes_chirho
        .iter()
        .filter(|route_chirho| route_chirho.route_chirho == constants_chirho::SPEND_ROUTE_CHIRHO);
    let route_chirho = routes_chirho.next().cloned().ok_or_else(|| {
        anyhow::anyhow!(
            "{REVIEWED_CANDIDATE_ROUTE_MISSING_REFUSAL_CHIRHO}: reviewed candidate has no spend route"
        )
    })?;
    if routes_chirho.next().is_some() {
        bail!(
            "{REVIEWED_CANDIDATE_ROUTE_DUPLICATE_REFUSAL_CHIRHO}: reviewed candidate has duplicate spend routes"
        );
    }
    Ok(route_chirho)
}

fn validate_review_report_chirho(
    root_chirho: &Path,
    source_review_report_chirho: &HashChirho,
) -> Result<ValidatedCreditsDemoCandidateChirho> {
    validate_hash_text_chirho(
        &source_review_report_chirho.0,
        REVIEWED_CANDIDATE_REPORT_INVALID_REFUSAL_CHIRHO,
    )?;
    let unverified_chirho: app_source_manifest_chirho::AppSourceReviewReportChirho =
        store_chirho::get_object_chirho(root_chirho, source_review_report_chirho).with_context(
            || {
                format!(
                    "{REVIEWED_CANDIDATE_REPORT_INVALID_REFUSAL_CHIRHO}: load review report {}",
                    source_review_report_chirho.0
                )
            },
        )?;
    if unverified_chirho.candidate_chirho.app_chirho != constants_chirho::APP_CHIRHO {
        bail!(
            "{REVIEWED_CANDIDATE_APP_MISMATCH_REFUSAL_CHIRHO}: report app '{}' is not '{}'",
            unverified_chirho.candidate_chirho.app_chirho,
            constants_chirho::APP_CHIRHO
        );
    }
    // Classify the demo route-selection defect by its own identity before the broader descriptor
    // verifier reports a generic candidate-shape failure. No coordinate is trusted from this pass;
    // the fully verified report below is selected again before use.
    unique_spend_route_chirho(&unverified_chirho)?;
    let owner_chirho = unverified_chirho.candidate_chirho.owner_chirho.clone();
    let candidate_chirho = unverified_chirho.candidate_chirho.root_dag_chirho.clone();
    let report_chirho =
        app_source_manifest_chirho::load_app_source_review_report_for_promotion_chirho(
            root_chirho,
            constants_chirho::APP_CHIRHO,
            &owner_chirho,
            source_review_report_chirho,
            Some(&candidate_chirho),
        )
        .with_context(|| {
            format!(
                "{REVIEWED_CANDIDATE_REPORT_INVALID_REFUSAL_CHIRHO}: review verification refused"
            )
        })?;
    let spend_route_chirho = unique_spend_route_chirho(&report_chirho)?;
    let pointer_chirho = CreditsDemoReviewedCandidatePointerChirho {
        schema_chirho: REVIEWED_CANDIDATE_POINTER_SCHEMA_CHIRHO.to_owned(),
        app_chirho: constants_chirho::APP_CHIRHO.to_owned(),
        owner_chirho,
        source_review_report_chirho: source_review_report_chirho.clone(),
        candidate_root_dag_chirho: candidate_chirho,
    };
    Ok(ValidatedCreditsDemoCandidateChirho {
        pointer_chirho,
        report_chirho,
        spend_route_chirho,
    })
}

/// Validate an explicit operator coordinate and persist its bounded locator exactly once.
///
/// This command is the one-off migration for roots created before fresh setup wrote this pointer.
/// New roots call the same function before promotion and never need an object-store scan.
///
/// SECURITY SHAPE (reviewer's precision note, S4U-R review): neither half alone gives the pinned
/// property — the validation chain proves "this pointer names a VALID, app-matching,
/// closure-checked review report"; the `create_new` no-overwrite proves "this is the one the
/// operator PINNED". Only together do they give "the valid report you pinned" — do not weaken
/// either believing the other covers it.
pub fn pin_reviewed_candidate_coordinates_chirho(
    root_chirho: &Path,
    source_review_report_hex_chirho: &str,
) -> Result<CreditsDemoReviewedCandidatePointerChirho> {
    let source_review_report_chirho = validate_hash_text_chirho(
        source_review_report_hex_chirho,
        REVIEWED_CANDIDATE_REPORT_INVALID_REFUSAL_CHIRHO,
    )?;
    persist_reviewed_candidate_pointer_chirho(root_chirho, &source_review_report_chirho)
}

pub fn persist_reviewed_candidate_pointer_chirho(
    root_chirho: &Path,
    source_review_report_chirho: &HashChirho,
) -> Result<CreditsDemoReviewedCandidatePointerChirho> {
    let validated_chirho = validate_review_report_chirho(root_chirho, source_review_report_chirho)?;
    let dir_chirho = require_safe_reviewed_inputs_dir_chirho(root_chirho)?;
    let path_chirho = dir_chirho.join(constants_chirho::REVIEWED_CANDIDATE_POINTER_FILE_CHIRHO);
    let mut bytes_chirho = serde_json::to_vec(&validated_chirho.pointer_chirho)?;
    bytes_chirho.push(b'\n');
    if bytes_chirho.len() as u64 > MAX_REVIEWED_CANDIDATE_POINTER_BYTES_CHIRHO {
        bail!("{REVIEWED_CANDIDATE_POINTER_INVALID_REFUSAL_CHIRHO}: pointer is oversized");
    }
    let mut file_chirho = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path_chirho)
        .with_context(|| {
            format!(
                "{REVIEWED_CANDIDATE_POINTER_UNSAFE_REFUSAL_CHIRHO}: create {} exactly once",
                path_chirho.display()
            )
        })?;
    if let Err(error_chirho) = file_chirho
        .write_all(&bytes_chirho)
        .and_then(|()| file_chirho.sync_all())
    {
        drop(file_chirho);
        let _remove_result_chirho = std::fs::remove_file(&path_chirho);
        return Err(error_chirho).context("persist reviewed-candidate pointer");
    }
    File::open(&dir_chirho)?.sync_all()?;
    Ok(validated_chirho.pointer_chirho)
}

fn load_validated_reviewed_candidate_chirho(
    root_chirho: &Path,
    reviewed_inputs_dir_chirho: &Path,
) -> Result<ValidatedCreditsDemoCandidateChirho> {
    let dir_chirho = require_safe_reviewed_inputs_dir_at_chirho(reviewed_inputs_dir_chirho)?;
    let path_chirho = dir_chirho.join(constants_chirho::REVIEWED_CANDIDATE_POINTER_FILE_CHIRHO);
    let bytes_chirho = read_bounded_pointer_bytes_chirho(&path_chirho)?;
    let pointer_chirho: CreditsDemoReviewedCandidatePointerChirho =
        serde_json::from_slice(&bytes_chirho).with_context(|| {
            format!("{REVIEWED_CANDIDATE_POINTER_INVALID_REFUSAL_CHIRHO}: parse pointer")
        })?;
    if pointer_chirho.schema_chirho != REVIEWED_CANDIDATE_POINTER_SCHEMA_CHIRHO
        || pointer_chirho.app_chirho != constants_chirho::APP_CHIRHO
    {
        bail!("{REVIEWED_CANDIDATE_POINTER_INVALID_REFUSAL_CHIRHO}: schema or app mismatch");
    }
    let validated_chirho =
        validate_review_report_chirho(root_chirho, &pointer_chirho.source_review_report_chirho)?;
    if pointer_chirho != validated_chirho.pointer_chirho {
        bail!(
            "{REVIEWED_CANDIDATE_POINTER_INVALID_REFUSAL_CHIRHO}: pointer differs from verified report coordinates"
        );
    }
    Ok(validated_chirho)
}

/// What a consumed root already carries. Every field is READ; none is assumed and none is a constant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuationInventoryChirho {
    /// The ledger substrate namespace directory — the same observation `setup_chirho` uses to refuse
    /// a non-fresh root, read here to require the opposite.
    pub ledger_substrate_present_chirho: bool,
    pub app_head_chirho: Option<HashChirho>,
    /// Every route this app has deployed, as `(route name, head)`, sorted. Route NAMES, not full
    /// branch names — the typed enumerator returns names, and this module no longer spells refs.
    pub route_heads_chirho: Vec<(String, HashChirho)>,
    pub price_book_head_chirho: Option<HashChirho>,
}

impl ContinuationInventoryChirho {
    /// True once the end state is reached: one app head, the reviewed spend-route head, one price
    /// head. An unrelated route cannot advance this demo-specific continuation.
    pub fn end_state_reached_chirho(&self) -> bool {
        self.app_head_chirho.is_some()
            && self
                .route_heads_chirho
                .iter()
                .any(|(route_chirho, _head_chirho)| {
                    route_chirho == constants_chirho::SPEND_ROUTE_CHIRHO
                })
            && self.price_book_head_chirho.is_some()
    }
}

/// Where a continuation must re-enter. Ordered: each phase depends on the one above it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinuationPhaseChirho {
    /// No app head yet — re-enter at promotion. This is the ONLY entry point the brief allows.
    AppPromotionChirho,
    /// App head present, no route head.
    RouteDeployChirho,
    /// App and route present, no price head.
    PriceBookChirho,
    /// Nothing left to do; a run from here must add zero rows, refs, or receipts.
    CompleteChirho,
}

/// Read what the root already has. **No coordinate is hardcoded**: the app name comes from the shared
/// constant the fresh setup also uses, the substrate namespace from the caller's verified config, and
/// every head from the root's own refs.
pub fn inventory_consumed_root_chirho(
    root_chirho: &Path,
    storage_namespace_chirho: &str,
) -> Result<ContinuationInventoryChirho> {
    let ledger_substrate_present_chirho = root_chirho.join(storage_namespace_chirho).exists();
    let refs_val_chirho = refs_chirho::load_refs_chirho(root_chirho).with_context(|| {
        format!(
            "read refs for continuation inventory at {}",
            root_chirho.display()
        )
    })?;

    let app_branch_chirho =
        cairn_chirho::app_chirho::app_branch_ref_name_chirho(constants_chirho::APP_CHIRHO);
    let app_head_chirho = refs_val_chirho
        .branches_chirho
        .get(&app_branch_chirho)
        .cloned();

    // Routes come from the TYPED enumerator, not a raw `app-route/` prefix this module owns.
    // S4P shipped the prefix with a comment claiming no public accessor existed; that comment named
    // `app_route_ref_head_chirho` (which is indeed `pub(crate)`) and missed
    // `deployed_app_route_names_chirho`, which is public and does exactly this. The
    // app-control-plane centralization guard caught it. Absence of one accessor was not absence of
    // the capability.
    let mut route_heads_chirho = Vec::new();
    for route_chirho in app_policy_chirho::deployed_app_route_names_chirho(
        &refs_val_chirho,
        constants_chirho::APP_CHIRHO,
    ) {
        if let Some(head_chirho) = app_policy_chirho::app_route_ref_target_chirho(
            &refs_val_chirho,
            constants_chirho::APP_CHIRHO,
            &route_chirho,
        ) {
            route_heads_chirho.push((route_chirho, head_chirho));
        }
    }
    route_heads_chirho.sort();

    // FAIL CLOSED, and the reason is specific rather than general hygiene. This read GATES a
    // mutation decision: `next_phase_chirho` routes to `PriceBookChirho` when the head is absent.
    // `current_price_book_hash_chirho` distinguishes "no price book" (`Ok(None)`) from "the price
    // history did not verify" (`Err` — see `effect_pricing_chirho.rs:245`, the ref-selects-no-
    // verified-signed-history refusal). Mapping that Err to None would read a root whose price ref
    // exists but does NOT verify as a root with no price at all, and send the continuation to mint
    // one over it. Absence is a fact about the root; an error is the absence of a fact.
    let price_book_head_chirho =
        cairn_chirho::effect_pricing_chirho::current_price_book_hash_chirho(
            root_chirho,
            constants_chirho::APP_CHIRHO,
        )
        .with_context(|| {
            format!(
                "read verified price book head for continuation inventory at {}",
                root_chirho.display()
            )
        })?;

    Ok(ContinuationInventoryChirho {
        ledger_substrate_present_chirho,
        app_head_chirho,
        route_heads_chirho,
        price_book_head_chirho,
    })
}

/// The named refusal a FRESH root gets.
///
/// The mirror of `setup_chirho::refuse_non_fresh_root_chirho`: that one refuses when substrate is
/// present, this one refuses when it is absent. Same observation, opposite direction, so the pair
/// cannot disagree about what "consumed" means.
pub const CONTINUATION_FRESH_ROOT_REFUSAL_CHIRHO: &str =
    "credits-demo continuation refuses a FRESH root: no ledger substrate present. \
     Run the fresh setup first; the continuation never regenesises";

/// Refuse to continue on a root that was never consumed.
pub fn require_consumed_root_chirho(inventory_chirho: &ContinuationInventoryChirho) -> Result<()> {
    if !inventory_chirho.ledger_substrate_present_chirho {
        bail!("{CONTINUATION_FRESH_ROOT_REFUSAL_CHIRHO}");
    }
    Ok(())
}

/// Which phase to re-enter at, derived ONLY from what the root actually carries.
pub fn next_phase_chirho(
    inventory_chirho: &ContinuationInventoryChirho,
) -> ContinuationPhaseChirho {
    if inventory_chirho.app_head_chirho.is_none() {
        return ContinuationPhaseChirho::AppPromotionChirho;
    }
    if !inventory_chirho
        .route_heads_chirho
        .iter()
        .any(|(route_chirho, _head_chirho)| route_chirho == constants_chirho::SPEND_ROUTE_CHIRHO)
    {
        return ContinuationPhaseChirho::RouteDeployChirho;
    }
    if inventory_chirho.price_book_head_chirho.is_none() {
        return ContinuationPhaseChirho::PriceBookChirho;
    }
    ContinuationPhaseChirho::CompleteChirho
}

/// What a continuation run did. `mutations_attempted_chirho == 0` is the idempotence witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuationReportChirho {
    pub entered_phase_chirho: ContinuationPhaseChirho,
    pub mutations_attempted_chirho: usize,
    pub inventory_before_chirho: ContinuationInventoryChirho,
}

fn promote_reviewed_app_chirho(
    root_chirho: &Path,
    reviewed_chirho: &ValidatedCreditsDemoCandidateChirho,
    authority_chirho: &dyn HeadTransitionAuthorityPortChirho,
) -> Result<()> {
    let source_manifest_chirho = reviewed_chirho
        .report_chirho
        .candidate_chirho
        .source_manifest_chirho
        .clone()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{REVIEWED_CANDIDATE_REPORT_INVALID_REFUSAL_CHIRHO}: report lacks source-manifest evidence"
            )
        })?;
    let accept_capability_escalation_chirho = !reviewed_chirho
        .report_chirho
        .review_chirho
        .added_capabilities_chirho
        .is_empty();
    let accept_cost_increase_chirho = reviewed_chirho
        .report_chirho
        .review_chirho
        .cost_delta_token_chirho
        > 0;
    let promotion_chirho =
        review_chirho::promote_candidate_with_review_evidence_and_head_transition_authority_chirho(
            root_chirho,
            review_chirho::PromoteCandidateReviewEvidenceInputChirho {
                app_chirho: constants_chirho::APP_CHIRHO,
                owner_principal_chirho: &reviewed_chirho.pointer_chirho.owner_chirho,
                candidate_chirho: reviewed_chirho
                    .pointer_chirho
                    .candidate_root_dag_chirho
                    .clone(),
                accept_capability_escalation_chirho,
                accept_cost_increase_chirho,
                require_review_policy_envelope_chirho: false,
                source_evidence_chirho: review_chirho::ReviewSourceEvidenceChirho {
                    source_review_report_chirho: Some(
                        reviewed_chirho
                            .pointer_chirho
                            .source_review_report_chirho
                            .clone(),
                    ),
                    source_manifest_chirho: Some(
                        review_chirho::ReviewSourceManifestEvidenceChirho {
                            effective_manifest_hash_chirho: source_manifest_chirho
                                .effective_manifest_hash_chirho,
                            raw_manifest_hash_chirho: source_manifest_chirho
                                .raw_manifest_hash_chirho,
                        },
                    ),
                },
            },
            authority_chirho,
        )?;
    if promotion_chirho.app_record_seq_chirho.is_none()
        || promotion_chirho.accepted_capability_escalation_chirho
            != accept_capability_escalation_chirho
        || promotion_chirho.accepted_cost_increase_chirho != accept_cost_increase_chirho
    {
        bail!(
            "{REVIEWED_CANDIDATE_REPORT_INVALID_REFUSAL_CHIRHO}: promotion result differs from verified review decisions"
        );
    }
    Ok(())
}

fn deploy_reviewed_route_chirho(
    root_chirho: &Path,
    reviewed_chirho: &ValidatedCreditsDemoCandidateChirho,
    authority_chirho: &dyn HeadTransitionAuthorityPortChirho,
) -> Result<()> {
    let install_chirho =
        app_source_manifest_chirho::install_reviewed_app_source_report_with_head_transition_authority_chirho(
            root_chirho,
            &reviewed_chirho.pointer_chirho.owner_chirho,
            &reviewed_chirho.report_chirho,
            authority_chirho,
        )?;
    if !install_chirho.routes_chirho.iter().any(|route_chirho| {
        route_chirho.route_chirho == reviewed_chirho.spend_route_chirho.route_chirho
            && route_chirho.dag_chirho == reviewed_chirho.spend_route_chirho.dag_chirho
    }) {
        bail!(
            "{REVIEWED_CANDIDATE_REPORT_INVALID_REFUSAL_CHIRHO}: installed routes omit the review-bound spend route"
        );
    }
    Ok(())
}

fn install_reviewed_price_book_chirho(
    root_chirho: &Path,
    reviewed_chirho: &ValidatedCreditsDemoCandidateChirho,
    authority_chirho: &dyn HeadTransitionAuthorityPortChirho,
) -> Result<()> {
    cairn_chirho::effect_pricing_chirho::set_price_book_with_head_transition_authority_chirho(
        root_chirho,
        constants_chirho::APP_CHIRHO,
        &reviewed_chirho.pointer_chirho.owner_chirho,
        None,
        BTreeMap::from([(
            constants_chirho::POSTGRES_REVERSIBLE_EFFECT_CHIRHO.to_owned(),
            constants_chirho::POSTGRES_REVERSIBLE_PRICE_CHIRHO,
        )]),
        0,
        authority_chirho,
    )?;
    Ok(())
}

fn phase_advanced_chirho(
    before_chirho: ContinuationPhaseChirho,
    after_chirho: ContinuationPhaseChirho,
) -> bool {
    matches!(
        (before_chirho, after_chirho),
        (
            ContinuationPhaseChirho::AppPromotionChirho,
            ContinuationPhaseChirho::RouteDeployChirho
                | ContinuationPhaseChirho::PriceBookChirho
                | ContinuationPhaseChirho::CompleteChirho
        ) | (
            ContinuationPhaseChirho::RouteDeployChirho,
            ContinuationPhaseChirho::PriceBookChirho | ContinuationPhaseChirho::CompleteChirho
        ) | (
            ContinuationPhaseChirho::PriceBookChirho,
            ContinuationPhaseChirho::CompleteChirho
        )
    )
}

fn run_credits_demo_continuation_with_inventory_chirho(
    root_chirho: &Path,
    reviewed_inputs_dir_chirho: &Path,
    storage_namespace_chirho: &str,
    inventory_before_chirho: ContinuationInventoryChirho,
    authority_chirho: &dyn HeadTransitionAuthorityPortChirho,
) -> Result<ContinuationReportChirho> {
    let entered_phase_chirho = next_phase_chirho(&inventory_before_chirho);
    // Load even for an already-complete root. A no-op continuation still proves its external review
    // bundle resolves against THIS root rather than greening without touching the relocated input.
    let reviewed_chirho =
        load_validated_reviewed_candidate_chirho(root_chirho, reviewed_inputs_dir_chirho)?;
    if entered_phase_chirho == ContinuationPhaseChirho::CompleteChirho {
        return Ok(ContinuationReportChirho {
            entered_phase_chirho,
            mutations_attempted_chirho: 0,
            inventory_before_chirho,
        });
    }
    let mut phase_chirho = entered_phase_chirho;
    let mut mutations_attempted_chirho = 0usize;
    loop {
        match phase_chirho {
            ContinuationPhaseChirho::AppPromotionChirho => {
                promote_reviewed_app_chirho(root_chirho, &reviewed_chirho, authority_chirho)?;
            }
            ContinuationPhaseChirho::RouteDeployChirho => {
                deploy_reviewed_route_chirho(root_chirho, &reviewed_chirho, authority_chirho)?;
            }
            ContinuationPhaseChirho::PriceBookChirho => {
                install_reviewed_price_book_chirho(
                    root_chirho,
                    &reviewed_chirho,
                    authority_chirho,
                )?;
            }
            ContinuationPhaseChirho::CompleteChirho => break,
        }
        mutations_attempted_chirho = mutations_attempted_chirho.saturating_add(1);
        let inventory_after_step_chirho =
            inventory_consumed_root_chirho(root_chirho, storage_namespace_chirho)?;
        let next_phase_chirho = next_phase_chirho(&inventory_after_step_chirho);
        if !phase_advanced_chirho(phase_chirho, next_phase_chirho) {
            bail!(
                "{CONTINUATION_PHASE_STALLED_REFUSAL_CHIRHO}: {phase_chirho:?} did not advance (observed {next_phase_chirho:?})"
            );
        }
        phase_chirho = next_phase_chirho;
        if phase_chirho == ContinuationPhaseChirho::CompleteChirho {
            break;
        }
    }
    Ok(ContinuationReportChirho {
        entered_phase_chirho,
        mutations_attempted_chirho,
        inventory_before_chirho,
    })
}

/// Re-enter a consumed root through a caller-supplied elected authority. Tests use this seam to
/// exercise named refusals; production obtains the same port from the resident host actor.
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`
/// under "Root Hygiene And Classifier Identity".
pub fn run_credits_demo_continuation_with_head_transition_authority_chirho(
    root_chirho: &Path,
    reviewed_inputs_dir_chirho: &Path,
    storage_namespace_chirho: &str,
    authority_chirho: &dyn HeadTransitionAuthorityPortChirho,
) -> Result<ContinuationReportChirho> {
    let inventory_chirho = inventory_consumed_root_chirho(root_chirho, storage_namespace_chirho)?;
    require_consumed_root_chirho(&inventory_chirho)?;
    let reviewed_inputs_dir_chirho =
        require_safe_external_reviewed_inputs_dir_chirho(root_chirho, reviewed_inputs_dir_chirho)?;
    run_credits_demo_continuation_with_inventory_chirho(
        root_chirho,
        &reviewed_inputs_dir_chirho,
        storage_namespace_chirho,
        inventory_chirho,
        authority_chirho,
    )
}

/// Re-enter a consumed root and drive every incomplete phase to the reviewed end state.
///
/// Skips every completed phase, refuses a fresh root by name, and on an already-complete root does
/// nothing at all — `mutations_attempted_chirho` stays 0, which is what makes a second invocation
/// provably free of new rows, refs, and receipts. The reviewed-input path is required and must live
/// outside the tenant root; this road has no root-relative fallback.
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`
/// under "Root Hygiene And Classifier Identity".
pub fn run_credits_demo_continuation_chirho(
    root_chirho: &Path,
    reviewed_inputs_dir_chirho: &Path,
    expected_config_digest_chirho: &str,
    storage_namespace_chirho: &str,
) -> Result<ContinuationReportChirho> {
    let inventory_chirho = inventory_consumed_root_chirho(root_chirho, storage_namespace_chirho)?;
    require_consumed_root_chirho(&inventory_chirho)?;
    let reviewed_inputs_dir_chirho =
        require_safe_external_reviewed_inputs_dir_chirho(root_chirho, reviewed_inputs_dir_chirho)?;
    let config_path_chirho =
        reviewed_inputs_dir_chirho.join(constants_chirho::HOST_CONFIG_FILE_CHIRHO);
    let config_chirho = cairn_chirho::config_chirho::load_digest_bound_config_chirho(
        &config_path_chirho,
        expected_config_digest_chirho,
    )
    .with_context(|| {
        format!(
            "load digest-bound credits-demo host config {}",
            config_path_chirho.display()
        )
    })?;
    let ledger_host_chirho = config_chirho
        .ledger_host_chirho
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("credits-demo host config lacks ledger_host_chirho"))?;
    if ledger_host_chirho.storage_namespace_chirho != storage_namespace_chirho {
        bail!(
            "CreditsDemoContinuationStorageNamespaceMismatchChirho: supplied '{}' but host config binds '{}'",
            storage_namespace_chirho,
            ledger_host_chirho.storage_namespace_chirho
        );
    }
    let resident_chirho = cairn_ledger_host_chirho::open_resident_effect_journal_handle_chirho(
        root_chirho,
        &config_path_chirho,
        ledger_host_chirho,
        None,
    )?;
    run_credits_demo_continuation_with_inventory_chirho(
        root_chirho,
        &reviewed_inputs_dir_chirho,
        storage_namespace_chirho,
        inventory_chirho,
        resident_chirho.head_transition_authority_chirho(),
    )
}

#[cfg(test)]
#[path = "continuation_tests_chirho.rs"]
mod continuation_tests_chirho;
