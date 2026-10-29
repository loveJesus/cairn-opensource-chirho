// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The item-6 healing-drill's test-kind SELECTED-ROOT LAYOUT schema and a local (no-host) validator
//! that confirms a freshly-staged throwaway drill root satisfies the geo node's custody bindings and
//! obeys the drill-namespace path convention (never the elector root, never `/var/lib/cairn-chirho`).
//!
//! This is brick 6.5-b, the selected-root slice of
//! `spec-chirho/workstream-state-chirho/item6-5-hosted-packaging-design-chirho.md` §2.b. It stages the
//! CAPACITY to validate a root; it creates no root, signs no writer-era authorization (offline signer
//! / 6.5-e), runs no host, and serves nothing.
//!
//! ## What it REUSES vs what is NEW
//! The four geo-node custody bindings already exist and run inside the geo node's serve entrypoints
//! (`cairn-ledger-geo-node-chirho`). This crate reuses them so the validator asserts the same
//! predicate the node runs, without binding a port:
//! * the two FILE-custody checks are called verbatim —
//!   [`verify_cluster_node_file_config_custody_chirho`] and [`verify_host_ledger_config_custody_chirho`];
//! * the two ROOT bindings (group + config-root) are recomposed from the IDENTICAL public primitives
//!   the geo node's private checks call ([`consistency_group_for_root_chirho`], [`tenant_root_chirho`]
//!   + canonicalize), so no substantive custody logic is duplicated and the crate never links the
//!     serve stack.
//!
//! The one GENUINELY-NEW property is the drill-namespace path convention: nothing else rejects a root
//! for being the production or elector root, so [`check_item6_drill_root_path_convention_chirho`] owns
//! that safety invariant.
//!
//! Out of scope here (they belong to the geo node's cluster/config preflight, not the selected-root
//! layout): cluster posture, the voter floor, `postgres_effect` content, and `membership_control`
//! content. The writer-era activation authorization is treated as an OPAQUE required file (present +
//! path validity + private-file custody); it is NOT parsed and its signature is NOT verified here.

use anyhow::Result;
use cairn_config_chirho::config_chirho::{load_config_chirho, ConfigChirho};
use cairn_ledger_host_chirho::verify_host_ledger_config_custody_chirho;
use cairn_tenant_chirho::tenant_chirho::tenant_root_chirho;
use cairn_writer_elector_http_chirho::cluster_file_config_chirho::{
    load_cluster_node_file_config_chirho, verify_cluster_node_file_config_custody_chirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_for_root_chirho, writer_authority_era_chirho, ConsistencyGroupIdChirho,
    WriterAuthorityEraChirho,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Component, Path, PathBuf};

/// Schema tag of the validated, resolved drill-root layout evidence.
pub const ITEM6_DRILL_ROOT_LAYOUT_SCHEMA_V1_CHIRHO: &str = "item6-drill-root-layout-v1-chirho";

/// The canonical drill namespace for a hosted item-6 drill: one throwaway root per owner-capable host
/// lives at `<namespace>/<owner-node>/current-root-chirho`. Deliberately NOT the elector root and NOT
/// the original production root.
pub const CANONICAL_ITEM6_DRILL_NAMESPACE_CHIRHO: &str = "/var/lib/cairn-item6-drill-chirho";

/// The original production runtime root a drill root may NEVER be (or sit under).
pub const FORBIDDEN_PRODUCTION_ROOT_CHIRHO: &str = "/var/lib/cairn-chirho";

/// The election-only elector root a drill root may NEVER be (or sit under).
pub const FORBIDDEN_ELECTOR_ROOT_CHIRHO: &str = "/var/lib/cairn-elector-chirho";

/// The bounded era label a well-formed (freshly staged, pre-activation) drill root reports.
const FRESH_WRITER_ERA_LABEL_CHIRHO: &str = "local-chirho";

/// The operator-declared paths of one owner-capable host's drill node — the validator INPUT.
///
/// Everything else (raft dir, sign root, writer-era authorization path, consistency group) is
/// resolved FROM the cluster config the validator loads, so those single sources of truth cannot
/// drift from a second copy carried here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Item6DrillRootLayoutChirho {
    /// The throwaway selected money-authority root for this drill node.
    pub selected_root_chirho: PathBuf,
    /// The drill namespace `selected_root_chirho` must live under (default:
    /// [`CANONICAL_ITEM6_DRILL_NAMESPACE_CHIRHO`]). Parameterized so a local fixture can validate under
    /// a temp namespace while the forbidden production/elector roots stay fixed constants.
    pub drill_namespace_chirho: PathBuf,
    /// The cluster election config JSON (group, members, raft dir, sign root, writer-era authorization
    /// path, membership control).
    pub cluster_config_chirho: PathBuf,
    /// The ledger runtime config TOML (its effective root must bind to `selected_root_chirho`).
    pub ledger_config_chirho: PathBuf,
}

impl Item6DrillRootLayoutChirho {
    /// A layout under the canonical hosted drill namespace ([`CANONICAL_ITEM6_DRILL_NAMESPACE_CHIRHO`]).
    pub fn under_canonical_namespace_chirho(
        selected_root_chirho: PathBuf,
        cluster_config_chirho: PathBuf,
        ledger_config_chirho: PathBuf,
    ) -> Self {
        Self {
            selected_root_chirho,
            drill_namespace_chirho: PathBuf::from(CANONICAL_ITEM6_DRILL_NAMESPACE_CHIRHO),
            cluster_config_chirho,
            ledger_config_chirho,
        }
    }
}

/// The validated, resolved drill-root layout — the validator OUTPUT and a host-private preflight
/// evidence record. Every field is a typed path or bounded label; there is no free-text surface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedItem6DrillRootLayoutChirho {
    pub schema_chirho: String,
    pub selected_root_chirho: PathBuf,
    pub drill_namespace_chirho: PathBuf,
    pub cluster_config_chirho: PathBuf,
    pub ledger_config_chirho: PathBuf,
    /// The durable election state directory (raft) named by the cluster config — same as the elector.
    pub durable_dir_chirho: PathBuf,
    /// The election sign root named by the cluster config — same as the elector.
    pub sign_root_chirho: PathBuf,
    /// The OPAQUE offline-signed writer-era activation authorization file the cluster config declares,
    /// or `None` when the config OMITS it. The seed-first drill skips the geo writer-era ceremony (the
    /// seed latches Elected via H3 regenesis and mints no geo activation file), so its config omits
    /// this field and step (6) is skipped; a config that DECLARES a path has it verified and recorded.
    pub writer_era_activation_authorization_chirho: Option<PathBuf>,
    /// The canonical consistency-group id both the root and the cluster config agree on.
    pub consistency_group_id_chirho: String,
    /// The persisted writer-authority era of the staged root (always `local-chirho` when well-formed).
    pub writer_era_chirho: String,
    /// True once every reused custody binding and the path convention have passed.
    pub custody_verified_chirho: bool,
}

/// The distinct, named ways a drill-root layout is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Item6DrillRootLayoutRefusalChirho {
    // --- path convention (pure, lexical; no filesystem) ---
    SelectedRootNotAbsoluteChirho,
    SelectedRootNotNormalizedChirho,
    SelectedRootIsProductionRootChirho,
    SelectedRootIsElectorRootChirho,
    DrillNamespaceInvalidChirho,
    SelectedRootOutsideDrillNamespaceChirho,
    // --- canonical forbidden-root backstop (filesystem; resolves symlinks + case folding) ---
    CanonicalSelectedRootIsForbiddenChirho,
    // --- custody bindings (filesystem; reuse the geo-node checks/primitives) ---
    ClusterConfigCustodyChirho,
    LedgerConfigCustodyChirho,
    ConsistencyGroupMismatchChirho,
    ConfigRootBindingMismatchChirho,
    WriterEraAuthorizationFileInvalidChirho,
    // --- freshness (filesystem; reuse) ---
    SelectedRootAlreadyActivatedChirho,
    // --- initialisation (filesystem) ---
    //
    // These three exist because `writer_authority_era_chirho` maps a MISSING writer fence to
    // `LocalChirho`, which is also what a correctly staged pre-activation root reports. The freshness
    // check below therefore cannot distinguish "staged and fresh" from "this is not a cairn root at
    // all", and answered the reassuring one. They are kept DISTINCT rather than folded: an
    // unreadable root is not an absent one, and collapsing them re-creates the same defect behind a
    // smaller door.
    SelectedRootNeverOpenedChirho,
    SelectedRootStructureUnreadableChirho,
    SelectedRootStructureInvalidChirho,
}

impl fmt::Display for Item6DrillRootLayoutRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(match self {
            Self::SelectedRootNotAbsoluteChirho => "drill selected root must be an absolute path",
            Self::SelectedRootNotNormalizedChirho => {
                "drill selected root must be normalized (no `.` or `..` components)"
            }
            Self::SelectedRootIsProductionRootChirho => {
                "drill selected root must not be, or sit under, the production root /var/lib/cairn-chirho"
            }
            Self::SelectedRootIsElectorRootChirho => {
                "drill selected root must not be, or sit under, the elector root /var/lib/cairn-elector-chirho"
            }
            Self::DrillNamespaceInvalidChirho => {
                "drill namespace must be an absolute, normalized, non-production, non-elector path"
            }
            Self::SelectedRootOutsideDrillNamespaceChirho => {
                "drill selected root must sit under the configured drill namespace"
            }
            Self::CanonicalSelectedRootIsForbiddenChirho => {
                "drill selected root canonicalizes to, or under, the production or elector root \
                 (symlink/case-resolved)"
            }
            Self::ClusterConfigCustodyChirho => "cluster election config custody refused",
            Self::LedgerConfigCustodyChirho => "ledger runtime config custody refused",
            Self::ConsistencyGroupMismatchChirho => {
                "selected root and cluster config name different consistency groups"
            }
            Self::ConfigRootBindingMismatchChirho => {
                "selected root differs from the ledger config's effective runtime root"
            }
            Self::WriterEraAuthorizationFileInvalidChirho => {
                "writer-era activation authorization file is not a private, same-owner regular file at an absolute path"
            }
            Self::SelectedRootAlreadyActivatedChirho => {
                "drill selected root is already elected-activated; a staged drill root must be fresh (Local era)"
            }
            Self::SelectedRootNeverOpenedChirho => {
                "drill selected root has never been opened: no named lock surface is present"
            }
            Self::SelectedRootStructureUnreadableChirho => {
                "drill selected root's named lock surface exists but could not be read"
            }
            Self::SelectedRootStructureInvalidChirho => {
                "drill selected root's named lock surface is present but is not a directory"
            }
        })
    }
}

impl std::error::Error for Item6DrillRootLayoutRefusalChirho {}

/// Reject any `.` / `..` component so the lexical `starts_with` reasoning below cannot be evaded.
fn is_normalized_chirho(path_chirho: &Path) -> bool {
    path_chirho.components().all(|component_chirho| {
        !matches!(component_chirho, Component::ParentDir | Component::CurDir)
    })
}

/// Component-wise containment: `candidate` is `base` or a descendant of it. Component-wise (via
/// [`Path::starts_with`]) so `/var/lib/cairn-chirho-drill` is NOT treated as inside
/// `/var/lib/cairn-chirho`.
fn path_is_within_chirho(candidate_chirho: &Path, base_chirho: &Path) -> bool {
    candidate_chirho.starts_with(base_chirho)
}

/// The two roots a drill selected root may never be, or sit under: the original production root and
/// the election-only elector root. One source of truth for both the lexical convention check and the
/// canonical backstop below.
fn forbidden_roots_chirho() -> [&'static Path; 2] {
    [
        Path::new(FORBIDDEN_PRODUCTION_ROOT_CHIRHO),
        Path::new(FORBIDDEN_ELECTOR_ROOT_CHIRHO),
    ]
}

fn is_forbidden_root_chirho(path_chirho: &Path) -> bool {
    forbidden_roots_chirho()
        .iter()
        .any(|forbidden_chirho| path_is_within_chirho(path_chirho, forbidden_chirho))
}

/// Canonicalize the deepest existing ancestor of `path` (the path itself when it exists), resolving
/// every symlink and case fold along the way. Returns `None` only if nothing on the path can be
/// canonicalized. Used to re-assert the forbidden-root invariant on the REAL target a symlink or a
/// case variant resolves to — [`check_item6_drill_root_path_convention_chirho`] reasons on raw
/// components and is blind to both. A freshly-staged drill root exists at validation time, so the
/// path itself normally canonicalizes; the ancestor walk only covers a not-yet-created leaf under an
/// already-symlinked parent, and containment under a forbidden root is inherited by every descendant.
fn canonical_existing_ancestor_chirho(path_chirho: &Path) -> Option<PathBuf> {
    let mut candidate_chirho = Some(path_chirho);
    while let Some(current_chirho) = candidate_chirho {
        if let Ok(canonical_chirho) = current_chirho.canonicalize() {
            return Some(canonical_chirho);
        }
        candidate_chirho = current_chirho.parent();
    }
    None
}

/// Backstop core: refuse if the canonical form of `selected_root` is, or sits under, any of
/// `forbidden_roots`. Parameterized on the forbidden set so a hermetic test can point a symlink at a
/// temp fixture standing in for the production root; production calls
/// [`check_canonical_selected_root_not_forbidden_chirho`], which passes the real constants and so
/// cannot be weakened by any caller.
fn check_canonical_selected_root_not_forbidden_against_chirho(
    selected_root_chirho: &Path,
    forbidden_roots_chirho: &[&Path],
) -> Result<(), Item6DrillRootLayoutRefusalChirho> {
    if let Some(canonical_chirho) = canonical_existing_ancestor_chirho(selected_root_chirho) {
        if forbidden_roots_chirho
            .iter()
            .any(|forbidden_chirho| path_is_within_chirho(&canonical_chirho, forbidden_chirho))
        {
            return Err(Item6DrillRootLayoutRefusalChirho::CanonicalSelectedRootIsForbiddenChirho);
        }
    }
    Ok(())
}

/// The authoritative canonical backstop for the genuinely-new 6.5-b never-production /
/// never-elector invariant. [`check_item6_drill_root_path_convention_chirho`] rejects the production
/// and elector roots LEXICALLY on the raw path, so a symlink under the drill namespace pointing at
/// one of them — or a case variant on a case-insensitive filesystem — would pass it. This re-asserts
/// the invariant on the CANONICAL selected root (all symlinks and case folds resolved), closing that
/// blindness. The lexical check stays as the fast, filesystem-free first gate; this is the
/// filesystem-touching backstop that actually owns the invariant.
pub fn check_canonical_selected_root_not_forbidden_chirho(
    selected_root_chirho: &Path,
) -> Result<(), Item6DrillRootLayoutRefusalChirho> {
    check_canonical_selected_root_not_forbidden_against_chirho(
        selected_root_chirho,
        &forbidden_roots_chirho(),
    )
}

/// The GENUINELY-NEW 6.5-b invariant: a drill selected root is an absolute, normalized path that is
/// neither the production nor the elector root and sits under the configured drill namespace.
///
/// Pure and lexical — it touches no filesystem, so it is checkable on constants without a staged root.
/// The forbidden-root checks run BEFORE namespace containment so a production/elector root always
/// refuses with its specific reason, even under a permissive namespace.
pub fn check_item6_drill_root_path_convention_chirho(
    selected_root_chirho: &Path,
    drill_namespace_chirho: &Path,
) -> Result<(), Item6DrillRootLayoutRefusalChirho> {
    use Item6DrillRootLayoutRefusalChirho as RefusalChirho;
    if !drill_namespace_chirho.is_absolute()
        || !is_normalized_chirho(drill_namespace_chirho)
        || is_forbidden_root_chirho(drill_namespace_chirho)
    {
        return Err(RefusalChirho::DrillNamespaceInvalidChirho);
    }
    if !selected_root_chirho.is_absolute() {
        return Err(RefusalChirho::SelectedRootNotAbsoluteChirho);
    }
    if !is_normalized_chirho(selected_root_chirho) {
        return Err(RefusalChirho::SelectedRootNotNormalizedChirho);
    }
    if path_is_within_chirho(
        selected_root_chirho,
        Path::new(FORBIDDEN_PRODUCTION_ROOT_CHIRHO),
    ) {
        return Err(RefusalChirho::SelectedRootIsProductionRootChirho);
    }
    if path_is_within_chirho(
        selected_root_chirho,
        Path::new(FORBIDDEN_ELECTOR_ROOT_CHIRHO),
    ) {
        return Err(RefusalChirho::SelectedRootIsElectorRootChirho);
    }
    if !path_is_within_chirho(selected_root_chirho, drill_namespace_chirho) {
        return Err(RefusalChirho::SelectedRootOutsideDrillNamespaceChirho);
    }
    Ok(())
}

/// The named-lock surface. Its PRESENCE means something has opened this directory as a root; its
/// ABSENCE means nothing ever has.
///
/// **This is deliberately NOT called a birth marker, because it is not one.** An earlier version of
/// this module claimed the surface is provisioned only by the root BIRTH path, taking that from a
/// disposition comment. **Measured false:** `canonical_lock_path_chirho` creates it with
/// `create_dir_all` on ANY named-lock acquisition, and birth is one of at least six production users
/// of that machinery. A census for a genuinely birth-exclusive surface reachable from this crate came
/// back empty — the nearest candidate, the resident-writer identity, is written by BOTH birth and
/// elected authority, and lives behind a dependency this crate deliberately does not take.
///
/// So the honest predicate is the weaker true one, and the refusal identity says so.
pub const NAMED_LOCK_SURFACE_CHIRHO: &str = "locks-chirho";

/// Refuse a selected root that nothing has ever opened, distinguishing the three ways that can fail.
///
/// **KNOWN LIMIT, stated here rather than discovered later.** This asks "has a named lock ever opened
/// this directory", NOT "was this born as a cairn root". Those coincide on the happy path and diverge
/// in one case: **a root whose birth BEGAN, took a lock, and failed before completing carries the
/// surface and PASSES this check.** `a_touched_but_not_born_root_passes_and_that_is_the_known_limit_chirho`
/// pins that behaviour so it is a recorded limitation rather than a surprise. Closing it needs a
/// genuine birth marker or a wider crate boundary, and is an OPEN design requirement.
///
/// WHY THIS EXISTS, stated at its own line because the gap it closes is invisible by reading:
/// step (7) below classifies freshness with `writer_authority_era_chirho`, and that function maps a
/// MISSING writer fence to `WriterAuthorityEraChirho::LocalChirho` — the same value a correctly
/// staged pre-activation root reports. One value, two worlds, and the freshness check answered the
/// reassuring one, returning `custody_verified_chirho: true` over a bare directory.
///
/// The three outcomes are deliberately NOT folded together. `Path::exists()` is unusable here
/// because it reports `false` for permission-denied, which would post an unreadable root into the
/// absent branch — the original defect with a smaller door. `symlink_metadata` is used rather than
/// `metadata` so a symlink standing in for the surface is refused as invalid rather than followed to
/// something that happens to be a directory elsewhere.
pub fn check_selected_root_has_been_opened_chirho(
    selected_root_chirho: &Path,
) -> Result<(), Item6DrillRootLayoutRefusalChirho> {
    use Item6DrillRootLayoutRefusalChirho as RefusalChirho;
    let surface_chirho = selected_root_chirho.join(NAMED_LOCK_SURFACE_CHIRHO);
    match std::fs::symlink_metadata(&surface_chirho) {
        Ok(metadata_chirho) if metadata_chirho.is_dir() => Ok(()),
        Ok(_) => Err(RefusalChirho::SelectedRootStructureInvalidChirho),
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => {
            Err(RefusalChirho::SelectedRootNeverOpenedChirho)
        }
        Err(_) => Err(RefusalChirho::SelectedRootStructureUnreadableChirho),
    }
}

/// Validate one freshly-staged drill root against the drill-namespace path convention and the reused
/// geo-node custody bindings. No host, no root creation, no writer-era signing.
///
/// Workflow: `spec-chirho/workstream-state-chirho/item6-5-hosted-packaging-design-chirho.md` §2.b.
pub fn validate_item6_drill_root_layout_chirho(
    layout_chirho: &Item6DrillRootLayoutChirho,
) -> Result<ResolvedItem6DrillRootLayoutChirho> {
    use Item6DrillRootLayoutRefusalChirho as RefusalChirho;

    // (1) The new path convention — pure, before any filesystem access.
    check_item6_drill_root_path_convention_chirho(
        &layout_chirho.selected_root_chirho,
        &layout_chirho.drill_namespace_chirho,
    )?;
    let selected_root_chirho = layout_chirho.selected_root_chirho.as_path();

    // (1b) Canonical forbidden-root backstop — step (1) reasons on the RAW path, so a symlink under
    // the drill namespace pointing at the production/elector root (or a case variant on a
    // case-insensitive filesystem) would pass it. Re-assert the never-production / never-elector
    // invariant on the CANONICAL selected root before any custody read, DAG run, or side effect.
    check_canonical_selected_root_not_forbidden_chirho(selected_root_chirho)?;

    // (2) Cluster election config file custody — REUSED verbatim.
    verify_cluster_node_file_config_custody_chirho(
        selected_root_chirho,
        &layout_chirho.cluster_config_chirho,
    )
    .map_err(|error_chirho| error_chirho.context(RefusalChirho::ClusterConfigCustodyChirho))?;
    let loaded_cluster_chirho = load_cluster_node_file_config_chirho(
        &layout_chirho.cluster_config_chirho,
    )
    .map_err(|error_chirho| error_chirho.context(RefusalChirho::ClusterConfigCustodyChirho))?;

    // (3) Group binding — single source of truth in `check_group_binding_chirho`, recomposed from
    // the identical public primitive the geo node's private
    // `verify_resident_gd7_geo_group_binding_chirho` calls (and drift-guarded against it from the
    // geo crate).
    check_group_binding_chirho(
        selected_root_chirho,
        &loaded_cluster_chirho.cluster_chirho.group_chirho,
    )?;

    // (4) Ledger runtime config file custody — REUSED verbatim.
    verify_host_ledger_config_custody_chirho(
        selected_root_chirho,
        &layout_chirho.ledger_config_chirho,
    )
    .map_err(|error_chirho| error_chirho.context(RefusalChirho::LedgerConfigCustodyChirho))?;
    let runtime_config_chirho = load_config_chirho(&layout_chirho.ledger_config_chirho)
        .map_err(|error_chirho| error_chirho.context(RefusalChirho::LedgerConfigCustodyChirho))?;

    // (5) Config-root binding — recomposed from the identical primitives the geo node's private
    // `verify_resident_gd7_geo_config_root_binding_chirho` uses.
    check_config_root_binding_chirho(selected_root_chirho, &runtime_config_chirho)?;

    // (6) Writer-era activation authorization — verified as an OPAQUE required file (present + path
    // validity + private-file custody) ONLY when the cluster config DECLARES a path. The seed-first
    // drill skips the geo writer-era ceremony (the seed latches Elected via H3 regenesis, minting no
    // geo activation file), so its config OMITS this field; an absent field means there is no ceremony
    // artifact to verify and step (6) is SKIPPED. A DECLARED path is verified exactly as before — the
    // ceremony flow is preserved and a declared-but-invalid file still refuses
    // `WriterEraAuthorizationFileInvalidChirho`. Not the H3 activation, which the seed enforces
    // elsewhere; not the geo-node runtime activation gate, which the winner geo node still enforces at
    // startup. NOT parsed, NOT signature-verified here.
    let authorization_path_chirho = loaded_cluster_chirho
        .writer_era_activation_authorization_chirho
        .clone();
    if let Some(declared_path_chirho) = authorization_path_chirho.as_deref() {
        verify_opaque_writer_era_authorization_file_chirho(
            selected_root_chirho,
            declared_path_chirho,
        )?;
    }

    // (6b) Has-been-opened — BEFORE freshness, because freshness cannot see this. `LocalChirho` is
    // returned both by a correctly staged pre-activation root and by a directory that is not a cairn
    // root at all, so without this step (7) passes an empty directory and this function returns
    // `custody_verified_chirho: true` over it.
    check_selected_root_has_been_opened_chirho(selected_root_chirho)?;

    // (7) Freshness — a staged drill root is pre-activation (Local era). Reuses `writer_authority_era`.
    let era_chirho = writer_authority_era_chirho(selected_root_chirho).map_err(|error_chirho| {
        error_chirho.context(RefusalChirho::SelectedRootAlreadyActivatedChirho)
    })?;
    if era_chirho != WriterAuthorityEraChirho::LocalChirho {
        return Err(RefusalChirho::SelectedRootAlreadyActivatedChirho.into());
    }

    Ok(ResolvedItem6DrillRootLayoutChirho {
        schema_chirho: ITEM6_DRILL_ROOT_LAYOUT_SCHEMA_V1_CHIRHO.to_owned(),
        selected_root_chirho: layout_chirho.selected_root_chirho.clone(),
        drill_namespace_chirho: layout_chirho.drill_namespace_chirho.clone(),
        cluster_config_chirho: layout_chirho.cluster_config_chirho.clone(),
        ledger_config_chirho: layout_chirho.ledger_config_chirho.clone(),
        durable_dir_chirho: loaded_cluster_chirho
            .cluster_chirho
            .durable_dir_chirho
            .clone(),
        sign_root_chirho: loaded_cluster_chirho
            .cluster_chirho
            .sign_root_chirho
            .clone(),
        writer_era_activation_authorization_chirho: authorization_path_chirho,
        consistency_group_id_chirho: loaded_cluster_chirho
            .cluster_chirho
            .group_chirho
            .canonical_id_chirho(),
        writer_era_chirho: FRESH_WRITER_ERA_LABEL_CHIRHO.to_owned(),
        custody_verified_chirho: true,
    })
}

/// The exact group binding the geo node enforces, recomposed from the identical public primitive its
/// private `verify_resident_gd7_geo_group_binding_chirho` calls: the selected root's DERIVED
/// consistency group must equal the cluster config's configured group. Public so the geo node's
/// drift-guard can prove this recomposed copy stays in lockstep with the private original.
pub fn check_group_binding_chirho(
    selected_root_chirho: &Path,
    configured_group_chirho: &ConsistencyGroupIdChirho,
) -> Result<()> {
    use Item6DrillRootLayoutRefusalChirho as RefusalChirho;
    let actual_group_chirho =
        consistency_group_for_root_chirho(selected_root_chirho).map_err(|error_chirho| {
            error_chirho.context(RefusalChirho::ConsistencyGroupMismatchChirho)
        })?;
    if actual_group_chirho != *configured_group_chirho {
        return Err(RefusalChirho::ConsistencyGroupMismatchChirho.into());
    }
    Ok(())
}

/// The exact effective-root binding the geo node enforces, recomposed from its public primitives:
/// the selected root must canonicalize to the ledger config's effective runtime root (tenant-adjusted).
/// Public so the geo node's drift-guard can prove this recomposed copy stays in lockstep with its
/// private `verify_resident_gd7_geo_config_root_binding_chirho`.
pub fn check_config_root_binding_chirho(
    selected_root_chirho: &Path,
    runtime_config_chirho: &ConfigChirho,
) -> Result<()> {
    use Item6DrillRootLayoutRefusalChirho as RefusalChirho;
    let configured_root_chirho = PathBuf::from(&runtime_config_chirho.root_chirho);
    let effective_root_chirho = match runtime_config_chirho
        .tenant_chirho
        .as_deref()
        .filter(|tenant_id_chirho| !tenant_id_chirho.trim().is_empty())
    {
        Some(tenant_id_chirho) => tenant_root_chirho(&configured_root_chirho, tenant_id_chirho)
            .map_err(|error_chirho| {
                error_chirho.context(RefusalChirho::ConfigRootBindingMismatchChirho)
            })?,
        None => configured_root_chirho,
    };
    let canonical_selected_chirho =
        selected_root_chirho
            .canonicalize()
            .map_err(|error_chirho| {
                anyhow::Error::new(error_chirho)
                    .context(RefusalChirho::ConfigRootBindingMismatchChirho)
            })?;
    let canonical_configured_chirho =
        effective_root_chirho
            .canonicalize()
            .map_err(|error_chirho| {
                anyhow::Error::new(error_chirho)
                    .context(RefusalChirho::ConfigRootBindingMismatchChirho)
            })?;
    if canonical_selected_chirho != canonical_configured_chirho {
        return Err(RefusalChirho::ConfigRootBindingMismatchChirho.into());
    }
    Ok(())
}

/// Confirm the writer-era activation authorization exists as a private, same-owner regular file at an
/// absolute path — OPAQUELY. It is not read, parsed, or signature-verified here; that is the offline
/// operator signer's job (6.5-e), consumed at node startup. This reuses the ledger-host private-file
/// custody check for the file boundary the activation load also requires.
fn verify_opaque_writer_era_authorization_file_chirho(
    selected_root_chirho: &Path,
    authorization_path_chirho: &Path,
) -> Result<()> {
    use Item6DrillRootLayoutRefusalChirho as RefusalChirho;
    if !authorization_path_chirho.is_absolute() {
        return Err(RefusalChirho::WriterEraAuthorizationFileInvalidChirho.into());
    }
    verify_host_ledger_config_custody_chirho(selected_root_chirho, authorization_path_chirho)
        .map_err(|error_chirho| {
            error_chirho.context(RefusalChirho::WriterEraAuthorizationFileInvalidChirho)
        })?;
    Ok(())
}

#[cfg(test)]
mod tests_chirho;
