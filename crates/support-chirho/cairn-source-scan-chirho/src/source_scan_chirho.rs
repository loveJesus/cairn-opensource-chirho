// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! One workspace-aware source walker shared by every source guard — so guards keep seeing code
//! after modules move into workspace crates — plus the balanced-tree guards (file line cap,
//! directory fanout cap) with shrink-only grandfather lists.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use syn::parse::Parser;

#[path = "source_scan_chirho/jsonl_surface_discovery_chirho.rs"]
mod jsonl_surface_discovery_chirho;
pub use jsonl_surface_discovery_chirho::{
    production_jsonl_logical_surface_inventory_chirho, production_root_jsonl_log_names_chirho,
    ProductionJsonlLogicalSurfaceChirho, ProductionJsonlLogicalSurfaceCoverageGapsChirho,
    ProductionJsonlLogicalSurfaceInventoryChirho, REFS_REFLOG_LOGICAL_SURFACE_CHIRHO,
};

fn is_workspace_manifest_chirho(path_chirho: &Path) -> bool {
    let Ok(text_chirho) = std::fs::read_to_string(path_chirho) else {
        return false;
    };
    text_chirho
        .lines()
        .any(|line_chirho| line_chirho.trim() == "[workspace]")
}

/// A repository boundary: a directory holding `.git` — a DIRECTORY in a main checkout, a FILE in a
/// linked worktree. Both shapes count, because both mark "this checkout ends here". An IO error
/// answering the question also counts: at this seam the fail-closed direction is to STOP, never to
/// keep climbing into whatever tree happens to sit above.
fn is_repository_boundary_chirho(dir_chirho: &Path) -> bool {
    dir_chirho.join(".git").try_exists().unwrap_or(true)
}

/// The workspace root. This crate can live under `crates/`, so `CARGO_MANIFEST_DIR` is only the
/// search start, not necessarily the answer.
///
/// The upward walk STOPS at a repository boundary. For both normal cases this changes nothing: a
/// main checkout and a linked worktree each carry `.git` and the workspace manifest at the SAME
/// level, and the manifest is tested first, so the walk returns before the boundary is consulted.
/// The boundary exists for the escape case only. Agent worktrees live at `.claude/worktrees/<id>`
/// INSIDE the main checkout, whose root manifest ALSO declares `[workspace]`; with no boundary, a
/// walk that fails to match the LOCAL manifest for any reason keeps climbing, leaves the worktree,
/// and binds to the enclosing checkout. Every guard would then scan a NEIGHBOURING seat's tree and
/// report green about it while the local tree holds the defect — a failure that is silent and
/// fails OPEN, which is the dangerous direction. The boundary turns that into a refusal.
///
/// HONEST SCOPE, so no later reader inherits a stronger claim than was proven: the escape was
/// demonstrated by inducing the trigger ARTIFICIALLY — rewriting the local header to
/// `[workspace] # comment`, valid TOML that defeats this exact-match predicate. Measured
/// differentially at the returned path (identical canary, identical location, only root resolution
/// varied): predicate intact resolved to the worktree and the canary fired; predicate defeated
/// resolved to the enclosing checkout and the suite reported 372 passed in silence. NO NATURAL
/// TRIGGER HAS BEEN MEASURED. This is a latent fail-open closed on principle, and is NOT claimed as
/// the cause of any observed failure.
///
/// Reaching a boundary with no workspace manifest PANICS rather than falling back to
/// `CARGO_MANIFEST_DIR` as this once did. That fallback handed every guard a near-empty inventory,
/// and a guard that silently scans nothing is green-by-emptiness — the same fail-open in a smaller
/// costume. Panicking is contained: no crate depends on this one, so its only callers are its own
/// guard suite, which is exactly where a loud refusal belongs.
pub fn workspace_root_chirho() -> PathBuf {
    static WORKSPACE_ROOT_CHIRHO: OnceLock<PathBuf> = OnceLock::new();
    WORKSPACE_ROOT_CHIRHO
        .get_or_init(|| {
            let start_chirho = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let mut dir_chirho = start_chirho.clone();
            loop {
                if is_workspace_manifest_chirho(&dir_chirho.join("Cargo.toml")) {
                    return dir_chirho;
                }
                if is_repository_boundary_chirho(&dir_chirho) {
                    panic!(
                        "cairn-source-scan-chirho: no `[workspace]` manifest between {} and the \
                         repository boundary at {}. Refusing to climb past it: the next match \
                         above a boundary belongs to a DIFFERENT checkout, and every guard would \
                         then scan that tree and report green about it while this one holds the \
                         defect. Check that the local root manifest's `[workspace]` header is on \
                         a line of its own.",
                        start_chirho.display(),
                        dir_chirho.display()
                    );
                }
                if !dir_chirho.pop() {
                    panic!(
                        "cairn-source-scan-chirho: no `[workspace]` manifest and no repository \
                         boundary anywhere above {}. Refusing to fall back to the manifest \
                         directory: the guards would scan a near-empty inventory and pass by \
                         emptiness.",
                        start_chirho.display()
                    );
                }
            }
        })
        .clone()
}

#[cfg(test)]
mod workspace_root_boundary_tests_chirho {
    use super::*;

    fn scratch_dir_chirho(name_chirho: &str) -> PathBuf {
        let dir_chirho = std::env::temp_dir().join(format!(
            "cairn-source-scan-boundary-chirho-{}-{name_chirho}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir_chirho);
        std::fs::create_dir_all(&dir_chirho).expect("scratch dir for boundary test");
        dir_chirho
    }

    /// Both `.git` shapes must count. Miss the FILE shape and every linked worktree climbs out of
    /// itself into the enclosing checkout; miss the DIRECTORY shape and a main checkout does.
    #[test]
    fn repository_boundary_counts_git_file_and_git_directory_chirho() {
        let plain_chirho = scratch_dir_chirho("plain");
        assert!(
            !is_repository_boundary_chirho(&plain_chirho),
            "a directory with no `.git` is not a repository boundary"
        );

        let worktree_chirho = scratch_dir_chirho("worktree");
        std::fs::write(worktree_chirho.join(".git"), "gitdir: /elsewhere\n").expect("git file");
        assert!(
            is_repository_boundary_chirho(&worktree_chirho),
            "a linked worktree carries `.git` as a FILE and must still stop the walk"
        );

        let checkout_chirho = scratch_dir_chirho("checkout");
        std::fs::create_dir_all(checkout_chirho.join(".git")).expect("git dir");
        assert!(
            is_repository_boundary_chirho(&checkout_chirho),
            "a main checkout carries `.git` as a DIRECTORY and must still stop the walk"
        );

        for dir_chirho in [plain_chirho, worktree_chirho, checkout_chirho] {
            let _ = std::fs::remove_dir_all(dir_chirho);
        }
    }

    /// The outcome the boundary exists to protect: the resolved root and the crate being scanned
    /// must belong to the SAME checkout. Note the containment check alone cannot say this — an
    /// agent worktree is nested inside the main checkout, so an escaped root still "contains" the
    /// manifest dir. Only the absence of a crossed boundary distinguishes them.
    #[test]
    fn resolved_workspace_root_is_not_across_a_repository_boundary_chirho() {
        let root_chirho = workspace_root_chirho();
        let manifest_chirho = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        assert!(
            manifest_chirho.starts_with(&root_chirho),
            "resolved root {} does not contain this crate at {}",
            root_chirho.display(),
            manifest_chirho.display()
        );
        // Deliberately an INDEPENDENT instrument: this walks with its own `.git` test instead of
        // calling `is_repository_boundary_chirho`, so one regression cannot blind both arms.
        let mut dir_chirho = manifest_chirho.clone();
        while dir_chirho != root_chirho {
            assert!(
                !dir_chirho.join(".git").exists(),
                "resolved workspace root {} lies ACROSS the repository boundary at {} (walk \
                 started at {}). The guards would be measuring a DIFFERENT checkout than the one \
                 holding this file.",
                root_chirho.display(),
                dir_chirho.display(),
                manifest_chirho.display()
            );
            assert!(
                dir_chirho.pop(),
                "walk from {} ran off the top without reaching the resolved root {}",
                manifest_chirho.display(),
                root_chirho.display()
            );
        }
    }
}

fn workspace_relative_chirho(path_chirho: &Path) -> String {
    path_chirho
        .strip_prefix(workspace_root_chirho())
        .unwrap_or(path_chirho)
        .to_string_lossy()
        .to_string()
}

fn collect_rs_files_chirho(dir_chirho: &Path, out_chirho: &mut Vec<PathBuf>) {
    let Ok(entries_chirho) = std::fs::read_dir(dir_chirho) else {
        return;
    };
    for entry_chirho in entries_chirho.flatten() {
        let path_chirho = entry_chirho.path();
        if path_chirho.is_dir() {
            // Skip dot-directories and `target` HERE, not only in the crate-discovery walker.
            // Agent worktrees under `.claude/` carry STALE COPIES of real source -- one held 266
            // CLI command declarations against the tracked 229 -- so a scanner that reaches one is
            // measuring a doppelganger of the file it means to guard, silently and confidently.
            // Today no caller passes a root from which a dot-directory is reachable, so this
            // changes no result. That is exactly the problem: the guarantee lived in the ROOTS
            // PASSED, and nothing in this function pinned it, so a future refactor handing it a
            // wider root would start scanning stale worktrees with no test failing.
            let name_chirho = entry_chirho.file_name().to_string_lossy().to_string();
            if name_chirho.starts_with('.') || name_chirho == "target" {
                continue;
            }
            collect_rs_files_chirho(&path_chirho, out_chirho);
        } else if path_chirho
            .extension()
            .and_then(|ext_chirho| ext_chirho.to_str())
            == Some("rs")
        {
            out_chirho.push(path_chirho);
        }
    }
}

fn collect_workspace_crate_src_dirs_chirho(dir_chirho: &Path, out_chirho: &mut Vec<PathBuf>) {
    let Ok(entries_chirho) = std::fs::read_dir(dir_chirho) else {
        return;
    };
    for entry_chirho in entries_chirho.flatten() {
        let path_chirho = entry_chirho.path();
        if !path_chirho.is_dir() {
            continue;
        }
        let name_chirho = entry_chirho.file_name().to_string_lossy().to_string();
        if name_chirho.starts_with('.') || name_chirho == "target" {
            continue;
        }
        let src_chirho = path_chirho.join("src");
        if path_chirho.join("Cargo.toml").is_file() && src_chirho.is_dir() {
            out_chirho.push(src_chirho);
        }
        collect_workspace_crate_src_dirs_chirho(&path_chirho, out_chirho);
    }
}

/// Every production source file in the workspace: the root package's `src/` tree plus every
/// recursively discovered workspace crate's `src/` tree. Crate `tests/` directories are all-test
/// code, not production, and so are `#[cfg(test)]`-only module files whose PARENT declares them
/// `#[cfg(test)] mod <name>;` (a whole-file cfg-test module split into its own file, whatever its
/// name). Filenames alone never remove a file from the production surface: a production module may
/// legitimately end in `_tests_chirho.rs`. Resolution is deliberately fail-safe: an unresolved or
/// ambiguous declaration keeps the file scanned, while a resolved module or Cargo target outside
/// this inventory is a loud error rather than an omitted source file. A production file that merely
/// CONTAINS an inline `#[cfg(test)] mod tests` also stays scanned because its parent declaration is
/// not cfg-test. The graph is resolved once per test process and cached; later guards clone only the
/// stable path inventory instead of reparsing the workspace.
pub fn workspace_production_rs_files_chirho() -> Vec<PathBuf> {
    static PRODUCTION_FILES_CHIRHO: OnceLock<Vec<PathBuf>> = OnceLock::new();
    PRODUCTION_FILES_CHIRHO
        .get_or_init(|| {
            let root_chirho = workspace_root_chirho();
            let mut files_chirho = Vec::new();
            collect_rs_files_chirho(&root_chirho.join("src"), &mut files_chirho);
            let mut crate_src_dirs_chirho = Vec::new();
            collect_workspace_crate_src_dirs_chirho(
                &root_chirho.join("crates"),
                &mut crate_src_dirs_chirho,
            );
            for crate_src_chirho in crate_src_dirs_chirho {
                collect_rs_files_chirho(&crate_src_chirho, &mut files_chirho);
            }
            production_rs_files_from_candidates_chirho(files_chirho)
        })
        .clone()
}

fn production_rs_files_from_candidates_chirho(mut files_chirho: Vec<PathBuf>) -> Vec<PathBuf> {
    let cfg_test_targets_chirho = cfg_test_declared_module_targets_chirho(&files_chirho);
    files_chirho.retain(|path_chirho| {
        path_chirho
            .canonicalize()
            .map(|canonical_chirho| !cfg_test_targets_chirho.contains(&canonical_chirho))
            .unwrap_or(true)
    });
    files_chirho.sort();
    files_chirho.dedup();
    files_chirho
}

struct ModuleEdgeChirho {
    target_chirho: PathBuf,
    module_base_chirho: PathBuf,
    cfg_test_chirho: bool,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct ModuleVisitStateChirho {
    source_chirho: PathBuf,
    module_base_chirho: PathBuf,
    cfg_test_chirho: bool,
}

fn nearest_package_manifest_chirho(path_chirho: &Path) -> Option<PathBuf> {
    path_chirho
        .parent()?
        .ancestors()
        .map(|ancestor_chirho| ancestor_chirho.join("Cargo.toml"))
        .find(|manifest_chirho| manifest_chirho.is_file())
}

fn insert_existing_candidate_chirho(
    path_chirho: PathBuf,
    candidates_chirho: &BTreeSet<PathBuf>,
    roots_chirho: &mut BTreeSet<PathBuf>,
) {
    let Ok(canonical_chirho) = path_chirho.canonicalize() else {
        return;
    };
    if candidates_chirho.contains(&canonical_chirho) {
        roots_chirho.insert(canonical_chirho);
    }
}

fn insert_declared_cargo_target_chirho(
    path_chirho: PathBuf,
    candidates_chirho: &BTreeSet<PathBuf>,
    roots_chirho: &mut BTreeSet<PathBuf>,
) {
    let Ok(canonical_chirho) = path_chirho.canonicalize() else {
        return;
    };
    assert!(
        candidates_chirho.contains(&canonical_chirho),
        "declared Cargo target escaped the production source inventory: {}",
        canonical_chirho.display()
    );
    roots_chirho.insert(canonical_chirho);
}

/// Cargo targets are production roots even when another source file also names them as a module.
/// Seed conventional lib/main/bin roots plus explicit `[lib]` and `[[bin]]` paths. An unreadable or
/// malformed manifest cannot produce a buildable custom target; conventional roots still fail safe.
pub(crate) fn cargo_target_roots_chirho(
    files_chirho: &[PathBuf],
    candidates_chirho: &BTreeSet<PathBuf>,
) -> BTreeSet<PathBuf> {
    let mut roots_chirho = BTreeSet::new();
    let mut package_files_chirho = BTreeMap::<PathBuf, Vec<&PathBuf>>::new();
    for path_chirho in files_chirho {
        if let Some(manifest_chirho) = nearest_package_manifest_chirho(path_chirho) {
            package_files_chirho
                .entry(manifest_chirho)
                .or_default()
                .push(path_chirho);
        }
    }

    for (manifest_chirho, package_files_chirho) in package_files_chirho {
        let Some(package_dir_chirho) = manifest_chirho.parent() else {
            continue;
        };
        let src_dir_chirho = package_dir_chirho.join("src");
        for conventional_root_chirho in [
            src_dir_chirho.join("lib.rs"),
            src_dir_chirho.join("main.rs"),
        ] {
            insert_existing_candidate_chirho(
                conventional_root_chirho,
                candidates_chirho,
                &mut roots_chirho,
            );
        }
        let bin_dir_chirho = src_dir_chirho.join("bin");
        for path_chirho in package_files_chirho {
            let Ok(relative_chirho) = path_chirho.strip_prefix(&bin_dir_chirho) else {
                continue;
            };
            let component_count_chirho = relative_chirho.components().count();
            let file_name_chirho = relative_chirho
                .file_name()
                .and_then(|name_chirho| name_chirho.to_str());
            let automatic_bin_root_chirho = (component_count_chirho == 1
                && relative_chirho
                    .extension()
                    .is_some_and(|extension_chirho| extension_chirho == "rs"))
                || (component_count_chirho == 2 && file_name_chirho == Some("main.rs"));
            if automatic_bin_root_chirho {
                insert_existing_candidate_chirho(
                    path_chirho.clone(),
                    candidates_chirho,
                    &mut roots_chirho,
                );
            }
        }
        let Ok(text_chirho) = std::fs::read_to_string(&manifest_chirho) else {
            continue;
        };
        let Ok(value_chirho) = text_chirho.parse::<toml::Value>() else {
            continue;
        };
        if let Some(path_chirho) = value_chirho
            .get("lib")
            .and_then(toml::Value::as_table)
            .and_then(|table_chirho| table_chirho.get("path"))
            .and_then(toml::Value::as_str)
        {
            insert_declared_cargo_target_chirho(
                package_dir_chirho.join(path_chirho),
                candidates_chirho,
                &mut roots_chirho,
            );
        }
        if let Some(bins_chirho) = value_chirho.get("bin").and_then(toml::Value::as_array) {
            for bin_chirho in bins_chirho {
                let Some(path_chirho) = bin_chirho
                    .as_table()
                    .and_then(|table_chirho| table_chirho.get("path"))
                    .and_then(toml::Value::as_str)
                else {
                    continue;
                };
                insert_declared_cargo_target_chirho(
                    package_dir_chirho.join(path_chirho),
                    candidates_chirho,
                    &mut roots_chirho,
                );
            }
        }
    }
    roots_chirho
}

pub(crate) fn has_exact_cfg_test_attribute_chirho(attributes_chirho: &[syn::Attribute]) -> bool {
    attributes_chirho.iter().any(|attribute_chirho| {
        attribute_chirho.path().is_ident("cfg")
            && matches!(
                &attribute_chirho.meta,
                syn::Meta::List(list_chirho) if list_chirho.tokens.to_string() == "test"
            )
    })
}

pub(crate) fn module_path_attribute_chirho(
    attributes_chirho: &[syn::Attribute],
) -> Result<Option<PathBuf>, ()> {
    let mut paths_chirho = Vec::new();
    for attribute_chirho in attributes_chirho {
        if !attribute_chirho.path().is_ident("path") {
            continue;
        }
        let syn::Meta::NameValue(value_chirho) = &attribute_chirho.meta else {
            return Err(());
        };
        let syn::Expr::Lit(expression_chirho) = &value_chirho.value else {
            return Err(());
        };
        let syn::Lit::Str(path_chirho) = &expression_chirho.lit else {
            return Err(());
        };
        paths_chirho.push(PathBuf::from(path_chirho.value()));
    }
    if paths_chirho.len() > 1 {
        return Err(());
    }
    Ok(paths_chirho.pop())
}

fn collect_conditional_path_meta_chirho(
    meta_chirho: &syn::Meta,
    paths_chirho: &mut Vec<PathBuf>,
) -> Result<bool, ()> {
    match meta_chirho {
        syn::Meta::NameValue(value_chirho) if value_chirho.path.is_ident("path") => {
            let syn::Expr::Lit(expression_chirho) = &value_chirho.value else {
                return Err(());
            };
            let syn::Lit::Str(path_chirho) = &expression_chirho.lit else {
                return Err(());
            };
            paths_chirho.push(PathBuf::from(path_chirho.value()));
            Ok(true)
        }
        syn::Meta::Path(path_chirho)
        | syn::Meta::List(syn::MetaList {
            path: path_chirho, ..
        }) if path_chirho.is_ident("path") => Err(()),
        syn::Meta::List(list_chirho) if list_chirho.path.is_ident("cfg_attr") => {
            collect_conditional_module_paths_from_list_chirho(list_chirho, paths_chirho)
        }
        _ => Ok(false),
    }
}

fn collect_conditional_module_paths_from_list_chirho(
    list_chirho: &syn::MetaList,
    paths_chirho: &mut Vec<PathBuf>,
) -> Result<bool, ()> {
    let metas_chirho = syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
        .parse2(list_chirho.tokens.clone())
        .map_err(|_error_chirho| ())?;
    let mut metas_chirho = metas_chirho.iter();
    let Some(_condition_chirho) = metas_chirho.next() else {
        return Err(());
    };
    let mut found_chirho = false;
    for meta_chirho in metas_chirho {
        found_chirho |= collect_conditional_path_meta_chirho(meta_chirho, paths_chirho)?;
    }
    Ok(found_chirho)
}

pub(crate) fn conditional_module_paths_chirho(
    attributes_chirho: &[syn::Attribute],
) -> Result<Option<Vec<PathBuf>>, ()> {
    let mut paths_chirho = Vec::new();
    let mut found_chirho = false;
    for attribute_chirho in attributes_chirho {
        if !attribute_chirho.path().is_ident("cfg_attr") {
            continue;
        }
        let syn::Meta::List(list_chirho) = &attribute_chirho.meta else {
            return Err(());
        };
        found_chirho |=
            collect_conditional_module_paths_from_list_chirho(list_chirho, &mut paths_chirho)?;
    }
    Ok(found_chirho.then_some(paths_chirho))
}

fn literal_include_path_chirho(macro_chirho: &syn::Macro) -> Result<Option<PathBuf>, ()> {
    if !macro_chirho.path.is_ident("include") {
        return Ok(None);
    }
    let paths_chirho = syn::punctuated::Punctuated::<syn::LitStr, syn::Token![,]>::parse_terminated
        .parse2(macro_chirho.tokens.clone())
        .map_err(|_error_chirho| ())?;
    if paths_chirho.len() != 1 {
        return Err(());
    }
    Ok(paths_chirho
        .first()
        .map(|path_chirho| PathBuf::from(path_chirho.value())))
}

#[derive(Default)]
pub(crate) struct ModuleTargetResolutionChirho {
    pub(crate) targets_chirho: BTreeSet<(PathBuf, PathBuf)>,
    pub(crate) keep_all_scanned_chirho: bool,
}

fn canonical_module_target_chirho(
    candidate_chirho: &Path,
    explicit_path_chirho: bool,
    module_name_chirho: &str,
) -> Result<Option<(PathBuf, PathBuf)>, ()> {
    if !candidate_chirho.exists() {
        return Ok(None);
    }
    let canonical_chirho = candidate_chirho
        .canonicalize()
        .map_err(|_error_chirho| ())?;
    let Some(parent_chirho) = canonical_chirho.parent() else {
        return Err(());
    };
    let module_base_chirho = if explicit_path_chirho
        || canonical_chirho
            .file_name()
            .is_some_and(|name_chirho| name_chirho == "mod.rs")
    {
        parent_chirho.to_path_buf()
    } else {
        parent_chirho.join(module_name_chirho)
    };
    Ok(Some((canonical_chirho, module_base_chirho)))
}

pub(crate) fn resolved_external_module_target_chirho(
    module_base_chirho: &Path,
    path_attribute_base_chirho: &Path,
    module_chirho: &syn::ItemMod,
) -> ModuleTargetResolutionChirho {
    let conditional_paths_chirho = match conditional_module_paths_chirho(&module_chirho.attrs) {
        Ok(paths_chirho) => paths_chirho,
        Err(()) => {
            return ModuleTargetResolutionChirho {
                keep_all_scanned_chirho: true,
                ..ModuleTargetResolutionChirho::default()
            };
        }
    };
    let explicit_path_chirho = match module_path_attribute_chirho(&module_chirho.attrs) {
        Ok(path_chirho) => path_chirho,
        Err(()) => {
            return ModuleTargetResolutionChirho {
                keep_all_scanned_chirho: true,
                ..ModuleTargetResolutionChirho::default()
            };
        }
    };
    if explicit_path_chirho.is_some() && conditional_paths_chirho.is_some() {
        return ModuleTargetResolutionChirho {
            keep_all_scanned_chirho: true,
            ..ModuleTargetResolutionChirho::default()
        };
    }
    let module_name_chirho = module_chirho.ident.to_string();
    let mut targets_chirho = BTreeSet::new();
    let mut conventional_ambiguous_chirho = false;
    if let Some(explicit_path_chirho) = &explicit_path_chirho {
        let candidate_chirho = path_attribute_base_chirho.join(explicit_path_chirho);
        match canonical_module_target_chirho(&candidate_chirho, true, &module_name_chirho) {
            Ok(Some(target_chirho)) => {
                targets_chirho.insert(target_chirho);
            }
            Ok(None) | Err(()) => {
                return ModuleTargetResolutionChirho {
                    keep_all_scanned_chirho: true,
                    ..ModuleTargetResolutionChirho::default()
                };
            }
        }
    } else {
        let conventional_candidates_chirho = [
            module_base_chirho.join(format!("{module_name_chirho}.rs")),
            module_base_chirho.join(&module_name_chirho).join("mod.rs"),
        ];
        let mut conventional_targets_chirho = BTreeSet::new();
        for candidate_chirho in conventional_candidates_chirho {
            match canonical_module_target_chirho(&candidate_chirho, false, &module_name_chirho) {
                Ok(Some(target_chirho)) => {
                    conventional_targets_chirho.insert(target_chirho);
                }
                Ok(None) => {}
                Err(()) => {
                    return ModuleTargetResolutionChirho {
                        keep_all_scanned_chirho: true,
                        ..ModuleTargetResolutionChirho::default()
                    };
                }
            }
        }
        conventional_ambiguous_chirho = conventional_targets_chirho.len() > 1;
        if !conventional_ambiguous_chirho {
            targets_chirho.extend(conventional_targets_chirho);
        }
    }
    if let Some(paths_chirho) = conditional_paths_chirho {
        for path_chirho in paths_chirho {
            let candidate_chirho = path_attribute_base_chirho.join(path_chirho);
            match canonical_module_target_chirho(&candidate_chirho, true, &module_name_chirho) {
                Ok(Some(target_chirho)) => {
                    targets_chirho.insert(target_chirho);
                }
                Ok(None) => {}
                Err(()) => {
                    return ModuleTargetResolutionChirho {
                        keep_all_scanned_chirho: true,
                        ..ModuleTargetResolutionChirho::default()
                    };
                }
            }
        }
    }
    if targets_chirho.is_empty() && !conventional_ambiguous_chirho {
        return ModuleTargetResolutionChirho {
            keep_all_scanned_chirho: true,
            ..ModuleTargetResolutionChirho::default()
        };
    }
    ModuleTargetResolutionChirho {
        targets_chirho,
        keep_all_scanned_chirho: false,
    }
}

fn collect_module_edges_chirho(
    items_chirho: &[syn::Item],
    module_base_chirho: &Path,
    path_attribute_base_chirho: &Path,
    include_base_chirho: &Path,
    inherited_cfg_test_chirho: bool,
    edges_chirho: &mut Vec<ModuleEdgeChirho>,
    keep_all_scanned_chirho: &mut bool,
) {
    for item_chirho in items_chirho {
        let syn::Item::Mod(module_chirho) = item_chirho else {
            let syn::Item::Macro(include_chirho) = item_chirho else {
                continue;
            };
            let include_path_chirho = match literal_include_path_chirho(&include_chirho.mac) {
                Ok(Some(path_chirho)) => path_chirho,
                Ok(None) => continue,
                Err(()) => {
                    *keep_all_scanned_chirho = true;
                    continue;
                }
            };
            let target_chirho = include_base_chirho.join(include_path_chirho);
            let Ok(target_chirho) = target_chirho.canonicalize() else {
                *keep_all_scanned_chirho = true;
                continue;
            };
            if !target_chirho.is_file() {
                *keep_all_scanned_chirho = true;
                continue;
            }
            edges_chirho.push(ModuleEdgeChirho {
                target_chirho,
                module_base_chirho: module_base_chirho.to_path_buf(),
                cfg_test_chirho: inherited_cfg_test_chirho
                    || has_exact_cfg_test_attribute_chirho(&include_chirho.attrs),
            });
            continue;
        };
        let cfg_test_chirho =
            inherited_cfg_test_chirho || has_exact_cfg_test_attribute_chirho(&module_chirho.attrs);
        if let Some((_brace_chirho, nested_items_chirho)) = &module_chirho.content {
            if conditional_module_paths_chirho(&module_chirho.attrs)
                .map(|paths_chirho| paths_chirho.is_some())
                .unwrap_or(true)
            {
                // A conditional path on an inline module changes every nested external module's
                // base. Without a build cfg there is no bounded target set to prove, so exclusions
                // fail safe globally for this inventory invocation.
                *keep_all_scanned_chirho = true;
                continue;
            }
            let explicit_path_chirho = match module_path_attribute_chirho(&module_chirho.attrs) {
                Ok(path_chirho) => path_chirho,
                Err(()) => {
                    *keep_all_scanned_chirho = true;
                    continue;
                }
            };
            let nested_base_chirho = explicit_path_chirho
                .map(|path_chirho| path_attribute_base_chirho.join(path_chirho))
                .unwrap_or_else(|| module_base_chirho.join(module_chirho.ident.to_string()));
            collect_module_edges_chirho(
                nested_items_chirho,
                &nested_base_chirho,
                &nested_base_chirho,
                include_base_chirho,
                cfg_test_chirho,
                edges_chirho,
                keep_all_scanned_chirho,
            );
            continue;
        }
        let resolution_chirho = resolved_external_module_target_chirho(
            module_base_chirho,
            path_attribute_base_chirho,
            module_chirho,
        );
        *keep_all_scanned_chirho |= resolution_chirho.keep_all_scanned_chirho;
        for (target_chirho, target_module_base_chirho) in resolution_chirho.targets_chirho {
            edges_chirho.push(ModuleEdgeChirho {
                target_chirho,
                module_base_chirho: target_module_base_chirho,
                cfg_test_chirho,
            });
        }
    }
}

/// Resolve external module declarations from Cargo target roots instead of filename conventions.
/// Traversal carries each file's logical module base separately from its physical directory, which
/// is required when `#[path]` decouples the module name from the source filename. Inline and external
/// modules and literal item-position `include!` sources propagate exact `#[cfg(test)]` context to
/// descendants. Literal includes resolve from the physical declaring file, independently of the
/// logical module base used by `mod` and `#[path]`. Files unreachable from a Cargo root stay scanned,
/// so orphan aliases and disconnected cycles cannot suppress source. External `#[path]` files follow
/// rustc's `mod.rs`-like nested-module base, while inline `#[path]` values name a directory. Ambiguous
/// declarations stay scanned locally;
/// unresolved declarations/includes, malformed attributes, parse failures, and an unbounded cycle
/// disable exclusion for the whole invocation.
/// A resolved target outside the initial source inventory is RED because retaining only the known
/// files would still omit executable Rust. Production reachability always wins over test-only
/// reachability for a shared target. The bounded walk is
/// O((files + resolved module edges) log files).
fn cfg_test_declared_module_targets_chirho(files_chirho: &[PathBuf]) -> BTreeSet<PathBuf> {
    let mut candidates_chirho = BTreeSet::new();
    for path_chirho in files_chirho {
        let Ok(canonical_chirho) = path_chirho.canonicalize() else {
            return BTreeSet::new();
        };
        candidates_chirho.insert(canonical_chirho);
    }
    let cargo_roots_chirho = cargo_target_roots_chirho(files_chirho, &candidates_chirho);
    let mut pending_chirho = VecDeque::new();
    for source_chirho in cargo_roots_chirho {
        let Some(module_base_chirho) = source_chirho.parent().map(Path::to_path_buf) else {
            return BTreeSet::new();
        };
        pending_chirho.push_back(ModuleVisitStateChirho {
            source_chirho,
            module_base_chirho,
            cfg_test_chirho: false,
        });
    }
    let mut visited_chirho = BTreeSet::new();
    let mut production_chirho = BTreeSet::new();
    let mut cfg_test_chirho = BTreeSet::new();
    let state_limit_chirho = candidates_chirho.len().saturating_mul(4).max(1);
    while let Some(state_chirho) = pending_chirho.pop_front() {
        if !visited_chirho.insert(state_chirho.clone()) {
            continue;
        }
        if visited_chirho.len() > state_limit_chirho {
            return BTreeSet::new();
        }
        let seen_chirho = if state_chirho.cfg_test_chirho {
            &mut cfg_test_chirho
        } else {
            &mut production_chirho
        };
        seen_chirho.insert(state_chirho.source_chirho.clone());
        let Ok(text_chirho) = std::fs::read_to_string(&state_chirho.source_chirho) else {
            #[cfg(test)]
            eprintln!(
                "source inventory fail-safe: unreadable {}",
                state_chirho.source_chirho.display()
            );
            return BTreeSet::new();
        };
        let Ok(parsed_chirho) = syn::parse_file(&text_chirho) else {
            #[cfg(test)]
            eprintln!(
                "source inventory fail-safe: unparseable {}",
                state_chirho.source_chirho.display()
            );
            return BTreeSet::new();
        };
        let Some(path_attribute_base_chirho) = state_chirho.source_chirho.parent() else {
            return BTreeSet::new();
        };
        let mut edges_chirho = Vec::new();
        let mut keep_all_scanned_chirho = false;
        collect_module_edges_chirho(
            &parsed_chirho.items,
            &state_chirho.module_base_chirho,
            path_attribute_base_chirho,
            path_attribute_base_chirho,
            state_chirho.cfg_test_chirho,
            &mut edges_chirho,
            &mut keep_all_scanned_chirho,
        );
        if keep_all_scanned_chirho {
            #[cfg(test)]
            eprintln!(
                "source inventory fail-safe: unresolved declaration in {}",
                state_chirho.source_chirho.display()
            );
            return BTreeSet::new();
        }
        for edge_chirho in edges_chirho {
            assert!(
                candidates_chirho.contains(&edge_chirho.target_chirho),
                "resolved Rust module target escaped the production source inventory: {}",
                edge_chirho.target_chirho.display()
            );
            pending_chirho.push_back(ModuleVisitStateChirho {
                source_chirho: edge_chirho.target_chirho,
                module_base_chirho: edge_chirho.module_base_chirho,
                cfg_test_chirho: edge_chirho.cfg_test_chirho,
            });
        }
    }
    cfg_test_chirho.retain(|target_chirho| !production_chirho.contains(target_chirho));
    cfg_test_chirho
}

#[cfg(test)]
fn is_cfg_test_declared_module_file_chirho(path_chirho: &Path) -> bool {
    let Some(src_dir_chirho) = path_chirho.ancestors().find(|ancestor_chirho| {
        ancestor_chirho
            .file_name()
            .is_some_and(|name_chirho| name_chirho == "src")
    }) else {
        return false;
    };
    let mut files_chirho = Vec::new();
    collect_rs_files_chirho(src_dir_chirho, &mut files_chirho);
    let targets_chirho = cfg_test_declared_module_targets_chirho(&files_chirho);
    path_chirho
        .canonicalize()
        .map(|canonical_chirho| targets_chirho.contains(&canonical_chirho))
        .unwrap_or(false)
}

/// Every `.rs` file under `src/` and `crates/` (tests included) — the balanced-tree scope.
pub fn workspace_all_rs_files_chirho() -> Vec<PathBuf> {
    let root_chirho = workspace_root_chirho();
    let mut files_chirho = Vec::new();
    collect_rs_files_chirho(&root_chirho.join("src"), &mut files_chirho);
    collect_rs_files_chirho(&root_chirho.join("crates"), &mut files_chirho);
    files_chirho.sort();
    files_chirho.dedup();
    files_chirho
}

fn push_line_padding_chirho(out_chirho: &mut String, line_chirho: &str) {
    if line_chirho.ends_with('\n') {
        out_chirho.push('\n');
    }
}

fn is_cfg_test_attribute_line_chirho(line_chirho: &str) -> bool {
    let Some(after_chirho) = line_chirho.strip_prefix("#[cfg(test)]") else {
        return false;
    };
    after_chirho.trim().is_empty()
        || after_chirho
            .chars()
            .next()
            .map(|ch_chirho| ch_chirho.is_whitespace())
            .unwrap_or(false)
}

fn inline_cfg_test_declaration_chirho(line_chirho: &str) -> Option<&str> {
    let after_chirho = line_chirho.strip_prefix("#[cfg(test)]")?;
    let declaration_chirho = after_chirho.trim_start();
    (!declaration_chirho.is_empty()).then_some(declaration_chirho)
}

fn is_stacked_attribute_line_chirho(line_chirho: &str) -> bool {
    line_chirho.starts_with("#[") && line_chirho.trim_end().ends_with(']')
}

fn declaration_keyword_chirho(line_chirho: &str) -> Option<&'static str> {
    if line_chirho.starts_with("use ") {
        Some("use")
    } else if line_chirho.starts_with("mod ") {
        Some("mod")
    } else if line_chirho.starts_with("static ") {
        Some("static")
    } else if line_chirho.starts_with("const ") {
        Some("const")
    } else if line_chirho.starts_with("type ") {
        Some("type")
    } else if line_chirho.starts_with("pub ") || line_chirho.starts_with("pub(") {
        Some("pub")
    } else {
        None
    }
}

#[cfg(test)]
pub(crate) fn field_line_is_private_chirho(line_chirho: &str, field_needle_chirho: &str) -> bool {
    line_chirho.trim_start().starts_with(field_needle_chirho)
}

fn declaration_allows_braces_chirho(keyword_chirho: &str, line_chirho: &str) -> bool {
    keyword_chirho == "use"
        || (keyword_chirho == "pub"
            && (line_chirho.starts_with("pub use ")
                || line_chirho.starts_with("pub(crate) use ")
                || line_chirho.starts_with("pub(super) use ")))
}

fn likely_lifetime_start_chirho(chars_chirho: &[(usize, char)], index_chirho: usize) -> bool {
    let Some((_, next_chirho)) = chars_chirho.get(index_chirho + 1) else {
        return false;
    };
    if !(*next_chirho == '_' || next_chirho.is_ascii_alphabetic()) {
        return false;
    }
    chars_chirho
        .get(index_chirho + 2)
        .is_none_or(|(_, after_chirho)| *after_chirho != '\'')
}

#[derive(Default)]
struct CodeScanStateChirho {
    block_comment_depth_chirho: usize,
    in_string_chirho: bool,
    string_escaped_chirho: bool,
    in_char_chirho: bool,
    char_escaped_chirho: bool,
    raw_string_hashes_chirho: Option<usize>,
}

fn raw_string_start_chirho(
    chars_chirho: &[(usize, char)],
    index_chirho: usize,
) -> Option<(usize, usize)> {
    let mut cursor_chirho = index_chirho;
    if chars_chirho
        .get(cursor_chirho)
        .is_some_and(|(_, ch_chirho)| matches!(ch_chirho, 'b' | 'c'))
    {
        cursor_chirho += 1;
    }
    if chars_chirho
        .get(cursor_chirho)
        .is_none_or(|(_, ch_chirho)| *ch_chirho != 'r')
    {
        return None;
    }
    cursor_chirho += 1;
    let mut hashes_chirho = 0usize;
    while chars_chirho
        .get(cursor_chirho)
        .is_some_and(|(_, ch_chirho)| *ch_chirho == '#')
    {
        hashes_chirho += 1;
        cursor_chirho += 1;
    }
    chars_chirho
        .get(cursor_chirho)
        .is_some_and(|(_, ch_chirho)| *ch_chirho == '"')
        .then_some((hashes_chirho, cursor_chirho - index_chirho + 1))
}

fn raw_string_end_chirho(
    chars_chirho: &[(usize, char)],
    index_chirho: usize,
    hashes_chirho: usize,
) -> bool {
    chars_chirho
        .get(index_chirho)
        .is_some_and(|(_, ch_chirho)| *ch_chirho == '"')
        && (0..hashes_chirho).all(|offset_chirho| {
            chars_chirho
                .get(index_chirho + offset_chirho + 1)
                .is_some_and(|(_, ch_chirho)| *ch_chirho == '#')
        })
}

fn code_line_scan_chirho(
    line_chirho: &str,
    state_chirho: &mut CodeScanStateChirho,
) -> Vec<(usize, char)> {
    let chars_chirho: Vec<(usize, char)> = line_chirho.char_indices().collect();
    let mut out_chirho = Vec::new();
    let mut index_chirho = 0usize;
    while let Some((byte_idx_chirho, ch_chirho)) = chars_chirho.get(index_chirho).copied() {
        if state_chirho.block_comment_depth_chirho > 0 {
            if ch_chirho == '/'
                && chars_chirho
                    .get(index_chirho + 1)
                    .is_some_and(|(_, next_chirho)| *next_chirho == '*')
            {
                state_chirho.block_comment_depth_chirho += 1;
                index_chirho += 2;
                continue;
            }
            if ch_chirho == '*'
                && chars_chirho
                    .get(index_chirho + 1)
                    .is_some_and(|(_, next_chirho)| *next_chirho == '/')
            {
                state_chirho.block_comment_depth_chirho -= 1;
                index_chirho += 2;
                continue;
            }
            index_chirho += 1;
            continue;
        }
        if let Some(hashes_chirho) = state_chirho.raw_string_hashes_chirho {
            if raw_string_end_chirho(&chars_chirho, index_chirho, hashes_chirho) {
                state_chirho.raw_string_hashes_chirho = None;
                index_chirho += hashes_chirho + 1;
            } else {
                index_chirho += 1;
            }
            continue;
        }
        if state_chirho.in_string_chirho {
            if state_chirho.string_escaped_chirho {
                state_chirho.string_escaped_chirho = false;
            } else if ch_chirho == '\\' {
                state_chirho.string_escaped_chirho = true;
            } else if ch_chirho == '"' {
                state_chirho.in_string_chirho = false;
            }
            index_chirho += 1;
            continue;
        }
        if state_chirho.in_char_chirho {
            if state_chirho.char_escaped_chirho {
                state_chirho.char_escaped_chirho = false;
            } else if ch_chirho == '\\' {
                state_chirho.char_escaped_chirho = true;
            } else if ch_chirho == '\'' {
                state_chirho.in_char_chirho = false;
            }
            index_chirho += 1;
            continue;
        }
        if ch_chirho == '/'
            && chars_chirho
                .get(index_chirho + 1)
                .is_some_and(|(_, next_chirho)| *next_chirho == '/')
        {
            break;
        }
        if ch_chirho == '/'
            && chars_chirho
                .get(index_chirho + 1)
                .is_some_and(|(_, next_chirho)| *next_chirho == '*')
        {
            state_chirho.block_comment_depth_chirho = 1;
            index_chirho += 2;
            continue;
        }
        if let Some((hashes_chirho, consumed_chirho)) =
            raw_string_start_chirho(&chars_chirho, index_chirho)
        {
            state_chirho.raw_string_hashes_chirho = Some(hashes_chirho);
            index_chirho += consumed_chirho;
            continue;
        }
        if ch_chirho == '"' {
            state_chirho.in_string_chirho = true;
            state_chirho.string_escaped_chirho = false;
            index_chirho += 1;
            continue;
        }
        if ch_chirho == '\'' && !likely_lifetime_start_chirho(&chars_chirho, index_chirho) {
            state_chirho.in_char_chirho = true;
            state_chirho.char_escaped_chirho = false;
            index_chirho += 1;
            continue;
        }
        out_chirho.push((byte_idx_chirho, ch_chirho));
        index_chirho += 1;
    }
    out_chirho
}

fn code_chars_chirho(
    line_chirho: &str,
    state_chirho: &mut CodeScanStateChirho,
) -> impl Iterator<Item = char> {
    code_line_scan_chirho(line_chirho, state_chirho)
        .into_iter()
        .map(|(_, ch_chirho)| ch_chirho)
}

fn code_ends_with_semicolon_chirho(code_chirho: &[char]) -> bool {
    code_chirho
        .iter()
        .rfind(|ch_chirho| !ch_chirho.is_whitespace())
        .is_some_and(|ch_chirho| *ch_chirho == ';')
}

fn has_disallowed_brace_before_semicolon_chirho(
    keyword_chirho: &str,
    line_chirho: &str,
    code_chirho: &[char],
) -> bool {
    if declaration_allows_braces_chirho(keyword_chirho, line_chirho) {
        return false;
    }
    for ch_chirho in code_chirho {
        if *ch_chirho == ';' {
            return false;
        }
        if *ch_chirho == '{' {
            return true;
        }
    }
    false
}

fn cfg_test_declaration_skip_len_chirho(
    lines_chirho: &[&str],
    start_chirho: usize,
) -> Option<usize> {
    let first_chirho = lines_chirho.get(start_chirho)?;
    if !is_cfg_test_attribute_line_chirho(first_chirho) {
        return None;
    }

    if let Some(declaration_chirho) = inline_cfg_test_declaration_chirho(first_chirho) {
        let keyword_chirho = declaration_keyword_chirho(declaration_chirho)?;
        let mut state_chirho = CodeScanStateChirho::default();
        let code_chirho: Vec<char> =
            code_chars_chirho(declaration_chirho, &mut state_chirho).collect();
        return (code_ends_with_semicolon_chirho(&code_chirho)
            && !has_disallowed_brace_before_semicolon_chirho(
                keyword_chirho,
                declaration_chirho,
                &code_chirho,
            ))
        .then_some(1);
    }

    let mut index_chirho = start_chirho + 1;
    while lines_chirho
        .get(index_chirho)
        .map(|line_chirho| is_stacked_attribute_line_chirho(line_chirho))
        .unwrap_or(false)
    {
        index_chirho += 1;
    }
    let declaration_line_chirho = lines_chirho.get(index_chirho)?.trim_end();
    let keyword_chirho = declaration_keyword_chirho(declaration_line_chirho)?;

    let mut scan_chirho = index_chirho;
    let mut state_chirho = CodeScanStateChirho::default();
    while let Some(line_chirho) = lines_chirho.get(scan_chirho) {
        let code_chirho: Vec<char> = code_chars_chirho(line_chirho, &mut state_chirho).collect();
        if has_disallowed_brace_before_semicolon_chirho(keyword_chirho, line_chirho, &code_chirho) {
            return None;
        }
        if code_ends_with_semicolon_chirho(&code_chirho) {
            return Some(scan_chirho - start_chirho + 1);
        }
        scan_chirho += 1;
    }

    None
}

fn cfg_test_block_skip_len_chirho(lines_chirho: &[&str], start_chirho: usize) -> Option<usize> {
    let first_chirho = lines_chirho.get(start_chirho)?;
    if !is_cfg_test_attribute_line_chirho(first_chirho) {
        return None;
    }

    let inline_declaration_chirho = inline_cfg_test_declaration_chirho(first_chirho);
    let mut declaration_start_chirho = start_chirho;
    if inline_declaration_chirho.is_none() {
        declaration_start_chirho = start_chirho + 1;
        while lines_chirho
            .get(declaration_start_chirho)
            .map(|line_chirho| is_stacked_attribute_line_chirho(line_chirho))
            .unwrap_or(false)
        {
            declaration_start_chirho += 1;
        }
    }

    let mut index_chirho = declaration_start_chirho;
    let mut balance_chirho = 0isize;
    let mut saw_open_chirho = false;
    let mut state_chirho = CodeScanStateChirho::default();
    while let Some(line_chirho) = lines_chirho.get(index_chirho) {
        let scan_line_chirho = if index_chirho == declaration_start_chirho {
            inline_declaration_chirho.unwrap_or(line_chirho)
        } else {
            line_chirho
        };
        for ch_chirho in code_chars_chirho(scan_line_chirho, &mut state_chirho) {
            if !saw_open_chirho && ch_chirho == ';' {
                return None;
            }
            if ch_chirho == '{' {
                saw_open_chirho = true;
                balance_chirho += 1;
            } else if saw_open_chirho && ch_chirho == '}' {
                balance_chirho -= 1;
            }
        }
        if saw_open_chirho && balance_chirho <= 0 {
            return Some(index_chirho - start_chirho + 1);
        }
        index_chirho += 1;
    }

    None
}

fn outer_item_prefix_line_chirho(line_chirho: &str) -> bool {
    let trimmed_chirho = line_chirho.trim();
    trimmed_chirho.starts_with("///")
        || (trimmed_chirho.starts_with("#[") && trimmed_chirho.ends_with(']'))
}

fn cfg_test_item_prefix_start_chirho(lines_chirho: &[&str], cfg_index_chirho: usize) -> usize {
    let mut start_chirho = cfg_index_chirho;
    let mut cursor_chirho = cfg_index_chirho;
    while cursor_chirho > 0 && lines_chirho[cursor_chirho - 1].trim().is_empty() {
        cursor_chirho -= 1;
    }
    let attribute_end_chirho = cursor_chirho;
    while cursor_chirho > 0 && outer_item_prefix_line_chirho(lines_chirho[cursor_chirho - 1]) {
        cursor_chirho -= 1;
    }
    if cursor_chirho < attribute_end_chirho {
        start_chirho = cursor_chirho;
    }
    start_chirho
}

/// The production text of a source file. Line-leading cfg-test declarations and balanced cfg-test
/// braced items, including their attached outer documentation and attributes, are skipped with
/// blank-line padding so production code after test helpers remains visible to source guards with
/// honest line numbers. Unbalanced or unrecognized cfg-test regions are retained and scanned
/// fail-safe rather than silently hiding a possible production region.
pub fn production_text_chirho(text_chirho: &str) -> Cow<'_, str> {
    let lines_chirho: Vec<&str> = text_chirho.split_inclusive('\n').collect();
    let mut skipped_chirho = vec![false; lines_chirho.len()];
    let mut changed_chirho = false;
    let mut index_chirho = 0usize;

    while index_chirho < lines_chirho.len() {
        let line_chirho = lines_chirho[index_chirho];
        if is_cfg_test_attribute_line_chirho(line_chirho) {
            if let Some(skip_len_chirho) =
                cfg_test_declaration_skip_len_chirho(&lines_chirho, index_chirho)
                    .or_else(|| cfg_test_block_skip_len_chirho(&lines_chirho, index_chirho))
            {
                changed_chirho = true;
                let prefix_start_chirho =
                    cfg_test_item_prefix_start_chirho(&lines_chirho, index_chirho);
                for skipped_line_chirho in
                    &mut skipped_chirho[prefix_start_chirho..index_chirho + skip_len_chirho]
                {
                    *skipped_line_chirho = true;
                }
                index_chirho += skip_len_chirho;
                continue;
            }
            // Treat unrecognized cfg-test regions as retained-and-scanned (fail-closed)
            index_chirho += 1;
            continue;
        }
        index_chirho += 1;
    }

    if changed_chirho {
        let mut out_chirho = String::with_capacity(text_chirho.len());
        for (line_chirho, skipped_line_chirho) in lines_chirho.iter().zip(skipped_chirho.iter()) {
            if *skipped_line_chirho {
                push_line_padding_chirho(&mut out_chirho, line_chirho);
            } else {
                out_chirho.push_str(line_chirho);
            }
        }
        Cow::Owned(out_chirho)
    } else {
        Cow::Borrowed(text_chirho)
    }
}

/// `(workspace-relative path, 1-based line, trimmed text)` for every nonempty, non-comment
/// production line in the workspace. Labels are full relative paths so guard allowlists cannot be
/// bypassed by placing matching text in a different crate's same-named file.
pub fn production_source_lines_chirho() -> Vec<(String, usize, String)> {
    let mut lines_chirho = Vec::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let label_chirho = workspace_relative_chirho(&path_chirho);
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        for (idx_chirho, line_text_chirho) in
            production_text_chirho(&text_chirho).lines().enumerate()
        {
            let trimmed_chirho = line_text_chirho.trim();
            if trimmed_chirho.is_empty() || trimmed_chirho.starts_with("//") {
                continue;
            }
            lines_chirho.push((
                label_chirho.clone(),
                idx_chirho + 1,
                trimmed_chirho.to_string(),
            ));
        }
    }
    lines_chirho
}

/// Production lines containing `needle_chirho`.
pub fn production_source_lines_matching_chirho(
    needle_chirho: &str,
) -> Vec<(String, usize, String)> {
    production_source_lines_chirho()
        .into_iter()
        .filter(|(_file_chirho, _line_chirho, text_chirho)| text_chirho.contains(needle_chirho))
        .collect()
}

/// The CLI's production source text — the concatenated production text of every non-test file in
/// the `cairn-cli-chirho` crate (args + dispatch + the thin main), falling back to the historical
/// root `src/main.rs`. Panics if neither exists so the guards fail loudly instead of going blind.
pub fn production_main_source_chirho() -> String {
    let root_chirho = workspace_root_chirho();
    let cli_src_chirho = root_chirho.join("crates/cairn-cli-chirho/src");
    if cli_src_chirho.is_dir() {
        let mut files_chirho = Vec::new();
        collect_rs_files_chirho(&cli_src_chirho, &mut files_chirho);
        let files_chirho = production_rs_files_from_candidates_chirho(files_chirho);
        let mut out_chirho = String::new();
        for path_chirho in files_chirho {
            let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
            out_chirho.push_str(&production_text_chirho(&text_chirho));
            out_chirho.push('\n');
        }
        return out_chirho;
    }
    let legacy_main_chirho = root_chirho.join("src/main.rs");
    if legacy_main_chirho.exists() {
        let text_chirho = std::fs::read_to_string(legacy_main_chirho).unwrap();
        return production_text_chirho(&text_chirho).to_string();
    }
    panic!(
        "CLI source not found for source guards (looked in crates/cairn-cli-chirho/src/ and src/main.rs)"
    );
}

#[cfg(test)]
#[path = "production_scan_tests_chirho.rs"]
mod production_scan_tests_chirho;
#[cfg(test)]
mod tests_chirho {
    use super::*;
    #[path = "cas_object_plane_walk_guard_tests_chirho.rs"]
    mod cas_object_plane_walk_guard_tests_chirho;
    #[path = "cf6_cf7_transition_chirho/cf6_doc_cli_declared_guard_tests_chirho.rs"]
    mod cf6_doc_cli_declared_guard_tests_chirho;
    #[path = "cf6_cf7_transition_chirho/cf6_regenesis_guard_tests_chirho.rs"]
    mod cf6_regenesis_guard_tests_chirho;
    #[path = "cf6_cf7_transition_chirho/cf7_projection_json_guard_tests_chirho.rs"]
    mod cf7_projection_json_guard_tests_chirho;
    #[path = "cf8_clause_map_guard_tests_chirho.rs"]
    mod cf8_clause_map_guard_tests_chirho;
    #[path = "cf6_cf7_transition_chirho/cf8_planner_authority_guard_tests_chirho.rs"]
    mod cf8_planner_authority_guard_tests_chirho;

    #[path = "cf6_cf7_transition_chirho/cf8_move_control_addressing_guard_tests_chirho.rs"]
    mod cf8_move_control_addressing_guard_tests_chirho;

    #[path = "cf6_cf7_transition_chirho/cf8_ledger_config_digest_guard_tests_chirho.rs"]
    mod cf8_ledger_config_digest_guard_tests_chirho;

    #[path = "cf6_cf7_transition_chirho/cf8_registry_port_guard_tests_chirho.rs"]
    mod cf8_registry_port_guard_tests_chirho;
    #[path = "cf6_cf7_transition_chirho/cf8_tenant_placement_verifier_guard_tests_chirho.rs"]
    mod cf8_tenant_placement_verifier_guard_tests_chirho;
    #[path = "gd7_digest_determinism_guard_tests_chirho.rs"]
    mod gd7_digest_determinism_guard_tests_chirho;
    #[path = "gd7_effect_warrant_consumer_guard_tests_chirho.rs"]
    mod gd7_effect_warrant_consumer_guard_tests_chirho;
    #[path = "geo_genesis_guard_tests_chirho.rs"]
    mod geo_genesis_guard_tests_chirho;
    #[path = "gg7_placement_unit_guard_tests_chirho.rs"]
    mod gg7_placement_unit_guard_tests_chirho;
    #[path = "ha1_command_service_chirho/mod_tests_chirho.rs"]
    mod ha1_command_service_chirho;
    #[path = "ha1_guards_chirho/ha1_customer_write_guard_tests_chirho.rs"]
    mod ha1_customer_write_guard_tests_chirho;
    #[path = "ha1_guards_chirho/ha1_run_intent_aborted_reader_guard_tests_chirho.rs"]
    mod ha1_run_intent_aborted_reader_guard_tests_chirho;
    #[path = "ha1_guards_chirho/ha1_run_intent_startup_preflight_guard_tests_chirho.rs"]
    mod ha1_run_intent_startup_preflight_guard_tests_chirho;
    #[path = "ha1_guards_chirho/ha1_runtime_facade_guard_tests_chirho.rs"]
    mod ha1_runtime_facade_guard_tests_chirho;
    #[path = "ha2_guards_chirho/ha2_external_io_guard_tests_chirho.rs"]
    mod ha2_external_io_guard_tests_chirho;
    #[path = "ha2_guards_chirho/ha2_resource_lock_order_guard_tests_chirho.rs"]
    mod ha2_resource_lock_order_guard_tests_chirho;
    #[path = "ha2_guards_chirho/ha2_resource_policy_guard_tests_chirho.rs"]
    mod ha2_resource_policy_guard_tests_chirho;
    #[path = "ha2_guards_chirho/ha2_served_write_relay_guard_tests_chirho.rs"]
    mod ha2_served_write_relay_guard_tests_chirho;
    #[path = "ha2_writer_head_guard_tests_chirho.rs"]
    mod ha2_writer_head_guard_tests_chirho;
    #[path = "ha_gate1_flip_guard_tests_chirho.rs"]
    mod ha_gate1_flip_guard_tests_chirho;
    #[path = "item6_barrier_boundary_guard_tests_chirho.rs"]
    mod item6_barrier_boundary_guard_tests_chirho;
    #[path = "item7_mirror_join_guard_tests_chirho.rs"]
    mod item7_mirror_join_guard_tests_chirho;
    #[path = "cf6_cf7_transition_chirho/ledger_host_authoring_cli_guard_tests_chirho.rs"]
    mod ledger_host_authoring_cli_guard_tests_chirho;
    #[path = "cf6_cf7_transition_chirho/ledger_host_authoring_signer_fence_guard_tests_chirho.rs"]
    mod ledger_host_authoring_signer_fence_guard_tests_chirho;
    #[path = "ledger_host_storage_custody_guard_tests_chirho.rs"]
    mod ledger_host_storage_custody_guard_tests_chirho;
    #[path = "cf6_cf7_transition_chirho/ledger_host_test_kind_fence_guard_tests_chirho.rs"]
    mod ledger_host_test_kind_fence_guard_tests_chirho;
    #[path = "reviewed_principal_guard_tests_chirho.rs"]
    mod reviewed_principal_guard_tests_chirho;
    #[path = "workspace_hygiene_guard_tests_chirho.rs"]
    mod workspace_hygiene_guard_tests_chirho;
}
