// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Prove a tenant root holds at most one customer app, so the root stays the atomic unit of
//! placement, authority, and migration.
//!
//! THIS IS NOT A CAPACITY LIMIT, and a reader who takes it for one has it backwards. Many tenant
//! roots live on one shard, and hundreds of apps per shard is the expected growth path. G1
//! constrains only what can be MOVED, AUTHORIZED, and AUDITED as a unit: two customers sharing one
//! root could not be migrated independently, and their private-key custody, erasure obligations,
//! and audit coordinates would straddle the boundary. One customer app per TENANT ROOT; many tenant
//! roots per SHARD.
//!
//! This is the state half of G1, and it is THE control rather than a complement to an install-door
//! check. A door proves only what future installs will do, never what the existing state is -- and
//! here the door provably cannot be made complete: `deploy_app_chirho` has several production
//! callers, and `cairn-chirho branch <name> <to>` writes a caller-supplied branch name through
//! `commit_head_chirho` with `AnyCurrentChirho`, so an operator can mint an `app/` ref with no
//! signed deploy record behind it. A door refusal is therefore defence-in-depth on the common path.
//! Only a check of the state itself can answer whether a root satisfies G1.
//!
//! `PlatformRootChirho` is exempt because it is operator/dev only and explicitly NOT a placement
//! unit. That mirrors the existing boundary in the opposite direction, where customer
//! `WriteStoreChirho` execution refuses to run on the platform root at all.
//!
//! KNOWN BOUND -- REFS ARE NOT THE WHOLE STATE. An app head is written in two phases: the signed
//! `AppRecordChirho` is appended first, the `app/{name}` ref moves second. Between them a second
//! customer app exists as durable, authorized state with no branch key, and
//! `recover_app_head_chirho(root, app)` completes it later from `(root, app)` alone with no fresh
//! authorization. `src/app_runtime_chirho/app_chirho/app_tests_chirho/ha2_head_commit_tests_chirho.rs`
//! ships a test that constructs exactly that state. So a refs-derived app set UNDERCOUNTS, in the
//! permissive direction, and this module does not pretend otherwise: the real control takes the app
//! set as an argument, and the refs-only path says so in its name.
//!
//! RECORDED DECISION -- the exemption arm cannot distinguish "platform root" from "unmarked root",
//! and we accept that deliberately rather than inherit it by accident. Marker ABSENCE is the
//! canonical representation of the platform root (`prepare_tenant_root_chirho` writes no marker for
//! it), so `tenant_id_for_root_chirho` returns `PlatformRootChirho` both for a genuine platform root
//! and for a legacy pre-marker root. The two are structurally identical; no check can separate them.
//! We accept it because fresh regenesis discards pre-marker roots with no migration, so the
//! conflation has no live subject. Note honestly what kind of fact that is: it is a CALLER-SET fact,
//! not a structural one. If pre-marker roots are ever reintroduced, this exemption silently widens
//! and this decision must be revisited.

use crate::tenant_chirho::{tenant_id_for_root_chirho, TenantIdChirho};
use anyhow::{bail, Result};
use cairn_core_chirho::model_chirho::RefsChirho;
use cairn_core_chirho::refs_chirho::load_refs_chirho;
use std::path::Path;

/// Branch-key prefix of a customer app head ref (`app/{name}`).
pub const CUSTOMER_APP_REF_PREFIX_CHIRHO: &str = "app/";

/// The app name in an `app/{name}` head ref, or `None` when the key is not exactly one app head.
///
/// Exactness is the whole point. `app-route/{app}/{route}` carries a different prefix, and app
/// names are validated to contain no slash, so a well-formed app head has exactly one slash. A key
/// like `app/foo/bar` is therefore NOT an app head and must not be counted as a second app.
pub fn customer_app_name_from_branch_chirho(branch_chirho: &str) -> Option<&str> {
    let name_chirho = branch_chirho.strip_prefix(CUSTOMER_APP_REF_PREFIX_CHIRHO)?;
    if name_chirho.is_empty() || name_chirho.contains('/') {
        return None;
    }
    Some(name_chirho)
}

/// Every customer app head ref in the root, in branch-key order.
pub fn customer_app_names_chirho(refs_chirho: &RefsChirho) -> Vec<&str> {
    refs_chirho
        .branches_chirho
        .keys()
        .filter_map(|branch_chirho| customer_app_name_from_branch_chirho(branch_chirho))
        .collect()
}

/// `app/`-prefixed branch keys that are NOT well-formed app heads.
///
/// These should not exist: the sole production writer of `branches_chirho` is
/// `refs_chirho::save_refs_chirho`, and every app-head former produces the exact `app/{name}` form.
/// We still surface them, because the alternative is to silently ignore a key we cannot classify --
/// and silently ignoring an unclassified app-prefixed key UNDERCOUNTS apps, which makes the
/// invariant pass in exactly the case we cannot explain. Refusing is the direction that costs
/// coverage rather than granting a pass.
pub fn unclassified_app_prefixed_branches_chirho(refs_chirho: &RefsChirho) -> Vec<&str> {
    refs_chirho
        .branches_chirho
        .keys()
        .filter(|branch_chirho| branch_chirho.starts_with(CUSTOMER_APP_REF_PREFIX_CHIRHO))
        .filter(|branch_chirho| customer_app_name_from_branch_chirho(branch_chirho).is_none())
        .map(String::as_str)
        .collect()
}

/// Verify G1 for ONE ROOT, deriving both the tenant and the refs from that one path.
///
/// This is the production entry point, and it takes a path rather than a `(tenant, refs)` pair on
/// purpose. With two independent values a caller could hand in `PlatformRootChirho` alongside a
/// CUSTOMER root's refs and collect a free exemption -- the exemption arm would be selected by an
/// unbound argument. That is caller-controlled authority confusion, the same defect class as a
/// caller-named FROM account. Deriving both from one root makes the mismatched pair
/// UNREPRESENTABLE, which is strictly stronger than documenting that callers must not do it.
///
/// `additional_app_names_chirho` is where a caller supplies apps this crate cannot see -- above all
/// prepared-but-unapplied deploy records, which are real authorized apps with no branch key yet (see
/// the KNOWN BOUND note). Pass an empty slice ONLY when you genuinely mean "applied heads are the
/// whole question"; a caller that can reach deploy records and passes nothing is asserting something
/// it has not checked.
/// On success it RETURNS THE APPLIED HEAD NAMES it judged, so a caller can report what was actually
/// examined without loading the refs a second time. A verification that cannot say what it looked at
/// invites a pass over nothing to be read as a pass.
pub fn verify_single_customer_app_root_at_path_chirho(
    root_chirho: &Path,
    additional_app_names_chirho: &[&str],
) -> Result<Vec<String>> {
    let tenant_chirho = tenant_id_for_root_chirho(root_chirho)?;
    let refs_chirho = load_refs_chirho(root_chirho)?;
    let applied_chirho = customer_app_names_chirho(&refs_chirho)
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    if tenant_chirho.is_platform_root_chirho() {
        return Ok(applied_chirho);
    }
    verify_single_customer_app_root_from_applied_refs_chirho(
        &tenant_chirho,
        &refs_chirho,
        additional_app_names_chirho,
    )?;
    Ok(applied_chirho)
}

/// Verify G1 against a CALLER-SUPPLIED COMPLETE app set. Inner form; keeps the classification logic
/// testable without a filesystem. Production callers use
/// [`verify_single_customer_app_root_at_path_chirho`], whose authority binding cannot be forged.
///
/// The app set is a parameter, not derived here, and that is deliberate. An app head is written in
/// TWO phases -- the signed `AppRecordChirho` is appended first, the `app/{name}` ref moves second --
/// so between those phases a second customer app exists as durable, authorized state with NO branch
/// key at all. `recover_app_head_chirho(root, app)` later completes it from `(root, app)` alone,
/// with no fresh authorization. A refs-only judgement therefore MISSES a real second app, in the
/// permissive direction.
///
/// Taking the app set as an argument makes that incompleteness impossible to inherit by accident: a
/// caller must decide what "every app this root holds" means, rather than being handed a partial
/// answer that looks complete. Callers that can see prepared-but-unapplied deploy records must union
/// them in.
pub(crate) fn verify_single_customer_app_root_chirho(
    tenant_chirho: &TenantIdChirho,
    app_names_chirho: &[&str],
) -> Result<()> {
    if tenant_chirho.is_platform_root_chirho() {
        return Ok(());
    }
    if app_names_chirho.len() > 1 {
        bail!(
            "tenant root {tenant_chirho} holds {} customer apps ({}); a tenant root is the atomic \
             unit of placement, authority, and migration, so it must hold at most one. This is NOT \
             a capacity limit: many tenant roots per shard is the expected growth path. Two \
             customers in one root could not be migrated, authorized, or erased independently",
            app_names_chirho.len(),
            app_names_chirho.join(", ")
        );
    }

    Ok(())
}

/// Verify G1 using ONLY the applied refs. Incomplete by construction -- read this before using it.
///
/// This sees apps whose head ref has already moved. It does NOT see a prepared-but-unapplied deploy
/// record, which is a real, authorized second app awaiting only `recover_app_head_chirho`. So a pass
/// here means "no G1 violation among APPLIED heads", never "this root satisfies G1".
///
/// It fails closed on app-prefixed keys it cannot classify, and unions in whatever the caller knows
/// about that the refs cannot show. This is the single implementation of the check;
/// [`verify_single_customer_app_root_at_path_chirho`] is the production entry that feeds it a tenant
/// and refs derived from ONE root, so the two cannot disagree about which root is being judged.
pub(crate) fn verify_single_customer_app_root_from_applied_refs_chirho(
    tenant_chirho: &TenantIdChirho,
    refs_chirho: &RefsChirho,
    additional_app_names_chirho: &[&str],
) -> Result<()> {
    if tenant_chirho.is_platform_root_chirho() {
        return Ok(());
    }

    let unclassified_chirho = unclassified_app_prefixed_branches_chirho(refs_chirho);
    if !unclassified_chirho.is_empty() {
        bail!(
            "tenant root {tenant_chirho} carries app-prefixed refs that are not well-formed app \
             heads ({}); refusing to judge the one-customer-app invariant on refs this check \
             cannot classify",
            unclassified_chirho.join(", ")
        );
    }

    let mut app_names_chirho = customer_app_names_chirho(refs_chirho);
    for extra_chirho in additional_app_names_chirho {
        if !app_names_chirho.contains(extra_chirho) {
            app_names_chirho.push(extra_chirho);
        }
    }
    verify_single_customer_app_root_chirho(tenant_chirho, &app_names_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_core_chirho::model_chirho::HashChirho;
    use std::collections::BTreeMap;

    fn refs_with_branches_chirho(names_chirho: &[&str]) -> RefsChirho {
        let mut branches_chirho = BTreeMap::new();
        for name_chirho in names_chirho {
            branches_chirho.insert(
                (*name_chirho).to_string(),
                HashChirho("00".repeat(32).to_string()),
            );
        }
        RefsChirho {
            branches_chirho,
            tags_chirho: BTreeMap::new(),
            head_chirho: "main".to_string(),
        }
    }

    fn tenant_chirho() -> TenantIdChirho {
        TenantIdChirho::TenantChirho("acme-chirho".to_string())
    }

    // --- the three state arms G1 is specified by ---

    #[test]
    fn one_app_tenant_root_passes_chirho() {
        let refs_chirho = refs_with_branches_chirho(&["main", "app/contact-chirho"]);
        assert!(verify_single_customer_app_root_from_applied_refs_chirho(
            &tenant_chirho(),
            &refs_chirho,
            &[]
        )
        .is_ok());
    }

    #[test]
    fn two_customer_app_tenant_root_fails_chirho() {
        let refs_chirho =
            refs_with_branches_chirho(&["main", "app/contact-chirho", "app/intake-chirho"]);
        let err_chirho = verify_single_customer_app_root_from_applied_refs_chirho(
            &tenant_chirho(),
            &refs_chirho,
            &[],
        )
        .expect_err("two customer apps in one tenant root must refuse");
        let text_chirho = err_chirho.to_string();
        assert!(
            text_chirho.contains("app/contact-chirho") || text_chirho.contains("contact-chirho")
        );
        assert!(text_chirho.contains("intake-chirho"));
    }

    #[test]
    fn platform_root_with_two_apps_is_exempt_chirho() {
        // The exempt arm is what stops G1 being read as a density ceiling: the platform root is
        // operator/dev only and is explicitly not a placement unit.
        let refs_chirho = refs_with_branches_chirho(&["main", "app/one-chirho", "app/two-chirho"]);
        assert!(verify_single_customer_app_root_from_applied_refs_chirho(
            &TenantIdChirho::PlatformRootChirho,
            &refs_chirho,
            &[]
        )
        .is_ok());
    }

    // --- the refusal must not read as a capacity limit ---

    #[test]
    fn refusal_names_the_migration_unit_and_denies_being_a_capacity_limit_chirho() {
        let refs_chirho = refs_with_branches_chirho(&["app/a-chirho", "app/b-chirho"]);
        let text_chirho = verify_single_customer_app_root_from_applied_refs_chirho(
            &tenant_chirho(),
            &refs_chirho,
            &[],
        )
        .expect_err("must refuse")
        .to_string();
        assert!(
            text_chirho.contains("placement, authority, and migration"),
            "the refusal must say WHICH unit it protects: {text_chirho}"
        );
        assert!(
            text_chirho.contains("NOT a capacity limit"),
            "the refusal must deny being a density ceiling: {text_chirho}"
        );
        assert!(
            text_chirho.contains("many tenant roots per shard"),
            "the refusal must state the expected growth path: {text_chirho}"
        );
    }

    // --- the prefix near-miss, fixtured BOTH ways ---

    #[test]
    fn app_route_refs_are_not_customer_apps_chirho() {
        // `app-route/{app}/{route}` is per-app, so routes follow from the app rule and must never
        // be counted as apps in their own right. One app with many routes still satisfies G1.
        let refs_chirho = refs_with_branches_chirho(&[
            "main",
            "app/contact-chirho",
            "app-route/contact-chirho/submit-chirho",
            "app-route/contact-chirho/list-chirho",
            "app-route/contact-chirho/reveal-chirho",
        ]);
        assert_eq!(
            customer_app_names_chirho(&refs_chirho),
            vec!["contact-chirho"]
        );
        assert!(verify_single_customer_app_root_from_applied_refs_chirho(
            &tenant_chirho(),
            &refs_chirho,
            &[]
        )
        .is_ok());
    }

    #[test]
    fn app_route_prefix_is_not_swallowed_by_the_app_prefix_chirho() {
        // The near-miss stated directly: "app-route/" must NOT be treated as an unclassified
        // "app/" key, or every routed app would refuse.
        let refs_chirho = refs_with_branches_chirho(&["app-route/contact-chirho/submit-chirho"]);
        assert!(unclassified_app_prefixed_branches_chirho(&refs_chirho).is_empty());
        assert_eq!(customer_app_name_from_branch_chirho("app-route/x/y"), None);
    }

    // --- fail-closed on what we cannot classify ---

    #[test]
    fn unclassifiable_app_prefixed_ref_refuses_rather_than_undercounting_chirho() {
        // A deeper `app/{a}/{b}` key is not a well-formed head. Silently skipping it would
        // UNDERCOUNT apps and let the invariant pass on state we cannot explain.
        let refs_chirho =
            refs_with_branches_chirho(&["app/contact-chirho", "app/odd-chirho/extra"]);
        assert_eq!(
            customer_app_names_chirho(&refs_chirho),
            vec!["contact-chirho"]
        );
        let text_chirho = verify_single_customer_app_root_from_applied_refs_chirho(
            &tenant_chirho(),
            &refs_chirho,
            &[],
        )
        .expect_err("an unclassifiable app-prefixed ref must refuse, not pass")
        .to_string();
        assert!(
            text_chirho.contains("app/odd-chirho/extra"),
            "{text_chirho}"
        );
        assert!(text_chirho.contains("cannot classify"), "{text_chirho}");
    }

    #[test]
    fn bare_app_prefix_is_unclassifiable_chirho() {
        let refs_chirho = refs_with_branches_chirho(&["app/"]);
        assert_eq!(customer_app_name_from_branch_chirho("app/"), None);
        assert_eq!(
            unclassified_app_prefixed_branches_chirho(&refs_chirho),
            vec!["app/"]
        );
        assert!(verify_single_customer_app_root_from_applied_refs_chirho(
            &tenant_chirho(),
            &refs_chirho,
            &[]
        )
        .is_err());
    }

    // --- an empty root is not a violation ---

    #[test]
    fn root_with_no_apps_passes_chirho() {
        let refs_chirho = refs_with_branches_chirho(&["main", "ledger/main"]);
        assert!(customer_app_names_chirho(&refs_chirho).is_empty());
        assert!(verify_single_customer_app_root_from_applied_refs_chirho(
            &tenant_chirho(),
            &refs_chirho,
            &[]
        )
        .is_ok());
    }

    // --- the guard must be able to FAIL, or its green means nothing ---

    #[test]
    fn positive_control_the_check_actually_distinguishes_chirho() {
        // Known-true input beside known-false input, same tenant, same shape. If these two ever
        // agree, the instrument has stopped measuring.
        let compliant_chirho = refs_with_branches_chirho(&["app/only-chirho"]);
        let violating_chirho = refs_with_branches_chirho(&["app/one-chirho", "app/two-chirho"]);
        assert!(verify_single_customer_app_root_from_applied_refs_chirho(
            &tenant_chirho(),
            &compliant_chirho,
            &[]
        )
        .is_ok());
        assert!(verify_single_customer_app_root_from_applied_refs_chirho(
            &tenant_chirho(),
            &violating_chirho,
            &[]
        )
        .is_err());
    }

    // --- the caller-supplied complete set: the real control ---

    #[test]
    fn complete_app_set_refuses_two_apps_and_exempts_platform_root_chirho() {
        let two_chirho = ["contact-chirho", "intake-chirho"];
        assert!(verify_single_customer_app_root_chirho(&tenant_chirho(), &two_chirho).is_err());
        assert!(verify_single_customer_app_root_chirho(&tenant_chirho(), &["only-chirho"]).is_ok());
        assert!(verify_single_customer_app_root_chirho(&tenant_chirho(), &[]).is_ok());
        assert!(verify_single_customer_app_root_chirho(
            &TenantIdChirho::PlatformRootChirho,
            &two_chirho
        )
        .is_ok());
    }

    #[test]
    fn applied_refs_path_undercounts_a_prepared_app_and_the_complete_path_does_not_chirho() {
        // THE KNOWN BOUND, pinned as behaviour rather than left as prose. An app head is written in
        // two phases; between them the second app has a signed deploy record but NO branch key.
        // Model that state: refs carry only the applied app.
        let refs_chirho = refs_with_branches_chirho(&["main", "app/applied-chirho"]);

        // The refs-only path cannot see the prepared app, and PASSES. This is the permissive
        // direction, and it is exactly why this path carries its bound in its name.
        assert!(
            verify_single_customer_app_root_from_applied_refs_chirho(
                &tenant_chirho(),
                &refs_chirho,
                &[]
            )
            .is_ok(),
            "documents the undercount -- if this ever fails, the refs path grew sight of prepared \
             records and the KNOWN BOUND note must be revisited"
        );

        // A caller that unions in the prepared record gets the right answer. This is the whole
        // reason the real control takes the app set as an argument.
        let mut complete_chirho = customer_app_names_chirho(&refs_chirho);
        complete_chirho.push("prepared-chirho");
        assert!(
            verify_single_customer_app_root_chirho(&tenant_chirho(), &complete_chirho).is_err(),
            "the complete set must catch what the refs-only view misses"
        );
    }

    // --- the &Path entry: the authority binding must be UNFORGEABLE, proved on a real root ---

    fn tmp_platform_root_chirho() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        let now_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d_chirho| d_chirho.as_millis())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("cairn-g1-test-{n_chirho}-{now_chirho}"))
    }

    fn tenant_root_with_apps_chirho(branches_chirho: &[&str]) -> std::path::PathBuf {
        let platform_chirho = tmp_platform_root_chirho();
        let tenant_root_chirho =
            crate::tenant_chirho::prepare_tenant_root_chirho(&platform_chirho, "acme-chirho")
                .expect("prepare tenant root");
        cairn_core_chirho::refs_chirho::save_refs_chirho(
            &tenant_root_chirho,
            &refs_with_branches_chirho(branches_chirho),
        )
        .expect("save refs");
        tenant_root_chirho
    }

    #[test]
    fn path_entry_refuses_two_applied_apps_on_a_real_tenant_root_chirho() {
        let root_chirho =
            tenant_root_with_apps_chirho(&["main", "app/one-chirho", "app/two-chirho"]);
        let text_chirho = verify_single_customer_app_root_at_path_chirho(&root_chirho, &[])
            .expect_err("two applied apps in one tenant root must refuse")
            .to_string();
        assert!(text_chirho.contains("one-chirho") && text_chirho.contains("two-chirho"));
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn path_entry_unions_prepared_apps_the_refs_cannot_show_chirho() {
        // The F1 case, end to end: ONE applied head on disk, plus a prepared-but-unapplied deploy
        // the caller knows about. Refs alone say "compliant"; the union says otherwise.
        let root_chirho = tenant_root_with_apps_chirho(&["main", "app/applied-chirho"]);
        assert!(
            verify_single_customer_app_root_at_path_chirho(&root_chirho, &[]).is_ok(),
            "applied heads alone are compliant -- this is exactly the blind spot"
        );
        assert!(
            verify_single_customer_app_root_at_path_chirho(&root_chirho, &["prepared-chirho"])
                .is_err(),
            "a caller that supplies the prepared app must get a refusal"
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn path_entry_exempts_an_unmarked_root_and_that_is_the_recorded_decision_chirho() {
        // No tenant marker => PlatformRootChirho => exempt, even with two apps. Pinning the
        // RECORDED DECISION so the conflation cannot widen silently without a test noticing.
        let root_chirho = tmp_platform_root_chirho();
        std::fs::create_dir_all(&root_chirho).expect("mkdir");
        cairn_core_chirho::refs_chirho::save_refs_chirho(
            &root_chirho,
            &refs_with_branches_chirho(&["app/one-chirho", "app/two-chirho"]),
        )
        .expect("save refs");
        assert!(verify_single_customer_app_root_at_path_chirho(&root_chirho, &[]).is_ok());
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
