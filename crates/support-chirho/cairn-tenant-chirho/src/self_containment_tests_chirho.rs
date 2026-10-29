// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Resolving elsewhere is not resolving here, and a green over zero references is not a preliminary check.

use super::*;
use std::collections::BTreeSet;

/// A resolver that knows only what is inside THIS tenant root.
struct TenantScopedResolverChirho {
    present_chirho: BTreeSet<String>,
}

impl TenantObjectResolverChirho for TenantScopedResolverChirho {
    fn resolves_in_tenant_chirho(&self, hash_chirho: &str) -> bool {
        self.present_chirho.contains(hash_chirho)
    }
}

fn resolver_chirho(present_chirho: &[&str]) -> TenantScopedResolverChirho {
    TenantScopedResolverChirho {
        present_chirho: present_chirho
            .iter()
            .map(|h_chirho| h_chirho.to_string())
            .collect(),
    }
}

fn reference_chirho(
    log_chirho: &str,
    seq_chirho: u64,
    hash_chirho: &str,
) -> TenantLogReferenceChirho {
    TenantLogReferenceChirho {
        log_name_chirho: log_chirho.to_string(),
        seq_chirho,
        hash_chirho: hash_chirho.to_string(),
    }
}

#[test]
fn a_root_whose_references_all_resolve_is_self_contained_chirho() {
    let verdict_chirho = verify_tenant_self_containment_chirho(
        &[
            reference_chirho("app-log-chirho", 1, "aaa"),
            reference_chirho("effect-log-chirho", 7, "bbb"),
        ],
        &resolver_chirho(&["aaa", "bbb", "unused-ccc"]),
    );
    assert!(verdict_chirho.is_self_contained_over_evidence_chirho());
    assert_eq!(verdict_chirho.references_checked_chirho, 2);
}

#[test]
fn a_dangling_reference_is_named_with_its_log_and_seq_chirho() {
    // An operator repairing a root needs the SITE, not just the missing hash.
    let verdict_chirho = verify_tenant_self_containment_chirho(
        &[
            reference_chirho("app-log-chirho", 1, "aaa"),
            reference_chirho("effect-log-chirho", 42, "missing-bbb"),
        ],
        &resolver_chirho(&["aaa"]),
    );
    assert!(!verdict_chirho.is_self_contained_over_evidence_chirho());
    assert_eq!(
        verdict_chirho.refusals_chirho,
        vec![SelfContainmentRefusalChirho::DanglingReferenceChirho {
            log_name_chirho: "effect-log-chirho".to_string(),
            seq_chirho: 42,
            hash_chirho: "missing-bbb".to_string(),
        }]
    );
}

#[test]
fn an_object_that_resolves_elsewhere_is_still_dangling_here_chirho() {
    // THE DISTINCTION THE VERIFIER EXISTS FOR. This resolver is tenant-scoped: it does not know about
    // a sibling tenant's root or a shared CAS. A resolver answering the GLOBAL question would make
    // this verifier pass on exactly the roots it exists to catch — the ones that look fine until they
    // are moved to another machine.
    let sibling_has_it_chirho = resolver_chirho(&[]); // this tenant has nothing
    let verdict_chirho = verify_tenant_self_containment_chirho(
        &[reference_chirho(
            "app-log-chirho",
            3,
            "lives-in-sibling-root",
        )],
        &sibling_has_it_chirho,
    );
    assert!(!verdict_chirho.is_self_contained_over_evidence_chirho());
    assert_eq!(verdict_chirho.refusals_chirho.len(), 1);
}

#[test]
fn a_green_over_zero_references_is_not_a_preliminary_migration_check_chirho() {
    // Vacuity guard. "No refusals" is trivially true of an empty list, and a caller reading only a
    // boolean could not tell that apart from a root that was actually checked.
    let verdict_chirho = verify_tenant_self_containment_chirho(&[], &resolver_chirho(&["aaa"]));
    assert!(verdict_chirho.refusals_chirho.is_empty(), "nothing dangles");
    assert!(
        !verdict_chirho.is_self_contained_over_evidence_chirho(),
        "but zero references checked is not a self-containment claim"
    );
    assert_eq!(verdict_chirho.references_checked_chirho, 0);
}

#[test]
fn every_site_is_reported_not_every_distinct_hash_chirho() {
    // One missing object named from three logs is three repair sites. Collapsing duplicates would
    // tell an operator to fix one thing and leave two references broken.
    let verdict_chirho = verify_tenant_self_containment_chirho(
        &[
            reference_chirho("log-a-chirho", 1, "missing"),
            reference_chirho("log-b-chirho", 2, "missing"),
            reference_chirho("log-c-chirho", 3, "missing"),
        ],
        &resolver_chirho(&[]),
    );
    assert_eq!(
        verdict_chirho.refusals_chirho.len(),
        3,
        "three sites reference the same missing object; all three need repair"
    );
    assert_eq!(verdict_chirho.references_checked_chirho, 3);
}

#[test]
fn refusals_preserve_input_order_so_reports_are_stable_chirho() {
    let verdict_chirho = verify_tenant_self_containment_chirho(
        &[
            reference_chirho("log-z-chirho", 9, "gone-1"),
            reference_chirho("log-a-chirho", 1, "present"),
            reference_chirho("log-m-chirho", 5, "gone-2"),
        ],
        &resolver_chirho(&["present"]),
    );
    let hashes_chirho = verdict_chirho
        .refusals_chirho
        .iter()
        .map(|r_chirho| match r_chirho {
            SelfContainmentRefusalChirho::DanglingReferenceChirho { hash_chirho, .. } => {
                hash_chirho.as_str()
            }
            // This arm exercises the ONE-ROOT form, which cannot produce the source-compared
            // variant. Named rather than wildcarded so a future variant fails here loudly.
            SelfContainmentRefusalChirho::LostAgainstSourceChirho { .. } => {
                unreachable!("the one-root verifier has no source to compare against")
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(hashes_chirho, vec!["gone-1", "gone-2"]);
}

#[test]
fn source_compared_containment_separates_lost_from_never_an_object_chirho() {
    use crate::self_containment_chirho::verify_tenant_self_containment_against_source_chirho;
    // THE MEASUREMENT THAT FORCED THIS, on a live drill root: 79 of 95 tokens in a HEALTHY serving
    // root did not resolve — every one a pubkey, token hash, principal hash or idempotency digest,
    // while every field naming a real object resolved 100%. The one-root form must refuse all 79,
    // because without a source it cannot tell them from lost objects. With a source it can, and only
    // one of the three cases is a fault.
    let references_chirho = vec![
        reference_chirho("app-log-chirho", 1, "carried-object"), // resolves HERE
        reference_chirho("app-log-chirho", 2, "lost-object"),    // at SOURCE only -> the fault
        reference_chirho("identities-chirho", 3, "a-pubkey"),    // NOWHERE -> not a reference
    ];
    let verdict_chirho = verify_tenant_self_containment_against_source_chirho(
        &references_chirho,
        &resolver_chirho(&["carried-object"]),
        &resolver_chirho(&["carried-object", "lost-object"]),
    );

    assert_eq!(
        verdict_chirho.verdict_chirho.refusals_chirho,
        vec![SelfContainmentRefusalChirho::LostAgainstSourceChirho {
            log_name_chirho: "app-log-chirho".to_owned(),
            seq_chirho: 2,
            hash_chirho: "lost-object".to_owned(),
        }],
        "exactly the object the source still has and the target does not"
    );
    assert_eq!(
        verdict_chirho.unresolved_anywhere_chirho, 1,
        "the token that is not a CAS reference is COUNTED, so an operator can see it, and is not a \
         refusal, because refusing it refuses every public key in the root"
    );
    assert_eq!(
        verdict_chirho.verdict_chirho.references_checked_chirho, 2,
        "only tokens the SOURCE resolved count as evidence — a pubkey is not a reference checked"
    );

    // AND THE VACUITY GUARD MUST SURVIVE THE CHANGE. A target compared against a source that
    // resolves nothing has proven nothing, and must not pass by having nothing to lose.
    let vacuous_chirho = verify_tenant_self_containment_against_source_chirho(
        &references_chirho,
        &resolver_chirho(&[]),
        &resolver_chirho(&[]),
    );
    assert!(
        !vacuous_chirho
            .verdict_chirho
            .is_self_contained_over_evidence_chirho(),
        "zero references resolved at the source is not a clearance"
    );
    assert_eq!(vacuous_chirho.unresolved_anywhere_chirho, 3);
}
