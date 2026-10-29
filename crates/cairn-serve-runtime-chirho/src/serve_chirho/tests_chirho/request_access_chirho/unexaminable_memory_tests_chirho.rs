// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The shared JSONL absence brick's memory arms: a log seen present keeps that knowledge through a fault and its later
//! disappearance, a permission lost in place on a warmed log is never answered from what was cached, the legacy keys
//! K1 retired stay retired under a revocations-log fault, and every refusal leaves `private, no-store` without naming
//! the log, the path or the fault. Over a real local server, except K1's arm, which drives the production handler.
//! Tasklist: `spec-chirho/tasklists-chirho/26-10-08_23-20-tasklist-jsonl_absence_cache_door-chirho.md`.

use super::limited_key_fixture_chirho::{
    get_route_chirho, KeyedTenantChirho, OpeningsChirho, VIEW_ROUTE_CHIRHO,
};
use super::unexaminable_key_log_tests_chirho::{
    bounded_request_chirho, browser_session_chirho, key_list_chirho, key_root_chirho,
    root_at_chirho, with_server_chirho, AnswerChirho, REVOCATIONS_LOG_CHIRHO, SECRET_CHIRHO,
    TEMPERATURES_CHIRHO, TOKEN_LOG_CHIRHO,
};
use super::unexaminable_log_tests_chirho::{
    apply_fault_chirho, bounded_call_chirho, deploy_app_chirho, judge_cases_chirho, restore_chirho,
    CaseChirho, ACCESS_LOG_CHIRHO, FAULTS_CHIRHO, GUARDED_APP_CHIRHO, ROUTE_CHIRHO,
};
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Words a refusal must never carry: the log's name, the fault, or the engine's own refusal text.
const DETAIL_WORDS_CHIRHO: [&str; 6] = [
    ".jsonl",
    "link",
    "pipe",
    "directory",
    "never read as empty",
    "now missing",
];

/// A refusal is acceptable only as one: not 2xx, not hung, leaving `private, no-store`, and naming no detail.
fn private_detail_safe_refusal_chirho(
    answer_chirho: Option<&AnswerChirho>,
    root_chirho: &Path,
) -> (String, bool) {
    let Some(answer_chirho) = answer_chirho else {
        return ("hung".to_string(), false);
    };
    let leaked_chirho: Vec<&str> = DETAIL_WORDS_CHIRHO
        .iter()
        .copied()
        .filter(|word_chirho| answer_chirho.body_chirho.contains(word_chirho))
        .collect();
    let root_named_chirho = answer_chirho
        .body_chirho
        .contains(&root_chirho.display().to_string());
    let private_chirho = answer_chirho.cache_control_chirho.as_deref() == Some("private, no-store");
    let refused_chirho = !(200..300).contains(&answer_chirho.status_chirho);
    (
        format!(
            "{} cache={} body={}{}{}",
            answer_chirho.status_chirho,
            answer_chirho
                .cache_control_chirho
                .as_deref()
                .unwrap_or("<none>"),
            answer_chirho.body_chirho.lines().next().unwrap_or_default(),
            if leaked_chirho.is_empty() {
                String::new()
            } else {
                format!(" [DETAIL {leaked_chirho:?}]")
            },
            if root_named_chirho {
                " [ROOT NAMED]"
            } else {
                ""
            }
        ),
        refused_chirho && private_chirho && leaked_chirho.is_empty() && !root_named_chirho,
    )
}

fn get_chirho(
    addr_chirho: &str,
    path_chirho: &str,
    cookie_chirho: Option<&str>,
) -> Option<AnswerChirho> {
    let headers_chirho: Vec<(&str, &str)> = cookie_chirho
        .map(|cookie_chirho| vec![("cookie", cookie_chirho)])
        .unwrap_or_default();
    bounded_request_chirho(addr_chirho, "GET", path_chirho, &headers_chirho, b"")
}

/// SEEN PRESENT, THEN FAULTED, THEN MISSING, STILL REFUSES; RESTORED, RECOVERS. For every fault, on three logs read
/// warm over a real server: her key list (the token view), a revoked session (the revocations view), and an anonymous
/// visitor to a signed-in-only app (the access policy, through the verified-view cache). After the fault is in place,
/// and again after the path is left empty, each refuses: privately, naming no detail. Once the regular log is back,
/// each answers as it did. The memory's lifetime is the bounded view slot or cache entry in this process.
///
/// MIGRATION PATH: a 2xx after the disappearance means the fault reset what was seen present, and the missing log was
/// read as empty: no keys, no revocations, no policy (public).
#[test]
fn a_log_seen_present_then_faulted_then_missing_still_refuses_chirho() {
    let mut cases_chirho: Vec<CaseChirho> = Vec::new();
    let mut record_chirho =
        |case_chirho: String, answer_chirho: String, acceptable_chirho: bool| {
            cases_chirho.push(CaseChirho {
                case_chirho,
                answer_chirho,
                acceptable_chirho,
            })
        };
    let page_chirho = format!("/app-chirho/{GUARDED_APP_CHIRHO}/{ROUTE_CHIRHO}");
    for fault_chirho in FAULTS_CHIRHO {
        // The token view: her key list.
        let (root_chirho, cookie_chirho, _key_chirho) =
            key_root_chirho(&format!("memory-tokens-{fault_chirho:?}"));
        let log_chirho = root_chirho.join(TOKEN_LOG_CHIRHO);
        let saved_chirho = std::fs::read(&log_chirho).unwrap();
        with_server_chirho(&root_chirho, |addr_chirho| {
            let warm_chirho = key_list_chirho(addr_chirho, &cookie_chirho);
            record_chirho(
                format!("tokens {fault_chirho:?}, warm (control)"),
                warm_chirho.clone(),
                warm_chirho == "200 keys=1",
            );
            apply_fault_chirho(&root_chirho, &log_chirho, fault_chirho, Some(&saved_chirho));
            for step_chirho in ["faulted", "missing"] {
                if step_chirho == "missing" {
                    restore_chirho(&log_chirho, fault_chirho, None);
                }
                let (answer_chirho, acceptable_chirho) = private_detail_safe_refusal_chirho(
                    get_chirho(
                        addr_chirho,
                        "/auth-chirho/keys-chirho",
                        Some(&cookie_chirho),
                    )
                    .as_ref(),
                    &root_chirho,
                );
                record_chirho(
                    format!("tokens {fault_chirho:?}, {step_chirho}"),
                    answer_chirho,
                    acceptable_chirho,
                );
            }
            std::fs::write(&log_chirho, &saved_chirho).unwrap();
            let restored_chirho = key_list_chirho(addr_chirho, &cookie_chirho);
            record_chirho(
                format!("tokens {fault_chirho:?}, restored (control)"),
                restored_chirho.clone(),
                restored_chirho == "200 keys=1",
            );
        });
        let _ = std::fs::remove_dir_all(&root_chirho);

        // The revocations view: a revoked session.
        let root_chirho = temp_root_chirho(&format!("memory-revocations-{fault_chirho:?}"));
        let alice_chirho = identity_chirho::register_identity_with_credential_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
            SECRET_CHIRHO,
        )
        .unwrap()
        .principal_chirho;
        let (revoked_cookie_chirho, revoked_token_chirho) =
            browser_session_chirho(&root_chirho, &alice_chirho);
        identity_chirho::revoke_session_token_chirho(
            &root_chirho,
            &alice_chirho,
            &revoked_token_chirho,
            &alice_chirho,
            "measurement",
        )
        .unwrap();
        let log_chirho = root_chirho.join(REVOCATIONS_LOG_CHIRHO);
        let saved_chirho = std::fs::read(&log_chirho).unwrap();
        with_server_chirho(&root_chirho, |addr_chirho| {
            let warm_chirho = key_list_chirho(addr_chirho, &revoked_cookie_chirho);
            record_chirho(
                format!("revocations {fault_chirho:?}, warm (control)"),
                warm_chirho.clone(),
                warm_chirho.starts_with("401"),
            );
            apply_fault_chirho(&root_chirho, &log_chirho, fault_chirho, Some(&saved_chirho));
            for step_chirho in ["faulted", "missing"] {
                if step_chirho == "missing" {
                    restore_chirho(&log_chirho, fault_chirho, None);
                }
                let (answer_chirho, acceptable_chirho) = private_detail_safe_refusal_chirho(
                    get_chirho(
                        addr_chirho,
                        "/auth-chirho/keys-chirho",
                        Some(&revoked_cookie_chirho),
                    )
                    .as_ref(),
                    &root_chirho,
                );
                record_chirho(
                    format!("revocations {fault_chirho:?}, {step_chirho}"),
                    answer_chirho,
                    acceptable_chirho,
                );
            }
            std::fs::write(&log_chirho, &saved_chirho).unwrap();
            let restored_chirho = key_list_chirho(addr_chirho, &revoked_cookie_chirho);
            record_chirho(
                format!("revocations {fault_chirho:?}, restored (control)"),
                restored_chirho.clone(),
                restored_chirho.starts_with("401"),
            );
        });
        let _ = std::fs::remove_dir_all(&root_chirho);

        // The access policy, through the verified-view cache: an anonymous visitor to a signed-in-only app.
        let root_chirho = temp_root_chirho(&format!("memory-access-{fault_chirho:?}"));
        deploy_app_chirho(&root_chirho, GUARDED_APP_CHIRHO, true);
        let log_chirho = root_chirho.join(ACCESS_LOG_CHIRHO);
        let saved_chirho = std::fs::read(&log_chirho).unwrap();
        with_server_chirho(&root_chirho, |addr_chirho| {
            let warm_chirho = get_chirho(addr_chirho, &page_chirho, None)
                .map(|answer_chirho| answer_chirho.status_chirho);
            record_chirho(
                format!("access {fault_chirho:?}, warm (control)"),
                format!("{warm_chirho:?}"),
                warm_chirho == Some(401),
            );
            apply_fault_chirho(&root_chirho, &log_chirho, fault_chirho, Some(&saved_chirho));
            for step_chirho in ["faulted", "missing"] {
                if step_chirho == "missing" {
                    restore_chirho(&log_chirho, fault_chirho, None);
                }
                let (answer_chirho, acceptable_chirho) = private_detail_safe_refusal_chirho(
                    get_chirho(addr_chirho, &page_chirho, None).as_ref(),
                    &root_chirho,
                );
                record_chirho(
                    format!("access {fault_chirho:?}, {step_chirho}"),
                    answer_chirho,
                    acceptable_chirho,
                );
            }
            std::fs::write(&log_chirho, &saved_chirho).unwrap();
            let restored_chirho = get_chirho(addr_chirho, &page_chirho, None)
                .map(|answer_chirho| answer_chirho.status_chirho);
            record_chirho(
                format!("access {fault_chirho:?}, restored (control)"),
                format!("{restored_chirho:?}"),
                restored_chirho == Some(401),
            );
        });
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
    judge_cases_chirho(&cases_chirho);
}

/// PERMISSION LOST IN PLACE ON A WARMED LOG IS NEVER ANSWERED FROM WHAT WAS CACHED. A signed-in visitor reads a
/// signed-in-only app (200, the policy now cached), and her key list answers (200, the token view warm). Each log is
/// then made unreadable on the same inode, with the same length and modification time, and the denied open is proven
/// first. Each road must now refuse, privately and naming no detail; a cached 200 would turn a failed open into usable
/// data. With the mode restored, each answers 200 again.
#[test]
fn permission_lost_in_place_on_a_warmed_log_refuses_chirho() {
    use std::os::unix::fs::MetadataExt;
    let mut cases_chirho: Vec<CaseChirho> = Vec::new();
    let mut record_chirho =
        |case_chirho: String, answer_chirho: String, acceptable_chirho: bool| {
            cases_chirho.push(CaseChirho {
                case_chirho,
                answer_chirho,
                acceptable_chirho,
            })
        };
    let lose_in_place_chirho = |log_chirho: &Path| {
        let before_chirho = std::fs::symlink_metadata(log_chirho).unwrap();
        std::fs::set_permissions(log_chirho, std::fs::Permissions::from_mode(0o000)).unwrap();
        let after_chirho = std::fs::symlink_metadata(log_chirho).unwrap();
        assert_eq!(
            (
                before_chirho.ino(),
                before_chirho.len(),
                before_chirho.mtime(),
                before_chirho.mtime_nsec()
            ),
            (
                after_chirho.ino(),
                after_chirho.len(),
                after_chirho.mtime(),
                after_chirho.mtime_nsec()
            ),
            "the same inode, length and modification time"
        );
        assert_eq!(
            std::fs::File::open(log_chirho).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied,
            "the fault must actually deny the open"
        );
    };
    let regain_chirho = |log_chirho: &Path| {
        std::fs::set_permissions(log_chirho, std::fs::Permissions::from_mode(0o600)).unwrap();
    };

    // The access policy, cached: a signed-in visitor.
    let root_chirho = temp_root_chirho("permission-access");
    deploy_app_chirho(&root_chirho, GUARDED_APP_CHIRHO, true);
    let visitor_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
    )
    .unwrap()
    .principal_chirho;
    let (cookie_chirho, _) = browser_session_chirho(&root_chirho, &visitor_chirho);
    let page_chirho = format!("/app-chirho/{GUARDED_APP_CHIRHO}/{ROUTE_CHIRHO}");
    let log_chirho = root_chirho.join(ACCESS_LOG_CHIRHO);
    with_server_chirho(&root_chirho, |addr_chirho| {
        let warm_chirho = get_chirho(addr_chirho, &page_chirho, Some(&cookie_chirho))
            .map(|answer_chirho| answer_chirho.status_chirho);
        record_chirho(
            "access, warm (control)".to_string(),
            format!("{warm_chirho:?}"),
            warm_chirho == Some(200),
        );
        lose_in_place_chirho(&log_chirho);
        let (answer_chirho, acceptable_chirho) = private_detail_safe_refusal_chirho(
            get_chirho(addr_chirho, &page_chirho, Some(&cookie_chirho)).as_ref(),
            &root_chirho,
        );
        record_chirho(
            "access, permission lost in place".to_string(),
            answer_chirho,
            acceptable_chirho,
        );
        regain_chirho(&log_chirho);
        let restored_chirho = get_chirho(addr_chirho, &page_chirho, Some(&cookie_chirho))
            .map(|answer_chirho| answer_chirho.status_chirho);
        record_chirho(
            "access, restored (control)".to_string(),
            format!("{restored_chirho:?}"),
            restored_chirho == Some(200),
        );
    });
    let _ = std::fs::remove_dir_all(&root_chirho);

    // The token view, warm: her key list.
    let (root_chirho, cookie_chirho, _key_chirho) = key_root_chirho("permission-tokens");
    let log_chirho = root_chirho.join(TOKEN_LOG_CHIRHO);
    with_server_chirho(&root_chirho, |addr_chirho| {
        let warm_chirho = key_list_chirho(addr_chirho, &cookie_chirho);
        record_chirho(
            "tokens, warm (control)".to_string(),
            warm_chirho.clone(),
            warm_chirho == "200 keys=1",
        );
        lose_in_place_chirho(&log_chirho);
        let (answer_chirho, acceptable_chirho) = private_detail_safe_refusal_chirho(
            get_chirho(
                addr_chirho,
                "/auth-chirho/keys-chirho",
                Some(&cookie_chirho),
            )
            .as_ref(),
            &root_chirho,
        );
        record_chirho(
            "tokens, permission lost in place".to_string(),
            answer_chirho,
            acceptable_chirho,
        );
        regain_chirho(&log_chirho);
        let restored_chirho = key_list_chirho(addr_chirho, &cookie_chirho);
        record_chirho(
            "tokens, restored (control)".to_string(),
            restored_chirho.clone(),
            restored_chirho == "200 keys=1",
        );
    });
    let _ = std::fs::remove_dir_all(&root_chirho);
    judge_cases_chirho(&cases_chirho);
}

/// THE LEGACY KEYS K1 RETIRED STAY RETIRED under a revocations-log fault. A legacy key issued before the app opted in
/// was retired at opt-in, its session revoked. For every fault, cold (a root never read in this process) and warm, the
/// retired key is still refused on the opened route, and never hung. Restored, it is refused as before.
///
/// MIGRATION PATH: a 2xx means an unexaminable revocations log read as "no revocations" and brought back a key the
/// app's opt-in retired.
#[test]
fn legacy_keys_retired_by_k1_stay_retired_under_a_revocations_fault_chirho() {
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    let mut cases_chirho: Vec<CaseChirho> = Vec::new();
    for fault_chirho in FAULTS_CHIRHO {
        for temperature_chirho in TEMPERATURES_CHIRHO {
            let label_chirho = format!(
                "memory-k1-{temperature_chirho}-{}",
                format!("{fault_chirho:?}").to_lowercase()
            );
            let tenant_chirho =
                KeyedTenantChirho::new_chirho(&label_chirho, OpeningsChirho::NONE_CHIRHO, 1);
            let legacy_chirho = tenant_chirho
                .try_legacy_bearer_chirho(0)
                .expect("a legacy app issues a legacy key");
            // A K1-era root: a legacy client before the app's first opening, which K4 refuses (built through the seam).
            cairn_chirho::oauth_chirho::with_k1_era_opening_chirho(|| {
                tenant_chirho.deploy_chirho(OpeningsChirho::PAGE_CHIRHO, |_| {})
            });
            // The tenant root sits at <platform>/tenants-chirho/<tenant>; a cold case moves the whole platform root.
            let platform_chirho = tenant_chirho
                .root_chirho
                .parent()
                .and_then(Path::parent)
                .unwrap()
                .to_path_buf();
            let inside_chirho = tenant_chirho
                .root_chirho
                .strip_prefix(&platform_chirho)
                .unwrap()
                .to_path_buf();
            let platform_chirho = root_at_chirho(&platform_chirho, temperature_chirho);
            let tenant_root_chirho = platform_chirho.join(inside_chirho);
            let state_chirho =
                super::app_route_fixture_chirho::growth_state_chirho(&tenant_root_chirho);
            let log_chirho = tenant_root_chirho.join(REVOCATIONS_LOG_CHIRHO);
            let saved_chirho = std::fs::read(&log_chirho).unwrap();
            let read_chirho = |state_chirho: &AppStateChirho| {
                let state_chirho = state_chirho.clone();
                let legacy_chirho = legacy_chirho.clone();
                bounded_call_chirho(&runtime_chirho, move || async move {
                    get_route_chirho(&state_chirho, &legacy_chirho, VIEW_ROUTE_CHIRHO)
                        .await
                        .0
                        .as_u16()
                })
                .map_or_else(
                    || "hung".to_string(),
                    |status_chirho| status_chirho.to_string(),
                )
            };
            if temperature_chirho == "warm" {
                let warm_chirho = read_chirho(&state_chirho);
                cases_chirho.push(CaseChirho {
                    case_chirho: format!(
                        "k1 warm {fault_chirho:?}, retired before the fault (control)"
                    ),
                    acceptable_chirho: warm_chirho == "403",
                    answer_chirho: warm_chirho,
                });
            }
            apply_fault_chirho(
                &tenant_root_chirho,
                &log_chirho,
                fault_chirho,
                Some(&saved_chirho),
            );
            let faulted_chirho = read_chirho(&state_chirho);
            cases_chirho.push(CaseChirho {
                case_chirho: format!("k1 {temperature_chirho} {fault_chirho:?}"),
                acceptable_chirho: faulted_chirho != "hung" && !faulted_chirho.starts_with('2'),
                answer_chirho: faulted_chirho,
            });
            restore_chirho(&log_chirho, fault_chirho, Some(&saved_chirho));
            let restored_chirho = read_chirho(&state_chirho);
            cases_chirho.push(CaseChirho {
                case_chirho: format!(
                    "k1 {temperature_chirho} {fault_chirho:?}, restored (control)"
                ),
                acceptable_chirho: restored_chirho == "403",
                answer_chirho: restored_chirho,
            });
            drop(tenant_chirho);
            let _ = std::fs::remove_dir_all(&platform_chirho);
        }
    }
    runtime_chirho.shutdown_timeout(std::time::Duration::from_secs(2));
    judge_cases_chirho(&cases_chirho);
}
