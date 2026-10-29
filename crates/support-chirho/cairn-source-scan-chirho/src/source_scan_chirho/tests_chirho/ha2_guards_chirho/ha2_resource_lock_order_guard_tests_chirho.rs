// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

const APPEND_LOCK_SCOPE_MARKERS_CHIRHO: &[&str] = &[
    "with_append_log_lock_chirho(",
    "with_ledger_authority_lock_chirho(",
    "with_gate1_authority_scope_chirho(",
    // Added ahead of any migration, per the adversarial money-path audit: these lists are keyed on
    // LITERAL HELPER NAMES, so a call site moving to an unlisted helper silently leaves the guard's
    // view while the guard stays GREEN.
    // NOT added here: with_resource_policy_authority_scope_chirho. Its sibling external-IO list
    // carries it and this one must not -- this guard asserts the resource-policy named lock stays
    // OUTSIDE authority scopes, so listing the resource-policy scope itself makes the check
    // self-contradictory. The two lists differ BY INTENT, not by drift.
    "with_reused_or_issued_elected_writer_fence_chirho(",
    "with_head_transition_scope_chirho(",
];

fn authority_marker_starts_pending_scope_chirho(trimmed_chirho: &str) -> bool {
    if trimmed_chirho.starts_with("||") {
        return false;
    }
    APPEND_LOCK_SCOPE_MARKERS_CHIRHO
        .iter()
        .any(|marker_chirho| {
            trimmed_chirho.starts_with(marker_chirho)
                || trimmed_chirho.contains(&format!("::{marker_chirho}"))
        })
}

fn brace_delta_chirho(text_chirho: &str) -> isize {
    text_chirho.matches('{').count() as isize - text_chirho.matches('}').count() as isize
}

fn resource_policy_named_lock_inside_authority_scope_sites_chirho() -> Vec<String> {
    let mut sites_chirho = Vec::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let rel_chirho = workspace_relative_chirho(&path_chirho);
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let production_chirho = production_text_chirho(&text_chirho);
        sites_chirho.extend(
            resource_policy_named_lock_inside_authority_scope_sites_in_text_chirho(
                &rel_chirho,
                &production_chirho,
            ),
        );
    }
    sites_chirho.sort();
    sites_chirho
}

fn resource_policy_named_lock_inside_authority_scope_sites_in_text_chirho(
    rel_chirho: &str,
    text_chirho: &str,
) -> Vec<String> {
    let mut sites_chirho = Vec::new();
    let mut in_authority_scope_chirho = false;
    let mut depth_chirho = 0isize;
    let mut saw_scope_body_chirho = false;
    let mut pending_authority_scope_chirho = false;
    for (line_index_chirho, line_chirho) in text_chirho.lines().enumerate() {
        let trimmed_chirho = line_chirho.trim();
        if APPEND_LOCK_SCOPE_MARKERS_CHIRHO
            .iter()
            .any(|marker_chirho| trimmed_chirho.contains(marker_chirho))
        {
            if trimmed_chirho.contains('{') {
                in_authority_scope_chirho = true;
                depth_chirho = 0;
                saw_scope_body_chirho = false;
            } else {
                pending_authority_scope_chirho =
                    authority_marker_starts_pending_scope_chirho(trimmed_chirho);
            }
        }
        if pending_authority_scope_chirho && trimmed_chirho.contains('{') {
            in_authority_scope_chirho = true;
            depth_chirho = 0;
            saw_scope_body_chirho = false;
            pending_authority_scope_chirho = false;
        }
        if in_authority_scope_chirho {
            let raw_resource_named_lock_chirho = trimmed_chirho.contains("with_named_lock_chirho(")
                && trimmed_chirho.contains("resource-policy/");
            let resource_authority_wrapper_chirho =
                trimmed_chirho.contains("with_resource_policy_authority_scope_chirho(");
            if raw_resource_named_lock_chirho || resource_authority_wrapper_chirho {
                sites_chirho.push(format!(
                    "{rel_chirho}:{}:resource-policy-named-lock-inside-authority-scope: {trimmed_chirho}",
                    line_index_chirho + 1
                ));
            }
            depth_chirho += brace_delta_chirho(trimmed_chirho);
            saw_scope_body_chirho |= trimmed_chirho.contains('{');
            if saw_scope_body_chirho && depth_chirho <= 0 {
                in_authority_scope_chirho = false;
            }
        }
        if pending_authority_scope_chirho
            && !trimmed_chirho.is_empty()
            && trimmed_chirho.ends_with(';')
        {
            pending_authority_scope_chirho = false;
        }
    }
    sites_chirho
}

#[test]
fn ha2_resource_policy_named_lock_stays_outside_authority_scopes_chirho() {
    let sites_chirho = resource_policy_named_lock_inside_authority_scope_sites_chirho();
    assert!(
        sites_chirho.is_empty(),
        "resource policy named lock must stay OUTER to writer-fence/append authority scopes: {sites_chirho:?}"
    );
}

#[test]
fn ha2_resource_policy_lock_order_guard_catches_gate1_reverse_order_chirho() {
    let text_chirho = r#"
        fn probe_chirho(root_chirho: &Path) -> Result<()> {
            writer_head_chirho::with_gate1_authority_scope_chirho(root_chirho, |_fence_chirho| {
                seqlog_chirho::with_named_lock_chirho(root_chirho, "resource-policy/app", || Ok(()))
            })?;
            Ok(())
        }
    "#;
    let sites_chirho = resource_policy_named_lock_inside_authority_scope_sites_in_text_chirho(
        "probe.rs",
        text_chirho,
    );
    assert!(
        !sites_chirho.is_empty(),
        "with_gate1_authority_scope -> resource-policy named lock inversion must be caught"
    );
}

#[test]
fn ha2_resource_policy_lock_order_guard_catches_append_reverse_order_chirho() {
    let text_chirho = r#"
        fn probe_chirho(root_chirho: &Path) -> Result<()> {
            seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
                seqlog_chirho::with_named_lock_chirho(root_chirho, "resource-policy/app", || Ok(()))
            })?;
            Ok(())
        }
    "#;
    let sites_chirho = resource_policy_named_lock_inside_authority_scope_sites_in_text_chirho(
        "probe.rs",
        text_chirho,
    );
    assert!(
        !sites_chirho.is_empty(),
        "append-lock -> resource-policy named lock inversion must be caught"
    );
}

#[test]
fn ha2_resource_policy_lock_order_guard_does_not_extend_from_braceless_marker_chirho() {
    let text_chirho = r#"
        fn wrapper_chirho(root_chirho: &Path) -> Result<()> {
            || writer_head_chirho::with_gate1_authority_scope_chirho(root_chirho, action_chirho),
            {
                seqlog_chirho::with_named_lock_chirho(root_chirho, "resource-policy/app", || Ok(()))?;
            }
            Ok(())
        }
    "#;
    let sites_chirho = resource_policy_named_lock_inside_authority_scope_sites_in_text_chirho(
        "probe.rs",
        text_chirho,
    );
    assert!(
        sites_chirho.is_empty(),
        "brace-less authority-scope marker expressions must not extend into a later unrelated resource-policy named lock"
    );
}
