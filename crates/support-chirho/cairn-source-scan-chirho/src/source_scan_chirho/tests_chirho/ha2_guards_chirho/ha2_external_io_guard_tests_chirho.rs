// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

fn brace_delta_chirho(text_chirho: &str) -> isize {
    text_chirho.matches('{').count() as isize - text_chirho.matches('}').count() as isize
}

const APPEND_LOCK_EXTERNAL_IO_MARKERS_CHIRHO: &[&str] = &[
    "create_stripe_transfer_chirho(",
    "call_email_provider_chirho(",
    "reqwest::blocking",
    "ureq::",
    "SmtpTransport",
    "lettre::",
    ".send_form(",
    ".call(",
    "run_net_request_with_private_headers_chirho(",
    "send_crm_email_chirho(",
];

const APPEND_LOCK_SCOPE_MARKERS_CHIRHO: &[&str] = &[
    "with_append_log_lock_chirho(",
    "with_ledger_authority_lock_chirho(",
    "with_gate1_authority_scope_chirho(",
    "with_resource_policy_authority_scope_chirho(",
    // Added ahead of any migration, per the adversarial money-path audit. These lists are keyed on
    // LITERAL HELPER NAMES, so a call site that moves to a helper absent from the list silently
    // leaves the guard's view -- the guard stays GREEN while covering less. Listing the elected
    // helpers BEFORE any code moves means coverage cannot be lost by the move.
    "with_reused_or_issued_elected_writer_fence_chirho(",
    "with_head_transition_scope_chirho(",
];

fn append_lock_marker_starts_pending_scope_chirho(trimmed_chirho: &str) -> bool {
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

fn append_lock_external_io_sites_chirho() -> Vec<String> {
    let mut sites_chirho = Vec::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let rel_chirho = workspace_relative_chirho(&path_chirho);
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let production_chirho = production_text_chirho(&text_chirho);
        sites_chirho.extend(append_lock_external_io_sites_in_text_chirho(
            &rel_chirho,
            &production_chirho,
        ));
    }
    sites_chirho.sort();
    sites_chirho
}

fn append_lock_external_io_sites_in_text_chirho(
    rel_chirho: &str,
    text_chirho: &str,
) -> Vec<String> {
    let mut sites_chirho = Vec::new();
    let mut in_append_lock_chirho = false;
    let mut depth_chirho = 0isize;
    let mut saw_lock_body_chirho = false;
    let mut pending_lock_scope_chirho = false;
    for (line_index_chirho, line_chirho) in text_chirho.lines().enumerate() {
        let trimmed_chirho = line_chirho.trim();
        if APPEND_LOCK_SCOPE_MARKERS_CHIRHO
            .iter()
            .any(|marker_chirho| trimmed_chirho.contains(marker_chirho))
        {
            if trimmed_chirho.contains('{') {
                in_append_lock_chirho = true;
                depth_chirho = 0;
                saw_lock_body_chirho = false;
            } else {
                pending_lock_scope_chirho =
                    append_lock_marker_starts_pending_scope_chirho(trimmed_chirho);
            }
        }
        if pending_lock_scope_chirho && trimmed_chirho.contains('{') {
            in_append_lock_chirho = true;
            depth_chirho = 0;
            saw_lock_body_chirho = false;
            pending_lock_scope_chirho = false;
        }
        if in_append_lock_chirho {
            for marker_chirho in APPEND_LOCK_EXTERNAL_IO_MARKERS_CHIRHO {
                if trimmed_chirho.contains(marker_chirho) {
                    sites_chirho.push(format!(
                        "{rel_chirho}:{}:{marker_chirho}",
                        line_index_chirho + 1
                    ));
                }
            }
            depth_chirho += brace_delta_chirho(trimmed_chirho);
            saw_lock_body_chirho |= trimmed_chirho.contains('{');
            if saw_lock_body_chirho && depth_chirho <= 0 {
                in_append_lock_chirho = false;
            }
        }
        if pending_lock_scope_chirho && !trimmed_chirho.is_empty() && trimmed_chirho.ends_with(';')
        {
            pending_lock_scope_chirho = false;
        }
    }
    sites_chirho
}

#[test]
fn ha2_external_io_guard_catches_sync_io_inside_append_lock_chirho() {
    let text_chirho = r#"
        fn probe_chirho(root_chirho: &Path) -> Result<()> {
            seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
                call_email_provider_chirho(root_chirho, b"body")?;
                let _response_chirho = reqwest::blocking::get(url_chirho)?;
                Ok(())
            })?;
            Ok(())
        }
    "#;
    let sites_chirho = append_lock_external_io_sites_in_text_chirho("probe.rs", text_chirho);
    assert!(
        sites_chirho
            .iter()
            .any(|site_chirho| site_chirho.contains("call_email_provider_chirho(")),
        "call_email_provider_chirho under append lock must be caught: {sites_chirho:?}"
    );
    assert!(
        sites_chirho
            .iter()
            .any(|site_chirho| site_chirho.contains("reqwest::blocking")),
        "reqwest::blocking under append lock must be caught: {sites_chirho:?}"
    );
}

#[test]
fn ha2_external_io_guard_catches_sync_io_inside_ledger_authority_lock_chirho() {
    let text_chirho = r#"
        fn probe_chirho(root_chirho: &Path) -> Result<()> {
            ledger_chirho::with_ledger_authority_lock_chirho(root_chirho, |_authority_chirho| {
                create_stripe_transfer_chirho(root_chirho)?;
                Ok(())
            })?;
            Ok(())
        }
    "#;
    let sites_chirho = append_lock_external_io_sites_in_text_chirho("probe.rs", text_chirho);
    assert!(
        sites_chirho
            .iter()
            .any(|site_chirho| site_chirho.contains("create_stripe_transfer_chirho(")),
        "create_stripe_transfer_chirho under ledger authority lock must be caught: {sites_chirho:?}"
    );
}

#[test]
fn ha2_external_io_guard_catches_sync_io_inside_gate1_authority_scope_chirho() {
    let text_chirho = r#"
        fn probe_chirho(root_chirho: &Path) -> Result<()> {
            head_commit_chirho::with_gate1_authority_scope_chirho(root_chirho, |_fence_chirho| {
                create_stripe_transfer_chirho(root_chirho)?;
                Ok(())
            })?;
            Ok(())
        }
    "#;
    let sites_chirho = append_lock_external_io_sites_in_text_chirho("probe.rs", text_chirho);
    assert!(
        sites_chirho
            .iter()
            .any(|site_chirho| site_chirho.contains("create_stripe_transfer_chirho(")),
        "create_stripe_transfer_chirho under Gate 1 authority scope must be caught: {sites_chirho:?}"
    );
}

#[test]
fn ha2_external_io_guard_catches_sync_io_inside_resource_policy_authority_scope_chirho() {
    let text_chirho = r#"
        fn probe_chirho(root_chirho: &Path) -> Result<()> {
            resource_chirho::with_resource_policy_authority_scope_chirho(root_chirho, "app", |_fence_chirho| {
                create_stripe_transfer_chirho(root_chirho)?;
                Ok(())
            })?;
            Ok(())
        }
    "#;
    let sites_chirho = append_lock_external_io_sites_in_text_chirho("probe.rs", text_chirho);
    assert!(
        sites_chirho
            .iter()
            .any(|site_chirho| site_chirho.contains("create_stripe_transfer_chirho(")),
        "create_stripe_transfer_chirho under resource policy authority scope must be caught: {sites_chirho:?}"
    );
}

#[test]
fn ha2_external_io_guard_does_not_extend_from_braceless_scope_marker_chirho() {
    let text_chirho = r#"
        fn wrapper_chirho(root_chirho: &Path) -> Result<()> {
            || writer_head_chirho::with_gate1_authority_scope_chirho(root_chirho, action_chirho),
            {
                create_stripe_transfer_chirho(root_chirho)?;
            }
            Ok(())
        }
    "#;
    assert!(
        append_lock_external_io_sites_in_text_chirho("probe.rs", text_chirho).is_empty(),
        "brace-less authority-scope marker expressions must not extend into a later unrelated block"
    );
}

#[test]
fn ha2_external_io_guard_does_not_extend_past_fallible_lock_close_chirho() {
    let text_chirho = r#"
        fn probe_chirho(root_chirho: &Path) -> Result<()> {
            seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
                Ok(())
            })?;
            call_email_provider_chirho(root_chirho, b"body")?;
            let _response_chirho = reqwest::blocking::get(url_chirho)?;
            Ok(())
        }
    "#;
    assert!(
        append_lock_external_io_sites_in_text_chirho("probe.rs", text_chirho).is_empty(),
        "sync IO after a fallible append-lock closure must not be treated as inside the lock"
    );
}

#[test]
fn ha2_external_io_under_append_lock_debt_is_seeded_and_cannot_grow_chirho() {
    let expected_chirho: BTreeSet<String> = [].into_iter().map(str::to_string).collect();
    let actual_chirho = append_lock_external_io_sites_chirho()
        .into_iter()
        .map(|site_chirho| {
            let mut parts_chirho = site_chirho.splitn(3, ':');
            let file_chirho = parts_chirho.next().unwrap();
            let _line_chirho = parts_chirho.next().unwrap();
            let marker_chirho = parts_chirho.next().unwrap();
            format!("{file_chirho}:{marker_chirho}")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_chirho,
        expected_chirho,
        "HA2 external IO under append lock debt changed; all known sync external IO has been moved out of append locks, and any new IO-under-lock site must be reviewed: {:?}",
        append_lock_external_io_sites_chirho()
    );
}
