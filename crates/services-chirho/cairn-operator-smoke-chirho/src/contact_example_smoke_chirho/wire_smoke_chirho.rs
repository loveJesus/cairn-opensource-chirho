// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Local HTTP lifecycle for the contact example smoke.

use anyhow::{bail, Result};
use cairn_chirho::{cas_chirho, privacy_chirho, query_chirho};
use std::path::Path;

use super::evidence_chirho::{
    assert_no_contact_pii_chirho, persistent_effect_record_count_chirho, wire_evidence_chirho,
};
use super::http_smoke_chirho::{
    http_body_text_chirho, try_http_get_for_smoke_chirho, try_http_request_for_smoke_chirho,
    unused_local_port_chirho, wait_for_serve_health_chirho,
};
use super::types_chirho::{
    ContactExampleReadEvidenceChirho, ContactExampleRevealEvidenceChirho,
    ContactExampleWireRunChirho, CONTACT_EXAMPLE_REVEAL_EVIDENCE_SCHEMA_CHIRHO,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ContactListMutationFingerprintChirho {
    persistent_effects_chirho: usize,
    volatile_bytes_chirho: u64,
    billing_bytes_chirho: u64,
}

fn path_bytes_chirho(path_chirho: &Path) -> u64 {
    std::fs::metadata(path_chirho)
        .map(|metadata_chirho| metadata_chirho.len())
        .unwrap_or(0)
}

fn top_level_prefix_bytes_chirho(root_chirho: &Path, prefix_chirho: &str) -> Result<u64> {
    let mut bytes_chirho = 0_u64;
    for entry_chirho in std::fs::read_dir(root_chirho)? {
        let entry_chirho = entry_chirho?;
        if !entry_chirho.file_type()?.is_file()
            || !entry_chirho
                .file_name()
                .to_str()
                .is_some_and(|name_chirho| name_chirho.starts_with(prefix_chirho))
        {
            continue;
        }
        bytes_chirho = bytes_chirho
            .checked_add(entry_chirho.metadata()?.len())
            .ok_or_else(|| anyhow::anyhow!("top-level evidence byte count overflow"))?;
    }
    Ok(bytes_chirho)
}

fn contact_list_mutation_fingerprint_chirho(
    root_chirho: &Path,
) -> Result<ContactListMutationFingerprintChirho> {
    Ok(ContactListMutationFingerprintChirho {
        persistent_effects_chirho: persistent_effect_record_count_chirho(root_chirho)?,
        volatile_bytes_chirho: path_bytes_chirho(
            &cairn_chirho::effect_chirho::volatile_effect_records_path_chirho(root_chirho),
        ),
        billing_bytes_chirho: top_level_prefix_bytes_chirho(root_chirho, "billing-")?,
    })
}
pub(super) fn run_contact_example_wire_smoke_chirho(
    root_chirho: &Path,
    owner_chirho: &str,
    owner_bearer_chirho: &str,
    raw_body_chirho: &[u8],
    pii_needles_chirho: &[&str],
) -> Result<ContactExampleWireRunChirho> {
    let (owner_kind_chirho, owner_id_chirho) = owner_chirho
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("owner principal '{owner_chirho}' is not kind/id shaped"))?;
    let port_chirho = unused_local_port_chirho()?;
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let server_chirho = format!("http://{addr_chirho}");
    let root_for_server_chirho = root_chirho.to_path_buf();
    let runtime_chirho = tokio::runtime::Runtime::new()?;
    runtime_chirho.block_on(async {
        let server_task_chirho = tokio::spawn(async move {
            cairn_serve_runtime_chirho::serve_quiet_chirho(
                &root_for_server_chirho,
                port_chirho,
                8,
                String::new(),
            )
            .await
        });
        wait_for_serve_health_chirho(&addr_chirho)?;

        let page_response_chirho =
            try_http_get_for_smoke_chirho(&addr_chirho, "/contact-demo-chirho")?;
        let page_text_chirho = http_body_text_chirho(&page_response_chirho);
        if page_response_chirho.status_chirho != 200
            || !page_text_chirho.contains("hx-post=\"/app-chirho/contact\"")
            || !page_text_chirho.contains("hx-post=\"/app-chirho/contact/contact-list\"")
        {
            bail!("contact demo page did not expose the expected htmx contact routes");
        }
        let page_chirho = wire_evidence_chirho(
            "GET",
            "/contact-demo-chirho",
            &page_response_chirho,
            pii_needles_chirho,
        )?;

        let submit_response_chirho = try_http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/app-chirho/contact",
            &[(
                "content-type",
                "application/x-www-form-urlencoded;charset=UTF-8",
            )],
            raw_body_chirho,
        )?;
        let submit_text_chirho = http_body_text_chirho(&submit_response_chirho);
        if submit_response_chirho.status_chirho != 200
            || !submit_text_chirho.contains("data-contact-chirho=\"received\"")
        {
            bail!("contact submit route did not return the safe received partial");
        }
        let submit_chirho = wire_evidence_chirho(
            "POST",
            "/app-chirho/contact",
            &submit_response_chirho,
            pii_needles_chirho,
        )?;

        let before_list_chirho = contact_list_mutation_fingerprint_chirho(root_chirho)?;
        let list_response_chirho = try_http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/app-chirho/contact/contact-list",
            &[],
            b"",
        )?;
        let list_text_chirho = http_body_text_chirho(&list_response_chirho);
        // The first line pins the refusal IDENTITY and a knowledge line must follow it; the needle
        // clauses witness NON-LEAK independently, so a widened constant cannot stay green in
        // lockstep. The zero-mutation fingerprint below carries the behavioral half of this arm.
        if list_response_chirho.status_chirho != 400
            || !list_text_chirho
                .starts_with(cairn_serve_runtime_chirho::APP_EXECUTION_REFUSAL_BODY_CHIRHO)
            || !list_text_chirho.contains("\nknowledge: ")
            || list_text_chirho.contains("QueryEffectChirho")
            || list_text_chirho.contains("legacy money road")
        {
            bail!("contact list refresh route did not return the opaque app-execution refusal");
        }
        let after_list_chirho = contact_list_mutation_fingerprint_chirho(root_chirho)?;
        let zero_effect_volatile_billing_mutation_chirho = after_list_chirho == before_list_chirho;
        if !zero_effect_volatile_billing_mutation_chirho {
            bail!("refused served contact-list read mutated effect, volatile, or billing evidence");
        }
        let list_refresh_chirho = wire_evidence_chirho(
            "POST",
            "/app-chirho/contact/contact-list",
            &list_response_chirho,
            pii_needles_chirho,
        )?;

        // Workflow: CF6 serve-repoint transition. This direct no-effect read is operator evidence;
        // it is never injected into the served route that refused above.
        let rows_chirho = query_chirho::query_prefix_chirho(root_chirho, "contacts-chirho", 50)?;
        if rows_chirho.len() != 1 {
            bail!("expected one safe contact row, found {}", rows_chirho.len());
        }
        let contact_key_chirho = rows_chirho[0].key_chirho.clone();
        if !contact_key_chirho.starts_with("contacts-chirho/")
            || contact_key_chirho == "contacts-chirho/latest"
        {
            bail!("contact key '{contact_key_chirho}' is not a scoped safe contact key");
        }
        assert_no_contact_pii_chirho(
            "query contact key",
            contact_key_chirho.as_bytes(),
            pii_needles_chirho,
        )?;
        let read_evidence_chirho = vec![
            ContactExampleReadEvidenceChirho::ServedRefusedNoLedgerSourceChirho {
                route_chirho: "/app-chirho/contact/contact-list".to_string(),
                status_chirho: list_response_chirho.status_chirho,
                refusal_chirho: "legacy-money-road-query-effect-chirho".to_string(),
                zero_effect_volatile_billing_mutation_chirho,
            },
            ContactExampleReadEvidenceChirho::OperatorDirectReadChirho {
                operation_chirho: "query-prefix-chirho".to_string(),
                row_count_chirho: rows_chirho.len(),
            },
        ];
        assert_no_contact_pii_chirho(
            "query contact value",
            rows_chirho[0].value_chirho.as_bytes(),
            pii_needles_chirho,
        )?;

        let app_state_path_chirho =
            format!("/app-state-chirho/{owner_kind_chirho}/{owner_id_chirho}/contact");
        let missing_owner_session_response_chirho = try_http_request_for_smoke_chirho(
            &addr_chirho,
            "GET",
            &app_state_path_chirho,
            &[],
            b"",
        )?;
        if missing_owner_session_response_chirho.status_chirho != 401 {
            bail!(
                "owner app-state route without bearer returned {}, expected 401",
                missing_owner_session_response_chirho.status_chirho
            );
        }
        let missing_owner_session_chirho = wire_evidence_chirho(
            "GET",
            &app_state_path_chirho,
            &missing_owner_session_response_chirho,
            pii_needles_chirho,
        )?;

        let app_state_response_chirho = try_http_request_for_smoke_chirho(
            &addr_chirho,
            "GET",
            &app_state_path_chirho,
            &[("authorization", owner_bearer_chirho)],
            b"",
        )?;
        let app_state_text_chirho = http_body_text_chirho(&app_state_response_chirho);
        if app_state_response_chirho.status_chirho != 200
            || !app_state_text_chirho.contains("Reveal private body")
            || !app_state_text_chirho.contains(&contact_key_chirho)
        {
            bail!("owner app-state route did not show the safe contact row controls");
        }
        let app_state_chirho = wire_evidence_chirho(
            "GET",
            &app_state_path_chirho,
            &app_state_response_chirho,
            pii_needles_chirho,
        )?;

        let reveal_path_chirho = format!("{app_state_path_chirho}/reveal-chirho");
        let reveal_body_chirho = format!("key_chirho={contact_key_chirho}");
        let reveal_response_chirho = try_http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &reveal_path_chirho,
            &[
                ("authorization", owner_bearer_chirho),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            reveal_body_chirho.as_bytes(),
        )?;
        let reveal_text_chirho = http_body_text_chirho(&reveal_response_chirho);
        let contains_expected_private_body_chirho = reveal_text_chirho
            .contains("name_chirho=Alice+Example")
            && reveal_text_chirho.contains("email_chirho=alice%40example.com")
            && reveal_text_chirho.contains("message_chirho=Apartment+above+the+bakery");
        if reveal_response_chirho.status_chirho != 200 || !contains_expected_private_body_chirho {
            bail!("owner reveal route did not return the governed private body");
        }
        let reveal_chirho = ContactExampleRevealEvidenceChirho {
            schema_chirho: CONTACT_EXAMPLE_REVEAL_EVIDENCE_SCHEMA_CHIRHO,
            method_chirho: "POST".to_string(),
            path_chirho: reveal_path_chirho,
            status_chirho: reveal_response_chirho.status_chirho,
            body_bytes_chirho: reveal_response_chirho.body_chirho.len(),
            body_chirho: cas_chirho::hash_chirho(&reveal_response_chirho.body_chirho),
            contains_expected_private_body_chirho,
            access_records_chirho: privacy_chirho::load_privacy_access_records_chirho(root_chirho)?
                .len(),
        };

        server_task_chirho.abort();
        let _ = server_task_chirho.await;
        Ok(ContactExampleWireRunChirho {
            server_chirho,
            page_chirho,
            submit_chirho,
            list_refresh_chirho,
            read_evidence_chirho,
            missing_owner_session_chirho,
            app_state_chirho,
            reveal_chirho,
            contact_key_chirho,
        })
    })
}
