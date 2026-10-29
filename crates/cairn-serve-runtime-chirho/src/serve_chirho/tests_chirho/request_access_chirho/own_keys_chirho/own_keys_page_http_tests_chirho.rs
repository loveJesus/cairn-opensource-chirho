// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K3's served Account page: a route holding the owner's-keys card, through the production GET handler, renders the
//! signed-in viewer's own rows to her browser and nothing to a key.
//! Workflow: the owner's keys page (K3),
//! `spec-chirho/workflows-chirho/identity-auth-chirho/own-keys-page-chirho.md`.

use super::own_keys_fixture_chirho::AccountTenantChirho;
use super::*;

fn key_id_chirho(issue_chirho: &oauth_chirho::ScopedTokenIssueChirho) -> String {
    oauth_chirho::scoped_key_id_chirho(&issue_chirho.record_chirho.token_hash_chirho)
}

/// THE ACCOUNT PAGE. User 0 holds two legacy keys and user 1 one. User 0's browser GET of the account route renders
/// her answer: available, her two rows oldest first, never user 1's row, never a key or a key's hash. Her own legacy
/// key on the same route is refused by the owner's-keys door, and the refusal carries none of her rows.
///
/// MIGRATION PATH: user 1's row in her answer means the door read by something other than the host's session
/// principal; a key reading the list means the door admitted a key context; an empty list here means a failure read as
/// "no keys".
#[test]
fn the_account_page_answers_her_own_keys_to_her_browser_and_nothing_to_a_key_chirho() {
    let tenant_chirho = AccountTenantChirho::new_chirho("own-keys-account-page", 2);
    let hers_chirho = [
        tenant_chirho.legacy_key_chirho(0),
        tenant_chirho.legacy_key_chirho(0),
    ];
    let theirs_chirho = tenant_chirho.legacy_key_chirho(1);
    let state_chirho = tenant_chirho.state_chirho();
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let (status_chirho, body_chirho) = tenant_chirho
            .get_account_chirho(&state_chirho, &tenant_chirho.cookie_chirho(0))
            .await;
        assert_eq!(status_chirho, StatusCode::OK, "{body_chirho}");
        let answer_chirho: serde_json::Value = serde_json::from_str(&body_chirho).unwrap();
        assert_eq!(answer_chirho["schema_chirho"], "own-keys-read-v1-chirho");
        assert_eq!(answer_chirho["state_chirho"], "available-chirho");
        let listed_chirho: Vec<String> = answer_chirho["keys_chirho"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row_chirho| row_chirho["key_id_chirho"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            listed_chirho,
            hers_chirho.iter().map(key_id_chirho).collect::<Vec<_>>(),
            "her two keys, oldest first"
        );
        assert!(!body_chirho.contains(&key_id_chirho(&theirs_chirho)));
        for issue_chirho in hers_chirho.iter().chain([&theirs_chirho]) {
            assert!(
                !body_chirho.contains(&issue_chirho.token_chirho),
                "never a key"
            );
            assert!(
                !body_chirho.contains(&issue_chirho.record_chirho.token_hash_chirho),
                "never a key's hash"
            );
        }

        // Her own key, on the same route: the door refuses any key's context, so the run fails without a list.
        let (status_chirho, body_chirho) = tenant_chirho
            .get_account_chirho(
                &state_chirho,
                &AccountTenantChirho::bearer_chirho(&hers_chirho[0].token_chirho),
            )
            .await;
        assert!(!status_chirho.is_success(), "{status_chirho} {body_chirho}");
        for issue_chirho in &hers_chirho {
            assert!(!body_chirho.contains(&key_id_chirho(issue_chirho)));
        }
        // The control: the same browser read still answers, so the refusal was the key's.
        let (status_chirho, _) = tenant_chirho
            .get_account_chirho(&state_chirho, &tenant_chirho.cookie_chirho(0))
            .await;
        assert_eq!(status_chirho, StatusCode::OK);
    });
}
