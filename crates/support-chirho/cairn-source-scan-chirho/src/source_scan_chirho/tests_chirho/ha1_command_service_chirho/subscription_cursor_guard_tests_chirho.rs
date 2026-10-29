// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;

const SUBSCRIPTION_CONTROL_PLANE_MANIFEST_CHIRHO: &str =
    "crates/services-chirho/cairn-subscription-control-plane-chirho/Cargo.toml";
const SUBSCRIPTION_CONTROL_PLANE_LIB_CHIRHO: &str =
    "crates/services-chirho/cairn-subscription-control-plane-chirho/src/lib.rs";
const SUBSCRIPTION_CONTROL_PLANE_DIGESTS_CHIRHO: &str =
    "crates/services-chirho/cairn-subscription-control-plane-chirho/src/digests_chirho.rs";
const SUBSCRIPTION_CURSOR_CHIRHO: &str =
    "crates/services-chirho/cairn-subscription-control-plane-chirho/src/cursor_chirho.rs";
const SIGNER_CHIRHO: &str = "crates/support-chirho/cairn-signer-chirho/src/signer_chirho.rs";

fn between_chirho<'a>(text_chirho: &'a str, start_chirho: &str, end_chirho: &str) -> &'a str {
    let start_index_chirho = text_chirho
        .find(start_chirho)
        .unwrap_or_else(|| panic!("missing start marker {start_chirho}"));
    let tail_chirho = &text_chirho[start_index_chirho..];
    let end_index_chirho = tail_chirho
        .find(end_chirho)
        .unwrap_or_else(|| panic!("missing end marker {end_chirho}"));
    &tail_chirho[..end_index_chirho]
}

fn forbidden_cursor_writer_sites_chirho(text_chirho: &str) -> Vec<&'static str> {
    [
        "std::fs",
        "fs::write(",
        "File::create(",
        "OpenOptions",
        "store_chirho::put",
        "append_",
        "set_branch_chirho(",
        "commit_head_chirho(",
        "remove_branch_chirho(",
        "deploy_app_chirho(",
        "undeploy_app_chirho(",
        "transfer_chirho(",
        "settle_",
        "provider_chirho",
        "append_gate1_authority_record_chirho(",
    ]
    .into_iter()
    .filter(|needle_chirho| text_chirho.contains(needle_chirho))
    .collect()
}

#[test]
fn subscription_cursor_keeps_signer_root_pin_auth_and_source_order_chirho() {
    let root_chirho = workspace_root_chirho();
    let cursor_chirho =
        std::fs::read_to_string(root_chirho.join(SUBSCRIPTION_CURSOR_CHIRHO)).unwrap();
    let production_chirho = production_text_chirho(&cursor_chirho);
    assert!(forbidden_cursor_writer_sites_chirho(&production_chirho).is_empty());
    for required_chirho in [
        "sign_message_with_existing_key_chirho(",
        "existing_pubkey_hex_chirho(root_chirho)",
        "verify_with_root_pubkey_chirho(",
        "current_subscription_control_plane_witness_chirho(",
        "derive_subscription_binding_digests_chirho(",
        "constant_time_digest_matches_chirho(",
        "verified_gate1_authority_records_chirho(root_chirho)",
        "previous_record_digest_at_cut_chirho(",
        "GATE1_AUTHORITY_RECORD_DIGEST_PREFIX_CHIRHO",
    ] {
        assert!(
            production_chirho.contains(required_chirho),
            "signed cursor must retain {required_chirho}"
        );
    }
    for forbidden_chirho in [
        "verify_with_pubkey_chirho(",
        "sign_message_chirho(root_chirho",
        "URL_SAFE.encode(",
        "URL_SAFE.decode(",
    ] {
        assert!(
            !production_chirho.contains(forbidden_chirho),
            "signed cursor must reject unsafe mechanism {forbidden_chirho}"
        );
    }

    let resume_chirho = between_chirho(
        &cursor_chirho,
        "pub(super) fn try_resume_gate1_subscription_cursor_chirho(",
        "\nfn validate_current_binding_chirho(",
    );
    let root_pin_chirho = resume_chirho.find("expected_key_id_chirho").unwrap();
    let signature_chirho = resume_chirho
        .find("verify_with_root_pubkey_chirho(")
        .unwrap();
    let current_auth_chirho = resume_chirho
        .find("current_subscription_control_plane_witness_chirho(")
        .unwrap();
    let binding_chirho = resume_chirho
        .find("validate_current_binding_chirho(")
        .unwrap();
    let source_chirho = resume_chirho
        .find("source_chirho.verified_records_chirho(root_chirho)")
        .unwrap();
    assert!(root_pin_chirho < signature_chirho);
    assert!(signature_chirho < current_auth_chirho);
    assert!(current_auth_chirho < binding_chirho);
    assert!(binding_chirho < source_chirho);
    assert_eq!(
        resume_chirho
            .matches("source_chirho.verified_records_chirho(root_chirho)")
            .count(),
        1,
        "resume must perform exactly one verified source read after current authorization"
    );
}

#[test]
fn subscription_cursor_codec_and_outputs_stay_bounded_and_private_chirho() {
    let root_chirho = workspace_root_chirho();
    let manifest_chirho =
        std::fs::read_to_string(root_chirho.join(SUBSCRIPTION_CONTROL_PLANE_MANIFEST_CHIRHO))
            .unwrap();
    for dependency_chirho in [
        "base64 = \"0.22\"",
        "serde = { version = \"1\", features = [\"derive\"] }",
        "serde_json = \"1\"",
        "cairn-signer-chirho =",
        "cairn-subscribe-chirho =",
    ] {
        assert!(manifest_chirho.contains(dependency_chirho));
    }
    let lib_chirho =
        std::fs::read_to_string(root_chirho.join(SUBSCRIPTION_CONTROL_PLANE_LIB_CHIRHO)).unwrap();
    let digests_chirho =
        std::fs::read_to_string(root_chirho.join(SUBSCRIPTION_CONTROL_PLANE_DIGESTS_CHIRHO))
            .unwrap();
    for source_chirho in [&lib_chirho, &digests_chirho] {
        assert!(!source_chirho.contains("Serialize"));
        assert!(!source_chirho.contains("Deserialize"));
        assert!(!source_chirho.contains("serde_json"));
        assert!(!source_chirho.contains("base64"));
    }

    let cursor_chirho =
        std::fs::read_to_string(root_chirho.join(SUBSCRIPTION_CURSOR_CHIRHO)).unwrap();
    for required_chirho in [
        "subscribe-gate1-cursor-v1-chirho",
        "gate1-authority-log-chirho",
        "SUBSCRIPTION_CURSOR_TTL_MS_CHIRHO: u64 = 15 * 60 * 1_000",
        "SUBSCRIPTION_CURSOR_MAX_ENCODED_BYTES_CHIRHO: usize = 4_096",
        "#[serde(deny_unknown_fields)]",
        "URL_SAFE_NO_PAD",
        "serde_json::to_vec(&envelope_chirho)? != decoded_chirho",
        "URL_SAFE_NO_PAD.encode(&decoded_chirho) != token_chirho.0",
    ] {
        assert!(cursor_chirho.contains(required_chirho));
    }
    assert!(cursor_chirho.contains("pub struct OpaqueSubscriptionCursorTokenChirho(String);"));
    let validated_start_chirho = cursor_chirho
        .find("pub struct ValidatedSubscriptionCursorChirho {")
        .unwrap();
    let validated_tail_chirho = &cursor_chirho[validated_start_chirho..];
    let validated_end_chirho = validated_tail_chirho.find("\n}\n").unwrap();
    assert_eq!(
        validated_tail_chirho[..validated_end_chirho]
            .matches("\n    pub ")
            .count(),
        0
    );
    for forbidden_chirho in [
        "#[derive(Debug",
        "Serialize for OpaqueSubscriptionCursorTokenChirho",
        "Serialize for ValidatedSubscriptionCursorChirho",
        "pub fn subscription_id_chirho(",
        "pub fn subscription_id_value_chirho(",
    ] {
        assert!(!cursor_chirho.contains(forbidden_chirho));
    }
}

#[test]
fn existing_key_cursor_signer_is_load_only_and_pair_checked_chirho() {
    let root_chirho = workspace_root_chirho();
    let signer_chirho = std::fs::read_to_string(root_chirho.join(SIGNER_CHIRHO)).unwrap();
    let existing_signer_chirho = between_chirho(
        &signer_chirho,
        "pub fn sign_message_with_existing_key_chirho(",
        "\n/// The cairn instance public key",
    );
    for required_chirho in [
        "sign_with_existing_key_possession_chirho(root_chirho, message_chirho)?",
        ".into_signature_hex_chirho()",
    ] {
        assert!(existing_signer_chirho.contains(required_chirho));
    }
    for forbidden_chirho in [
        "load_or_create_signing_key_chirho(",
        "create_dir_all",
        "File::create",
        "OpenOptions",
        "write(",
        "write_file",
        "set_permissions",
        "with_named_lock_chirho",
    ] {
        assert!(
            !existing_signer_chirho.contains(forbidden_chirho),
            "existing-key cursor signer must remain load-only: {forbidden_chirho}"
        );
    }

    let possession_signer_chirho = between_chirho(
        &signer_chirho,
        "pub fn sign_with_existing_key_possession_chirho(",
        "\n/// The cairn instance public key",
    );
    for required_chirho in [
        "load_existing_signing_keypair_chirho(root_chirho)?",
        "key_chirho.pubkey_hex_chirho()",
        "key_chirho.sign_message_chirho(message_chirho)",
    ] {
        assert!(possession_signer_chirho.contains(required_chirho));
    }

    let pair_loader_chirho = between_chirho(
        &signer_chirho,
        "fn load_existing_signing_keypair_chirho(",
        "\nfn read_existing_private_seed_chirho(",
    );
    for required_chirho in [
        "read_existing_private_seed_chirho",
        "read_existing_public_key_chirho",
        "validate_existing_key_owners_chirho",
        "stored_public_key_chirho != key_chirho.pubkey_hex_chirho()",
        "seed_chirho.zeroize()",
    ] {
        assert!(pair_loader_chirho.contains(required_chirho));
    }
}

#[test]
fn subscription_cursor_guard_fixtures_catch_unsafe_signer_and_embedded_key_chirho() {
    let create_capable_chirho = "sign_message_chirho(root_chirho, &unsigned_chirho)?";
    let embedded_key_chirho =
        "verify_with_pubkey_chirho(&envelope_chirho.key_id_chirho, message_chirho, sig_chirho)?";
    assert!(create_capable_chirho.contains("sign_message_chirho(root_chirho"));
    assert!(embedded_key_chirho.contains("verify_with_pubkey_chirho("));
}
