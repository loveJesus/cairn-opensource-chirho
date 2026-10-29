// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::super::*;

fn registration_parameter_count_chirho(source_chirho: &str, signature_chirho: &str) -> usize {
    let parameters_start_chirho = source_chirho
        .find(signature_chirho)
        .map(|offset_chirho| offset_chirho + signature_chirho.len())
        .expect("identity registration function must remain present");
    let parameters_chirho = source_chirho[parameters_start_chirho..]
        .split_once(") -> Result<IdentityRecordChirho>")
        .map(|(parameters_chirho, _rest_chirho)| parameters_chirho)
        .expect("identity registration signature must keep its reviewed return type");
    parameters_chirho
        .split(',')
        .filter(|parameter_chirho| !parameter_chirho.trim().is_empty())
        .count()
}

/// The TYPE of each parameter, in order, whitespace-normalized. A count cannot tell a money
/// parameter from a reviewed one at the same arity; the exact type list can (claude2 #29330).
fn registration_parameter_types_chirho(source_chirho: &str, signature_chirho: &str) -> Vec<String> {
    let parameters_start_chirho = source_chirho
        .find(signature_chirho)
        .map(|offset_chirho| offset_chirho + signature_chirho.len())
        .expect("identity registration function must remain present");
    let parameters_chirho = source_chirho[parameters_start_chirho..]
        .split_once(") -> Result<IdentityRecordChirho>")
        .map(|(parameters_chirho, _rest_chirho)| parameters_chirho)
        .expect("identity registration signature must keep its reviewed return type");
    parameters_chirho
        .split(',')
        .filter(|parameter_chirho| !parameter_chirho.trim().is_empty())
        .map(|parameter_chirho| {
            parameter_chirho
                .split_once(':')
                .map(|(_name_chirho, type_chirho)| type_chirho)
                .unwrap_or(parameter_chirho)
                .split_whitespace()
                .collect::<String>()
        })
        .collect()
}

#[test]
fn identity_owned_legacy_money_surface_stays_absent_chirho() {
    let root_chirho = workspace_root_chirho();
    let identity_chirho =
        std::fs::read_to_string(root_chirho.join("src/edge_flows_chirho/identity_chirho.rs"))
            .unwrap();
    assert!(!identity_chirho.contains("ledger_chirho"));
    assert!(!identity_chirho.contains("CASH_RESERVE_ACCOUNT_CHIRHO"));
    assert!(!identity_chirho.contains("TOKEN_ISSUER_ACCOUNT_CHIRHO"));
    assert!(!identity_chirho.contains("CENTS_PER_TOKEN_CHIRHO"));
    assert!(!identity_chirho.contains("\"identity registration grant\""));
    assert!(!identity_chirho.contains("ledger_chirho::transfer_chirho"));
    assert!(
        !identity_chirho.contains("grant_chirho"),
        "the identity core must not retain a money-shaped registration argument or bail"
    );
    assert_eq!(
        registration_parameter_count_chirho(&identity_chirho, "pub fn register_identity_chirho("),
        2,
        "credentialless registration must expose only root and principal kind"
    );
    assert_eq!(
        registration_parameter_count_chirho(
            &identity_chirho,
            "pub fn register_identity_with_credential_chirho("
        ),
        3,
        "credential registration must expose only root, principal kind, and credential"
    );
    assert_eq!(
        registration_parameter_count_chirho(
            &identity_chirho,
            "fn register_identity_internal_chirho("
        ),
        4,
        "identity creation core must accept only root, principal kind, credential, and principal \
         source (drawn, or reviewed for the test-kind geo seed); never a money parameter"
    );
    assert_eq!(
        registration_parameter_types_chirho(
            &identity_chirho,
            "fn register_identity_internal_chirho("
        ),
        [
            "&Path",
            "PrincipalKindChirho",
            "Option<&str>",
            "PrincipalSourceChirho<'_>"
        ],
        "identity creation core's parameter TYPES are pinned: no money parameter can take a slot"
    );
    let reviewed_chirho = std::fs::read_to_string(
        root_chirho.join("src/edge_flows_chirho/identity_chirho/reviewed_principal_chirho.rs"),
    )
    .unwrap();
    assert_eq!(
        registration_parameter_types_chirho(
            &reviewed_chirho,
            "pub fn register_identity_with_reviewed_principal_chirho("
        ),
        ["&Path", "PrincipalKindChirho", "&str", "Option<&str>"],
        "the reviewed registration takes only root, kind, principal and credential; never money"
    );

    for deleted_symbol_chirho in [
        "convert_cash_to_token_chirho(",
        "verify_token_solvency_chirho(",
        "wallet_view_chirho(",
        "wallet_view_html_chirho(",
        "wallet_error_html_chirho(",
        "WalletViewChirho",
        "TokenSolvencyChirho",
    ] {
        assert!(
            production_source_lines_matching_chirho(deleted_symbol_chirho).is_empty(),
            "legacy issuance, wallet, and solvency symbol '{deleted_symbol_chirho}' must stay absent"
        );
    }
}

#[test]
fn identity_money_cli_and_http_routes_stay_absent_chirho() {
    let root_chirho = workspace_root_chirho();
    let args_chirho =
        std::fs::read_to_string(root_chirho.join("crates/cairn-cli-chirho/src/args_chirho.rs"))
            .unwrap();
    let auth_args_chirho = std::fs::read_to_string(
        root_chirho
            .join("crates/cairn-cli-chirho/src/args_chirho/product_chirho/auth_args_chirho.rs"),
    )
    .unwrap();
    let serve_chirho = std::fs::read_to_string(
        root_chirho.join("crates/cairn-serve-runtime-chirho/src/serve_chirho.rs"),
    )
    .unwrap();
    for command_chirho in ["wallet\"", "wallet-convert", "wallet-solvency"] {
        assert!(
            !args_chirho.contains(command_chirho),
            "legacy identity money command '{command_chirho}' must stay absent"
        );
    }
    assert!(!auth_args_chirho.contains("long = \"grant\""));
    assert!(!serve_chirho.contains("/wallet-chirho/:kind_chirho/:id_chirho"));
}

#[test]
fn removed_registration_grant_field_remains_fail_closed_and_audited_chirho() {
    let root_chirho = workspace_root_chirho();
    let request_chirho =
        std::fs::read_to_string(root_chirho.join("src/edge_flows_chirho/identity_chirho.rs"))
            .unwrap();
    let handler_chirho = std::fs::read_to_string(
        root_chirho
            .join("crates/cairn-serve-runtime-chirho/src/serve_chirho/auth_wallet_chirho.rs"),
    )
    .unwrap();
    assert!(!request_chirho.contains("pub grant_chirho: i64"));
    assert!(handler_chirho.contains("legacy_grant_present_chirho"));
    assert!(handler_chirho.contains("grant_chirho is unavailable after CF6"));
    assert!(handler_chirho.contains("register_error_chirho("));
    let grant_rejection_offset_chirho = handler_chirho
        .find("if legacy_grant_present_chirho {")
        .expect("legacy grant rejection must remain explicit");
    let identity_registration_offset_chirho = handler_chirho
        .find("match identity_chirho::register_identity_with_credential_chirho(")
        .expect("identity registration call must remain visible to the ordering guard");
    assert!(
        grant_rejection_offset_chirho < identity_registration_offset_chirho,
        "legacy grant rejection must run before identity creation"
    );
}
