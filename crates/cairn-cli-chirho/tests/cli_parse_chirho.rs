// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use cairn_cli_chirho::args_chirho::{CliChirho, CommandChirho};
use clap::Parser;
use std::path::PathBuf;

#[test]
fn credits_demo_operator_commands_stay_report_dispatched_chirho() {
    let source_chirho =
        include_str!("../src/cli_helpers_chirho/reporting_chirho/report_cli_chirho.rs");
    for needle_chirho in [
        "CommandChirho::CreditsDemoInputsAuthorChirho",
        "run_credits_demo_inputs_author_report_chirho",
        "CommandChirho::CreditsDemoProviderPrepareChirho",
        "run_credits_demo_provider_prepare_report_chirho",
        "CommandChirho::CreditsDemoConcurrencyTokenChirho",
        "run_credits_demo_concurrency_token_report_chirho",
        "CommandChirho::CreditsDemoGeoSeedChirho",
        "run_credits_demo_geo_seed_report_chirho",
        "CommandChirho::CreditsDemoContinuationChirho",
        "run_credits_demo_continuation_report_chirho",
        "CommandChirho::CreditsDemoReviewedCandidatePinChirho",
        "run_credits_demo_reviewed_candidate_pin_report_chirho",
    ] {
        assert!(
            source_chirho.contains(needle_chirho),
            "credits-demo operator CLI dispatch lost {needle_chirho}"
        );
    }
}

#[test]
fn credits_demo_continuation_requires_an_external_reviewed_inputs_path_chirho() {
    let missing_chirho = match CliChirho::try_parse_from([
        "cairn-chirho",
        "--root",
        ".cairn-chirho",
        "credits-demo-continuation",
        "--storage-namespace-chirho",
        "tenant-ledger-chirho",
    ]) {
        Ok(_cli_chirho) => {
            panic!("the migration continuation must not have a root-relative input fallback")
        }
        Err(error_chirho) => error_chirho,
    };
    assert_eq!(
        missing_chirho.kind(),
        clap::error::ErrorKind::MissingRequiredArgument,
        "absence must reach clap's required-coordinate gate"
    );
    assert!(
        missing_chirho
            .to_string()
            .contains("--reviewed-inputs-dir-chirho"),
        "the required coordinate must be named in the CLI refusal"
    );

    let cli_chirho = CliChirho::try_parse_from([
        "cairn-chirho",
        "--root",
        ".cairn-chirho",
        "credits-demo-continuation",
        "--reviewed-inputs-dir-chirho",
        "/operator-evidence-chirho/reviewed-inputs-chirho",
        "--expected-config-digest-chirho",
        "87d0635dc870574c904f2454d6d42dadcfc69b9a2e2adef5ab76d70007ee8a81",
        "--storage-namespace-chirho",
        "tenant-ledger-chirho",
    ])
    .unwrap();
    match cli_chirho.command_chirho {
        CommandChirho::CreditsDemoContinuationChirho(args_chirho) => {
            assert_eq!(
                args_chirho.reviewed_inputs_dir_chirho,
                PathBuf::from("/operator-evidence-chirho/reviewed-inputs-chirho")
            );
            assert_eq!(args_chirho.storage_namespace_chirho, "tenant-ledger-chirho");
            assert_eq!(
                args_chirho.expected_config_digest_chirho,
                "87d0635dc870574c904f2454d6d42dadcfc69b9a2e2adef5ab76d70007ee8a81"
            );
        }
        other_chirho => panic!(
            "expected credits-demo-continuation, got {:?}",
            std::mem::discriminant(&other_chirho)
        ),
    }
}

#[test]
fn credits_demo_reviewed_candidate_pin_requires_the_explicit_report_hash_chirho() {
    let hash_chirho = "a".repeat(64);
    let cli_chirho = CliChirho::try_parse_from([
        "cairn-chirho",
        "--root",
        ".cairn-chirho",
        "credits-demo-reviewed-candidate-pin",
        "--source-review-report-chirho",
        &hash_chirho,
    ])
    .unwrap();
    match cli_chirho.command_chirho {
        CommandChirho::CreditsDemoReviewedCandidatePinChirho(args_chirho) => {
            assert_eq!(args_chirho.source_review_report_chirho, hash_chirho);
        }
        other_chirho => panic!(
            "expected credits-demo-reviewed-candidate-pin, got {:?}",
            std::mem::discriminant(&other_chirho)
        ),
    }
}

#[test]
fn ledger_runtime_preflight_requires_the_reviewed_config_path_chirho() {
    let cli_chirho = CliChirho::try_parse_from([
        "cairn-chirho",
        "--root",
        ".cairn-chirho",
        "ledger-runtime-preflight-chirho",
        "--config-chirho",
        "reauth-config-chirho.toml",
        "--expected-config-digest-chirho",
        "87d0635dc870574c904f2454d6d42dadcfc69b9a2e2adef5ab76d70007ee8a81",
    ])
    .unwrap();
    match cli_chirho.command_chirho {
        CommandChirho::LedgerRuntimePreflightChirho(args_chirho) => {
            assert_eq!(
                args_chirho.config_path_chirho,
                PathBuf::from("reauth-config-chirho.toml")
            );
            assert_eq!(
                args_chirho.expected_config_digest_chirho,
                "87d0635dc870574c904f2454d6d42dadcfc69b9a2e2adef5ab76d70007ee8a81"
            );
        }
        other_chirho => panic!(
            "expected ledger-runtime-preflight-chirho command, got {:?}",
            std::mem::discriminant(&other_chirho)
        ),
    }
}

#[test]
fn credits_demo_geo_seed_requires_the_reviewed_seed_coordinates_chirho() {
    let cli_chirho = CliChirho::try_parse_from([
        "cairn-chirho",
        "--root",
        ".cairn-chirho",
        "credits-demo-geo-seed-chirho",
        "--config-chirho",
        "host-config-chirho.toml",
        "--expected-config-digest-chirho",
        "87d0635dc870574c904f2454d6d42dadcfc69b9a2e2adef5ab76d70007ee8a81",
        "--plan-chirho",
        "plan-canonical-chirho.json",
        "--expected-plan-digest-chirho",
        "cb954aa53f8e6410ba2a854e41078a50a49569f32b3acb3d516652bdcf778ed4",
        "--issuer-secret-name-chirho",
        "credits-demo-offline-issuer-chirho",
        "--activation-authorization-chirho",
        "reviewed-inputs-chirho/activation-authorization-chirho.json",
        "--expected-activation-authorization-digest-chirho",
        "resident-ledger-activation-authorization-blake3-v1-chirho:\
         0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "--payer-credential-secret-name-chirho",
        "credits-demo-payer-credential-chirho",
        "--app-root-chirho",
        "examples-chirho/tree-credits-demo-chirho",
        "--json",
    ])
    .unwrap();
    match cli_chirho.command_chirho {
        CommandChirho::CreditsDemoGeoSeedChirho(args_chirho) => {
            assert_eq!(
                args_chirho.config_chirho,
                PathBuf::from("host-config-chirho.toml")
            );
            assert_eq!(
                args_chirho.expected_config_digest_chirho,
                "87d0635dc870574c904f2454d6d42dadcfc69b9a2e2adef5ab76d70007ee8a81"
            );
            assert_eq!(
                args_chirho.plan_chirho,
                PathBuf::from("plan-canonical-chirho.json")
            );
            assert_eq!(
                args_chirho.app_root_chirho,
                PathBuf::from("examples-chirho/tree-credits-demo-chirho")
            );
            assert!(args_chirho.json_chirho);
        }
        other_chirho => panic!(
            "expected credits-demo-geo-seed-chirho, got {:?}",
            std::mem::discriminant(&other_chirho)
        ),
    }
}
use std::sync::atomic::{AtomicU64, Ordering};

#[test]
fn archived_external_provider_commands_are_absent_chirho() {
    for command_chirho in [
        "provider-price-set",
        "provider-prices",
        "external-verify",
        "external-usage",
        "provider-suspense",
    ] {
        let Err(error_chirho) = CliChirho::try_parse_from(["cairn-chirho", command_chirho]) else {
            panic!("archived external command '{command_chirho}' unexpectedly parsed");
        };
        assert_eq!(
            error_chirho.kind(),
            clap::error::ErrorKind::InvalidSubcommand
        );
    }
}

#[test]
fn archived_coupon_commands_are_absent_chirho() {
    for command_chirho in [
        "coupon-create",
        "coupon-redeem",
        "coupons",
        "coupon-redemptions",
        "stripe-identity-record",
        "stripe-identities",
        "coupon-verify",
    ] {
        let Err(error_chirho) = CliChirho::try_parse_from(["cairn-chirho", command_chirho]) else {
            panic!("archived coupon command '{command_chirho}' unexpectedly parsed");
        };
        assert_eq!(
            error_chirho.kind(),
            clap::error::ErrorKind::InvalidSubcommand
        );
    }
}

#[test]
fn archived_gas_grant_command_is_absent_chirho() {
    let Err(error_chirho) = CliChirho::try_parse_from(["cairn-chirho", "gas-grant"]) else {
        panic!("archived gas-grant command unexpectedly parsed");
    };
    assert_eq!(
        error_chirho.kind(),
        clap::error::ErrorKind::InvalidSubcommand
    );
}

#[test]
fn archived_ledger_post_command_is_absent_chirho() {
    let Err(error_chirho) = CliChirho::try_parse_from(["cairn-chirho", "ledger-post"]) else {
        panic!("archived ledger-post command unexpectedly parsed");
    };
    assert_eq!(
        error_chirho.kind(),
        clap::error::ErrorKind::InvalidSubcommand
    );
}

#[test]
fn archived_gas_refresh_floor_command_is_absent_chirho() {
    let Err(error_chirho) = CliChirho::try_parse_from(["cairn-chirho", "gas-refresh-floor"]) else {
        panic!("archived gas-refresh-floor command unexpectedly parsed");
    };
    assert_eq!(
        error_chirho.kind(),
        clap::error::ErrorKind::InvalidSubcommand
    );
}

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-cli-{label_chirho}-{}-{n_chirho}",
        std::process::id()
    ))
}

#[test]
fn reporting_cli_commands_parse_chirho() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let privacy_scan_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "privacy-scan",
                "--json",
                "--fail-on-findings",
            ])
            .unwrap();
            match privacy_scan_chirho.command_chirho {
                CommandChirho::PrivacyScanChirho(args_chirho) => {
                    let cairn_cli_chirho::args_chirho::privacy_args_chirho::PrivacyScanArgsChirho {
                        json_chirho,
                        fail_on_findings_chirho,
                    } = args_chirho;
                    assert!(json_chirho);
                    assert!(fail_on_findings_chirho);
                }
                other_chirho => panic!(
                    "expected privacy-scan command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }
            let privacy_verify_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "privacy-verify",
                "--json",
                "--fail-on-empty-evidence",
            ])
            .unwrap();
            assert!(matches!(
                privacy_verify_chirho.command_chirho,
                CommandChirho::PrivacyVerifyChirho(args_chirho)
                    if args_chirho.json_chirho && args_chirho.fail_on_empty_evidence_chirho
            ));
            let compliance_evidence_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "compliance-evidence-generate",
                "--framework",
                "soc2",
                "--fail-on-failed-sources",
                "--fail-on-coverage-gaps",
                "--fail-on-manual-controls",
            ])
            .unwrap();
            match compliance_evidence_chirho.command_chirho {
                CommandChirho::ComplianceEvidenceGenerateChirho(args_chirho) => {
                    let cairn_cli_chirho::args_chirho::compliance_args_chirho::ComplianceEvidenceGenerateArgsChirho {
                        frameworks_chirho,
                        fail_on_failed_sources_chirho,
                        fail_on_coverage_gaps_chirho,
                        fail_on_manual_controls_chirho,
                        ..
                    } = args_chirho;
                    assert_eq!(frameworks_chirho, vec!["soc2".to_string()]);
                    assert!(fail_on_failed_sources_chirho);
                    assert!(fail_on_coverage_gaps_chirho);
                    assert!(fail_on_manual_controls_chirho);
                }
                other_chirho => panic!(
                    "expected compliance-evidence-generate command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }
            let list_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "volatile-effects",
            ])
            .unwrap();
            assert!(matches!(
                list_chirho.command_chirho,
                CommandChirho::VolatileEffectsChirho(args_chirho) if !args_chirho.json_chirho
            ));
            let list_json_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "volatile-effects",
                "--json",
            ])
            .unwrap();
            assert!(matches!(
                list_json_chirho.command_chirho,
                CommandChirho::VolatileEffectsChirho(args_chirho) if args_chirho.json_chirho
            ));
            let verify_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "volatile-effects-verify",
            ])
            .unwrap();
            assert!(matches!(
                verify_chirho.command_chirho,
                CommandChirho::VolatileEffectsVerifyChirho(args_chirho) if !args_chirho.json_chirho
            ));
            let verify_json_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "volatile-effects-verify",
                "--json",
            ])
            .unwrap();
            assert!(matches!(
                verify_json_chirho.command_chirho,
                CommandChirho::VolatileEffectsVerifyChirho(args_chirho) if args_chirho.json_chirho
            ));
            let run_cache_verify_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "run-cache-verify",
                "--json",
            ])
            .unwrap();
            assert!(matches!(
                run_cache_verify_chirho.command_chirho,
                CommandChirho::RunCacheVerifyChirho(args_chirho) if args_chirho.json_chirho
            ));
            let compliance_verify_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "compliance-evidence-verify",
                "--fail-on-failed-sources",
                "--fail-on-coverage-gaps",
                "--fail-on-manual-controls",
            ])
            .unwrap();
            match compliance_verify_chirho.command_chirho {
                CommandChirho::ComplianceEvidenceVerifyChirho(args_chirho) => {
                    let cairn_cli_chirho::args_chirho::compliance_args_chirho::ComplianceEvidenceVerifyArgsChirho {
                        pack_chirho,
                        fail_on_failed_sources_chirho,
                        fail_on_coverage_gaps_chirho,
                        fail_on_manual_controls_chirho,
                    } = args_chirho;
                    assert!(pack_chirho.is_none());
                    assert!(fail_on_failed_sources_chirho);
                    assert!(fail_on_coverage_gaps_chirho);
                    assert!(fail_on_manual_controls_chirho);
                }
                other_chirho => panic!(
                    "expected compliance-evidence-verify command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }
            let data_residency_verify_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "data-residency-verify",
                "--fail-on-violations",
            ])
            .unwrap();
            assert!(matches!(
                data_residency_verify_chirho.command_chirho,
                CommandChirho::DataResidencyVerifyChirho(args_chirho)
                    if args_chirho.fail_on_violations_chirho
            ));
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn runtime_package_smoke_cli_accepts_json_report_flag_chirho() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let cli_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "runtime-package-smoke",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "--server",
                "https://example.test",
                "--json",
                "--input",
                "hello",
                "--expect-output",
                "HELLO",
            ])
            .unwrap();
            match cli_chirho.command_chirho {
                CommandChirho::RuntimePackageSmokeChirho(args_chirho) => {
                    let cairn_cli_chirho::args_chirho::core_args_chirho::RuntimePackageSmokeArgsChirho {
                        package_chirho,
                        server_chirho,
                        json_chirho,
                        input_chirho,
                        expect_output_chirho,
                    } = args_chirho;
                    assert_eq!(
                        package_chirho,
                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    );
                    assert_eq!(server_chirho, "https://example.test");
                    assert!(json_chirho);
                    assert_eq!(input_chirho.as_deref(), Some("hello"));
                    assert_eq!(expect_output_chirho.as_deref(), Some("HELLO"));
                }
                other_chirho => panic!(
                    "expected runtime-package-smoke command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn identity_and_oauth_cli_accept_credential_file_chirho() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let credential_set_cli_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "identity-credential-set",
                "owner/example-chirho",
                "--credential-file",
                "/tmp/existing-owner-credential-chirho",
            ])
            .unwrap();
            match credential_set_cli_chirho.command_chirho {
                CommandChirho::IdentityCredentialSetChirho(args_chirho) => {
                    let cairn_cli_chirho::args_chirho::auth_args_chirho::IdentityCredentialSetArgsChirho {
                        principal_chirho,
                        credential_file_chirho,
                    } = args_chirho;
                    assert_eq!(principal_chirho, "owner/example-chirho");
                    assert_eq!(
                        credential_file_chirho,
                        PathBuf::from("/tmp/existing-owner-credential-chirho")
                    );
                }
                other_chirho => panic!(
                    "expected identity-credential-set command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }
            assert!(CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "identity-credential-set",
                "owner/example-chirho",
                "--credential",
                "inline-secret-chirho",
            ])
            .is_err());

            // The reset command parses like set (file only, never an inline value) and carries its
            // own reason default.
            let credential_reset_cli_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "identity-credential-reset",
                "user/example-chirho",
                "--credential-file",
                "/tmp/replacement-credential-chirho",
            ])
            .unwrap();
            match credential_reset_cli_chirho.command_chirho {
                CommandChirho::IdentityCredentialResetChirho(args_chirho) => {
                    let cairn_cli_chirho::args_chirho::auth_args_chirho::IdentityCredentialResetArgsChirho {
                        principal_chirho,
                        credential_file_chirho,
                        reason_chirho,
                    } = args_chirho;
                    assert_eq!(principal_chirho, "user/example-chirho");
                    assert_eq!(
                        credential_file_chirho,
                        PathBuf::from("/tmp/replacement-credential-chirho")
                    );
                    assert_eq!(reason_chirho, "operator-credential-reset-chirho");
                }
                other_chirho => panic!(
                    "expected identity-credential-reset command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }
            assert!(CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "identity-credential-reset",
                "user/example-chirho",
                "--credential",
                "inline-secret-chirho",
            ])
            .is_err());
            assert!(matches!(
                CliChirho::try_parse_from([
                    "cairn-chirho",
                    "--root",
                    ".cairn-chirho",
                    "identity-credential-resets-verify",
                ])
                .unwrap()
                .command_chirho,
                CommandChirho::IdentityCredentialResetsVerifyChirho
            ));

            let identity_cli_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "identity-register",
                "--kind",
                "owner",
                "--credential-file",
                "/tmp/identity-credential-chirho",
            ])
            .unwrap();
            match identity_cli_chirho.command_chirho {
                CommandChirho::IdentityRegisterChirho(args_chirho) => {
                    let cairn_cli_chirho::args_chirho::auth_args_chirho::IdentityRegisterArgsChirho {
                        kind_chirho,
                        credential_chirho,
                        credential_file_chirho,
                        ..
                    } = args_chirho;
                    assert_eq!(kind_chirho, "owner");
                    assert!(credential_chirho.is_none());
                    assert_eq!(
                        credential_file_chirho.unwrap(),
                        PathBuf::from("/tmp/identity-credential-chirho")
                    );
                }
                other_chirho => panic!(
                    "expected identity-register command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }

            let oauth_cli_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "oauth-token",
                "--principal",
                "user/example-chirho",
                "--credential-file",
                "/tmp/oauth-credential-chirho",
                "--client",
                "client/example-chirho",
                "--scope",
                "invoke_chirho",
            ])
            .unwrap();
            match oauth_cli_chirho.command_chirho {
                CommandChirho::OauthTokenChirho(args_chirho) => {
                    let cairn_cli_chirho::args_chirho::auth_args_chirho::OauthTokenArgsChirho {
                        principal_chirho,
                        credential_chirho,
                        credential_file_chirho,
                        client_chirho,
                        scopes_chirho,
                        ..
                    } = args_chirho;
                    assert_eq!(principal_chirho, "user/example-chirho");
                    assert!(credential_chirho.is_none());
                    assert_eq!(
                        credential_file_chirho.unwrap(),
                        PathBuf::from("/tmp/oauth-credential-chirho")
                    );
                    assert_eq!(client_chirho, "client/example-chirho");
                    assert_eq!(scopes_chirho, vec!["invoke_chirho".to_string()]);
                }
                other_chirho => panic!(
                    "expected oauth-token command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn operator_smoke_cli_accepts_json_flags_chirho() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let contact_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "contact-example-smoke",
                "--manifest",
                "examples-chirho/contact-persisting-source-manifest-chirho.example.json",
                "--json",
            ])
            .unwrap();
            match contact_chirho.command_chirho {
                CommandChirho::ContactExampleSmokeChirho(args_chirho) => {
                    let cairn_cli_chirho::args_chirho::app_args_chirho::ContactExampleSmokeArgsChirho {
                        manifest_chirho,
                        json_chirho,
                    } = args_chirho;
                    assert_eq!(
                        manifest_chirho.unwrap(),
                        PathBuf::from(
                            "examples-chirho/contact-persisting-source-manifest-chirho.example.json"
                        )
                    );
                    assert!(json_chirho);
                }
                other_chirho => panic!(
                    "expected contact-example-smoke command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }

            let inputs_author_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "credits-demo-inputs-author-chirho",
                "--payer-chirho",
                "user/0123456789abcdef",
                "--config-output-chirho",
                "reviewed-inputs-chirho/config-chirho.toml",
                "--plan-output-chirho",
                "reviewed-inputs-chirho/plan-chirho.json",
                "--activation-authorization-output-chirho",
                "reviewed-inputs-chirho/activation-authorization-chirho.json",
                "--issuer-secret-name-chirho",
                "credits-demo-offline-issuer-chirho",
                "--activation-secret-name-chirho",
                "credits-demo-offline-activation-chirho",
                "--payer-credential-secret-name-chirho",
                "credits-demo-payer-credential-chirho",
                "--destination-authority-enrollment-chirho",
                "reviewed-inputs-chirho/destination-authority-enrollment-chirho.json",
                "--expected-destination-authority-enrollment-digest-chirho",
                "43d0635dc870574c904f2454d6d42dadcfc69b9a2e2adef5ab76d70007ee8a81",
                "--cluster-genesis-roster-chirho",
                "cluster-genesis-chirho/membership-roster-chirho.jsonl",
                "--cluster-genesis-roster-head-chirho",
                "cluster-genesis-chirho/membership-roster-head-chirho.json",
                "--cluster-genesis-roster-operator-pubkey-hex-chirho",
                "53d0635dc870574c904f2454d6d42dadcfc69b9a2e2adef5ab76d70007ee8a81",
                "--serve-port-chirho",
                "8798",
                "--json",
            ])
            .unwrap();
            match inputs_author_chirho.command_chirho {
                CommandChirho::CreditsDemoInputsAuthorChirho(args_chirho) => {
                    assert_eq!(args_chirho.payer_chirho, "user/0123456789abcdef");
                    assert_eq!(
                        args_chirho.config_output_chirho,
                        PathBuf::from("reviewed-inputs-chirho/config-chirho.toml")
                    );
                    assert_eq!(
                        args_chirho.plan_output_chirho,
                        PathBuf::from("reviewed-inputs-chirho/plan-chirho.json")
                    );
                    assert_eq!(
                        args_chirho.activation_authorization_output_chirho,
                        PathBuf::from(
                            "reviewed-inputs-chirho/activation-authorization-chirho.json"
                        )
                    );
                    assert_eq!(
                        args_chirho.issuer_secret_name_chirho,
                        "credits-demo-offline-issuer-chirho"
                    );
                    assert_eq!(
                        args_chirho.activation_secret_name_chirho,
                        "credits-demo-offline-activation-chirho"
                    );
                    assert_eq!(
                        args_chirho.payer_credential_secret_name_chirho,
                        "credits-demo-payer-credential-chirho"
                    );
                    assert_eq!(
                        args_chirho.destination_authority_enrollment_path_chirho,
                        PathBuf::from(
                            "reviewed-inputs-chirho/destination-authority-enrollment-chirho.json"
                        )
                    );
                    assert_eq!(
                        args_chirho.expected_destination_authority_enrollment_digest_chirho,
                        "43d0635dc870574c904f2454d6d42dadcfc69b9a2e2adef5ab76d70007ee8a81"
                    );
                    assert_eq!(
                        args_chirho.cluster_genesis_roster_path_chirho,
                        PathBuf::from("cluster-genesis-chirho/membership-roster-chirho.jsonl")
                    );
                    assert_eq!(
                        args_chirho.cluster_genesis_roster_head_path_chirho,
                        PathBuf::from("cluster-genesis-chirho/membership-roster-head-chirho.json")
                    );
                    assert_eq!(
                        args_chirho.cluster_genesis_roster_operator_pubkey_hex_chirho,
                        "53d0635dc870574c904f2454d6d42dadcfc69b9a2e2adef5ab76d70007ee8a81"
                    );
                    assert_eq!(args_chirho.serve_port_chirho, 8798);
                    assert!(args_chirho.json_chirho);
                }
                other_chirho => panic!(
                    "expected credits-demo-inputs-author-chirho command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }

            let provider_prepare_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "credits-demo-provider-prepare-chirho",
                "--connection-secret-name-chirho",
                "credits-demo-pg-dsn-chirho",
                "--json",
            ])
            .unwrap();
            match provider_prepare_chirho.command_chirho {
                CommandChirho::CreditsDemoProviderPrepareChirho(args_chirho) => {
                    assert_eq!(
                        args_chirho.connection_secret_name_chirho,
                        "credits-demo-pg-dsn-chirho"
                    );
                    assert!(args_chirho.json_chirho);
                }
                other_chirho => panic!(
                    "expected credits-demo-provider-prepare-chirho command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }

            let concurrency_token_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "credits-demo-concurrency-token-chirho",
                "--connection-secret-name-chirho",
                "credits-demo-pg-dsn-chirho",
            ])
            .unwrap();
            match concurrency_token_chirho.command_chirho {
                CommandChirho::CreditsDemoConcurrencyTokenChirho(args_chirho) => {
                    assert_eq!(
                        args_chirho.connection_secret_name_chirho,
                        "credits-demo-pg-dsn-chirho"
                    );
                }
                other_chirho => panic!(
                    "expected credits-demo-concurrency-token-chirho command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }

            let credits_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "credits-demo-smoke",
                "--config-chirho",
                "host-config-chirho.toml",
                "--expected-config-digest-chirho",
                "87d0635dc870574c904f2454d6d42dadcfc69b9a2e2adef5ab76d70007ee8a81",
                "--plan-chirho",
                "plan-canonical-chirho.json",
                "--expected-plan-digest-chirho",
                "cb954aa53f8e6410ba2a854e41078a50a49569f32b3acb3d516652bdcf778ed4",
                "--issuer-secret-name-chirho",
                "credits-demo-offline-issuer-chirho",
                "--activation-authorization-chirho",
                "reviewed-inputs-chirho/activation-authorization-chirho.json",
                "--expected-activation-authorization-digest-chirho",
                "resident-ledger-activation-authorization-blake3-v1-chirho:\
                 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "--payer-credential-secret-name-chirho",
                "credits-demo-payer-credential-chirho",
                "--app-root-chirho",
                "examples-chirho/tree-credits-demo-chirho",
                "--json",
            ])
            .unwrap();
            match credits_chirho.command_chirho {
                CommandChirho::CreditsDemoSmokeChirho(args_chirho) => {
                    let cairn_cli_chirho::args_chirho::app_args_chirho::CreditsDemoSmokeArgsChirho {
                        config_chirho,
                        expected_config_digest_chirho,
                        plan_chirho,
                        expected_plan_digest_chirho,
                        issuer_secret_name_chirho,
                        activation_authorization_chirho,
                        expected_activation_authorization_digest_chirho,
                        payer_credential_secret_name_chirho,
                        app_root_chirho,
                        manifest_chirho,
                        json_chirho,
                    } = args_chirho;
                    assert_eq!(config_chirho, PathBuf::from("host-config-chirho.toml"));
                    assert_eq!(
                        expected_config_digest_chirho,
                        "87d0635dc870574c904f2454d6d42dadcfc69b9a2e2adef5ab76d70007ee8a81"
                    );
                    assert_eq!(plan_chirho, PathBuf::from("plan-canonical-chirho.json"));
                    assert_eq!(
                        expected_plan_digest_chirho,
                        "cb954aa53f8e6410ba2a854e41078a50a49569f32b3acb3d516652bdcf778ed4"
                    );
                    assert_eq!(issuer_secret_name_chirho, "credits-demo-offline-issuer-chirho");
                    assert_eq!(
                        activation_authorization_chirho,
                        PathBuf::from(
                            "reviewed-inputs-chirho/activation-authorization-chirho.json"
                        )
                    );
                    assert_eq!(
                        expected_activation_authorization_digest_chirho,
                        "resident-ledger-activation-authorization-blake3-v1-chirho:\
                         0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    );
                    assert_eq!(
                        payer_credential_secret_name_chirho,
                        "credits-demo-payer-credential-chirho"
                    );
                    assert_eq!(
                        app_root_chirho,
                        PathBuf::from("examples-chirho/tree-credits-demo-chirho")
                    );
                    assert!(manifest_chirho.is_none());
                    assert!(json_chirho);
                }
                other_chirho => panic!(
                    "expected credits-demo-smoke command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }

            let agent_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "agent-authored-backend-smoke",
                "--manifest",
                "examples-chirho/agent-authored-backend-source-manifest-chirho.example.json",
                "--overcap-manifest",
                "examples-chirho/agent-authored-backend-overcap-source-manifest-chirho.example.json",
                "--undeclared-effect-manifest",
                "examples-chirho/agent-authored-backend-undeclared-effect-source-manifest-chirho.example.json",
                "--brief",
                "examples-chirho/agent-authored-backend-brief-chirho.md",
                "--json",
            ])
            .unwrap();
            match agent_chirho.command_chirho {
                CommandChirho::AgentAuthoredBackendSmokeChirho(args_chirho) => {
                    let cairn_cli_chirho::args_chirho::app_args_chirho::AgentAuthoredBackendSmokeArgsChirho {
                        manifest_chirho,
                        overcap_manifest_chirho,
                        undeclared_effect_manifest_chirho,
                        brief_chirho,
                        json_chirho,
                    } = args_chirho;
                    assert_eq!(
                        manifest_chirho.unwrap(),
                        PathBuf::from(
                            "examples-chirho/agent-authored-backend-source-manifest-chirho.example.json"
                        )
                    );
                    assert_eq!(
                        overcap_manifest_chirho.unwrap(),
                        PathBuf::from(
                            "examples-chirho/agent-authored-backend-overcap-source-manifest-chirho.example.json"
                        )
                    );
                    assert_eq!(
                        undeclared_effect_manifest_chirho.unwrap(),
                        PathBuf::from(
                            "examples-chirho/agent-authored-backend-undeclared-effect-source-manifest-chirho.example.json"
                        )
                    );
                    assert_eq!(
                        brief_chirho.unwrap(),
                        PathBuf::from("examples-chirho/agent-authored-backend-brief-chirho.md")
                    );
                    assert!(json_chirho);
                }
                other_chirho => panic!(
                    "expected agent-authored-backend-smoke command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }

            let learner_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "learner-handover-drill",
                "--fixture-root-chirho",
                "/tmp/cairn-learner-handover-fixture-cli-chirho",
                "--allow-non-fixture-root-chirho",
                "--json",
            ])
            .unwrap();
            match learner_chirho.command_chirho {
                CommandChirho::LearnerHandoverDrillChirho(args_chirho) => {
                    let cairn_cli_chirho::args_chirho::app_args_chirho::LearnerHandoverDrillArgsChirho {
                        json_chirho,
                        fixture_root_chirho,
                        allow_non_fixture_root_chirho,
                    } = args_chirho;
                    assert_eq!(
                        fixture_root_chirho.unwrap(),
                        PathBuf::from("/tmp/cairn-learner-handover-fixture-cli-chirho")
                    );
                    assert!(allow_non_fixture_root_chirho);
                    assert!(json_chirho);
                }
                other_chirho => panic!(
                    "expected learner-handover-drill command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn readiness_and_ops_cli_accept_fail_gates_chirho() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let launch_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "launch-readiness",
                "--manifest",
                "examples-chirho/contact-persisting-source-manifest-chirho.example.json",
                "--json",
                "--fail-on-production-blockers",
            ])
            .unwrap();
            match launch_chirho.command_chirho {
                CommandChirho::LaunchReadinessChirho(args_chirho) => {
                    let cairn_cli_chirho::args_chirho::app_args_chirho::LaunchReadinessArgsChirho {
                        manifest_chirho,
                        json_chirho,
                        fail_on_production_blockers_chirho,
                    } = args_chirho;
                    assert_eq!(
                        manifest_chirho.unwrap(),
                        PathBuf::from(
                            "examples-chirho/contact-persisting-source-manifest-chirho.example.json"
                        )
                    );
                    assert!(json_chirho);
                    assert!(fail_on_production_blockers_chirho);
                }
                other_chirho => panic!(
                    "expected launch-readiness command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }

            let restore_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "ops-restore-drill",
                "--json",
                "--fail-on-restore-blockers",
            ])
            .unwrap();
            match restore_chirho.command_chirho {
                CommandChirho::OpsRestoreDrillChirho(args_chirho) => {
                    let cairn_cli_chirho::args_chirho::app_args_chirho::OpsRestoreDrillArgsChirho {
                        json_chirho,
                        fail_on_restore_blockers_chirho,
                    } = args_chirho;
                    assert!(json_chirho);
                    assert!(fail_on_restore_blockers_chirho);
                }
                other_chirho => panic!(
                    "expected ops-restore-drill command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }

            let custody_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "ops-custody-inventory",
                "--json",
                "--config",
                "/etc/cairn-chirho/cairn-chirho.toml",
                "--env-file",
                "/etc/cairn-chirho/cairn-chirho.env",
                "--fail-on-custody-blockers",
            ])
            .unwrap();
            match custody_chirho.command_chirho {
                CommandChirho::OpsCustodyInventoryChirho(args_chirho) => {
                    let cairn_cli_chirho::args_chirho::app_args_chirho::OpsCustodyInventoryArgsChirho {
                        json_chirho,
                        config_chirho,
                        env_file_chirho,
                        fail_on_custody_blockers_chirho,
                    } = args_chirho;
                    assert!(json_chirho);
                    assert_eq!(
                        config_chirho.unwrap(),
                        PathBuf::from("/etc/cairn-chirho/cairn-chirho.toml")
                    );
                    assert_eq!(
                        env_file_chirho.unwrap(),
                        PathBuf::from("/etc/cairn-chirho/cairn-chirho.env")
                    );
                    assert!(fail_on_custody_blockers_chirho);
                }
                other_chirho => panic!(
                    "expected ops-custody-inventory command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn app_authoring_cli_accepts_review_and_deploy_flags_chirho() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let candidate_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "app-source-candidate",
                "--manifest",
                "examples-chirho/agent-authored-backend-source-manifest-chirho.example.json",
                "--owner",
                "owner/demo-chirho",
                "--json",
            ])
            .unwrap();
            match candidate_chirho.command_chirho {
                CommandChirho::AppSourceCandidateChirho(args_chirho) => {
                    let cairn_cli_chirho::args_chirho::app_args_chirho::AppSourceCandidateArgsChirho {
                        manifest_chirho,
                        owner_chirho,
                        json_chirho,
                    } = args_chirho;
                    assert_eq!(
                        manifest_chirho,
                        PathBuf::from(
                            "examples-chirho/agent-authored-backend-source-manifest-chirho.example.json"
                        )
                    );
                    assert_eq!(owner_chirho.as_deref(), Some("owner/demo-chirho"));
                    assert!(json_chirho);
                }
                other_chirho => panic!(
                    "expected app-source-candidate command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }

            let deploy_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "app-source-deploy",
                "examples-chirho/perffection-intake-source-manifest-chirho.example.json",
                "--owner",
                "owner/perffection-operator-chirho",
            ])
            .unwrap();
            match deploy_chirho.command_chirho {
                CommandChirho::AppSourceDeployChirho(args_chirho) => {
                    let cairn_cli_chirho::args_chirho::app_args_chirho::AppSourceDeployArgsChirho {
                        manifest_chirho,
                        owner_chirho,
                        allow_unreviewed_dev_chirho,
                    } = args_chirho;
                    assert_eq!(
                        manifest_chirho,
                        PathBuf::from(
                            "examples-chirho/perffection-intake-source-manifest-chirho.example.json"
                        )
                    );
                    assert_eq!(
                        owner_chirho.as_deref(),
                        Some("owner/perffection-operator-chirho")
                    );
                    assert!(!allow_unreviewed_dev_chirho);
                }
                other_chirho => panic!(
                    "expected app-source-deploy command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }

            let deploy_unreviewed_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "app-source-deploy",
                "examples-chirho/perffection-intake-source-manifest-chirho.example.json",
                "--owner",
                "owner/perffection-operator-chirho",
                "--allow-unreviewed-dev",
            ])
            .unwrap();
            match deploy_unreviewed_chirho.command_chirho {
                CommandChirho::AppSourceDeployChirho(args_chirho) => {
                    assert!(args_chirho.allow_unreviewed_dev_chirho);
                }
                other_chirho => panic!(
                    "expected app-source-deploy command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }

            let review_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "app-source-review",
                "--manifest",
                "examples-chirho/agent-authored-backend-overcap-source-manifest-chirho.example.json",
                "--owner",
                "owner/demo-chirho",
                "--json",
            ])
            .unwrap();
            match review_chirho.command_chirho {
                CommandChirho::AppSourceReviewChirho(args_chirho) => {
                    let cairn_cli_chirho::args_chirho::app_args_chirho::AppSourceReviewArgsChirho {
                        manifest_chirho,
                        owner_chirho,
                        json_chirho,
                        steward_view_chirho,
                    } = args_chirho;
                    assert_eq!(
                        manifest_chirho,
                        PathBuf::from(
                            "examples-chirho/agent-authored-backend-overcap-source-manifest-chirho.example.json"
                        )
                    );
                    assert_eq!(owner_chirho.as_deref(), Some("owner/demo-chirho"));
                    assert!(json_chirho);
                    assert!(!steward_view_chirho);
                }
                other_chirho => panic!(
                    "expected app-source-review command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }

            let template_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "template-registry-set",
                "--template-id",
                "tree-template-landing-chirho",
                "--root-dag",
                "abc123",
                "--response-content-type",
                "text/html; charset=utf-8",
            ])
            .unwrap();
            match template_chirho.command_chirho {
                CommandChirho::TemplateRegistrySetChirho(args_chirho) => {
                    assert_eq!(
                        args_chirho.template_id_chirho,
                        "tree-template-landing-chirho"
                    );
                    assert_eq!(args_chirho.root_dag_chirho, "abc123");
                    assert_eq!(
                        args_chirho.response_content_type_chirho,
                        "text/html; charset=utf-8"
                    );
                }
                other_chirho => panic!(
                    "expected template-registry-set command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn app_source_deploy_requires_loud_dev_bypass_chirho() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let root_chirho = tmp_root_chirho("source-deploy-dev-bypass");
            let root_arg_chirho = root_chirho.display().to_string();
            let cli_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                root_arg_chirho.as_str(),
                "app-source-deploy",
                "missing-manifest-chirho.json",
            ])
            .unwrap();
            let error_chirho = cairn_cli_chirho::dispatch_chirho::run_cli_chirho(cli_chirho)
                .expect_err(
                    "unreviewed app-source-deploy should require the explicit dev bypass flag",
                );
            assert!(error_chirho.to_string().contains("--allow-unreviewed-dev"));
            let _ = std::fs::remove_dir_all(root_chirho);
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn review_promote_cli_accepts_source_review_report_chirho() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let report_hash_chirho =
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            let cli_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "review-promote",
                "--app",
                "agent-demo",
                "--owner",
                "owner/demo-chirho",
                "--candidate",
                "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                "--source-review-report",
                report_hash_chirho,
            ])
            .unwrap();
            match cli_chirho.command_chirho {
                CommandChirho::ReviewPromoteChirho(args_chirho) => {
                    let cairn_cli_chirho::args_chirho::app_args_chirho::ReviewPromoteArgsChirho {
                        app_chirho,
                        owner_chirho,
                        candidate_chirho,
                        source_review_report_chirho,
                        source_manifest_chirho,
                        raw_manifest_chirho,
                        ..
                    } = args_chirho;
                    assert_eq!(app_chirho, "agent-demo");
                    assert_eq!(owner_chirho, "owner/demo-chirho");
                    assert_eq!(
                        candidate_chirho,
                        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                    );
                    assert_eq!(
                        source_review_report_chirho.as_deref(),
                        Some(report_hash_chirho)
                    );
                    assert!(source_manifest_chirho.is_none());
                    assert!(raw_manifest_chirho.is_none());
                }
                other_chirho => panic!(
                    "expected review-promote command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }

            let envelope_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "review-policy-envelope-set",
                "--app",
                "agent-demo",
                "--owner",
                "owner/demo-chirho",
                "--allow-capability",
                "ClockChirho",
                "--max-cost-token",
                "25",
                "--allow-contract-ref",
                "blessed-contract:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ])
            .unwrap();
            match envelope_chirho.command_chirho {
                CommandChirho::ReviewPolicyEnvelopeSetChirho(args_chirho) => {
                    assert_eq!(args_chirho.app_chirho, "agent-demo");
                    assert_eq!(args_chirho.owner_chirho, "owner/demo-chirho");
                    assert_eq!(
                        args_chirho.allowed_capability_labels_chirho,
                        vec!["ClockChirho".to_string()]
                    );
                    assert_eq!(args_chirho.max_candidate_cost_token_chirho, 25);
                    assert_eq!(
                        args_chirho.allowed_contract_refs_chirho,
                        vec![
                            "blessed-contract:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                .to_string()
                        ]
                    );
                }
                other_chirho => panic!(
                    "expected review-policy-envelope-set command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn identity_and_money_cli_accept_recent_flags_chirho() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let inventory_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                ".cairn-chirho",
                "identity-credential-inventory",
                "--json",
                "--fail-on-legacy",
            ])
            .unwrap();
            match inventory_chirho.command_chirho {
                CommandChirho::IdentityCredentialInventoryChirho(args_chirho) => {
                    let cairn_cli_chirho::args_chirho::auth_args_chirho::IdentityCredentialInventoryArgsChirho {
                        json_chirho,
                        fail_on_legacy_chirho,
                    } = args_chirho;
                    assert!(json_chirho);
                    assert!(fail_on_legacy_chirho);
                }
                other_chirho => panic!(
                    "expected identity-credential-inventory command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }
        })
        .unwrap()
        .join()
        .unwrap();
}
