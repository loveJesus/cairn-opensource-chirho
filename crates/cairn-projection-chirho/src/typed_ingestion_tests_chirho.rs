// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

    use super::*;
    use cairn_core_chirho::cas_chirho;
    use crate::projection_chirho::{
        materialize_live_byte_baseline_chirho, materialize_live_chirho,
    };
    use cairn_model_economic_chirho::{
        AssetChirho, BillingPayerKindChirho, BillingPolicyModeChirho, BillingTagsChirho,
        CreditHoldStatusChirho, PostingChirho, ResourceChargeChirho, ResourceDecisionChirho,
    };
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_root_chirho() -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let n_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        let now_ms_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        std::env::temp_dir().join(format!(
            "cairn-typed-ingestion-test-{n_chirho}-{now_ms_chirho}"
        ))
    }

    fn sig_chirho(seed_chirho: char) -> String {
        seed_chirho.to_string().repeat(128)
    }

    fn cas_hash_chirho(root_chirho: &Path, bytes_chirho: &[u8]) -> HashChirho {
        cas_chirho::add_chirho(root_chirho, bytes_chirho).unwrap()
    }

    fn write_record_chirho<TChirho: Serialize>(
        root_chirho: &Path,
        surface_chirho: &str,
        record_chirho: &TChirho,
    ) -> String {
        let line_chirho = serde_json::to_string(record_chirho).unwrap();
        fs::write(root_chirho.join(surface_chirho), format!("{line_chirho}\n")).unwrap();
        line_chirho
    }

    fn append_line_chirho(root_chirho: &Path, surface_chirho: &str, line_chirho: &str) {
        use std::io::Write;
        let mut file_chirho = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(root_chirho.join(surface_chirho))
            .unwrap();
        writeln!(file_chirho, "{line_chirho}").unwrap();
    }

    fn build_green_ring_a_root_chirho(root_chirho: &Path) -> Vec<String> {
        fs::create_dir_all(root_chirho).unwrap();
        let policy_hash_chirho = cas_hash_chirho(root_chirho, b"policy-bytes-chirho");
        let previous_policy_hash_chirho = cas_hash_chirho(root_chirho, b"previous-policy-chirho");
        let price_book_hash_chirho = cas_hash_chirho(root_chirho, b"price-book-chirho");
        let billing_policy_hash_chirho = cas_hash_chirho(root_chirho, b"billing-policy-chirho");
        let resource_policy_cas_hash_chirho =
            cas_hash_chirho(root_chirho, b"resource-policy-chirho");
        let previous_resource_hash_chirho =
            cas_hash_chirho(root_chirho, b"previous-resource-policy-chirho");

        let ledger_chirho = LedgerEntryChirho {
            seq_chirho: 0,
            schema_chirho: LEDGER_ENTRY_SCHEMA_CHIRHO.to_string(),
            memo_chirho: "ring-a ledger row".to_string(),
            postings_chirho: vec![
                PostingChirho {
                    account_chirho: "cash/customer-chirho".to_string(),
                    asset_chirho: AssetChirho::TokenChirho,
                    amount_chirho: -15,
                },
                PostingChirho {
                    account_chirho: "cash/platform-chirho".to_string(),
                    asset_chirho: AssetChirho::TokenChirho,
                    amount_chirho: 15,
                },
            ],
            billing_tags_chirho: BillingTagsChirho::default(),
            at_ms_chirho: 1,
            sig_chirho: sig_chirho('a'),
            op_binding_chirho: None,
        };
        let billing_policy_chirho = BillingPolicyRecordChirho {
            seq_chirho: 0,
            schema_chirho: BILLING_POLICY_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: "ring-a-chirho".to_string(),
            owner_principal_chirho: "owner/ring-a-chirho".to_string(),
            billing_policy_chirho: policy_hash_chirho,
            previous_chirho: Some(previous_policy_hash_chirho),
            at_ms_chirho: 2,
            transition_id_chirho: String::new(),
            prepared_writer_fence_epoch_chirho: None,
            sig_chirho: sig_chirho('b'),
        };
        let billing_usage_chirho = BillingUsageRecordChirho {
            seq_chirho: 0,
            schema_chirho: BILLING_USAGE_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: "ring-a-chirho".to_string(),
            effect_chirho: "WriteStoreChirho".to_string(),
            caller_chirho: "user/ring-a-chirho".to_string(),
            payer_chirho: "user/ring-a-chirho".to_string(),
            payer_kind_chirho: BillingPayerKindChirho::UserChirho,
            provider_chirho: "cairn-local-chirho".to_string(),
            price_chirho: 15,
            price_book_chirho: price_book_hash_chirho,
            billing_policy_chirho: Some(billing_policy_hash_chirho),
            mode_chirho: BillingPolicyModeChirho::UserPaysChirho,
            ledger_seq_chirho: 0,
            cache_hit_chirho: false,
            nway_settlement_chirho: false,
            external_provider_chirho: None,
            external_cost_token_chirho: 0,
            platform_fee_chirho: 0,
            owner_margin_chirho: 0,
            credit_hold_chirho: None,
            billing_tags_chirho: BillingTagsChirho::default(),
            at_ms_chirho: 3,
            sig_chirho: sig_chirho('c'),
        };
        let billing_compensation_chirho = BillingCompensationRecordChirho {
            seq_chirho: 0,
            schema_chirho: BILLING_COMPENSATION_RECORD_SCHEMA_CHIRHO.to_string(),
            original_usage_seq_chirho: 0,
            ledger_seq_chirho: 0,
            app_chirho: "app/ring-a-chirho".to_string(),
            caller_chirho: "user/ring-a-chirho".to_string(),
            payer_chirho: "user/ring-a-chirho".to_string(),
            amount_token_chirho: -15,
            reason_chirho: "operator correction".to_string(),
            billing_tags_chirho: BillingTagsChirho::default(),
            at_ms_chirho: 4,
            sig_chirho: sig_chirho('d'),
        };
        let credit_hold_chirho = CreditHoldRecordChirho {
            seq_chirho: 0,
            schema_chirho: CREDIT_HOLD_RECORD_SCHEMA_CHIRHO.to_string(),
            hold_id_chirho: "hold/ring-a-chirho".to_string(),
            hold_account_chirho: "hold/account-chirho".to_string(),
            app_chirho: "app/ring-a-chirho".to_string(),
            effect_chirho: "PaidEffectChirho".to_string(),
            caller_chirho: "user/ring-a-chirho".to_string(),
            payer_chirho: "user/ring-a-chirho".to_string(),
            authorized_token_chirho: 20,
            settled_token_chirho: 0,
            released_token_chirho: 0,
            reserve_ledger_seq_chirho: 0,
            settlement_ledger_seq_chirho: None,
            release_ledger_seq_chirho: None,
            status_chirho: CreditHoldStatusChirho::OpenChirho,
            billing_tags_chirho: BillingTagsChirho::default(),
            at_ms_chirho: 5,
            sig_chirho: sig_chirho('e'),
        };
        let resource_policy_chirho = ResourcePolicyRecordChirho {
            seq_chirho: 0,
            schema_chirho: RESOURCE_POLICY_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: "app/ring-a-chirho".to_string(),
            owner_principal_chirho: "owner/ring-a-chirho".to_string(),
            resource_policy_chirho: resource_policy_cas_hash_chirho.clone(),
            previous_chirho: None,
            at_ms_chirho: 6,
            transition_id_chirho: String::new(),
            prepared_writer_fence_epoch_chirho: None,
            sig_chirho: sig_chirho('f'),
        };
        let resource_unset_chirho = ResourcePolicyUnsetRecordChirho {
            seq_chirho: 0,
            schema_chirho: RESOURCE_POLICY_UNSET_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: "app/ring-a-chirho".to_string(),
            owner_principal_chirho: "owner/ring-a-chirho".to_string(),
            previous_chirho: previous_resource_hash_chirho,
            at_ms_chirho: 7,
            sig_chirho: sig_chirho('g'),
        };
        let resource_usage_chirho = ResourceUsageRecordChirho {
            seq_chirho: 0,
            schema_chirho: RESOURCE_USAGE_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: "app/ring-a-chirho".to_string(),
            user_chirho: "user/ring-a-chirho".to_string(),
            actor_chirho: "user/ring-a-chirho".to_string(),
            section_chirho: "store-chirho".to_string(),
            action_chirho: "write-chirho".to_string(),
            effect_chirho: Some("WriteStoreChirho".to_string()),
            run_chirho: None,
            resource_policy_chirho: resource_policy_cas_hash_chirho,
            charges_chirho: vec![ResourceChargeChirho {
                resource_chirho: "write-token-chirho".to_string(),
                amount_chirho: 1,
            }],
            bridges_chirho: Vec::new(),
            decision_chirho: ResourceDecisionChirho::AllowedChirho,
            at_ms_chirho: 8,
            sig_chirho: sig_chirho('h'),
        };
        let review_policy_envelope_chirho = ReviewPolicyEnvelopeRecordChirho {
            seq_chirho: 0,
            schema_chirho: REVIEW_POLICY_ENVELOPE_SCHEMA_CHIRHO.to_string(),
            app_chirho: "app/ring-a-chirho".to_string(),
            scope_chirho:
                cairn_model_review_chirho::ReviewPolicyEnvelopeScopeChirho::OwnerPrincipalChirho {
                    owner_principal_chirho: "owner/ring-a-chirho".to_string(),
                },
            allowed_capability_labels_chirho: vec!["ClockChirho".to_string()],
            max_candidate_cost_token_chirho: 0,
            allowed_contract_refs_chirho: Vec::new(),
            at_ms_chirho: 11,
            sig_chirho: sig_chirho('k'),
        };
        let gate1_anchor_chirho = Gate1LogAnchorRecordChirho {
            schema_chirho: GATE1_LOG_ANCHOR_RECORD_SCHEMA_CHIRHO.to_string(),
            seq_chirho: 0,
            family_chirho: "ledger-chirho.jsonl".to_string(),
            line_count_chirho: 1,
            prefix_digest_chirho: HashChirho("1".repeat(64)),
            state_digest_chirho: None,
            prev_anchor_hash_chirho: None,
            at_ms_chirho: 12,
            key_id_chirho: "2".repeat(64),
            sig_chirho: sig_chirho('l'),
        };

        vec![
            write_record_chirho(root_chirho, "ledger-chirho.jsonl", &ledger_chirho),
            write_record_chirho(
                root_chirho,
                "billing-policy-records-chirho.jsonl",
                &billing_policy_chirho,
            ),
            write_record_chirho(
                root_chirho,
                "billing-usage-chirho.jsonl",
                &billing_usage_chirho,
            ),
            write_record_chirho(
                root_chirho,
                "billing-compensations-chirho.jsonl",
                &billing_compensation_chirho,
            ),
            write_record_chirho(
                root_chirho,
                "credit-holds-chirho.jsonl",
                &credit_hold_chirho,
            ),
            write_record_chirho(
                root_chirho,
                "resource-policy-records-chirho.jsonl",
                &resource_policy_chirho,
            ),
            write_record_chirho(
                root_chirho,
                "resource-policy-unset-records-chirho.jsonl",
                &resource_unset_chirho,
            ),
            write_record_chirho(
                root_chirho,
                "resource-usage-chirho.jsonl",
                &resource_usage_chirho,
            ),
            write_record_chirho(
                root_chirho,
                "review-policy-envelopes-chirho.jsonl",
                &review_policy_envelope_chirho,
            ),
            write_record_chirho(
                root_chirho,
                "gate1-log-anchors-chirho.jsonl",
                &gate1_anchor_chirho,
            ),
        ]
    }

    #[test]
    fn typed_ingestion_ring_a_green_matches_live_clsd_chirho() {
        let root_chirho = tmp_root_chirho();
        let _lines_chirho = build_green_ring_a_root_chirho(&root_chirho);

        let report_chirho = verify_typed_ingestion_parity_chirho(&root_chirho).unwrap();
        assert_eq!(
            report_chirho.schema_chirho,
            TYPED_INGESTION_PARITY_REPORT_SCHEMA_CHIRHO
        );
        assert_eq!(report_chirho.typed_surface_count_chirho, 10);
        assert_eq!(
            report_chirho.static_surface_manifest_count_chirho,
            static_surface_manifest_chirho().len()
        );
        assert_eq!(report_chirho.checked_line_count_chirho, 10);
        assert!(report_chirho.clsd_digests_match_chirho);
        assert_eq!(
            report_chirho.typed_clsd_digest_chirho,
            report_chirho.typed_recover_clsd_digest_chirho
        );
        assert_eq!(
            report_chirho.live_clsd_digest_chirho,
            report_chirho.byte_baseline_clsd_digest_chirho
        );
        assert_eq!(
            report_chirho.typed_surface_names_chirho,
            ring_a_typed_surfaces_chirho()
                .iter()
                .map(|surface_chirho| surface_chirho.name_chirho.to_string())
                .collect::<Vec<_>>()
        );

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn materialize_live_wrapper_matches_byte_baseline_chirho() {
        let root_chirho = tmp_root_chirho();
        let _lines_chirho = build_green_ring_a_root_chirho(&root_chirho);

        let wrapper_digest_chirho =
            clsd_digest_chirho(&materialize_live_chirho(&root_chirho).unwrap());
        let baseline_digest_chirho =
            clsd_digest_chirho(&materialize_live_byte_baseline_chirho(&root_chirho).unwrap());
        assert_eq!(wrapper_digest_chirho, baseline_digest_chirho);

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn typed_recover_alias_matches_typed_ingestion_materializer_chirho() {
        let root_chirho = tmp_root_chirho();
        let _lines_chirho = build_green_ring_a_root_chirho(&root_chirho);

        let (typed_recover_state_chirho, typed_recover_count_chirho) =
            materialize_typed_recover_chirho(&root_chirho).unwrap();
        let (typed_ingestion_state_chirho, typed_ingestion_count_chirho) =
            materialize_typed_ingestion_chirho(&root_chirho).unwrap();
        assert_eq!(typed_recover_count_chirho, typed_ingestion_count_chirho);
        assert_eq!(
            clsd_digest_chirho(&typed_recover_state_chirho),
            clsd_digest_chirho(&typed_ingestion_state_chirho)
        );

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn typed_ingestion_surface_mapping_is_manifest_backed_chirho() {
        let manifest_chirho = static_surface_manifest_chirho()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        for surface_chirho in ring_a_typed_surfaces_chirho() {
            assert!(
                manifest_chirho.contains(surface_chirho.name_chirho),
                "typed surface {} must be present in static_surface_manifest_chirho",
                surface_chirho.name_chirho
            );
        }
    }

    #[test]
    fn typed_ingestion_unknown_extra_key_is_red_with_field_name_chirho() {
        let root_chirho = tmp_root_chirho();
        fs::create_dir_all(&root_chirho).unwrap();
        let ledger_chirho = LedgerEntryChirho {
            seq_chirho: 0,
            schema_chirho: LEDGER_ENTRY_SCHEMA_CHIRHO.to_string(),
            memo_chirho: "unknown key".to_string(),
            postings_chirho: Vec::new(),
            billing_tags_chirho: BillingTagsChirho::default(),
            at_ms_chirho: 1,
            sig_chirho: sig_chirho('k'),
            op_binding_chirho: None,
        };
        let mut line_chirho = serde_json::to_string(&ledger_chirho).unwrap();
        line_chirho.insert_str(line_chirho.len() - 1, ",\"surprise_chirho\":true");
        fs::write(
            root_chirho.join("ledger-chirho.jsonl"),
            format!("{line_chirho}\n"),
        )
        .unwrap();

        let error_chirho = verify_typed_ingestion_parity_chirho(&root_chirho).unwrap_err();
        let text_chirho = format!("{error_chirho:#}");
        assert!(text_chirho.contains("ledger-chirho.jsonl"));
        assert!(text_chirho.contains("surprise_chirho"));

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn typed_ingestion_unknown_nonempty_schema_is_red_chirho() {
        let root_chirho = tmp_root_chirho();
        fs::create_dir_all(&root_chirho).unwrap();
        let ledger_chirho = LedgerEntryChirho {
            seq_chirho: 0,
            schema_chirho: "ledger-entry-v9-chirho".to_string(),
            memo_chirho: "bad schema".to_string(),
            postings_chirho: Vec::new(),
            billing_tags_chirho: BillingTagsChirho::default(),
            at_ms_chirho: 1,
            sig_chirho: sig_chirho('l'),
            op_binding_chirho: None,
        };
        write_record_chirho(&root_chirho, "ledger-chirho.jsonl", &ledger_chirho);

        let error_chirho = verify_typed_ingestion_parity_chirho(&root_chirho).unwrap_err();
        let text_chirho = format!("{error_chirho:#}");
        assert!(text_chirho.contains("unsupported schema_chirho"));
        assert!(text_chirho.contains("ledger-entry-v9-chirho"));

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn typed_ingestion_reordered_json_bytes_are_red_before_digest_chirho() {
        let root_chirho = tmp_root_chirho();
        fs::create_dir_all(&root_chirho).unwrap();
        let reordered_line_chirho = format!(
            "{{\"memo_chirho\":\"reordered\",\"seq_chirho\":0,\"schema_chirho\":\"{}\",\"postings_chirho\":[],\"billing_tags_chirho\":{{}},\"at_ms_chirho\":1,\"sig_chirho\":\"{}\"}}",
            LEDGER_ENTRY_SCHEMA_CHIRHO,
            sig_chirho('m')
        );
        fs::write(
            root_chirho.join("ledger-chirho.jsonl"),
            format!("{reordered_line_chirho}\n"),
        )
        .unwrap();

        let error_chirho = verify_typed_ingestion_parity_chirho(&root_chirho).unwrap_err();
        let text_chirho = format!("{error_chirho:#}");
        assert!(text_chirho.contains("byte mismatch"));
        assert!(text_chirho.contains("first key order mismatch"));

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn typed_ingestion_missing_cas_dependency_stays_red_chirho() {
        let root_chirho = tmp_root_chirho();
        fs::create_dir_all(&root_chirho).unwrap();
        let missing_hash_chirho = HashChirho("b".repeat(64));
        let billing_policy_chirho = BillingPolicyRecordChirho {
            seq_chirho: 0,
            schema_chirho: BILLING_POLICY_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: "app/missing-cas-chirho".to_string(),
            owner_principal_chirho: "owner/missing-cas-chirho".to_string(),
            billing_policy_chirho: missing_hash_chirho,
            previous_chirho: None,
            at_ms_chirho: 1,
            transition_id_chirho: String::new(),
            prepared_writer_fence_epoch_chirho: None,
            sig_chirho: sig_chirho('n'),
        };
        write_record_chirho(
            &root_chirho,
            "billing-policy-records-chirho.jsonl",
            &billing_policy_chirho,
        );

        let error_chirho = verify_typed_ingestion_parity_chirho(&root_chirho).unwrap_err();
        assert!(format!("{error_chirho:#}").contains("Missing or tampered CAS dependency"));

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn typed_anchor_schema_is_required_from_first_record_chirho() {
        let root_chirho = tmp_root_chirho();
        fs::create_dir_all(&root_chirho).unwrap();
        let anchor_chirho = Gate1LogAnchorRecordChirho {
            schema_chirho: String::new(),
            seq_chirho: 0,
            family_chirho: "ledger-chirho.jsonl".to_string(),
            line_count_chirho: 1,
            prefix_digest_chirho: HashChirho("4".repeat(64)),
            state_digest_chirho: None,
            prev_anchor_hash_chirho: None,
            at_ms_chirho: 1,
            key_id_chirho: "5".repeat(64),
            sig_chirho: sig_chirho('s'),
        };
        write_record_chirho(
            &root_chirho,
            "gate1-log-anchors-chirho.jsonl",
            &anchor_chirho,
        );

        let error_chirho = typed_gate1_log_anchor_records_chirho(&root_chirho).unwrap_err();
        let text_chirho = format!("{error_chirho:#}");
        assert!(text_chirho.contains("unsupported schema_chirho"));
        assert!(text_chirho.contains("gate1-log-anchors-chirho.jsonl"));

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn typed_anchor_reordered_json_is_red_chirho() {
        let root_chirho = tmp_root_chirho();
        fs::create_dir_all(&root_chirho).unwrap();
        let line_chirho = format!(
            "{{\"seq_chirho\":0,\"schema_chirho\":\"{}\",\"family_chirho\":\"ledger-chirho.jsonl\",\"line_count_chirho\":1,\"prefix_digest_chirho\":\"{}\",\"at_ms_chirho\":1,\"key_id_chirho\":\"{}\",\"sig_chirho\":\"{}\"}}",
            GATE1_LOG_ANCHOR_RECORD_SCHEMA_CHIRHO,
            "6".repeat(64),
            "7".repeat(64),
            sig_chirho('t')
        );
        fs::write(
            root_chirho.join("gate1-log-anchors-chirho.jsonl"),
            format!("{line_chirho}\n"),
        )
        .unwrap();

        let error_chirho = typed_gate1_log_anchor_records_chirho(&root_chirho).unwrap_err();
        let text_chirho = format!("{error_chirho:#}");
        assert!(text_chirho.contains("byte mismatch"));
        assert!(text_chirho.contains("first key order mismatch"));

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn typed_ingestion_direct_materialize_pins_typed_path_cas_walk_chirho() {
        let root_chirho = tmp_root_chirho();
        fs::create_dir_all(&root_chirho).unwrap();
        let missing_hash_chirho = HashChirho("d".repeat(64));
        let billing_policy_chirho = BillingPolicyRecordChirho {
            seq_chirho: 0,
            schema_chirho: BILLING_POLICY_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: "app/direct-missing-cas-chirho".to_string(),
            owner_principal_chirho: "owner/direct-missing-cas-chirho".to_string(),
            billing_policy_chirho: missing_hash_chirho,
            previous_chirho: None,
            at_ms_chirho: 1,
            transition_id_chirho: String::new(),
            prepared_writer_fence_epoch_chirho: None,
            sig_chirho: sig_chirho('q'),
        };
        write_record_chirho(
            &root_chirho,
            "billing-policy-records-chirho.jsonl",
            &billing_policy_chirho,
        );

        let error_chirho = materialize_typed_ingestion_chirho(&root_chirho).unwrap_err();
        assert!(
            format!("{error_chirho:#}").contains("Missing or tampered CAS dependency"),
            "typed materialize itself must run CAS verification so live-road parity cannot mask a missing typed-path CAS walk"
        );

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn typed_billing_policy_loader_requires_cas_dependencies_chirho() {
        let root_chirho = tmp_root_chirho();
        fs::create_dir_all(&root_chirho).unwrap();
        let missing_hash_chirho = HashChirho("e".repeat(64));
        let billing_policy_chirho = BillingPolicyRecordChirho {
            seq_chirho: 0,
            schema_chirho: BILLING_POLICY_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: "app/loader-missing-cas-chirho".to_string(),
            owner_principal_chirho: "owner/loader-missing-cas-chirho".to_string(),
            billing_policy_chirho: missing_hash_chirho.clone(),
            previous_chirho: None,
            at_ms_chirho: 1,
            transition_id_chirho: String::new(),
            prepared_writer_fence_epoch_chirho: None,
            sig_chirho: sig_chirho('r'),
        };
        write_record_chirho(
            &root_chirho,
            "billing-policy-records-chirho.jsonl",
            &billing_policy_chirho,
        );

        let error_chirho = typed_billing_policy_records_chirho(&root_chirho).unwrap_err();
        let text_chirho = format!("{error_chirho:#}");
        assert!(text_chirho.contains("Missing or tampered CAS dependency"));
        assert!(text_chirho.contains("billing-policy-records-chirho.jsonl"));
        assert!(text_chirho.contains(&missing_hash_chirho.0));

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn typed_prefix_loader_requires_cas_dependencies_chirho() {
        let root_chirho = tmp_root_chirho();
        fs::create_dir_all(&root_chirho).unwrap();
        let missing_hash_chirho = HashChirho("f".repeat(64));
        let billing_policy_chirho = BillingPolicyRecordChirho {
            seq_chirho: 0,
            schema_chirho: BILLING_POLICY_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: "app/prefix-missing-cas-chirho".to_string(),
            owner_principal_chirho: "owner/prefix-missing-cas-chirho".to_string(),
            billing_policy_chirho: missing_hash_chirho.clone(),
            previous_chirho: None,
            at_ms_chirho: 1,
            transition_id_chirho: String::new(),
            prepared_writer_fence_epoch_chirho: None,
            sig_chirho: sig_chirho('u'),
        };
        write_record_chirho(
            &root_chirho,
            "billing-policy-records-chirho.jsonl",
            &billing_policy_chirho,
        );

        let error_chirho = typed_billing_policy_records_prefix_chirho(&root_chirho, 1).unwrap_err();
        let text_chirho = format!("{error_chirho:#}");
        assert!(text_chirho.contains("Missing or tampered CAS dependency"));
        assert!(text_chirho.contains("billing-policy-records-chirho.jsonl"));
        assert!(text_chirho.contains(&missing_hash_chirho.0));

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn typed_prefix_loader_ignores_unanchored_tail_chirho() {
        let root_chirho = tmp_root_chirho();
        fs::create_dir_all(&root_chirho).unwrap();
        let billing_policy_chirho = BillingPolicyRecordChirho {
            seq_chirho: 0,
            schema_chirho: BILLING_POLICY_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: "app/prefix-tail-chirho".to_string(),
            owner_principal_chirho: "owner/prefix-tail-chirho".to_string(),
            billing_policy_chirho: cas_hash_chirho(&root_chirho, b"prefix-tail-policy-chirho"),
            previous_chirho: None,
            at_ms_chirho: 1,
            transition_id_chirho: String::new(),
            prepared_writer_fence_epoch_chirho: None,
            sig_chirho: sig_chirho('v'),
        };
        write_record_chirho(
            &root_chirho,
            "billing-policy-records-chirho.jsonl",
            &billing_policy_chirho,
        );
        append_line_chirho(
            &root_chirho,
            "billing-policy-records-chirho.jsonl",
            "not-json-tail-chirho",
        );

        let records_chirho = typed_billing_policy_records_prefix_chirho(&root_chirho, 1).unwrap();
        assert_eq!(records_chirho.len(), 1);
        assert!(typed_billing_policy_records_chirho(&root_chirho).is_err());

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn typed_ingestion_malformed_middle_row_is_red_by_typed_parse_chirho() {
        let root_chirho = tmp_root_chirho();
        fs::create_dir_all(&root_chirho).unwrap();
        let ledger_chirho = LedgerEntryChirho {
            seq_chirho: 0,
            schema_chirho: LEDGER_ENTRY_SCHEMA_CHIRHO.to_string(),
            memo_chirho: "first".to_string(),
            postings_chirho: Vec::new(),
            billing_tags_chirho: BillingTagsChirho::default(),
            at_ms_chirho: 1,
            sig_chirho: sig_chirho('o'),
            op_binding_chirho: None,
        };
        append_line_chirho(
            &root_chirho,
            "ledger-chirho.jsonl",
            &serde_json::to_string(&ledger_chirho).unwrap(),
        );
        append_line_chirho(&root_chirho, "ledger-chirho.jsonl", "not-json");
        append_line_chirho(
            &root_chirho,
            "ledger-chirho.jsonl",
            &serde_json::to_string(&ledger_chirho).unwrap(),
        );

        let error_chirho = verify_typed_ingestion_parity_chirho(&root_chirho).unwrap_err();
        let text_chirho = format!("{error_chirho:#}");
        assert!(text_chirho.contains("typed ingestion parse failed"));
        assert!(text_chirho.contains("ledger-chirho.jsonl line 1"));

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn typed_ingestion_hybrid_untyped_cas_walk_stays_red_chirho() {
        let root_chirho = tmp_root_chirho();
        fs::create_dir_all(&root_chirho).unwrap();
        let missing_manifest_chirho = "c".repeat(64);
        let line_chirho = format!(
            "{{\"app_chirho\":\"hybrid-app\",\"manifest_hash_chirho\":\"{}\"}}",
            missing_manifest_chirho
        );
        fs::write(
            root_chirho.join("app-records-chirho.jsonl"),
            format!("{line_chirho}\n"),
        )
        .unwrap();

        let error_chirho = verify_typed_ingestion_parity_chirho(&root_chirho).unwrap_err();
        assert!(format!("{error_chirho:#}").contains("Missing or tampered CAS dependency"));

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn typed_ingestion_accepts_legacy_empty_schema_like_root_verifier_chirho() {
        let root_chirho = tmp_root_chirho();
        fs::create_dir_all(&root_chirho).unwrap();
        // Mirrors src/economic_flows_chirho/ledger_chirho.rs:524-526: empty schema is accepted;
        // unknown non-empty schema fails. This rung keeps that root verifier behavior.
        let legacy_ledger_chirho = LedgerEntryChirho {
            seq_chirho: 0,
            schema_chirho: String::new(),
            memo_chirho: "legacy empty schema".to_string(),
            postings_chirho: Vec::new(),
            billing_tags_chirho: BillingTagsChirho::default(),
            at_ms_chirho: 1,
            sig_chirho: sig_chirho('p'),
            op_binding_chirho: None,
        };
        let line_chirho =
            write_record_chirho(&root_chirho, "ledger-chirho.jsonl", &legacy_ledger_chirho);
        assert!(!line_chirho.contains("schema_chirho"));

        verify_typed_ingestion_parity_chirho(&root_chirho).unwrap();

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn billing_policy_typed_ingestion_accepts_canonical_v1_and_v2_only_chirho() {
        let v1_chirho = BillingPolicyRecordChirho {
            seq_chirho: 0,
            schema_chirho: BILLING_POLICY_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: "typed-billing-chirho".to_string(),
            owner_principal_chirho: "owner/typed-billing-chirho".to_string(),
            billing_policy_chirho: HashChirho("a".repeat(64)),
            previous_chirho: None,
            at_ms_chirho: 1,
            transition_id_chirho: String::new(),
            prepared_writer_fence_epoch_chirho: None,
            sig_chirho: "b".repeat(128),
        };
        let v1_line_chirho = serde_json::to_string(&v1_chirho).unwrap();
        assert_eq!(
            parse_billing_policy_record_chirho(&v1_line_chirho).unwrap(),
            v1_line_chirho
        );

        let mut v2_chirho = v1_chirho;
        v2_chirho.schema_chirho = BILLING_POLICY_RECORD_V2_SCHEMA_CHIRHO.to_string();
        v2_chirho.transition_id_chirho =
            "head-transition-blake3-chirho:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                .to_string();
        v2_chirho.prepared_writer_fence_epoch_chirho = Some(7);
        let v2_line_chirho = serde_json::to_string(&v2_chirho).unwrap();
        assert_eq!(
            parse_billing_policy_record_chirho(&v2_line_chirho).unwrap(),
            v2_line_chirho
        );

        v2_chirho.schema_chirho = "billing-policy-record-v3-chirho".to_string();
        let error_chirho = parse_billing_policy_record_chirho(
            &serde_json::to_string(&v2_chirho).unwrap(),
        )
        .unwrap_err()
        .to_string();
        assert!(error_chirho.contains("unsupported schema_chirho"));
    }
