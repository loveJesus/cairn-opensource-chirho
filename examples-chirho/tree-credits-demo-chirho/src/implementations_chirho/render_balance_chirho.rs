// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Render the credits balance page from the typed published-projection response. The runtime's
//! verdict, verified cost class, and evidence are authoritative; app code never derives staleness.
//!
//! Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md`.

use cairn_node_templating_chirho::escape_html_chirho;

use crate::types_chirho::published_projection_read_chirho::{
    AccountNetProjectionRowV1Chirho, PublishedProjectionEvidenceV2Chirho,
    PublishedProjectionReadResponseV2Chirho, PublishedProjectionVerdictV2Chirho,
    BALANCE_KIND_ID_CHIRHO,
};

pub fn render_balance_chirho(response_chirho: &PublishedProjectionReadResponseV2Chirho) -> String {
    match &response_chirho.outcome_chirho {
        PublishedProjectionVerdictV2Chirho::FreshChirho {
            evidence_chirho,
            lag_ms_chirho,
        } => render_servable_balance_chirho(
            response_chirho,
            "fresh-chirho",
            evidence_chirho,
            *lag_ms_chirho,
            None,
        ),
        PublishedProjectionVerdictV2Chirho::DegradedChirho {
            evidence_chirho,
            lag_ms_chirho,
            max_lag_ms_chirho,
        } => render_servable_balance_chirho(
            response_chirho,
            "degraded-chirho",
            evidence_chirho,
            *lag_ms_chirho,
            Some(*max_lag_ms_chirho),
        ),
        PublishedProjectionVerdictV2Chirho::ClassifierRefusedChirho { refusal_chirho } => {
            render_read_refusal_chirho("classifier-refused-chirho", refusal_chirho.label_chirho())
        }
        PublishedProjectionVerdictV2Chirho::GateRefusedChirho { refusal_chirho } => {
            render_read_refusal_chirho("gate-refused-chirho", refusal_chirho.label_chirho())
        }
    }
}

pub fn render_invalid_balance_transport_chirho() -> String {
    render_read_refusal_chirho("transport-refused-chirho", "invalid-transport-chirho")
}

fn render_servable_balance_chirho(
    response_chirho: &PublishedProjectionReadResponseV2Chirho,
    verdict_chirho: &str,
    evidence_chirho: &PublishedProjectionEvidenceV2Chirho,
    lag_ms_chirho: u64,
    max_lag_ms_chirho: Option<u64>,
) -> String {
    let Ok(Some(view_chirho)) = response_chirho.account_net_view_chirho() else {
        return render_invalid_balance_transport_chirho();
    };
    let mut matching_rows_chirho = view_chirho.rows_chirho.iter().filter(|row_chirho| {
        row_chirho.account_chirho.owner_chirho == response_chirho.viewer_principal_chirho
            && row_chirho.account_chirho.kind_id_chirho == BALANCE_KIND_ID_CHIRHO
    });
    let Some(row_chirho) = matching_rows_chirho.next() else {
        return render_read_refusal_chirho(
            "view-refused-chirho",
            "balance-coordinate-missing-chirho",
        );
    };
    if matching_rows_chirho.next().is_some() {
        return render_read_refusal_chirho(
            "view-refused-chirho",
            "balance-coordinate-duplicated-chirho",
        );
    }
    render_balance_page_chirho(
        row_chirho,
        verdict_chirho,
        evidence_chirho,
        lag_ms_chirho,
        max_lag_ms_chirho,
    )
}

fn render_balance_page_chirho(
    row_chirho: &AccountNetProjectionRowV1Chirho,
    verdict_chirho: &str,
    evidence_chirho: &PublishedProjectionEvidenceV2Chirho,
    lag_ms_chirho: u64,
    max_lag_ms_chirho: Option<u64>,
) -> String {
    let owner_chirho = escape_html_chirho(&row_chirho.account_chirho.owner_chirho);
    let kind_chirho = escape_html_chirho(&row_chirho.account_chirho.kind_id_chirho);
    let source_seq_chirho = evidence_chirho.source_seq_chirho;
    // The AUTHENTICATED cut coordinates the runtime handed this render — bounded ids/digests/ints
    // only — exposed as data attributes so operator evidence can bind the served page to its
    // exact named verified cut (never value-only) (#6071).
    let descriptor_chirho = escape_html_chirho(&evidence_chirho.descriptor_ref_chirho);
    let family_chirho = escape_html_chirho(&evidence_chirho.source_family_id_chirho);
    let prefix_chirho = escape_html_chirho(&evidence_chirho.signed_prefix_digest_chirho);
    let state_chirho = escape_html_chirho(&evidence_chirho.state_digest_chirho);
    let hlc_physical_chirho = evidence_chirho.source_hlc_chirho.physical_ms_chirho;
    let hlc_logical_chirho = evidence_chirho.source_hlc_chirho.logical_chirho;
    let verdict_detail_chirho = match max_lag_ms_chirho {
        Some(max_lag_ms_chirho) => format!(
            "{verdict_chirho}; source seq {source_seq_chirho}; lag {lag_ms_chirho} ms; contract max {max_lag_ms_chirho} ms"
        ),
        None => format!(
            "{verdict_chirho}; source seq {source_seq_chirho}; lag {lag_ms_chirho} ms"
        ),
    };
    format!(
        concat!(
            r#"<!doctype html><html><head><meta charset="utf-8"><title>Credits</title>"#,
            r#"<link rel="stylesheet" href="/app-assets-chirho/credits-demo-chirho/by-name-chirho/credits-demo-chirho.css">"#,
            r#"</head><body><main><h1>Prepaid credits</h1>"#,
            r#"<p class="balance-chirho"><strong>{balance_chirho}</strong> credits - {owner_chirho} / {kind_chirho}</p>"#,
            r#"<p class="staleness-chirho" data-projection-verdict-chirho="{verdict_chirho}""#,
            r#" data-projection-descriptor-chirho="{descriptor_chirho}""#,
            r#" data-projection-family-chirho="{family_chirho}""#,
            r#" data-projection-seq-chirho="{source_seq_chirho}""#,
            r#" data-projection-hlc-physical-chirho="{hlc_physical_chirho}""#,
            r#" data-projection-hlc-logical-chirho="{hlc_logical_chirho}""#,
            r#" data-projection-prefix-chirho="{prefix_chirho}""#,
            r#" data-projection-state-chirho="{state_chirho}">{verdict_detail_chirho}</p>"#,
            r#"<form method="post" action="/app-chirho/credits-demo-chirho/spend-chirho">"#,
            r#"<label>Item <select name="item_chirho"><option value="render-run-chirho">render-run-chirho</option></select></label>"#,
            r#"<label>Concurrency token <input name="concurrency_token_chirho" pattern="[0-9a-f]{{64}}" required></label>"#,
            r#"<button type="submit">Spend</button></form></main></body></html>"#
        ),
        balance_chirho = row_chirho.account_net_chirho,
        owner_chirho = owner_chirho,
        kind_chirho = kind_chirho,
        verdict_chirho = verdict_chirho,
        descriptor_chirho = descriptor_chirho,
        family_chirho = family_chirho,
        source_seq_chirho = source_seq_chirho,
        hlc_physical_chirho = hlc_physical_chirho,
        hlc_logical_chirho = hlc_logical_chirho,
        prefix_chirho = prefix_chirho,
        state_chirho = state_chirho,
        verdict_detail_chirho = verdict_detail_chirho,
    )
}

fn render_read_refusal_chirho(verdict_chirho: &str, reason_chirho: &str) -> String {
    format!(
        concat!(
            r#"<section data-credits-read-chirho="{verdict_chirho}">"#,
            r#"<h2>Credits unavailable</h2><p>{reason_chirho}</p></section>"#
        ),
        verdict_chirho = verdict_chirho,
        reason_chirho = reason_chirho,
    )
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::types_chirho::published_projection_read_chirho::{
        AccountIdV1Chirho, AccountNetProjectionViewV1Chirho,
        PublishedProjectionClassifierRefusalV2Chirho, PublishedProjectionCostClassV2Chirho,
        PublishedProjectionEvidenceV2Chirho, PublishedProjectionGateRefusalV2Chirho,
        PublishedProjectionHlcV2Chirho, ACCOUNT_NET_PROJECTION_VIEW_SCHEMA_V1_CHIRHO,
        PUBLISHED_PROJECTION_READ_RESPONSE_SCHEMA_V2_CHIRHO,
    };

    const VIEWER_PRINCIPAL_CHIRHO: &str = "user/0123456789abcdef";
    const OTHER_PRINCIPAL_CHIRHO: &str = "user/fedcba9876543210";

    fn evidence_chirho() -> PublishedProjectionEvidenceV2Chirho {
        PublishedProjectionEvidenceV2Chirho {
            descriptor_ref_chirho: "d".repeat(64),
            source_family_id_chirho: "credits-source-chirho".to_string(),
            source_seq_chirho: 19,
            source_hlc_chirho: PublishedProjectionHlcV2Chirho {
                physical_ms_chirho: 7,
                logical_chirho: 1,
            },
            signed_prefix_digest_chirho: "a".repeat(64),
            state_digest_chirho: "b".repeat(64),
        }
    }

    fn servable_response_chirho(
        outcome_chirho: PublishedProjectionVerdictV2Chirho,
    ) -> PublishedProjectionReadResponseV2Chirho {
        PublishedProjectionReadResponseV2Chirho {
            schema_chirho: PUBLISHED_PROJECTION_READ_RESPONSE_SCHEMA_V2_CHIRHO.to_string(),
            viewer_principal_chirho: VIEWER_PRINCIPAL_CHIRHO.to_string(),
            cost_class_chirho: Some(PublishedProjectionCostClassV2Chirho::StandingWriteRateChirho),
            outcome_chirho,
            view_chirho: Some(
                serde_json::to_value(AccountNetProjectionViewV1Chirho {
                    schema_chirho: ACCOUNT_NET_PROJECTION_VIEW_SCHEMA_V1_CHIRHO.to_string(),
                    rows_chirho: vec![
                        AccountNetProjectionRowV1Chirho {
                            account_chirho: AccountIdV1Chirho {
                                owner_chirho: VIEWER_PRINCIPAL_CHIRHO.to_string(),
                                kind_id_chirho: BALANCE_KIND_ID_CHIRHO.to_string(),
                            },
                            account_net_chirho: 740,
                        },
                        AccountNetProjectionRowV1Chirho {
                            account_chirho: AccountIdV1Chirho {
                                owner_chirho: OTHER_PRINCIPAL_CHIRHO.to_string(),
                                kind_id_chirho: BALANCE_KIND_ID_CHIRHO.to_string(),
                            },
                            account_net_chirho: 10,
                        },
                    ],
                })
                .unwrap(),
            ),
        }
    }

    #[test]
    fn fresh_and_degraded_render_the_verdict_without_local_lag_arithmetic_chirho() {
        let fresh_chirho = render_balance_chirho(&servable_response_chirho(
            PublishedProjectionVerdictV2Chirho::FreshChirho {
                evidence_chirho: evidence_chirho(),
                lag_ms_chirho: 0,
            },
        ));
        assert!(fresh_chirho.contains("fresh-chirho; source seq 19; lag 0 ms"));
        assert!(fresh_chirho.contains(">740</strong> credits"));
        assert!(fresh_chirho.contains(VIEWER_PRINCIPAL_CHIRHO));
        assert!(fresh_chirho.contains(&format!(
            "data-projection-descriptor-chirho=\"{}\"",
            "d".repeat(64)
        )));
        assert!(fresh_chirho.contains("data-projection-family-chirho=\"credits-source-chirho\""));
        assert!(fresh_chirho.contains("data-projection-seq-chirho=\"19\""));
        assert!(fresh_chirho.contains("data-projection-hlc-physical-chirho=\"7\""));
        assert!(fresh_chirho.contains("data-projection-hlc-logical-chirho=\"1\""));
        assert!(fresh_chirho.contains(&format!(
            "data-projection-prefix-chirho=\"{}\"",
            "a".repeat(64)
        )));
        assert!(fresh_chirho.contains(&format!(
            "data-projection-state-chirho=\"{}\"",
            "b".repeat(64)
        )));
        assert!(!fresh_chirho.contains(OTHER_PRINCIPAL_CHIRHO));
        assert_eq!(
            fresh_chirho,
            include_str!(
                "../../fixtures_chirho/node-expected-chirho/render_balance_fresh_output_chirho.html"
            )
        );

        let degraded_chirho = render_balance_chirho(&servable_response_chirho(
            PublishedProjectionVerdictV2Chirho::DegradedChirho {
                evidence_chirho: evidence_chirho(),
                lag_ms_chirho: 8,
                max_lag_ms_chirho: 20,
            },
        ));
        assert!(degraded_chirho.contains("degraded-chirho; source seq 19; lag 8 ms"));
        assert!(degraded_chirho.contains("contract max 20 ms"));
    }

    #[test]
    fn both_refusal_variants_render_bounded_partials_without_view_data_chirho() {
        let classifier_chirho = PublishedProjectionReadResponseV2Chirho {
            schema_chirho: PUBLISHED_PROJECTION_READ_RESPONSE_SCHEMA_V2_CHIRHO.to_string(),
            viewer_principal_chirho: VIEWER_PRINCIPAL_CHIRHO.to_string(),
            cost_class_chirho: Some(PublishedProjectionCostClassV2Chirho::StandingWriteRateChirho),
            outcome_chirho: PublishedProjectionVerdictV2Chirho::ClassifierRefusedChirho {
                refusal_chirho:
                    PublishedProjectionClassifierRefusalV2Chirho::StaleBeyondContractChirho {
                        lag_ms_chirho: 40,
                        max_lag_ms_chirho: 20,
                    },
            },
            view_chirho: None,
        };
        let classifier_html_chirho = render_balance_chirho(&classifier_chirho);
        assert!(classifier_html_chirho.contains("classifier-refused-chirho"));
        assert!(classifier_html_chirho.contains("stale-beyond-contract-chirho"));
        assert!(!classifier_html_chirho.contains("40"));

        let effect_cut_chirho = PublishedProjectionReadResponseV2Chirho {
            schema_chirho: PUBLISHED_PROJECTION_READ_RESPONSE_SCHEMA_V2_CHIRHO.to_string(),
            viewer_principal_chirho: VIEWER_PRINCIPAL_CHIRHO.to_string(),
            cost_class_chirho: Some(PublishedProjectionCostClassV2Chirho::StandingWriteRateChirho),
            outcome_chirho: PublishedProjectionVerdictV2Chirho::ClassifierRefusedChirho {
                refusal_chirho: PublishedProjectionClassifierRefusalV2Chirho::EffectCutBehindChirho,
            },
            view_chirho: None,
        };
        let effect_cut_html_chirho = render_balance_chirho(&effect_cut_chirho);
        assert!(effect_cut_html_chirho.contains("classifier-refused-chirho"));
        assert!(effect_cut_html_chirho.contains("effect-cut-behind-chirho"));
        assert!(!effect_cut_html_chirho.contains("750"));

        let gate_chirho = PublishedProjectionReadResponseV2Chirho {
            schema_chirho: PUBLISHED_PROJECTION_READ_RESPONSE_SCHEMA_V2_CHIRHO.to_string(),
            viewer_principal_chirho: VIEWER_PRINCIPAL_CHIRHO.to_string(),
            cost_class_chirho: None,
            outcome_chirho: PublishedProjectionVerdictV2Chirho::GateRefusedChirho {
                refusal_chirho: PublishedProjectionGateRefusalV2Chirho::ProjectionUnknownChirho,
            },
            view_chirho: None,
        };
        let gate_html_chirho = render_balance_chirho(&gate_chirho);
        assert!(gate_html_chirho.contains("gate-refused-chirho"));
        assert!(gate_html_chirho.contains("projection-unknown-chirho"));
    }

    #[test]
    fn served_balance_form_contains_no_caller_amount_authority_chirho() {
        let html_chirho = render_balance_chirho(&servable_response_chirho(
            PublishedProjectionVerdictV2Chirho::FreshChirho {
                evidence_chirho: evidence_chirho(),
                lag_ms_chirho: 0,
            },
        ));
        assert!(html_chirho.contains("name=\"item_chirho\""));
        assert!(html_chirho.contains("name=\"concurrency_token_chirho\""));
        assert!(!html_chirho.contains("amount"));
        assert!(!html_chirho.contains("report-run-chirho"));
    }

    #[test]
    fn missing_viewer_row_refuses_without_leaking_another_account_chirho() {
        let mut response_chirho =
            servable_response_chirho(PublishedProjectionVerdictV2Chirho::FreshChirho {
                evidence_chirho: evidence_chirho(),
                lag_ms_chirho: 0,
            });
        response_chirho.viewer_principal_chirho = "user/aaaaaaaaaaaaaaaa".to_string();

        let html_chirho = render_balance_chirho(&response_chirho);
        assert!(html_chirho.contains("balance-coordinate-missing-chirho"));
        assert!(!html_chirho.contains(VIEWER_PRINCIPAL_CHIRHO));
        assert!(!html_chirho.contains(OTHER_PRINCIPAL_CHIRHO));
        assert!(!html_chirho.contains("740"));
        assert!(!html_chirho.contains("10"));
    }
}
