// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Render Descriptor-D's typed terminal without inventing price, payer, or refund claims.
//!
//! Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md`.

use crate::types_chirho::postgres_effect_terminal_v1_chirho::{
    EffectTerminalDispositionV1Chirho, PostgresEffectTerminalV1Chirho,
};
use crate::types_chirho::reversible_postgres_request_v1_chirho::FIXED_SPEND_ITEM_CHIRHO;
use cairn_node_templating_chirho::escape_html_chirho;

pub fn render_spend_terminal_chirho(terminal_chirho: &PostgresEffectTerminalV1Chirho) -> String {
    match &terminal_chirho.disposition_chirho {
        EffectTerminalDispositionV1Chirho::CommittedChirho { result_ref_chirho } => format!(
            concat!(
                r#"<section class="spend-committed-chirho"><h2>Spend committed</h2>"#,
                r#"<p><code>{item_chirho}</code> reached terminal seq {terminal_seq_chirho}.</p>"#,
                r#"<p>Charge and payer came from verified signed policy, not this request.</p>"#,
                r#"<p>provider result: <code>{result_ref_chirho}</code></p>"#,
                r#"<p><a href="/app-chirho/credits-demo-chirho">view balance</a></p></section>"#,
            ),
            item_chirho = FIXED_SPEND_ITEM_CHIRHO,
            terminal_seq_chirho = terminal_chirho.terminal_seq_chirho,
            result_ref_chirho = escape_html_chirho(result_ref_chirho),
        ),
        EffectTerminalDispositionV1Chirho::DefiniteNoEffectChirho => format!(
            concat!(
                r#"<section class="spend-no-effect-chirho"><h2>Spend not committed</h2>"#,
                r#"<p>Descriptor-D closed at terminal seq {terminal_seq_chirho} with definite no effect.</p>"#,
                r#"<p><a href="/app-chirho/credits-demo-chirho">view balance</a></p></section>"#,
            ),
            terminal_seq_chirho = terminal_chirho.terminal_seq_chirho,
        ),
    }
}

pub fn render_spend_transport_refusal_chirho() -> String {
    concat!(
        r#"<section class="spend-refused-chirho"><h2>Spend refused</h2>"#,
        r#"<p>reason: <code>invalid-terminal-transport-chirho</code></p></section>"#,
    )
    .to_string()
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::types_chirho::postgres_effect_terminal_v1_chirho::EffectHlcV1Chirho;

    fn terminal_chirho(
        disposition_chirho: EffectTerminalDispositionV1Chirho,
    ) -> PostgresEffectTerminalV1Chirho {
        PostgresEffectTerminalV1Chirho {
            schema_chirho: "descriptor-d-postgres-effect-response-v1-chirho".to_string(),
            intent_ref_chirho: "a".repeat(64),
            hold_seq_chirho: 8,
            hold_record_digest_chirho: "b".repeat(64),
            hold_hlc_chirho: EffectHlcV1Chirho {
                physical_ms_chirho: 10,
                logical_chirho: 0,
            },
            terminal_seq_chirho: 9,
            terminal_record_digest_chirho: "c".repeat(64),
            terminal_hlc_chirho: EffectHlcV1Chirho {
                physical_ms_chirho: 11,
                logical_chirho: 0,
            },
            outcome_ref_chirho: "d".repeat(64),
            disposition_chirho,
        }
    }

    #[test]
    fn committed_disposition_is_the_only_success_claim_chirho() {
        let committed_chirho = render_spend_terminal_chirho(&terminal_chirho(
            EffectTerminalDispositionV1Chirho::CommittedChirho {
                result_ref_chirho: "e".repeat(64),
            },
        ));
        assert!(committed_chirho.contains("Spend committed"));
        assert!(committed_chirho.contains("verified signed policy"));
        assert!(!committed_chirho.contains("amount"));

        let no_effect_chirho = render_spend_terminal_chirho(&terminal_chirho(
            EffectTerminalDispositionV1Chirho::DefiniteNoEffectChirho,
        ));
        assert!(no_effect_chirho.contains("Spend not committed"));
        assert!(!no_effect_chirho.contains("Spend committed"));
    }
}
