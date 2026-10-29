// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Guest-side exact parser for Descriptor-D's terminal response transport.
//!
//! Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md`.

use serde::{Deserialize, Serialize};

pub const POSTGRES_EFFECT_TERMINAL_SCHEMA_V1_CHIRHO: &str =
    "descriptor-d-postgres-effect-response-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectHlcV1Chirho {
    pub physical_ms_chirho: u64,
    pub logical_chirho: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", deny_unknown_fields)]
pub enum EffectTerminalDispositionV1Chirho {
    #[serde(rename = "committed-chirho")]
    CommittedChirho { result_ref_chirho: String },
    #[serde(rename = "definite-no-effect-chirho")]
    DefiniteNoEffectChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresEffectTerminalV1Chirho {
    pub schema_chirho: String,
    pub intent_ref_chirho: String,
    pub hold_seq_chirho: u64,
    pub hold_record_digest_chirho: String,
    pub hold_hlc_chirho: EffectHlcV1Chirho,
    pub terminal_seq_chirho: u64,
    pub terminal_record_digest_chirho: String,
    pub terminal_hlc_chirho: EffectHlcV1Chirho,
    pub outcome_ref_chirho: String,
    pub disposition_chirho: EffectTerminalDispositionV1Chirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostgresEffectTerminalWireErrorChirho {
    MalformedChirho,
    NonCanonicalChirho,
    UnsupportedSchemaChirho,
    InvalidCoordinateChirho,
    TerminalBeforeHoldChirho,
}

pub fn parse_exact_postgres_effect_terminal_chirho(
    bytes_chirho: &[u8],
) -> Result<PostgresEffectTerminalV1Chirho, PostgresEffectTerminalWireErrorChirho> {
    let terminal_chirho: PostgresEffectTerminalV1Chirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_error_chirho| PostgresEffectTerminalWireErrorChirho::MalformedChirho)?;
    let canonical_chirho = serde_json::to_vec(&terminal_chirho)
        .map_err(|_error_chirho| PostgresEffectTerminalWireErrorChirho::MalformedChirho)?;
    if canonical_chirho != bytes_chirho {
        return Err(PostgresEffectTerminalWireErrorChirho::NonCanonicalChirho);
    }
    if terminal_chirho.schema_chirho != POSTGRES_EFFECT_TERMINAL_SCHEMA_V1_CHIRHO {
        return Err(PostgresEffectTerminalWireErrorChirho::UnsupportedSchemaChirho);
    }
    if ![
        terminal_chirho.intent_ref_chirho.as_str(),
        terminal_chirho.hold_record_digest_chirho.as_str(),
        terminal_chirho.terminal_record_digest_chirho.as_str(),
        terminal_chirho.outcome_ref_chirho.as_str(),
    ]
    .into_iter()
    .all(is_canonical_digest_chirho)
    {
        return Err(PostgresEffectTerminalWireErrorChirho::InvalidCoordinateChirho);
    }
    if let EffectTerminalDispositionV1Chirho::CommittedChirho { result_ref_chirho } =
        &terminal_chirho.disposition_chirho
    {
        if !is_canonical_digest_chirho(result_ref_chirho) {
            return Err(PostgresEffectTerminalWireErrorChirho::InvalidCoordinateChirho);
        }
    }
    if terminal_chirho.terminal_seq_chirho <= terminal_chirho.hold_seq_chirho {
        return Err(PostgresEffectTerminalWireErrorChirho::TerminalBeforeHoldChirho);
    }
    Ok(terminal_chirho)
}

fn is_canonical_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn checked_in_committed_terminal_is_exact_and_typed_chirho() {
        let bytes_chirho = include_bytes!(
            "../../fixtures_chirho/node-inputs-chirho/render_spend_terminal_committed_chirho.json"
        );
        let terminal_chirho = parse_exact_postgres_effect_terminal_chirho(bytes_chirho).unwrap();
        assert!(matches!(
            terminal_chirho.disposition_chirho,
            EffectTerminalDispositionV1Chirho::CommittedChirho { .. }
        ));

        let mut noncanonical_chirho = bytes_chirho.to_vec();
        noncanonical_chirho.push(b'\n');
        assert_eq!(
            parse_exact_postgres_effect_terminal_chirho(&noncanonical_chirho),
            Err(PostgresEffectTerminalWireErrorChirho::NonCanonicalChirho)
        );
    }
}
