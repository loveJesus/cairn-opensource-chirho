// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::terminal_chirho::*;
use anyhow::Result;
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;

const DIGEST_A_CHIRHO: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B_CHIRHO: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_C_CHIRHO: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const DIGEST_D_CHIRHO: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

struct FakeTerminalSignerChirho {
    root_chirho: &'static str,
}

impl EffectTerminalSignerPortChirho for FakeTerminalSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        Ok(signature_chirho(
            self.root_chirho,
            signed_content_line_chirho,
        ))
    }

    fn key_id_chirho(&self) -> String {
        format!("{}-key-chirho", self.root_chirho)
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == signature_chirho(self.root_chirho, signed_content_line_chirho)
    }
}

fn signature_chirho(root_chirho: &str, content_chirho: &str) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(root_chirho.as_bytes());
    hasher_chirho.update(content_chirho.as_bytes());
    hasher_chirho.finalize().to_hex().to_string()
}

fn digest_chirho(value_chirho: &str) -> DigestChirho {
    DigestChirho(value_chirho.to_owned())
}

fn unsigned_committed_outcome_chirho() -> EffectTerminalOutcomeChirho {
    EffectTerminalOutcomeChirho {
        schema_chirho: EFFECT_TERMINAL_OUTCOME_SCHEMA_V1_CHIRHO.to_owned(),
        intent_ref_chirho: digest_chirho(DIGEST_A_CHIRHO),
        provider_evidence_ref_chirho: digest_chirho(DIGEST_B_CHIRHO),
        disposition_chirho: EffectTerminalDispositionChirho::CommittedChirho {
            result_ref_chirho: digest_chirho(DIGEST_C_CHIRHO),
        },
        sig_chirho: String::new(),
        key_id_chirho: String::new(),
    }
}

fn signed_committed_outcome_chirho() -> EffectTerminalOutcomeChirho {
    sign_effect_terminal_outcome_chirho(
        unsigned_committed_outcome_chirho(),
        &FakeTerminalSignerChirho {
            root_chirho: "terminal-root-chirho",
        },
    )
    .unwrap()
}

#[test]
fn canonical_terminal_roundtrips_and_verifies_under_only_its_root_chirho() {
    let outcome_chirho = signed_committed_outcome_chirho();
    let line_chirho = canonical_effect_terminal_outcome_line_chirho(&outcome_chirho).unwrap();
    assert_eq!(
        effect_terminal_outcome_signed_content_line_chirho(&outcome_chirho).unwrap(),
        r#"{"schema_chirho":"effect-terminal-outcome-v1-chirho","intent_ref_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","provider_evidence_ref_chirho":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","disposition_chirho":{"kind_chirho":"committed-chirho","result_ref_chirho":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"sig_chirho":"","key_id_chirho":"terminal-root-chirho-key-chirho"}"#
    );
    assert_eq!(
        parse_canonical_effect_terminal_outcome_line_chirho(&line_chirho).unwrap(),
        outcome_chirho
    );
    let verified_chirho = verify_effect_terminal_outcome_line_chirho(
        &line_chirho,
        &FakeTerminalSignerChirho {
            root_chirho: "terminal-root-chirho",
        },
    )
    .unwrap();
    assert_eq!(verified_chirho.outcome_chirho(), &outcome_chirho);
    assert_eq!(
        parse_effect_terminal_key_chirho(verified_chirho.terminal_key_chirho()).unwrap(),
        outcome_chirho.intent_ref_chirho
    );
    assert!(matches!(
        verify_effect_terminal_outcome_line_chirho(
            &line_chirho,
            &FakeTerminalSignerChirho {
                root_chirho: "foreign-terminal-root-chirho",
            },
        ),
        Err(EffectTerminalWireErrorChirho::SignatureUnverifiedChirho)
    ));
}

#[test]
fn one_terminal_key_ignores_evidence_and_disposition_but_outcome_ref_does_not_chirho() {
    let committed_chirho = signed_committed_outcome_chirho();
    let committed_key_chirho = effect_terminal_key_chirho(&committed_chirho.intent_ref_chirho)
        .expect("valid intent ref derives the terminal key");
    let committed_ref_chirho = effect_terminal_outcome_ref_chirho(&committed_chirho).unwrap();

    let mut no_effect_chirho = unsigned_committed_outcome_chirho();
    no_effect_chirho.provider_evidence_ref_chirho = digest_chirho(DIGEST_D_CHIRHO);
    no_effect_chirho.disposition_chirho = EffectTerminalDispositionChirho::DefiniteNoEffectChirho;
    let no_effect_chirho = sign_effect_terminal_outcome_chirho(
        no_effect_chirho,
        &FakeTerminalSignerChirho {
            root_chirho: "terminal-root-chirho",
        },
    )
    .unwrap();
    assert_eq!(
        effect_terminal_key_chirho(&no_effect_chirho.intent_ref_chirho).unwrap(),
        committed_key_chirho
    );
    assert_ne!(
        effect_terminal_outcome_ref_chirho(&no_effect_chirho).unwrap(),
        committed_ref_chirho
    );

    let mut altered_signature_chirho = committed_chirho.clone();
    altered_signature_chirho.sig_chirho = DIGEST_D_CHIRHO.to_owned();
    assert_eq!(
        effect_terminal_outcome_ref_chirho(&altered_signature_chirho).unwrap(),
        committed_ref_chirho
    );
}

#[test]
fn terminal_namespace_recognizes_malformed_tails_but_parser_refuses_them_chirho() {
    for malformed_chirho in [
        EFFECT_TERMINAL_KEY_PREFIX_CHIRHO.to_owned(),
        format!("{EFFECT_TERMINAL_KEY_PREFIX_CHIRHO}XYZ"),
        format!("{EFFECT_TERMINAL_KEY_PREFIX_CHIRHO}{}", "A".repeat(64)),
        format!("{EFFECT_TERMINAL_KEY_PREFIX_CHIRHO}{}", "a".repeat(63)),
    ] {
        assert!(is_reserved_effect_terminal_key_chirho(&malformed_chirho));
        assert_eq!(
            parse_effect_terminal_key_chirho(&malformed_chirho),
            Err(EffectTerminalKeyErrorChirho::MalformedReservedChirho)
        );
    }
    assert!(!is_reserved_effect_terminal_key_chirho(
        "ordinary-key-chirho"
    ));
}

#[test]
fn terminal_parser_refuses_malleability_and_invalid_coordinates_chirho() {
    let line_chirho =
        canonical_effect_terminal_outcome_line_chirho(&signed_committed_outcome_chirho()).unwrap();
    assert!(
        parse_canonical_effect_terminal_outcome_line_chirho(&format!(" {line_chirho}")).is_err()
    );
    assert!(
        parse_canonical_effect_terminal_outcome_line_chirho(&format!("{line_chirho}\n")).is_err()
    );

    let unknown_chirho = line_chirho.replacen(
        r#"{"schema_chirho":"#,
        r#"{"unknown_chirho":1,"schema_chirho":"#,
        1,
    );
    assert!(parse_canonical_effect_terminal_outcome_line_chirho(&unknown_chirho).is_err());
    let duplicate_chirho = line_chirho.replacen(
        r#"{"schema_chirho":"effect-terminal-outcome-v1-chirho","#,
        r#"{"schema_chirho":"effect-terminal-outcome-v1-chirho","schema_chirho":"effect-terminal-outcome-v1-chirho","#,
        1,
    );
    assert!(parse_canonical_effect_terminal_outcome_line_chirho(&duplicate_chirho).is_err());

    let mut invalid_chirho = unsigned_committed_outcome_chirho();
    invalid_chirho.provider_evidence_ref_chirho = DigestChirho("XYZ".to_owned());
    assert!(matches!(
        sign_effect_terminal_outcome_chirho(
            invalid_chirho,
            &FakeTerminalSignerChirho {
                root_chirho: "terminal-root-chirho",
            },
        ),
        Err(EffectTerminalWireErrorChirho::InvalidCoordinateChirho {
            field_chirho: "provider_evidence_ref_chirho"
        })
    ));
}

#[test]
fn terminal_source_has_no_ambient_authority_chirho() {
    let source_chirho = include_str!("terminal_chirho.rs");
    for forbidden_chirho in ["std::fs", "std::env", "env::var", "std::net"] {
        assert!(
            !source_chirho.contains(forbidden_chirho),
            "terminal model gained ambient authority token {forbidden_chirho}"
        );
    }
}
