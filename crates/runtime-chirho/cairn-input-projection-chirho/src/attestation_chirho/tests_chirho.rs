// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

const HASH_CHIRHO: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn attestation_chirho() -> InputSchemaAttestationChirho {
    InputSchemaAttestationChirho {
        schema_chirho: INPUT_SCHEMA_ATTESTATION_SCHEMA_CHIRHO.to_string(),
        projected_schema_hash_chirho: HashChirho(HASH_CHIRHO.to_string()),
    }
}

#[test]
fn canonical_attestation_bytes_are_pinned_chirho() {
    let bytes_chirho =
        canonical_input_schema_attestation_bytes_chirho(&attestation_chirho()).unwrap();
    assert_eq!(
        bytes_chirho,
        br#"{"schema_chirho":"input-schema-attestation-v1-chirho","projected_schema_hash_chirho":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#
    );
    assert_eq!(
        parse_canonical_input_schema_attestation_chirho(&bytes_chirho).unwrap(),
        attestation_chirho()
    );
}

#[test]
fn malformed_noncanonical_and_unknown_attestations_fail_chirho() {
    for bytes_chirho in [
        br#"{"schema_chirho":"input-schema-attestation-v1-chirho","projected_schema_hash_chirho":"ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}"#.as_slice(),
        br#"{"projected_schema_hash_chirho":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","schema_chirho":"input-schema-attestation-v1-chirho"}"#.as_slice(),
        br#"{"schema_chirho":"input-schema-attestation-v1-chirho","projected_schema_hash_chirho":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","extra_chirho":true}"#.as_slice(),
        br#" {"schema_chirho":"input-schema-attestation-v1-chirho","projected_schema_hash_chirho":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#.as_slice(),
    ] {
        assert!(parse_canonical_input_schema_attestation_chirho(bytes_chirho).is_err());
    }
}
