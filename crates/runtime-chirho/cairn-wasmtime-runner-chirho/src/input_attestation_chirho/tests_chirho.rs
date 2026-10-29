// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use cairn_input_projection_chirho::attestation_chirho::INPUT_SCHEMA_ATTESTATION_SCHEMA_CHIRHO;

const HASH_CHIRHO: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn encode_u32_leb_chirho(mut value_chirho: u32, output_chirho: &mut Vec<u8>) {
    loop {
        let mut byte_chirho = (value_chirho & 0x7f) as u8;
        value_chirho >>= 7;
        if value_chirho != 0 {
            byte_chirho |= 0x80;
        }
        output_chirho.push(byte_chirho);
        if value_chirho == 0 {
            break;
        }
    }
}

fn wasm_with_sections_chirho(sections_chirho: &[(&str, &[u8])]) -> Vec<u8> {
    let mut wasm_chirho = b"\0asm\x01\0\0\0".to_vec();
    for (name_chirho, payload_chirho) in sections_chirho {
        let mut body_chirho = Vec::new();
        encode_u32_leb_chirho(name_chirho.len() as u32, &mut body_chirho);
        body_chirho.extend_from_slice(name_chirho.as_bytes());
        body_chirho.extend_from_slice(payload_chirho);
        wasm_chirho.push(0);
        encode_u32_leb_chirho(body_chirho.len() as u32, &mut wasm_chirho);
        wasm_chirho.extend_from_slice(&body_chirho);
    }
    wasm_chirho
}

fn attestation_bytes_chirho() -> Vec<u8> {
    format!(
        "{{\"schema_chirho\":\"{INPUT_SCHEMA_ATTESTATION_SCHEMA_CHIRHO}\",\"projected_schema_hash_chirho\":\"{HASH_CHIRHO}\"}}"
    )
    .into_bytes()
}

#[test]
fn reads_exactly_one_canonical_input_attestation_chirho() {
    let bytes_chirho = attestation_bytes_chirho();
    let wasm_chirho = wasm_with_sections_chirho(&[
        ("unrelated-chirho", b"ignored"),
        (INPUT_SCHEMA_CUSTOM_SECTION_CHIRHO, &bytes_chirho),
    ]);
    let actual_chirho = read_input_schema_attestation_chirho(&wasm_chirho).unwrap();
    assert_eq!(actual_chirho.projected_schema_hash_chirho.0, HASH_CHIRHO);
}

#[test]
fn missing_duplicate_malformed_and_noncanonical_sections_fail_chirho() {
    let bytes_chirho = attestation_bytes_chirho();
    let reordered_chirho = format!(
        "{{\"projected_schema_hash_chirho\":\"{HASH_CHIRHO}\",\"schema_chirho\":\"{INPUT_SCHEMA_ATTESTATION_SCHEMA_CHIRHO}\"}}"
    );
    for wasm_chirho in [
        wasm_with_sections_chirho(&[]),
        wasm_with_sections_chirho(&[
            (INPUT_SCHEMA_CUSTOM_SECTION_CHIRHO, &bytes_chirho),
            (INPUT_SCHEMA_CUSTOM_SECTION_CHIRHO, &bytes_chirho),
        ]),
        wasm_with_sections_chirho(&[(INPUT_SCHEMA_CUSTOM_SECTION_CHIRHO, b"not-json")]),
        wasm_with_sections_chirho(&[(
            INPUT_SCHEMA_CUSTOM_SECTION_CHIRHO,
            reordered_chirho.as_bytes(),
        )]),
    ] {
        assert!(read_input_schema_attestation_chirho(&wasm_chirho).is_err());
    }
}
