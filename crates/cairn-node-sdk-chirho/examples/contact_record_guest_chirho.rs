// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Brick-A guest node #1 (PURE): turns the M37.1 PII-safe ingress envelope into a SAFE durable
//! contact record and wraps it in a scoped WriteStore request. By the time this runs, `serve`
//! (input_mode = PrivateBlobRefChirho) has already crypto-shredded the raw POST body into a private
//! blob, so this node sees ONLY the `app-private-input-ref-v1-chirho` envelope (a safe ref + an
//! opaque subject) — never the name/email/message. It emits only safe metadata, so nothing
//! downstream (reify, CAS, audit) ever carries PII.

use base64::{engine::general_purpose::STANDARD as BASE64_CHIRHO, Engine as _};
use serde::{Deserialize, Serialize};
use std::string::String;
use std::vec::Vec;

/// The M37.1 ingress envelope (the only thing an input_mode = PrivateBlobRefChirho route hands the
/// DAG). `blob_chirho` is the opaque safe ref to the crypto-shredded private blob — passed through,
/// never interpreted here.
#[derive(Deserialize)]
struct PrivateInputEnvelopeChirho {
    #[serde(default)]
    schema_chirho: String,
    #[serde(default)]
    subject_chirho: String,
    #[serde(default)]
    blob_chirho: serde_json::Value,
}

/// The SAFE durable contact record — safe ref + opaque subject only, NO PII.
#[derive(Serialize)]
struct ContactRecordChirho {
    schema_chirho: &'static str,
    status_chirho: &'static str,
    subject_chirho: String,
    blob_chirho: serde_json::Value,
}

/// The scoped WriteStore request understood by the cairn effect layer. `key_chirho` is derived
/// from the safe ciphertext hash, so each submission gets a stable, non-PII key.
#[derive(Serialize)]
struct ScopedWriteStoreRequestChirho {
    schema_chirho: &'static str,
    key_chirho: String,
    value_base64_chirho: String,
}

fn contact_record_impl_chirho(input_chirho: &[u8]) -> Vec<u8> {
    let envelope_chirho = match serde_json::from_slice::<PrivateInputEnvelopeChirho>(input_chirho) {
        Ok(envelope_chirho) => envelope_chirho,
        Err(_error_chirho) => return error_record_chirho("invalid private-input envelope"),
    };
    // Guardrail: refuse anything that is not the PII-safe ingress envelope, so raw POST bytes can
    // never flow through this node into durable state.
    if envelope_chirho.schema_chirho != "app-private-input-ref-v1-chirho" {
        return error_record_chirho(
            "unexpected input schema (expected the private-input ref envelope)",
        );
    }
    let record_chirho = ContactRecordChirho {
        schema_chirho: "contact-record-v1-chirho",
        status_chirho: "received",
        subject_chirho: envelope_chirho.subject_chirho,
        blob_chirho: envelope_chirho.blob_chirho.clone(),
    };
    let record_bytes_chirho = match serde_json::to_vec(&record_chirho) {
        Ok(record_bytes_chirho) => record_bytes_chirho,
        Err(_error_chirho) => return error_record_chirho("encode failed"),
    };
    let Some(ciphertext_chirho) = envelope_chirho
        .blob_chirho
        .get("ciphertext_chirho")
        .and_then(|ciphertext_chirho| ciphertext_chirho.as_str())
    else {
        return error_record_chirho("missing private blob ciphertext hash");
    };
    let write_request_chirho = ScopedWriteStoreRequestChirho {
        schema_chirho: "scoped-write-store-v1-chirho",
        key_chirho: format!("contacts-chirho/{ciphertext_chirho}"),
        value_base64_chirho: BASE64_CHIRHO.encode(record_bytes_chirho),
    };
    serde_json::to_vec(&write_request_chirho)
        .unwrap_or_else(|_| error_record_chirho("encode write request failed"))
}

fn error_record_chirho(detail_chirho: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema_chirho": "contact-record-v1-chirho",
        "status_chirho": "error",
        "detail_chirho": detail_chirho,
    }))
    .unwrap_or_default()
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(contact_record_chirho, contact_record_impl_chirho);
