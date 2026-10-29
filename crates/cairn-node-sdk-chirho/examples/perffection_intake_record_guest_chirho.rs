// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Pure perffection intake node: turns a private ingress envelope into a safe durable prospect ref.

use base64::{engine::general_purpose::STANDARD as BASE64_CHIRHO, Engine as _};
use serde::{Deserialize, Serialize};
use std::string::String;
use std::vec::Vec;

#[derive(Deserialize)]
struct PrivateInputEnvelopeChirho {
    #[serde(default)]
    schema_chirho: String,
    #[serde(default)]
    subject_chirho: String,
    #[serde(default)]
    blob_chirho: serde_json::Value,
}

#[derive(Serialize)]
struct PerffectionIntakeRecordChirho {
    schema_chirho: &'static str,
    status_chirho: &'static str,
    source_chirho: &'static str,
    subject_chirho: String,
    blob_chirho: serde_json::Value,
}

#[derive(Serialize)]
struct ScopedWriteStoreRequestChirho {
    schema_chirho: &'static str,
    key_chirho: String,
    value_base64_chirho: String,
}

fn perffection_intake_record_impl_chirho(input_chirho: &[u8]) -> Vec<u8> {
    let envelope_chirho = match serde_json::from_slice::<PrivateInputEnvelopeChirho>(input_chirho) {
        Ok(envelope_chirho) => envelope_chirho,
        Err(_error_chirho) => return error_record_chirho("invalid private-input envelope"),
    };
    if envelope_chirho.schema_chirho != "app-private-input-ref-v1-chirho" {
        return error_record_chirho(
            "unexpected input schema (expected the private-input ref envelope)",
        );
    }
    let Some(ciphertext_chirho) = envelope_chirho
        .blob_chirho
        .get("ciphertext_chirho")
        .and_then(|ciphertext_chirho| ciphertext_chirho.as_str())
        .map(|ciphertext_chirho| ciphertext_chirho.to_string())
    else {
        return error_record_chirho("missing private blob ciphertext hash");
    };
    let record_chirho = PerffectionIntakeRecordChirho {
        schema_chirho: "perffection-intake-record-v1-chirho",
        status_chirho: "received",
        source_chirho: "perffection-cairn-dogfood-mvp-chirho",
        subject_chirho: envelope_chirho.subject_chirho,
        blob_chirho: envelope_chirho.blob_chirho,
    };
    let record_bytes_chirho = match serde_json::to_vec(&record_chirho) {
        Ok(record_bytes_chirho) => record_bytes_chirho,
        Err(_error_chirho) => return error_record_chirho("encode failed"),
    };
    let write_request_chirho = ScopedWriteStoreRequestChirho {
        schema_chirho: "scoped-write-store-v1-chirho",
        key_chirho: format!("perffection-intake-chirho/{ciphertext_chirho}"),
        value_base64_chirho: BASE64_CHIRHO.encode(record_bytes_chirho),
    };
    serde_json::to_vec(&write_request_chirho)
        .unwrap_or_else(|_| error_record_chirho("encode write request failed"))
}

fn error_record_chirho(detail_chirho: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema_chirho": "perffection-intake-record-v1-chirho",
        "status_chirho": "error",
        "detail_chirho": detail_chirho,
    }))
    .unwrap_or_default()
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(
    perffection_intake_record_chirho,
    perffection_intake_record_impl_chirho
);
