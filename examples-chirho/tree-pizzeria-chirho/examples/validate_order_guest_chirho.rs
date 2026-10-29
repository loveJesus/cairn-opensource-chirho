// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Boundary entry for the validate_order role (v0, generated-by-hand; the toolchain will emit this).
//! Plain input mode: it receives the raw POST body (JSON `OrderFormV1Chirho`). It is PURE — it
//! validates the order and wraps the durable record in a scoped WriteStore request keyed by the
//! order's content hash, so the blessed `save_order` reify node persists it under the `orders-chirho`
//! namespace. A dine-in order carries no PII (just a table number and item names), so the route runs
//! in plain mode; a delivery order with a name/address would use private-blob mode like the contact
//! app.

use base64::{engine::general_purpose::STANDARD as BASE64_CHIRHO, Engine as _};
use serde::Serialize;
use tree_pizzeria_chirho::implementations_chirho::validate_order_chirho::{
    order_ref_chirho, validate_order_chirho as validate_order_impl_fn_chirho,
};
use tree_pizzeria_chirho::types_chirho::order_v1_chirho::{
    OrderFormV1Chirho, OrderRecordV1Chirho, ORDER_RECORD_SCHEMA_CHIRHO,
};

/// The scoped WriteStore request understood by the cairn effect layer. `key_chirho` stays inside the
/// reify node's `write-store:orders-chirho` capability prefix, so the write cannot escape its scope.
#[derive(Serialize)]
struct ScopedWriteStoreRequestChirho {
    schema_chirho: &'static str,
    key_chirho: String,
    value_base64_chirho: String,
}

fn validate_order_impl_chirho(input_chirho: &[u8]) -> Vec<u8> {
    let order_ref_value_chirho = order_ref_chirho(input_chirho);
    let record_chirho = match serde_json::from_slice::<OrderFormV1Chirho>(input_chirho) {
        Ok(form_chirho) => validate_order_impl_fn_chirho(&form_chirho, &order_ref_value_chirho),
        Err(_error_chirho) => OrderRecordV1Chirho {
            schema_chirho: ORDER_RECORD_SCHEMA_CHIRHO.to_string(),
            status_chirho: "rejected".to_string(),
            order_ref_chirho: order_ref_value_chirho.clone(),
            table_chirho: 0,
            items_chirho: Vec::new(),
            detail_chirho: Some("we could not read your order".to_string()),
        },
    };
    let value_bytes_chirho = match serde_json::to_vec(&record_chirho) {
        Ok(value_bytes_chirho) => value_bytes_chirho,
        Err(_error_chirho) => return Vec::new(),
    };
    let request_chirho = ScopedWriteStoreRequestChirho {
        schema_chirho: "scoped-write-store-v1-chirho",
        key_chirho: format!("orders-chirho/{order_ref_value_chirho}"),
        value_base64_chirho: BASE64_CHIRHO.encode(value_bytes_chirho),
    };
    serde_json::to_vec(&request_chirho).unwrap_or_default()
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(validate_order_chirho, validate_order_impl_chirho);
