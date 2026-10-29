// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use serde::{Deserialize, Serialize};

/// The schema tag stamped into every durable order record.
pub const ORDER_RECORD_SCHEMA_CHIRHO: &str = "order-record-v1-chirho";

/// One line of an order: a menu item by name and how many of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderLineV1Chirho {
    pub name_chirho: String,
    pub qty_chirho: u32,
}

/// The raw order as it arrives from the world (untrusted): a table and its lines. A dine-in order,
/// so it carries no PII — just a table number and item names (hence the route runs in plain mode).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderFormV1Chirho {
    #[serde(default)]
    pub table_chirho: u32,
    #[serde(default)]
    pub items_chirho: Vec<OrderLineV1Chirho>,
}

/// The durable order record — also the blessed reify node's output, hence `render_confirmation`'s
/// input. `status_chirho` is "received" for an accepted order or "rejected" for one that failed
/// validation. Pricing is deliberately absent in v0: prices bind to the menu stone, which awaits
/// pin-threading (the same gated feature the menu page needs), and a price must never be trusted
/// from the client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderRecordV1Chirho {
    pub schema_chirho: String,
    pub status_chirho: String,
    pub order_ref_chirho: String,
    pub table_chirho: u32,
    pub items_chirho: Vec<OrderLineV1Chirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail_chirho: Option<String>,
}
